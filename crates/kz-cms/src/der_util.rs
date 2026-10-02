//! Minimal DER writer and TLV reader.
//!
//! The CMS structures produced by this crate are written by hand so that the
//! output is byte-for-byte what Kalkan (a BouncyCastle fork) produces, and so
//! that existing `SignerInfo`s are carried over verbatim when a signer is
//! added to an existing message.  Only single-byte tags are needed.

use der::asn1::ObjectIdentifier;
use der::Encode;

use crate::error::{Error, Result};

pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_SET: u8 = 0x31;
/// `[0]` constructed, context-specific.
pub(crate) const TAG_CTX0: u8 = 0xa0;
/// `[1]` constructed, context-specific.
pub(crate) const TAG_CTX1: u8 = 0xa1;

// ----- writer ---------------------------------------------------------------

/// Encode a DER length.
pub(crate) fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
}

/// `tag ‖ length ‖ content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// `SEQUENCE { items... }` from already-encoded items.
pub(crate) fn sequence(items: &[&[u8]]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &items.concat())
}

/// `SET OF` from already-encoded items, sorted as X.690 §11.6 requires
/// (encodings compared as octet strings, the shorter padded with zeros).
pub(crate) fn set_of(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort_by(|a, b| der_set_cmp(a, b));
    tlv(TAG_SET, &items.concat())
}

/// X.690 §11.6 ordering of SET OF components.
pub(crate) fn der_set_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            core::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    core::cmp::Ordering::Equal
}

/// `OBJECT IDENTIFIER`.
pub(crate) fn oid(o: &ObjectIdentifier) -> Vec<u8> {
    o.to_der().expect("OID encodes")
}

/// `NULL`.
pub(crate) fn null() -> Vec<u8> {
    vec![TAG_NULL, 0]
}

/// `OCTET STRING`.
pub(crate) fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, b)
}

/// `INTEGER` from a small non-negative value.
pub(crate) fn integer_u64(v: u64) -> Vec<u8> {
    integer_be(&v.to_be_bytes())
}

/// `INTEGER` from an unsigned big-endian magnitude.
pub(crate) fn integer_be(mag: &[u8]) -> Vec<u8> {
    let first = mag.iter().position(|&b| b != 0).unwrap_or(mag.len());
    let mut content = Vec::with_capacity(mag.len() - first + 1);
    if first == mag.len() {
        content.push(0);
    } else {
        if mag[first] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(&mag[first..]);
    }
    tlv(TAG_INTEGER, &content)
}

/// `AlgorithmIdentifier { oid, NULL }` — the form Kalkan writes.
pub(crate) fn alg_id_null(o: &ObjectIdentifier) -> Vec<u8> {
    sequence(&[&oid(o), &null()])
}

/// `Attribute { type, SET OF values }` from already-encoded values.
pub(crate) fn attribute(o: &ObjectIdentifier, values: Vec<Vec<u8>>) -> Vec<u8> {
    sequence(&[&oid(o), &set_of(values)])
}

// ----- reader ---------------------------------------------------------------

/// A parsed TLV with borrowed slices.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    /// Tag byte.
    pub tag: u8,
    /// Content octets.
    pub content: &'a [u8],
    /// The whole encoding (`tag ‖ length ‖ content`).
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Parse one TLV from the start of `input`; returns it and the remainder.
    pub fn read(input: &'a [u8]) -> Result<(Tlv<'a>, &'a [u8])> {
        let err = |m: &str| Error::Structure(m.to_owned());
        let &tag = input.first().ok_or_else(|| err("unexpected end of data"))?;
        if tag & 0x1f == 0x1f {
            return Err(err("multi-byte tags are not supported"));
        }
        let &l0 = input.get(1).ok_or_else(|| err("truncated length"))?;
        let (len, hdr) = if l0 < 0x80 {
            (l0 as usize, 2)
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(err("indefinite or oversized length (BER is not accepted)"));
            }
            let lb = input.get(2..2 + n).ok_or_else(|| err("truncated length"))?;
            let mut len = 0usize;
            for &b in lb {
                len = (len << 8) | b as usize;
            }
            (len, 2 + n)
        };
        let end = hdr.checked_add(len).ok_or_else(|| err("length overflow"))?;
        if end > input.len() {
            return Err(err("truncated value"));
        }
        Ok((
            Tlv {
                tag,
                content: &input[hdr..end],
                raw: &input[..end],
            },
            &input[end..],
        ))
    }

    /// Parse exactly one TLV spanning the whole input.
    pub fn parse(input: &'a [u8]) -> Result<Tlv<'a>> {
        let (t, rest) = Self::read(input)?;
        if !rest.is_empty() {
            return Err(Error::Structure("trailing bytes after DER value".into()));
        }
        Ok(t)
    }

    /// Parse exactly one TLV with the expected tag.
    pub fn parse_tag(input: &'a [u8], tag: u8) -> Result<Tlv<'a>> {
        Self::parse(input)?.expect(tag)
    }

    /// Check the tag.
    pub fn expect(self, tag: u8) -> Result<Tlv<'a>> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(Error::Structure(format!(
                "expected tag 0x{tag:02x}, found 0x{:02x}",
                self.tag
            )))
        }
    }

    /// All children of a constructed value.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (t, r) = Tlv::read(rest)?;
            out.push(t);
            rest = r;
        }
        Ok(out)
    }

    /// Decode the content as an OID.
    pub fn oid(&self) -> Result<ObjectIdentifier> {
        self.expect(TAG_OID)?;
        ObjectIdentifier::from_bytes(self.content)
            .map_err(|e| Error::Structure(format!("bad OID: {e}")))
    }

    /// Decode a small non-negative INTEGER.
    pub fn integer_u64(&self) -> Result<u64> {
        self.expect(TAG_INTEGER)?;
        if self.content.is_empty()
            || self.content.len() > 9
            || (self.content.len() == 9 && self.content[0] != 0)
        {
            return Err(Error::Structure("INTEGER out of range".into()));
        }
        if self.content[0] & 0x80 != 0 {
            return Err(Error::Structure("negative INTEGER".into()));
        }
        Ok(self
            .content
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64))
    }
}

/// A cursor over the children of a constructed value, consuming them in order.
pub(crate) struct Cursor<'a> {
    items: Vec<Tlv<'a>>,
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(parent: &Tlv<'a>) -> Result<Self> {
        Ok(Cursor {
            items: parent.children()?,
            pos: 0,
        })
    }

    /// Next child, which must exist.
    pub fn next(&mut self, what: &str) -> Result<Tlv<'a>> {
        let t = self
            .items
            .get(self.pos)
            .copied()
            .ok_or_else(|| Error::Structure(format!("missing {what}")))?;
        self.pos += 1;
        Ok(t)
    }

    /// Next child, which must exist and carry `tag`.
    pub fn next_tag(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>> {
        self.next(what)?.expect(tag)
    }

    /// Consume the next child if it carries `tag`.
    pub fn optional(&mut self, tag: u8) -> Option<Tlv<'a>> {
        match self.items.get(self.pos) {
            Some(t) if t.tag == tag => {
                self.pos += 1;
                Some(*t)
            }
            _ => None,
        }
    }

    /// Whether all children have been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.items.len()
    }
}

/// Re-tag an encoding (e.g. `[0] IMPLICIT` signed attributes → `SET`, as
/// RFC 5652 §5.4 requires when computing the signature).
pub(crate) fn retag(raw: &[u8], tag: u8) -> Vec<u8> {
    let mut v = raw.to_vec();
    if let Some(first) = v.first_mut() {
        *first = tag;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        assert_eq!(tlv(0x04, &[1, 2, 3]), vec![4, 3, 1, 2, 3]);
        let long = vec![0u8; 300];
        let enc = tlv(0x04, &long);
        assert_eq!(&enc[..4], &[0x04, 0x82, 0x01, 0x2c]);
        let t = Tlv::parse(&enc).unwrap();
        assert_eq!(t.content.len(), 300);
    }

    #[test]
    fn integers() {
        assert_eq!(integer_u64(1), vec![2, 1, 1]);
        assert_eq!(integer_u64(0), vec![2, 1, 0]);
        assert_eq!(integer_be(&[0x80]), vec![2, 2, 0, 0x80]);
        assert_eq!(integer_be(&[0, 0, 0x7f]), vec![2, 1, 0x7f]);
        assert_eq!(
            Tlv::parse(&integer_u64(0x1234))
                .unwrap()
                .integer_u64()
                .unwrap(),
            0x1234
        );
    }

    #[test]
    fn set_sorting_is_by_full_encoding() {
        // Longer encodings (bigger length byte) sort later even if their content starts lower.
        let a = tlv(0x30, &[0x09]);
        let b = tlv(0x30, &[0x01, 0x02]);
        let s = set_of(vec![b.clone(), a.clone()]);
        assert_eq!(s, tlv(0x31, &[a, b].concat()));
    }

    #[test]
    fn rejects_indefinite_length() {
        assert!(Tlv::parse(&[0x30, 0x80, 0, 0]).is_err());
    }
}
