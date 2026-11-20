//! Minimal DER writer for the structures this crate produces (PKCS#8, PKCS#12).
//! Only single-byte tags are needed.

use der::asn1::ObjectIdentifier;
use der::Encode;

/// Encode a DER length.
fn encode_len(len: usize, out: &mut Vec<u8>) {
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

/// `SEQUENCE { items... }`.
pub(crate) fn sequence(items: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

/// `SET OF`, components sorted as X.690 §11.6 requires.
pub(crate) fn set_of(mut items: Vec<Vec<u8>>) -> Vec<u8> {
    items.sort_by(|a, b| {
        let n = a.len().max(b.len());
        (0..n)
            .map(|i| {
                a.get(i)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&b.get(i).copied().unwrap_or(0))
            })
            .find(|o| o.is_ne())
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    tlv(0x31, &items.concat())
}

/// `OBJECT IDENTIFIER`.
pub(crate) fn oid(o: &ObjectIdentifier) -> Vec<u8> {
    o.to_der().expect("OID encodes")
}

/// `NULL`.
pub(crate) fn null() -> Vec<u8> {
    vec![0x05, 0]
}

/// `OCTET STRING`.
pub(crate) fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

/// `INTEGER` from a small non-negative value.
pub(crate) fn integer_u64(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = Vec::new();
    if bytes[first] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[first..]);
    tlv(0x02, &content)
}

/// `BMPString` (UTF-16BE).
pub(crate) fn bmp_string(s: &str) -> Vec<u8> {
    let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
    tlv(0x1e, &bytes)
}

/// `[n] EXPLICIT` (constructed, context-specific).
pub(crate) fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_ints() {
        assert_eq!(tlv(4, &[1, 2]), vec![4, 2, 1, 2]);
        assert_eq!(tlv(4, &[0; 200])[..3], [4, 0x81, 200]);
        assert_eq!(tlv(4, &[0; 300])[..4], [4, 0x82, 1, 44]);
        assert_eq!(integer_u64(0), vec![2, 1, 0]);
        assert_eq!(integer_u64(3), vec![2, 1, 3]);
        assert_eq!(integer_u64(1024), vec![2, 2, 4, 0]);
        assert_eq!(integer_u64(128), vec![2, 2, 0, 128]);
    }
}
