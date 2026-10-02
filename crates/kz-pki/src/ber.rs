//! Minimal BER reader.
//!
//! PKCS#12 files written by BouncyCastle/Kalkan use BER with indefinite lengths
//! (`30 80 ... 00 00`) and constructed OCTET STRINGs, which the strict `der`
//! crate refuses. This module parses such input into a small tree and can
//! re-encode any node as DER so that `der`-based types can be used on it.

use crate::error::{Error, Result};

/// A parsed BER node. Tags are limited to the single-byte form (tag numbers < 31),
/// which covers all of PKCS#12/X.509.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Primitive encoding: a tag byte and raw contents.
    Primitive {
        /// Identifier octet.
        tag: u8,
        /// Contents octets.
        bytes: Vec<u8>,
    },
    /// Constructed encoding: a tag byte and child nodes.
    Constructed {
        /// Identifier octet (constructed bit set).
        tag: u8,
        /// Child nodes.
        children: Vec<Node>,
    },
}

/// Universal tag number of `OCTET STRING`.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// Universal tag number of `BIT STRING`.
pub const TAG_BIT_STRING: u8 = 0x03;
/// Universal tag number of `INTEGER`.
pub const TAG_INTEGER: u8 = 0x02;
/// Universal tag number of `OBJECT IDENTIFIER`.
pub const TAG_OID: u8 = 0x06;
/// Universal tag of `SEQUENCE` (constructed bit included).
pub const TAG_SEQUENCE: u8 = 0x30;
/// Universal tag of `SET` (constructed bit included).
pub const TAG_SET: u8 = 0x31;
/// `BMPString`.
pub const TAG_BMP_STRING: u8 = 0x1e;

const CONSTRUCTED: u8 = 0x20;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Asn1(msg.into()))
}

impl Node {
    /// Parse exactly one BER element occupying the whole input.
    pub fn parse(input: &[u8]) -> Result<Node> {
        let (node, rest) = Node::parse_prefix(input)?;
        if !rest.is_empty() {
            return err(format!("{} trailing bytes after BER element", rest.len()));
        }
        Ok(node)
    }

    /// Parse one BER element from the start of `input`, returning the remainder.
    pub fn parse_prefix(input: &[u8]) -> Result<(Node, &[u8])> {
        let (tag, rest) = match input.split_first() {
            Some((t, r)) => (*t, r),
            None => return err("unexpected end of data"),
        };
        if tag & 0x1f == 0x1f {
            return err("multi-byte tags are not supported");
        }
        let (len, rest) = read_length(rest)?;
        let constructed = tag & CONSTRUCTED != 0;
        match len {
            Some(len) => {
                if rest.len() < len {
                    return err(format!("length {len} exceeds remaining {} bytes", rest.len()));
                }
                let (body, rest) = rest.split_at(len);
                let node = if constructed {
                    Node::Constructed {
                        tag,
                        children: parse_children(body)?,
                    }
                } else {
                    Node::Primitive {
                        tag,
                        bytes: body.to_vec(),
                    }
                };
                Ok((node, rest))
            }
            None => {
                if !constructed {
                    return err("indefinite length on a primitive element");
                }
                let mut children = Vec::new();
                let mut cur = rest;
                loop {
                    if cur.len() >= 2 && cur[0] == 0 && cur[1] == 0 {
                        cur = &cur[2..];
                        break;
                    }
                    if cur.is_empty() {
                        return err("missing end-of-contents octets");
                    }
                    let (child, next) = Node::parse_prefix(cur)?;
                    children.push(child);
                    cur = next;
                }
                Ok((Node::Constructed { tag, children }, cur))
            }
        }
    }

    /// Identifier octet.
    pub fn tag(&self) -> u8 {
        match self {
            Node::Primitive { tag, .. } | Node::Constructed { tag, .. } => *tag,
        }
    }

    /// Tag number (low five bits).
    pub fn tag_number(&self) -> u8 {
        self.tag() & 0x1f
    }

    /// Whether the node is context-specific (class bits `10`).
    pub fn is_context_specific(&self) -> bool {
        self.tag() & 0xc0 == 0x80
    }

    /// Children of a constructed node.
    pub fn children(&self) -> Result<&[Node]> {
        match self {
            Node::Constructed { children, .. } => Ok(children),
            Node::Primitive { tag, .. } => err(format!("expected constructed node, got tag 0x{tag:02x}")),
        }
    }

    /// `n`-th child of a constructed node.
    pub fn child(&self, n: usize) -> Result<&Node> {
        self.children()?
            .get(n)
            .ok_or_else(|| Error::Asn1(format!("missing child #{n} of tag 0x{:02x}", self.tag())))
    }

    /// Require a particular identifier octet.
    pub fn expect_tag(&self, tag: u8) -> Result<&Node> {
        if self.tag() == tag {
            Ok(self)
        } else {
            err(format!("expected tag 0x{tag:02x}, got 0x{:02x}", self.tag()))
        }
    }

    /// Contents of a string-like node, flattening constructed encodings
    /// (a constructed OCTET STRING is the concatenation of its segments).
    pub fn octets(&self) -> Result<Vec<u8>> {
        match self {
            Node::Primitive { bytes, .. } => Ok(bytes.clone()),
            Node::Constructed { children, .. } => {
                let mut out = Vec::new();
                for c in children {
                    out.extend(c.octets()?);
                }
                Ok(out)
            }
        }
    }

    /// Primitive contents; an error for constructed nodes.
    pub fn primitive(&self) -> Result<&[u8]> {
        match self {
            Node::Primitive { bytes, .. } => Ok(bytes),
            Node::Constructed { tag, .. } => err(format!("expected primitive node, got tag 0x{tag:02x}")),
        }
    }

    /// Decode an `OBJECT IDENTIFIER` node.
    pub fn oid(&self) -> Result<der::asn1::ObjectIdentifier> {
        let bytes = self.expect_tag(TAG_OID)?.primitive()?;
        Ok(der::asn1::ObjectIdentifier::from_bytes(bytes)?)
    }

    /// Decode a small non-negative `INTEGER` node.
    pub fn small_int(&self) -> Result<u32> {
        let bytes = self.expect_tag(TAG_INTEGER)?.primitive()?;
        if bytes.is_empty() || bytes.len() > 5 || (bytes.len() == 5 && bytes[0] != 0) {
            return err("INTEGER out of range");
        }
        let mut v: u32 = 0;
        for b in bytes {
            v = (v << 8) | u32::from(*b);
        }
        Ok(v)
    }

    /// Re-encode the node as DER (definite lengths; constructed universal
    /// strings are flattened to primitive form).
    pub fn to_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_der(&mut out);
        out
    }

    fn write_der(&self, out: &mut Vec<u8>) {
        match self {
            Node::Primitive { tag, bytes } => {
                out.push(*tag);
                write_length(out, bytes.len());
                out.extend_from_slice(bytes);
            }
            Node::Constructed { tag, children } => {
                let universal_string = *tag & 0xc0 == 0
                    && matches!(*tag & 0x1f, TAG_OCTET_STRING | TAG_BIT_STRING | 0x0c | 0x13 | 0x16 | 0x1e);
                if universal_string {
                    // Flatten to a primitive universal string.
                    let bytes = self.octets().unwrap_or_default();
                    out.push(*tag & !CONSTRUCTED);
                    write_length(out, bytes.len());
                    out.extend_from_slice(&bytes);
                    return;
                }
                let mut body = Vec::new();
                for c in children {
                    c.write_der(&mut body);
                }
                out.push(*tag);
                write_length(out, body.len());
                out.extend_from_slice(&body);
            }
        }
    }
}

fn parse_children(mut body: &[u8]) -> Result<Vec<Node>> {
    let mut children = Vec::new();
    while !body.is_empty() {
        let (child, rest) = Node::parse_prefix(body)?;
        children.push(child);
        body = rest;
    }
    Ok(children)
}

/// Returns `(Some(len), rest)` for definite lengths and `(None, rest)` for indefinite.
fn read_length(input: &[u8]) -> Result<(Option<usize>, &[u8])> {
    let (first, rest) = match input.split_first() {
        Some((f, r)) => (*f, r),
        None => return err("unexpected end of data in length"),
    };
    if first < 0x80 {
        return Ok((Some(usize::from(first)), rest));
    }
    if first == 0x80 {
        return Ok((None, rest));
    }
    let n = usize::from(first & 0x7f);
    if n > 4 || rest.len() < n {
        return err("unsupported length encoding");
    }
    let mut len: usize = 0;
    for b in &rest[..n] {
        len = (len << 8) | usize::from(*b);
    }
    Ok((Some(len), &rest[n..]))
}

fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let sig = &bytes[skip..];
    out.push(0x80 | sig.len() as u8);
    out.extend_from_slice(sig);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indefinite_length_roundtrip() {
        // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "c" } }
        let ber = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0x00, 0x00, 0x00, 0x00];
        let node = Node::parse(&ber).unwrap();
        assert_eq!(node.to_der(), vec![0x30, 0x05, 0x04, 0x03, b'a', b'b', b'c']);
        assert_eq!(node.child(0).unwrap().octets().unwrap(), b"abc");
    }

    #[test]
    fn long_length() {
        let mut out = Vec::new();
        write_length(&mut out, 0x280);
        assert_eq!(out, vec![0x82, 0x02, 0x80]);
        assert_eq!(read_length(&out).unwrap().0, Some(0x280));
    }
}
