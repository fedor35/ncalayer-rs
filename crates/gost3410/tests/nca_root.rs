//! End-to-end check against a real certificate: the self-signed GOST root of
//! the Kazakhstan NCA ("НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) 2022",
//! https://pki.gov.kz/cert/root_gost_2022.cer, signature algorithm
//! 1.2.398.3.10.1.1.2.3.2 = GOST R 34.10-2012-512 with Streebog-512,
//! parameters 1.2.398.3.10.1.1.2.2.1).
//!
//! This pins down every byte-order convention at once:
//! * public key = `x ‖ y` little-endian (RFC 4491 §2.3.2 / RFC 9215 §4.3),
//! * signature = `s ‖ r` big-endian (RFC 4491 §2.2.2 / RFC 9215 §2),
//! * `e` = Streebog output read as a little-endian integer.

use gost3410::{verify, HashAlg, NamedCurve, PublicKey, Signature};

const DER: &[u8] = include_bytes!("data/root_gost_2022.cer");

/// Minimal DER walker: returns (header_len, content_len) of the TLV at `pos`.
fn tlv(pos: usize) -> (usize, usize) {
    let l = DER[pos + 1] as usize;
    if l < 0x80 {
        (2, l)
    } else {
        let n = l & 0x7f;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | DER[pos + 2 + i] as usize;
        }
        (2 + n, len)
    }
}

struct Parts {
    tbs: &'static [u8],
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

fn parse() -> Parts {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    assert_eq!(DER[0], 0x30);
    let (hl, _) = tlv(0);
    let tbs_pos = hl;
    assert_eq!(DER[tbs_pos], 0x30);
    let (thl, tl) = tlv(tbs_pos);
    let tbs = &DER[tbs_pos..tbs_pos + thl + tl];

    // Walk the TBS: version[0], serial, sigalg, issuer, validity, subject, spki.
    let mut p = tbs_pos + thl;
    for _ in 0..6 {
        let (h, l) = tlv(p);
        p += h + l;
    }
    // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    assert_eq!(DER[p], 0x30);
    let (h, _) = tlv(p);
    let mut q = p + h;
    let (ah, al) = tlv(q); // AlgorithmIdentifier
    assert_eq!(DER[q], 0x30);
    // First OID inside must be 1.2.398.3.10.1.1.2.2 (gost3410-2012-512 key).
    assert_eq!(&DER[q + ah..q + ah + 11], &[0x06, 0x09, 0x2a, 0x83, 0x0e, 0x03, 0x0a, 0x01, 0x01, 0x02, 0x02]);
    q += ah + al;
    assert_eq!(DER[q], 0x03); // BIT STRING
    let (bh, bl) = tlv(q);
    let bits = &DER[q + bh..q + bh + bl];
    assert_eq!(bits[0], 0, "no unused bits");
    assert_eq!(bits[1], 0x04, "inner OCTET STRING");
    let (oh, ol) = tlv(q + bh + 1);
    let pubkey = bits[1 + oh..1 + oh + ol].to_vec();
    assert_eq!(pubkey.len(), 128);

    // signatureAlgorithm then signatureValue.
    let mut s = tbs_pos + thl + tl;
    let (h, l) = tlv(s);
    s += h + l;
    assert_eq!(DER[s], 0x03);
    let (sh, sl) = tlv(s);
    let sig_bits = &DER[s + sh..s + sh + sl];
    assert_eq!(sig_bits[0], 0);
    let signature = sig_bits[1..].to_vec();
    assert_eq!(signature.len(), 128);
    Parts { tbs, pubkey, signature }
}

#[test]
fn nca_root_gost_2022_self_signature_verifies() {
    let parts = parse();
    let nc = NamedCurve::Tc26Gost3410_12_512ParamSetA;
    let curve = nc.curve();
    let pk = PublicKey::from_bytes_x509(curve, &parts.pubkey).expect("x||y little-endian on curve");
    let sig = Signature::from_bytes_x509(curve, &parts.signature).expect("s||r big-endian");
    let digest = HashAlg::Streebog512.digest(parts.tbs);
    assert!(verify(curve, &pk, &digest, &sig), "root certificate self-signature");

    // The other plausible conventions must all fail, so the test is not vacuous.
    let mut rev = digest.clone();
    rev.reverse();
    assert!(!verify(curve, &pk, &rev, &sig), "big-endian digest interpretation is wrong");
    let swapped = Signature::from_bytes_gost(curve, &parts.signature).unwrap();
    assert!(!verify(curve, &pk, &digest, &swapped), "r||s order is wrong for X.509");
    assert!(verify(curve, &pk, &digest, &Signature::from_bytes_gost(curve, &sig.to_bytes_gost(curve)).unwrap()));
    assert_eq!(pk.to_bytes_x509(curve), parts.pubkey);
    assert_eq!(sig.to_bytes_x509(curve), parts.signature);
}
