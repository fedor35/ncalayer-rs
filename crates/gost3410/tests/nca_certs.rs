//! End-to-end check against real certificates of the Kazakhstan NCA
//! (<https://pki.gov.kz/cert/>):
//!
//! * `root_gost_2022.cer` — self-signed root "НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ
//!   (GOST) 2022";
//! * `nca_gost_2022.cer` — the issuing CA "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)
//!   2022", signed by the root.
//!
//! Both use signature algorithm 1.2.398.3.10.1.1.2.3.2 (GOST R 34.10-2012
//! 512 bit with Streebog-512) and key parameters 1.2.398.3.10.1.1.2.2.1.
//!
//! The tests pin every byte-order convention at once:
//! * public key = `x ‖ y` little-endian (RFC 4491 §2.3.2 / RFC 9215 §4.3),
//! * `e` = Streebog output read as a little-endian integer,
//! * signature = `r ‖ s` **little-endian** each — the NCA layout
//!   ([`Signature::from_bytes_kz`]), which is the byte reversal of the
//!   RFC 4491 / RFC 9215 `s_BE ‖ r_BE` layout.  The RFC layout is checked
//!   to *fail*, so the test is not vacuous.

use gost3410::{verify, HashAlg, NamedCurve, PublicKey, Signature};

const ROOT: &[u8] = include_bytes!("data/root_gost_2022.cer");
const NCA: &[u8] = include_bytes!("data/nca_gost_2022.cer");

/// Minimal DER walker: (header_len, content_len) of the TLV at `pos`.
fn tlv(d: &[u8], pos: usize) -> (usize, usize) {
    let l = d[pos + 1] as usize;
    if l < 0x80 {
        (2, l)
    } else {
        let n = l & 0x7f;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | d[pos + 2 + i] as usize;
        }
        (2 + n, len)
    }
}

struct Parts<'a> {
    tbs: &'a [u8],
    pubkey: Vec<u8>,
    signature: Vec<u8>,
}

fn parse(d: &[u8]) -> Parts<'_> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    assert_eq!(d[0], 0x30);
    let (hl, _) = tlv(d, 0);
    let tbs_pos = hl;
    assert_eq!(d[tbs_pos], 0x30);
    let (thl, tl) = tlv(d, tbs_pos);
    let tbs = &d[tbs_pos..tbs_pos + thl + tl];

    // Inside TBS: version[0], serial, sigalg, issuer, validity, subject, then SPKI.
    let mut p = tbs_pos + thl;
    for _ in 0..6 {
        let (h, l) = tlv(d, p);
        p += h + l;
    }
    assert_eq!(d[p], 0x30, "SubjectPublicKeyInfo");
    let (h, _) = tlv(d, p);
    let mut q = p + h;
    assert_eq!(d[q], 0x30, "AlgorithmIdentifier");
    let (ah, al) = tlv(d, q);
    // OID 1.2.398.3.10.1.1.2.2 = gost3410-2012-512 public key (KZ arc).
    assert_eq!(
        &d[q + ah..q + ah + 11],
        &[0x06, 0x09, 0x2a, 0x83, 0x0e, 0x03, 0x0a, 0x01, 0x01, 0x02, 0x02]
    );
    q += ah + al;
    assert_eq!(d[q], 0x03, "subjectPublicKey BIT STRING");
    let (bh, bl) = tlv(d, q);
    let bits = &d[q + bh..q + bh + bl];
    assert_eq!(bits[0], 0, "no unused bits");
    assert_eq!(bits[1], 0x04, "inner OCTET STRING");
    let (oh, ol) = tlv(d, q + bh + 1);
    let pubkey = bits[1 + oh..1 + oh + ol].to_vec();
    assert_eq!(pubkey.len(), 128);

    let mut s = tbs_pos + thl + tl;
    let (h, l) = tlv(d, s); // signatureAlgorithm
    s += h + l;
    assert_eq!(d[s], 0x03, "signatureValue BIT STRING");
    let (sh, sl) = tlv(d, s);
    let sig_bits = &d[s + sh..s + sh + sl];
    assert_eq!(sig_bits[0], 0);
    let signature = sig_bits[1..].to_vec();
    assert_eq!(signature.len(), 128);
    Parts {
        tbs,
        pubkey,
        signature,
    }
}

fn check(cert: &[u8], issuer_key: &[u8]) {
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let parts = parse(cert);
    let pk = PublicKey::from_bytes_x509(curve, issuer_key).expect("x||y little-endian, on curve");
    let digest = HashAlg::Streebog512.digest(parts.tbs);

    let sig = Signature::from_bytes_kz(curve, &parts.signature).expect("r_LE||s_LE");
    assert!(
        verify(curve, &pk, &digest, &sig),
        "signature verifies with the NCA layout"
    );
    assert_eq!(sig.to_bytes_kz(curve), parts.signature);

    // Alternatives must fail.
    let mut rev = digest.clone();
    rev.reverse();
    assert!(
        !verify(curve, &pk, &rev, &sig),
        "big-endian digest interpretation is wrong"
    );
    if let Ok(rfc) = Signature::from_bytes_rfc4491(curve, &parts.signature) {
        assert!(
            !verify(curve, &pk, &digest, &rfc),
            "RFC 4491 s_BE||r_BE is not what the NCA emits"
        );
    }
    if let Ok(gost) = Signature::from_bytes_gost(curve, &parts.signature) {
        assert!(
            !verify(curve, &pk, &digest, &gost),
            "r_BE||s_BE is not what the NCA emits"
        );
    }
    // The same (r, s) re-encoded in the RFC layout is just the reversed block.
    let mut rfc_bytes = sig.to_bytes_rfc4491(curve);
    rfc_bytes.reverse();
    assert_eq!(rfc_bytes, parts.signature);
}

#[test]
fn root_gost_2022_self_signature() {
    let root = parse(ROOT);
    check(ROOT, &root.pubkey);
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let pk = PublicKey::from_bytes_x509(curve, &root.pubkey).unwrap();
    assert_eq!(pk.to_bytes_x509(curve), root.pubkey, "x||y LE round-trips");
}

#[test]
fn nca_gost_2022_signed_by_root() {
    let root = parse(ROOT);
    check(NCA, &root.pubkey);
    // And NOT by its own key.
    let nca = parse(NCA);
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let own = PublicKey::from_bytes_x509(curve, &nca.pubkey).unwrap();
    let sig = Signature::from_bytes_kz(curve, &nca.signature).unwrap();
    assert!(!verify(
        curve,
        &own,
        &HashAlg::Streebog512.digest(nca.tbs),
        &sig
    ));
}
