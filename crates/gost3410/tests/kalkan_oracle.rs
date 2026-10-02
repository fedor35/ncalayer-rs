//! Cross-check against KalkanCrypt output produced by `tools/java-oracle`
//! (`tests/fixtures/test_gost512.vectors`): KZ paramSetA 512, Streebog-512.

use gost3410::{digest_for_curve, sign_deterministic, verify, NamedCurve, PublicKey, SecretKey, Signature};
use std::collections::HashMap;

fn vectors() -> HashMap<String, String> {
    include_str!("../../../tests/fixtures/test_gost512.vectors")
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn pad_hex(h: &str, len: usize) -> Vec<u8> {
    let mut s = h.to_string();
    while s.len() < len * 2 {
        s.insert(0, '0');
    }
    hex::decode(s).unwrap()
}

#[test]
fn kalkan_digest_is_streebog512_of_message() {
    let v = vectors();
    assert_eq!(hex::encode(digest_for_curve(NamedCurve::Tc26Gost3410_12_512ParamSetA, v["msg"].as_bytes())), v["digest"]);
}

#[test]
fn kalkan_private_key_yields_its_public_key() {
    let v = vectors();
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let d = SecretKey::from_bytes_be(curve, &pad_hex(&v["d"], 64)).unwrap();
    let q = d.public_key(curve);
    let mut want = pad_hex(&v["qx"], 64);
    want.extend(pad_hex(&v["qy"], 64));
    // to_bytes_x509 is x‖y little-endian; compare in big-endian via reversal of halves.
    let got = q.to_bytes_x509(curve);
    let (x, y) = got.split_at(64);
    let mut got_be: Vec<u8> = x.iter().rev().copied().collect();
    got_be.extend(y.iter().rev());
    assert_eq!(got_be, want);
    // And the SPKI from Java ends with exactly that x‖y LE blob.
    let spki = hex::decode(&v["spki"]).unwrap();
    assert!(spki.ends_with(&got));
}

#[test]
fn kalkan_message_signature_verifies_in_kz_layout() {
    let v = vectors();
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let spki = hex::decode(&v["spki"]).unwrap();
    let q = PublicKey::from_bytes_x509(curve, &spki[spki.len() - 128..]).unwrap();
    let digest = hex::decode(&v["digest"]).unwrap();
    let sig = hex::decode(&v["sig"]).unwrap();
    let kz = Signature::from_bytes_kz(curve, &sig).unwrap();
    assert!(verify(curve, &q, &digest, &kz), "Kalkan JCE signature must verify as r_LE||s_LE");
}

#[test]
fn kalkan_certificate_signature_verifies() {
    let v = vectors();
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let spki = hex::decode(&v["spki"]).unwrap();
    let q = PublicKey::from_bytes_x509(curve, &spki[spki.len() - 128..]).unwrap();
    let tbs = hex::decode(&v["cert_tbs"]).unwrap();
    let digest = digest_for_curve(NamedCurve::Tc26Gost3410_12_512ParamSetA, &tbs);
    let sig = Signature::from_bytes_kz(curve, &hex::decode(&v["cert_sig"]).unwrap()).unwrap();
    assert!(verify(curve, &q, &digest, &sig));
}

/// Produces a Rust signature in Kalkan layout for `tools/java-oracle/run.sh verify`.
#[test]
fn write_rust_signature_for_java_oracle() {
    let v = vectors();
    let curve = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    let d = SecretKey::from_bytes_be(curve, &pad_hex(&v["d"], 64)).unwrap();
    let digest = hex::decode(&v["digest"]).unwrap();
    let sig = sign_deterministic(curve, &d, &digest);
    assert!(verify(curve, &d.public_key(curve), &digest, &sig));
    let out = std::env::temp_dir().join("ncalayer-rs-rust-sig.hex");
    std::fs::write(&out, hex::encode(sig.to_bytes_kz(curve))).unwrap();
}
