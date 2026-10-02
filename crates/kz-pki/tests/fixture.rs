//! Tests against the NCA test container `tests/fixtures/test_gost512.p12`.

use std::collections::HashMap;

use kz_pki::{Cert, Error, Gost2015Curve, KeyStore, KeyUsageType, PrivateKey, PublicKey};

const P12: &[u8] = include_bytes!("../../../tests/fixtures/test_gost512.p12");
const VECTORS: &str = include_str!("../../../tests/fixtures/test_gost512.vectors");
const CER_PEM: &str = include_str!("../../../tests/fixtures/test_gost512.cer.pem");
const PASSWORD: &str = "Test1234";

fn vectors() -> HashMap<String, String> {
    VECTORS
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

fn open() -> KeyStore {
    KeyStore::open(P12, PASSWORD).expect("open p12")
}

#[test]
fn opens_with_alias_test() {
    let ks = open();
    assert_eq!(ks.entries.len(), 1);
    assert_eq!(ks.entries[0].alias, "test");
    assert!(ks.entry("test").is_some());
}

#[test]
fn wrong_password_is_reported() {
    match KeyStore::open(P12, "wrong") {
        Err(Error::WrongPassword) => {}
        other => panic!("expected WrongPassword, got {other:?}"),
    }
}

#[test]
fn private_key_matches_vectors() {
    let v = vectors();
    let ks = open();
    match &ks.entries[0].key {
        PrivateKey::Gost2015 { curve, d } => {
            assert_eq!(*curve, Gost2015Curve::A512);
            assert_eq!(hex::encode(d), v["d"]);
        }
        other => panic!("unexpected key {other:?}"),
    }
    assert_eq!(ks.entries[0].key.algorithm(), "ECGOST3410-2015-512");
}

#[test]
fn public_key_and_spki_match_vectors() {
    let v = vectors();
    let ks = open();
    let cert = &ks.entries[0].cert;
    assert_eq!(hex::encode(cert.spki_der().unwrap()), v["spki"]);
    match cert.public_key().unwrap() {
        PublicKey::Gost2015 { curve, x, y } => {
            assert_eq!(curve, Gost2015Curve::A512);
            assert_eq!(hex::encode(x), v["qx"]);
            assert_eq!(hex::encode(y), v["qy"]);
        }
        other => panic!("unexpected key {other:?}"),
    }
    assert_eq!(cert.algorithm().unwrap(), "ECGOST3410-2015-512");
}

#[test]
fn certificate_fields() {
    let v = vectors();
    let ks = open();
    let cert = &ks.entries[0].cert;
    assert_eq!(
        cert.subject_dn(),
        "CN=TEST GOST512,SERIALNUMBER=IIN000000000000,C=KZ"
    );
    assert_eq!(
        cert.issuer_dn(),
        "CN=TEST GOST512,SERIALNUMBER=IIN000000000000,C=KZ"
    );
    assert_eq!(cert.subject_cn().as_deref(), Some("TEST GOST512"));
    assert_eq!(cert.iin().as_deref(), Some("000000000000"));
    assert_eq!(cert.bin(), None);
    assert_eq!(cert.serial_number(), "1a0fd8c5966");
    assert_eq!(hex::encode(cert.tbs_der().unwrap()), v["cert_tbs"]);
    assert_eq!(hex::encode(cert.signature().unwrap()), v["cert_sig"]);
    assert_eq!(cert.signature_algorithm_oid().to_string(), v["sigalg_oid"]);
    // No EKU in the test certificate -> Signature.
    assert_eq!(cert.key_usage_type(), KeyUsageType::Signature);
    assert!(cert.policies().unwrap().is_empty());
    assert_eq!(cert.authority_key_identifier().unwrap(), None);
    // 2026-10-01T16:57:08Z -> 21:57:08 Asia/Almaty
    assert_eq!(cert.not_before_str().unwrap(), "01.10.2026 21:57:08");
    assert_eq!(cert.not_after_str().unwrap(), "02.10.2027 21:57:08");
    assert!(ks.entries[0].chain.is_empty());
}

#[test]
fn pem_matches_fixture() {
    let ks = open();
    let cert = &ks.entries[0].cert;
    let pem = cert.pem().unwrap();
    assert_eq!(pem.trim_end(), CER_PEM.trim_end());
    assert!(pem
        .lines()
        .skip(1)
        .take_while(|l| !l.starts_with("-----"))
        .all(|l| l.len() <= 64));
    let from_pem = Cert::from_pem(CER_PEM).unwrap();
    assert_eq!(from_pem.as_der(), cert.as_der());
}
