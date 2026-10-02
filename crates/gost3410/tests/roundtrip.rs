//! Sign / verify round trips, negative cases and encodings on all named curves.

use gost3410::{
    digest_for_curve, sign, sign_deterministic, verify, NamedCurve, PublicKey, SecretKey,
    Signature, U512,
};

#[test]
fn sign_verify_random_keys_all_curves() {
    let mut rng = rand::rng();
    for nc in NamedCurve::ALL {
        let c = nc.curve();
        for i in 0..3u8 {
            let key = SecretKey::random(c, &mut rng).unwrap();
            let pk = key.public_key(c);
            let msg = format!("message {i} on {nc:?}");
            let digest = digest_for_curve(nc, msg.as_bytes());
            assert_eq!(digest.len(), nc.hash_alg().output_len());

            let sig = sign(c, &key, &digest, &mut rng).unwrap();
            assert!(
                verify(c, &pk, &digest, &sig),
                "{nc:?}: valid signature verifies"
            );

            // Negative: other key.
            let other = SecretKey::random(c, &mut rng).unwrap().public_key(c);
            assert!(
                !verify(c, &other, &digest, &sig),
                "{nc:?}: wrong key rejected"
            );

            // Negative: tampered digest.
            let mut bad = digest.clone();
            bad[0] ^= 1;
            assert!(
                !verify(c, &pk, &bad, &sig),
                "{nc:?}: tampered digest rejected"
            );

            // Negative: tampered signature.
            let mut sig_r = sig;
            sig_r.r = sig_r.r.wrapping_add(&U512::ONE);
            assert!(!verify(c, &pk, &digest, &sig_r));
            let mut sig_s = sig;
            sig_s.s = sig_s.s.wrapping_sub(&U512::ONE);
            assert!(!verify(c, &pk, &digest, &sig_s));
            assert!(!verify(
                c,
                &pk,
                &digest,
                &Signature {
                    r: U512::ZERO,
                    s: sig.s
                }
            ));
            assert!(!verify(
                c,
                &pk,
                &digest,
                &Signature {
                    r: *c.order(),
                    s: sig.s
                }
            ));

            // Encodings round-trip.
            let rfc = sig.to_bytes_rfc4491(c);
            assert_eq!(rfc.len(), 2 * c.coordinate_len());
            assert_eq!(Signature::from_bytes_rfc4491(c, &rfc).unwrap(), sig);
            let gost = sig.to_bytes_gost(c);
            assert_eq!(Signature::from_bytes_gost(c, &gost).unwrap(), sig);
            assert_eq!(&gost[..c.coordinate_len()], &rfc[c.coordinate_len()..]);
            assert!(Signature::from_bytes_rfc4491(c, &rfc[1..]).is_err());
            let kz = sig.to_bytes_kz(c);
            let mut rfc_rev = rfc.clone();
            rfc_rev.reverse();
            assert_eq!(kz, rfc_rev);
            assert_eq!(Signature::from_bytes_kz(c, &kz).unwrap(), sig);
            assert!(Signature::from_bytes_kz(c, &vec![0u8; 2 * c.coordinate_len()]).is_err());

            let pkb = pk.to_bytes_x509(c);
            assert_eq!(pkb.len(), 2 * c.coordinate_len());
            assert_eq!(PublicKey::from_bytes_x509(c, &pkb).unwrap(), pk);
            let mut pkb_bad = pkb.clone();
            pkb_bad[0] ^= 1;
            assert!(
                PublicKey::from_bytes_x509(c, &pkb_bad).is_err(),
                "off-curve point rejected"
            );

            let skb = key.to_bytes_be(c);
            let key2 = SecretKey::from_bytes_be(c, &skb).unwrap();
            assert_eq!(key2.scalar(), key.scalar());
        }
    }
}

#[test]
fn deterministic_signing_is_stable_and_valid() {
    let mut rng = rand::rng();
    for nc in NamedCurve::ALL {
        let c = nc.curve();
        let key = SecretKey::random(c, &mut rng).unwrap();
        let pk = key.public_key(c);
        let digest = digest_for_curve(nc, b"deterministic");
        let s1 = sign_deterministic(c, &key, &digest);
        let s2 = sign_deterministic(c, &key, &digest);
        assert_eq!(s1, s2, "{nc:?}: same (d, e) gives same signature");
        assert!(verify(c, &pk, &digest, &s1));
        let other = digest_for_curve(nc, b"deterministic!");
        assert_ne!(sign_deterministic(c, &key, &other), s1);
        // A different key gives a different nonce even for the same digest.
        let key2 = SecretKey::random(c, &mut rng).unwrap();
        assert_ne!(sign_deterministic(c, &key2, &digest).r, s1.r);
    }
}

#[test]
fn secret_key_range_is_enforced() {
    let c = NamedCurve::Tc26Gost3410_2012_256ParamSetA.curve();
    assert!(SecretKey::from_scalar(c, U512::ZERO).is_err());
    assert!(SecretKey::from_scalar(c, *c.order()).is_err());
    assert!(SecretKey::from_scalar(c, c.order().wrapping_sub(&U512::ONE)).is_ok());
    assert!(SecretKey::from_scalar(c, U512::ONE).is_ok());
}

#[test]
fn zero_digest_maps_to_e_equal_one() {
    let c = NamedCurve::Tc26Gost3410_2012_256ParamSetA.curve();
    assert_eq!(c.e_from_digest(&[0u8; 32]), U512::ONE);
    // q itself reduces to 0 and therefore to 1 as well.
    let mut qle = c.order().to_le_bytes().as_ref()[..32].to_vec();
    assert_eq!(c.e_from_digest(&qle), U512::ONE);
    qle[0] ^= 2;
    assert_ne!(c.e_from_digest(&qle), U512::ONE);
}
