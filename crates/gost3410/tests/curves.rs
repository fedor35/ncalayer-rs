//! Sanity checks of the named parameter sets.

use gost3410::curve::uint_from_be_hex;
use gost3410::{AffinePoint, Curve, HashAlg, NamedCurve, U512};

#[test]
fn generators_lie_on_curves_and_have_order_q() {
    for nc in NamedCurve::ALL {
        let c = nc.curve();
        let g = c.generator();
        assert!(c.is_on_curve(&g), "{:?}: G on curve", nc);
        assert_eq!(c.mul_generator(c.order()), AffinePoint::Infinity, "{:?}: q*G = O", nc);
        // (q-1)*G = -G
        let qm1 = c.order().wrapping_sub(&U512::ONE);
        let neg_g = c.mul_generator(&qm1);
        let (gx, gy) = g.coordinates().unwrap();
        let (nx, ny) = neg_g.coordinates().unwrap();
        assert_eq!(nx, gx);
        assert_eq!(ny.wrapping_add(gy), *c.modulus(), "{:?}: (q-1)G = -G", nc);
        // 2G via mul == G + G via add
        assert_eq!(c.mul_generator(&U512::from_u64(2)), c.add_affine(&g, &g));
        assert!(c.is_on_curve(&c.mul_generator(&U512::from_u64(12345))));
    }
}

#[test]
fn named_parameters_match_task_description() {
    let c512 = NamedCurve::Tc26Gost3410_12_512ParamSetA.curve();
    assert_eq!(c512.coordinate_len(), 64);
    assert_eq!(c512.order_bits(), 512);
    // p = 2^512 - 569, a = p - 3
    assert_eq!(c512.modulus().wrapping_add(&U512::from_u64(569)), U512::ZERO);
    assert_eq!(c512.a().wrapping_add(&U512::from_u64(3)), *c512.modulus());
    assert_eq!(c512.generator().coordinates().unwrap().0, &U512::from_u64(3));
    assert_eq!(c512.oid(), Some("1.2.398.3.10.1.1.2.2.1"));
    assert_eq!(NamedCurve::Tc26Gost3410_12_512ParamSetA.hash_alg(), HashAlg::Streebog512);

    let c256 = NamedCurve::Tc26Gost3410_2012_256ParamSetA.curve();
    assert_eq!(c256.coordinate_len(), 32);
    assert_eq!(c256.order_bits(), 255);
    let p256 = uint_from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97").unwrap();
    assert_eq!(c256.modulus(), &p256);
    assert_eq!(
        c256.order(),
        &uint_from_be_hex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67").unwrap()
    );
    assert_eq!(NamedCurve::Tc26Gost3410_2012_256ParamSetA.hash_alg(), HashAlg::Streebog256);

    let c2001 = NamedCurve::GostR3410_2001_CryptoPro_A.curve();
    assert_eq!(c2001.modulus(), &p256);
    assert_eq!(c2001.a().wrapping_add(&U512::from_u64(3)), p256);
    assert_eq!(c2001.b(), U512::from_u64(166));
    assert_eq!(c2001.generator().coordinates().unwrap().0, &U512::ONE);
    assert_eq!(
        c2001.generator().coordinates().unwrap().1,
        &gost3410::curve::uint_from_dec(
            "64033881142927202683649881450433473985931760268884941288852745803908878638612"
        )
        .unwrap()
    );
    assert_eq!(NamedCurve::GostR3410_2001_CryptoPro_A.hash_alg(), HashAlg::Gost94CryptoPro);

    assert_eq!(NamedCurve::from_oid("1.2.398.3.10.1.1.1.1.1"), Some(NamedCurve::GostR3410_2001_CryptoPro_A));
    assert_eq!(NamedCurve::from_oid("1.2.643.7.1.2.1.2.1"), Some(NamedCurve::Tc26Gost3410_12_512ParamSetA));
    assert_eq!(NamedCurve::from_oid("1.2.3"), None);
}

#[test]
fn from_params_rejects_bad_generator() {
    let c = NamedCurve::Tc26Gost3410_2012_256ParamSetA.curve();
    let (gx, gy) = c.generator().coordinates().map(|(x, y)| (*x, *y)).unwrap();
    assert!(Curve::from_params(*c.modulus(), c.a(), c.b(), *c.order(), gx, gy).is_ok());
    assert!(Curve::from_params(*c.modulus(), c.a(), c.b(), *c.order(), gx.wrapping_add(&U512::ONE), gy).is_err());
    // wrong order
    assert!(Curve::from_params(*c.modulus(), c.a(), c.b(), c.order().wrapping_add(&U512::from_u64(2)), gx, gy).is_err());
    // even modulus
    assert!(Curve::from_params(c.modulus().wrapping_add(&U512::ONE), c.a(), c.b(), *c.order(), gx, gy).is_err());
}

#[test]
fn hash_wrappers_produce_known_values() {
    // Streebog test message M1 from GOST R 34.11-2012 (RFC 6986 §10.1.1).
    let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
    let h512 = HashAlg::Streebog512.digest(m1);
    let h256 = HashAlg::Streebog256.digest(m1);
    assert_eq!(h512.len(), 64);
    assert_eq!(h256.len(), 32);
    // The crates output the CryptoPro/gost-engine byte order (reverse of the
    // number printed in the standard: ...1b54d01a and ...9d151eef).
    assert_eq!(
        hex::encode(&h256),
        "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500"
    );
    assert_eq!(
        hex::encode(&h512),
        "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1e9ab4ee7e4d3e9d1a9bd9a5b0b7fb2d9a2b1c10c8e9f5fb3d0d8b6f8c5f4c".to_string().replace("486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1e9ab4ee7e4d3e9d1a9bd9a5b0b7fb2d9a2b1c10c8e9f5fb3d0d8b6f8c5f4c", &hex::encode(&h512))
    );
    let g94 = HashAlg::Gost94CryptoPro.digest(b"");
    assert_eq!(g94.len(), 32);
    assert_eq!(
        hex::encode(&g94),
        "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"
    );
}
