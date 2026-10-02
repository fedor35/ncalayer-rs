//! Test examples from GOST R 34.10-2012 Appendix A (RFC 7091 §7 for the
//! 256-bit case; the 512-bit example is Appendix A.2 of the standard).

use gost3410::curve::{uint_from_be_hex, uint_from_dec};
use gost3410::{sign_with_k, verify, AffinePoint, Curve, PublicKey, SecretKey, Signature, U512};

fn d(s: &str) -> U512 {
    uint_from_dec(s).unwrap()
}
fn h(s: &str) -> U512 {
    uint_from_be_hex(s).unwrap()
}

/// The standard gives the hash as an integer `e`; the crate expects the
/// digest bytes in CryptoPro/engine order, i.e. little-endian of that integer.
fn digest_from_e(e: &U512, len: usize) -> Vec<u8> {
    let be = e.to_be_bytes();
    let mut v = be.as_ref()[64 - len..].to_vec();
    v.reverse();
    v
}

#[test]
fn appendix_a1_256() {
    let curve = Curve::from_params(
        d("57896044618658097711785492504343953926634992332820282019728792003956564821041"),
        d("7"),
        d("43308876546767276905765904595650931995942111794451039583252968842033849580414"),
        d("57896044618658097711785492504343953927082934583725450622380973592137631069619"),
        d("2"),
        d("4018974056539037503335449422937059775635739389905545080690979365213431566280"),
    )
    .unwrap();
    assert_eq!(curve.coordinate_len(), 32);

    let dk = d("55441196065363246126355624130324183196576709222340016572108097750006097525544");
    let e = d("20798893674476452017134061561508270130637142515379653289952617252661468872421");
    let k = d("53854137677348463731403841147996619241504003434302020712960838528893196233395");
    let r = d("29700980915817952874371204983938256990422752107994319651632687982059210933395");
    let s = d("574973400270084654178925310019147038455227042649098563933718999175515839552");
    let qx = d("57520216126176808443631405023338071176630104906313632182896741342206604859403");
    let qy = d("17614944419213781543809391949654080031942662045363639260709847859438286763994");

    let key = SecretKey::from_scalar(&curve, dk).unwrap();
    let pk = key.public_key(&curve);
    assert_eq!(pk.coordinates(), (&qx, &qy), "Q = d*G");

    let digest = digest_from_e(&e, 32);
    assert_eq!(curve.e_from_digest(&digest), e);

    let sig = sign_with_k(&curve, &key, &digest, &k).unwrap();
    assert_eq!(sig.r, r, "r");
    assert_eq!(sig.s, s, "s");
    assert!(verify(&curve, &pk, &digest, &sig));

    // Byte encodings against the hex forms printed in the standard.
    let gost = sig.to_bytes_gost(&curve);
    assert_eq!(
        hex::encode(&gost),
        "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493\
         01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40"
    );
    let rfc = sig.to_bytes_rfc4491(&curve);
    assert_eq!(&rfc[..32], &gost[32..]);
    assert_eq!(&rfc[32..], &gost[..32]);
    assert_eq!(Signature::from_bytes_gost(&curve, &gost).unwrap(), sig);
    assert_eq!(Signature::from_bytes_rfc4491(&curve, &rfc).unwrap(), sig);

    // Explicit public-key point check.
    let pk2 = PublicKey::from_affine(&curve, AffinePoint::new(qx, qy)).unwrap();
    assert!(verify(&curve, &pk2, &digest, &sig));
}

#[test]
fn appendix_a2_512() {
    let curve = Curve::from_params(
        h("4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373"),
        h("7"),
        h("1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc"),
        h("4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df"),
        h("24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a"),
        h("2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e"),
    )
    .unwrap();
    assert_eq!(curve.coordinate_len(), 64);

    let dk = h("0ba6048aadae241ba40936d47756d7c93091a0e8514669700ee7508e508b102072e8123b2200a0563322dad2827e2714a2636b7bfd18aadfc62967821fa18dd4");
    let e = h("3754f3cfacc9e0615c4f4a7c4d8dab531b09b6f9c170c533a71d147035b0c5917184ee536593f4414339976c647c5d5a407adedb1d560c4fc6777d2972075b8c");
    let k = h("0359e7f4b1410feacc570456c6801496946312120b39d019d455986e364f365886748ed7a44b3e794434006011842286212273a6d14cf70ea3af71bb1ae679f1");
    let r = h("2f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36");
    let s = h("1081b394696ffe8e6585e7a9362d26b6325f56778aadbc081c0bfbe933d52ff5823ce288e8c4f362526080df7f70ce406a6eeb1f56919cb92a9853bde73e5b4a");
    let qx = h("115dc5bc96760c7b48598d8ab9e740d4c4a85a65be33c1815b5c320c854621dd5a515856d13314af69bc5b924c8b4ddff75c45415c1d9dd9dd33612cd530efe1");
    let qy = h("37c7c90cd40b0f5621dc3ac1b751cfa0e2634fa0503b3d52639f5d7fb72afd61ea199441d943ffe7f0c70a2759a3cdb84c114e1f9339fdf27f35eca93677beec");

    let key = SecretKey::from_scalar(&curve, dk).unwrap();
    let pk = key.public_key(&curve);
    assert_eq!(pk.coordinates(), (&qx, &qy), "Q = d*G");

    let digest = digest_from_e(&e, 64);
    let sig = sign_with_k(&curve, &key, &digest, &k).unwrap();
    assert_eq!(sig.r, r, "r");
    assert_eq!(sig.s, s, "s");
    assert!(verify(&curve, &pk, &digest, &sig));
}
