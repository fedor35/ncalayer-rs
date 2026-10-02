//! Elliptic curves `y^2 = x^3 + ax + b` over `F_p`, named parameter sets and
//! point arithmetic.
//!
//! # Side-channel notes
//!
//! * Field arithmetic uses `crypto_bigint`'s Montgomery form, which is
//!   constant-time with respect to the operand values.
//! * Scalar multiplication is a Montgomery ladder: the number of field
//!   operations does not depend on the scalar, but **the bit of the scalar is
//!   tested with a branch** and the special cases of the addition law (point
//!   at infinity, `P == Q`) are handled with branches too.  Treat the crate as
//!   *not* constant-time; this is acceptable for v1 because signing happens
//!   locally on the user's workstation.

use core::fmt;
use std::sync::LazyLock;

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{NonZero, Odd, U512};

use crate::{Error, Result};

const LIMBS: usize = U512::LIMBS;
type Fe = FixedMontyForm<LIMBS>;
type Mp = FixedMontyParams<LIMBS>;

/// Parse a big-endian hex string (any length up to 128 nibbles, optional
/// `0x` prefix, upper or lower case) into a [`U512`].
pub fn uint_from_be_hex(hex: &str) -> Result<U512> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    if hex.len() > 128 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidHex);
    }
    let mut padded = String::with_capacity(128);
    for _ in hex.len()..128 {
        padded.push('0');
    }
    padded.push_str(hex);
    Ok(U512::from_be_hex(&padded))
}

/// Parse a decimal string into a [`U512`] (wrapping on overflow; intended for
/// constants and test vectors).
pub fn uint_from_dec(dec: &str) -> Result<U512> {
    if dec.is_empty() || !dec.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidHex);
    }
    let ten = U512::from_u64(10);
    let mut acc = U512::ZERO;
    for b in dec.bytes() {
        acc = acc.wrapping_mul(&ten).wrapping_add(&U512::from_u64(u64::from(b - b'0')));
    }
    Ok(acc)
}

/// Convert a [`U512`] to a fixed-width big-endian byte string.
///
/// Panics if the value does not fit in `len` bytes.
pub(crate) fn to_be_bytes(v: &U512, len: usize) -> Vec<u8> {
    let full = v.to_be_bytes();
    let full: &[u8] = full.as_ref();
    assert!(full[..64 - len].iter().all(|&b| b == 0), "value does not fit");
    full[64 - len..].to_vec()
}

/// Read a big-endian byte string of at most 64 bytes.
pub(crate) fn from_be_bytes(bytes: &[u8]) -> U512 {
    assert!(bytes.len() <= 64);
    let mut buf = [0u8; 64];
    buf[64 - bytes.len()..].copy_from_slice(bytes);
    U512::from_be_slice(&buf)
}

/// Read a little-endian byte string of at most 64 bytes.
pub(crate) fn from_le_bytes(bytes: &[u8]) -> U512 {
    assert!(bytes.len() <= 64);
    let mut buf = [0u8; 64];
    buf[..bytes.len()].copy_from_slice(bytes);
    U512::from_le_slice(&buf)
}

/// A point in affine coordinates, or the point at infinity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AffinePoint {
    /// The neutral element `O`.
    Infinity,
    /// A finite point with coordinates in `[0, p-1]`.
    Point {
        /// `x` coordinate.
        x: U512,
        /// `y` coordinate.
        y: U512,
    },
}

impl AffinePoint {
    /// Construct a finite point (no curve check — see [`Curve::is_on_curve`]).
    pub const fn new(x: U512, y: U512) -> Self {
        AffinePoint::Point { x, y }
    }

    /// Coordinates of a finite point.
    pub fn coordinates(&self) -> Option<(&U512, &U512)> {
        match self {
            AffinePoint::Infinity => None,
            AffinePoint::Point { x, y } => Some((x, y)),
        }
    }
}

impl fmt::Debug for AffinePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AffinePoint::Infinity => f.write_str("Infinity"),
            AffinePoint::Point { x, y } => f
                .debug_struct("Point")
                .field("x", &x.to_string())
                .field("y", &y.to_string())
                .finish(),
        }
    }
}

/// Jacobian projective point `(X : Y : Z)` with `x = X/Z^2`, `y = Y/Z^3`.
/// `Z == 0` is the point at infinity.
#[derive(Clone)]
pub(crate) struct Jacobian {
    x: Fe,
    y: Fe,
    z: Fe,
}

/// An elliptic curve `y^2 = x^3 + ax + b` over `F_p` with a base point `G`
/// of prime order `q`.
pub struct Curve {
    name: &'static str,
    oid: Option<&'static str>,
    p: U512,
    fp: Mp,
    a: Fe,
    b: Fe,
    q: NonZero<U512>,
    fq: Mp,
    gx: U512,
    gy: U512,
    g: Jacobian,
    /// Number of bytes of a field element / scalar in encodings (32 or 64).
    coord_len: usize,
    /// Bit length of `q` (public; bounds the Montgomery ladder).
    q_bits: u32,
}

impl fmt::Debug for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Curve")
            .field("name", &self.name)
            .field("oid", &self.oid)
            .field("p", &self.p.to_string())
            .field("q", &self.q.as_ref().to_string())
            .finish()
    }
}

impl Curve {
    /// Build a curve from raw parameters and validate them.
    ///
    /// Checks performed: `p` and `q` are odd and larger than 3, `a`, `b`,
    /// `x`, `y` are reduced modulo `p`, `G = (x, y)` satisfies the curve
    /// equation and `q·G = O`.  Primality of `p` and `q` is **not** checked.
    pub fn from_params(p: U512, a: U512, b: U512, q: U512, x: U512, y: U512) -> Result<Self> {
        Self::from_params_named("custom", None, p, a, b, q, x, y)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_params_named(
        name: &'static str,
        oid: Option<&'static str>,
        p: U512,
        a: U512,
        b: U512,
        q: U512,
        x: U512,
        y: U512,
    ) -> Result<Self> {
        let three = U512::from_u64(3);
        if p <= three || q <= three {
            return Err(Error::InvalidCurveParams);
        }
        let p_odd = Odd::new(p).into_option().ok_or(Error::InvalidCurveParams)?;
        let q_odd = Odd::new(q).into_option().ok_or(Error::InvalidCurveParams)?;
        if a >= p || b >= p || x >= p || y >= p {
            return Err(Error::InvalidCurveParams);
        }
        let fp = Mp::new(p_odd);
        let fq = Mp::new(q_odd);
        let q_nz = NonZero::new(q).into_option().ok_or(Error::InvalidCurveParams)?;
        let q_bits = q.bits_vartime();
        let coord_len = if p.bits_vartime() <= 256 { 32 } else { 64 };
        let g = Jacobian {
            x: Fe::new(&x, &fp),
            y: Fe::new(&y, &fp),
            z: Fe::one(&fp),
        };
        let curve = Curve {
            name,
            oid,
            p,
            fp,
            a: Fe::new(&a, &fp),
            b: Fe::new(&b, &fp),
            q: q_nz,
            fq,
            gx: x,
            gy: y,
            g,
            coord_len,
            q_bits,
        };
        if !curve.is_on_curve(&AffinePoint::new(x, y)) {
            return Err(Error::InvalidCurveParams);
        }
        if !curve.mul(&curve.g, q_nz.as_ref()).is_infinity() {
            return Err(Error::InvalidCurveParams);
        }
        Ok(curve)
    }

    /// Human-readable name of the parameter set.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Object identifier of the parameter set (dotted decimal), if any.
    pub fn oid(&self) -> Option<&'static str> {
        self.oid
    }

    /// The field modulus `p`.
    pub fn modulus(&self) -> &U512 {
        &self.p
    }

    /// Coefficient `a`.
    pub fn a(&self) -> U512 {
        self.a.retrieve()
    }

    /// Coefficient `b`.
    pub fn b(&self) -> U512 {
        self.b.retrieve()
    }

    /// The (prime) order `q` of the base point.
    pub fn order(&self) -> &U512 {
        self.q.as_ref()
    }

    /// The base point `G`.
    pub fn generator(&self) -> AffinePoint {
        AffinePoint::new(self.gx, self.gy)
    }

    /// Byte length of one coordinate / scalar in fixed-width encodings
    /// (32 for 256-bit curves, 64 for 512-bit curves).
    pub fn coordinate_len(&self) -> usize {
        self.coord_len
    }

    /// Bit length of `q`.
    pub fn order_bits(&self) -> u32 {
        self.q_bits
    }

    pub(crate) fn fq(&self) -> &Mp {
        &self.fq
    }

    /// Reduce an arbitrary integer modulo `q`.
    pub fn reduce_scalar(&self, v: &U512) -> U512 {
        v.rem(&self.q)
    }

    /// Returns `true` if `v` is in `[1, q-1]`.
    pub fn is_valid_scalar(&self, v: &U512) -> bool {
        !bool::from(v.is_zero()) && v < self.q.as_ref()
    }

    /// Check that a point satisfies the curve equation.  The point at
    /// infinity is on the curve by definition.
    pub fn is_on_curve(&self, point: &AffinePoint) -> bool {
        match point {
            AffinePoint::Infinity => true,
            AffinePoint::Point { x, y } => {
                if x >= &self.p || y >= &self.p {
                    return false;
                }
                let x = Fe::new(x, &self.fp);
                let y = Fe::new(y, &self.fp);
                let lhs = y.square();
                let rhs = x.square().mul(&x).add(&self.a.mul(&x)).add(&self.b);
                lhs.retrieve() == rhs.retrieve()
            }
        }
    }

    // ----- projective arithmetic -------------------------------------------------

    pub(crate) fn identity(&self) -> Jacobian {
        Jacobian {
            x: Fe::one(&self.fp),
            y: Fe::one(&self.fp),
            z: Fe::zero(&self.fp),
        }
    }

    pub(crate) fn generator_jac(&self) -> &Jacobian {
        &self.g
    }

    pub(crate) fn to_jacobian(&self, point: &AffinePoint) -> Jacobian {
        match point {
            AffinePoint::Infinity => self.identity(),
            AffinePoint::Point { x, y } => Jacobian {
                x: Fe::new(x, &self.fp),
                y: Fe::new(y, &self.fp),
                z: Fe::one(&self.fp),
            },
        }
    }

    pub(crate) fn to_affine(&self, point: &Jacobian) -> AffinePoint {
        if point.is_infinity() {
            return AffinePoint::Infinity;
        }
        let zi = point
            .z
            .invert()
            .into_option()
            .expect("non-zero field element is invertible (p prime)");
        let zi2 = zi.square();
        let zi3 = zi2.mul(&zi);
        AffinePoint::Point {
            x: point.x.mul(&zi2).retrieve(),
            y: point.y.mul(&zi3).retrieve(),
        }
    }

    /// Point doubling ("dbl-2007-bl", general `a`).
    pub(crate) fn double(&self, p: &Jacobian) -> Jacobian {
        if p.is_infinity() {
            return self.identity();
        }
        let xx = p.x.square();
        let yy = p.y.square();
        let yyyy = yy.square();
        let zz = p.z.square();
        // S = 2*((X1+YY)^2 - XX - YYYY)
        let s = p.x.add(&yy).square().sub(&xx).sub(&yyyy).double();
        // M = 3*XX + a*ZZ^2
        let m = xx.double().add(&xx).add(&self.a.mul(&zz.square()));
        // T = M^2 - 2*S
        let t = m.square().sub(&s.double());
        // Y3 = M*(S-T) - 8*YYYY
        let y3 = m.mul(&s.sub(&t)).sub(&yyyy.double().double().double());
        // Z3 = (Y1+Z1)^2 - YY - ZZ
        let z3 = p.y.add(&p.z).square().sub(&yy).sub(&zz);
        Jacobian { x: t, y: y3, z: z3 }
    }

    /// Point addition ("add-2007-bl") with the special cases handled by
    /// branches.
    pub(crate) fn add(&self, p: &Jacobian, q: &Jacobian) -> Jacobian {
        if p.is_infinity() {
            return q.clone();
        }
        if q.is_infinity() {
            return p.clone();
        }
        let z1z1 = p.z.square();
        let z2z2 = q.z.square();
        let u1 = p.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = p.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&p.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let rr = s2.sub(&s1);
        if fe_is_zero(&h) {
            if fe_is_zero(&rr) {
                return self.double(p);
            }
            return self.identity();
        }
        let i = h.double().square();
        let j = h.mul(&i);
        let r = rr.double();
        let v = u1.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = p.z.add(&q.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        Jacobian { x: x3, y: y3, z: z3 }
    }

    /// Scalar multiplication `k·P` by a Montgomery ladder over `order_bits()`
    /// bits (the scalar must be below `2^order_bits()`; callers reduce
    /// modulo `q` first).
    pub(crate) fn mul(&self, p: &Jacobian, k: &U512) -> Jacobian {
        debug_assert!(k.bits_vartime() <= self.q_bits);
        let mut r0 = self.identity();
        let mut r1 = p.clone();
        for i in (0..self.q_bits).rev() {
            if k.bit_vartime(i) {
                r0 = self.add(&r0, &r1);
                r1 = self.double(&r1);
            } else {
                r1 = self.add(&r0, &r1);
                r0 = self.double(&r0);
            }
        }
        r0
    }

    /// `k·P` for an affine point, returning affine coordinates.
    pub fn mul_affine(&self, p: &AffinePoint, k: &U512) -> AffinePoint {
        let k = self.reduce_scalar(k);
        self.to_affine(&self.mul(&self.to_jacobian(p), &k))
    }

    /// `k·G`.
    pub fn mul_generator(&self, k: &U512) -> AffinePoint {
        let k = self.reduce_scalar(k);
        self.to_affine(&self.mul(&self.g, &k))
    }

    /// `P + Q` in affine coordinates.
    pub fn add_affine(&self, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        self.to_affine(&self.add(&self.to_jacobian(p), &self.to_jacobian(q)))
    }
}

fn fe_is_zero(v: &Fe) -> bool {
    bool::from(v.as_montgomery().is_zero())
}

impl Jacobian {
    pub(crate) fn is_infinity(&self) -> bool {
        fe_is_zero(&self.z)
    }
}

// ----- named parameter sets ---------------------------------------------------

/// Named parameter sets.
///
/// | Variant | TC26 / RFC name | KZ OID (НУЦ РК) | RU OID |
/// |---|---|---|---|
/// | [`Tc26Gost3410_12_512ParamSetA`](Self::Tc26Gost3410_12_512ParamSetA) | `id-tc26-gost-3410-12-512-paramSetA` (RFC 7836 §A.1) | `1.2.398.3.10.1.1.2.2.1` | `1.2.643.7.1.2.1.2.1` |
/// | [`Tc26Gost3410_2012_256ParamSetA`](Self::Tc26Gost3410_2012_256ParamSetA) | `id-tc26-gost-3410-2012-256-paramSetA` (RFC 7836 §A.2, Weierstrass form) | `1.2.398.3.10.1.1.2.1.1` | `1.2.643.7.1.2.1.1.1` |
/// | [`GostR3410_2001_CryptoPro_A`](Self::GostR3410_2001_CryptoPro_A) | `id-GostR3410-2001-CryptoPro-A-ParamSet` (RFC 4357 §11.4) | `1.2.398.3.10.1.1.1.1.1` | `1.2.643.2.2.35.1` |
///
/// The 256-bit TC26 curve is defined in RFC 7836 in twisted Edwards form;
/// the Weierstrass form used here is the one printed in RFC 7836 §A.2 (and
/// used by all X.509 implementations).  Its group has cofactor 4; `q` is the
/// order of the generator, not of the whole group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum NamedCurve {
    /// 512-bit curve used with Streebog-512 (GOST R 34.10-2012, 512 bit).
    Tc26Gost3410_12_512ParamSetA,
    /// 256-bit curve used with Streebog-256 (GOST R 34.10-2012, 256 bit).
    Tc26Gost3410_2012_256ParamSetA,
    /// 256-bit CryptoPro-A curve used with GOST R 34.11-94 (GOST R 34.10-2001 /
    /// ГОСТ 34.310-2004); needed only to verify legacy signatures.
    GostR3410_2001_CryptoPro_A,
}

impl NamedCurve {
    /// All named curves.
    pub const ALL: [NamedCurve; 3] = [
        NamedCurve::Tc26Gost3410_12_512ParamSetA,
        NamedCurve::Tc26Gost3410_2012_256ParamSetA,
        NamedCurve::GostR3410_2001_CryptoPro_A,
    ];

    /// The curve parameters (built once, cached for the process lifetime).
    pub fn curve(self) -> &'static Curve {
        match self {
            NamedCurve::Tc26Gost3410_12_512ParamSetA => &TC26_512_A,
            NamedCurve::Tc26Gost3410_2012_256ParamSetA => &TC26_256_A,
            NamedCurve::GostR3410_2001_CryptoPro_A => &CRYPTOPRO_2001_A,
        }
    }

    /// Kazakhstan (НУЦ РК) object identifier of the parameter set.
    pub fn oid_kz(self) -> &'static str {
        match self {
            NamedCurve::Tc26Gost3410_12_512ParamSetA => "1.2.398.3.10.1.1.2.2.1",
            NamedCurve::Tc26Gost3410_2012_256ParamSetA => "1.2.398.3.10.1.1.2.1.1",
            NamedCurve::GostR3410_2001_CryptoPro_A => "1.2.398.3.10.1.1.1.1.1",
        }
    }

    /// Russian (TC26 / CryptoPro) object identifier of the parameter set.
    pub fn oid_ru(self) -> &'static str {
        match self {
            NamedCurve::Tc26Gost3410_12_512ParamSetA => "1.2.643.7.1.2.1.2.1",
            NamedCurve::Tc26Gost3410_2012_256ParamSetA => "1.2.643.7.1.2.1.1.1",
            NamedCurve::GostR3410_2001_CryptoPro_A => "1.2.643.2.2.35.1",
        }
    }

    /// Look a parameter set up by either its KZ or RU OID.
    pub fn from_oid(oid: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.oid_kz() == oid || c.oid_ru() == oid)
    }

    /// The hash function this parameter set is used with.
    pub fn hash_alg(self) -> crate::HashAlg {
        match self {
            NamedCurve::Tc26Gost3410_12_512ParamSetA => crate::HashAlg::Streebog512,
            NamedCurve::Tc26Gost3410_2012_256ParamSetA => crate::HashAlg::Streebog256,
            NamedCurve::GostR3410_2001_CryptoPro_A => crate::HashAlg::Gost94CryptoPro,
        }
    }
}

fn h(s: &str) -> U512 {
    uint_from_be_hex(s).expect("valid constant")
}

/// RFC 7836 §A.1, `id-tc26-gost-3410-12-512-paramSetA`: p = 2^512 - 569, a = p - 3.
static TC26_512_A: LazyLock<Curve> = LazyLock::new(|| {
    Curve::from_params_named(
        "id-tc26-gost-3410-12-512-paramSetA",
        Some("1.2.398.3.10.1.1.2.2.1"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
        h("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
        h("3"),
        h("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
    )
    .expect("RFC 7836 512-bit paramSetA constants are valid")
});

/// RFC 7836 §A.2, `id-tc26-gost-3410-2012-256-paramSetA` in Weierstrass form:
/// p = 2^256 - 617.  The group has cofactor 4; `q` is the generator order.
static TC26_256_A: LazyLock<Curve> = LazyLock::new(|| {
    Curve::from_params_named(
        "id-tc26-gost-3410-2012-256-paramSetA",
        Some("1.2.398.3.10.1.1.2.1.1"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
        h("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
        h("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
        h("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
        h("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
        h("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
    )
    .expect("RFC 7836 256-bit paramSetA constants are valid")
});

/// RFC 4357 §11.4, `id-GostR3410-2001-CryptoPro-A-ParamSet`: p = 2^256 - 617,
/// a = p - 3, b = 166, G = (1, y).
static CRYPTOPRO_2001_A: LazyLock<Curve> = LazyLock::new(|| {
    Curve::from_params_named(
        "id-GostR3410-2001-CryptoPro-A-ParamSet",
        Some("1.2.398.3.10.1.1.1.1.1"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
        h("A6"),
        h("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
        h("1"),
        h("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
    )
    .expect("RFC 4357 CryptoPro-A constants are valid")
});
