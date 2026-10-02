//! Keys, signatures and the GOST R 34.10-2012 sign / verify procedures.

use core::fmt;

use crypto_bigint::modular::FixedMontyForm;
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::curve::{from_be_bytes, from_le_bytes, to_be_bytes, AffinePoint, Curve};
use crate::det::NonceGen;
use crate::{Error, Result, U512};

/// A signature `(r, s)` as integers in `[1, q-1]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// `r = x_C mod q`.
    pub r: U512,
    /// `s = (r·d + k·e) mod q`.
    pub s: U512,
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("r", &self.r.to_string())
            .field("s", &self.s.to_string())
            .finish()
    }
}

impl Signature {
    /// Encode as the standard's bit string `ζ = r̄ ‖ s̄`
    /// (GOST R 34.10-2012 §6.1 step 7, RFC 7091 §6.1): `r` then `s`, each a
    /// big-endian integer of `curve.coordinate_len()` bytes.  This is the
    /// order used in the standard's test examples; it is **not** what X.509
    /// certificates contain (see [`to_bytes_rfc4491`](Self::to_bytes_rfc4491)
    /// and [`to_bytes_kz`](Self::to_bytes_kz)).
    pub fn to_bytes_gost(&self, curve: &Curve) -> Vec<u8> {
        let len = curve.coordinate_len();
        let mut out = to_be_bytes(&self.r, len);
        out.extend(to_be_bytes(&self.s, len));
        out
    }

    /// Decode `r̄ ‖ s̄` (see [`to_bytes_gost`](Self::to_bytes_gost)).
    pub fn from_bytes_gost(curve: &Curve, bytes: &[u8]) -> Result<Self> {
        let len = curve.coordinate_len();
        check_len(bytes, 2 * len)?;
        let sig = Signature {
            r: from_be_bytes(&bytes[..len]),
            s: from_be_bytes(&bytes[len..]),
        };
        sig.validate(curve)?;
        Ok(sig)
    }

    /// Encode as specified for X.509 `signatureValue` and CMS
    /// `SignerInfo.signature` by the Russian profile: **`s` first, then
    /// `r`**, each a big-endian integer of `curve.coordinate_len()` bytes
    /// (RFC 4490 §2.2.2, RFC 4491 §2.2.2, RFC 9215 §2).  This is what
    /// CryptoPro CSP and gost-engine produce.  The result is the raw content
    /// of the `BIT STRING` / `OCTET STRING` (no DER wrapping).
    ///
    /// **Certificates issued by the Kazakhstan NCA do not use this layout**;
    /// see [`to_bytes_kz`](Self::to_bytes_kz).
    pub fn to_bytes_rfc4491(&self, curve: &Curve) -> Vec<u8> {
        let len = curve.coordinate_len();
        let mut out = to_be_bytes(&self.s, len);
        out.extend(to_be_bytes(&self.r, len));
        out
    }

    /// Decode the RFC 4491 / RFC 9215 form `s ‖ r` (big-endian each); see
    /// [`to_bytes_rfc4491`](Self::to_bytes_rfc4491).
    pub fn from_bytes_rfc4491(curve: &Curve, bytes: &[u8]) -> Result<Self> {
        let len = curve.coordinate_len();
        check_len(bytes, 2 * len)?;
        let sig = Signature {
            s: from_be_bytes(&bytes[..len]),
            r: from_be_bytes(&bytes[len..]),
        };
        sig.validate(curve)?;
        Ok(sig)
    }

    /// Encode as found in X.509 certificates issued by the Kazakhstan NCA
    /// (НУЦ РК / KalkanCrypt): **`r` first, then `s`, each little-endian**,
    /// `curve.coordinate_len()` bytes.  Byte for byte this is the reversal
    /// of the RFC 4491 layout (`reverse(s_BE ‖ r_BE) = r_LE ‖ s_LE`).
    ///
    /// Established empirically: the self-signature of
    /// `root_gost_2022.cer` and the signature of `nca_gost_2022.cer`
    /// (both from <https://pki.gov.kz/cert/>) verify only with this layout;
    /// see `tests/nca_certs.rs`.  No RFC describes it.
    pub fn to_bytes_kz(&self, curve: &Curve) -> Vec<u8> {
        let mut out = self.to_bytes_rfc4491(curve);
        out.reverse();
        out
    }

    /// Decode the NCA layout `r_LE ‖ s_LE`; see [`to_bytes_kz`](Self::to_bytes_kz).
    pub fn from_bytes_kz(curve: &Curve, bytes: &[u8]) -> Result<Self> {
        let len = curve.coordinate_len();
        check_len(bytes, 2 * len)?;
        let mut rev = bytes.to_vec();
        rev.reverse();
        Self::from_bytes_rfc4491(curve, &rev)
    }

    fn validate(&self, curve: &Curve) -> Result<()> {
        if curve.is_valid_scalar(&self.r) && curve.is_valid_scalar(&self.s) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

fn check_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        })
    }
}

/// A public key `Q = d·G`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey {
    point: AffinePoint,
}

impl PublicKey {
    /// Wrap an affine point after checking it is on the curve and not the
    /// point at infinity.
    pub fn from_affine(curve: &Curve, point: AffinePoint) -> Result<Self> {
        if point == AffinePoint::Infinity || !curve.is_on_curve(&point) {
            return Err(Error::PointNotOnCurve);
        }
        Ok(PublicKey { point })
    }

    /// The point `Q`.
    pub fn point(&self) -> &AffinePoint {
        &self.point
    }

    /// Coordinates `(x, y)`.
    pub fn coordinates(&self) -> (&U512, &U512) {
        self.point
            .coordinates()
            .expect("public key is never the point at infinity")
    }

    /// Encode as in X.509 `SubjectPublicKeyInfo` (RFC 4491 §2.3.2, RFC 9215
    /// §4.3): `x ‖ y`, each **little-endian**, `coordinate_len()` bytes.
    /// This is the content of the inner `OCTET STRING` (the DER
    /// `OCTET STRING` header and the outer `BIT STRING` are not included).
    pub fn to_bytes_x509(&self, curve: &Curve) -> Vec<u8> {
        let len = curve.coordinate_len();
        let (x, y) = self.coordinates();
        let mut out = to_be_bytes(x, len);
        out.reverse();
        let mut yb = to_be_bytes(y, len);
        yb.reverse();
        out.extend(yb);
        out
    }

    /// Decode the X.509 form `x ‖ y` (little-endian each).
    pub fn from_bytes_x509(curve: &Curve, bytes: &[u8]) -> Result<Self> {
        let len = curve.coordinate_len();
        check_len(bytes, 2 * len)?;
        let x = from_le_bytes(&bytes[..len]);
        let y = from_le_bytes(&bytes[len..]);
        Self::from_affine(curve, AffinePoint::new(x, y))
    }
}

/// A secret scalar `d` in `[1, q-1]`.  Zeroized on drop.
#[derive(Clone)]
pub struct SecretKey {
    d: U512,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.d.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl SecretKey {
    /// Wrap a scalar after checking `1 <= d < q`.
    pub fn from_scalar(curve: &Curve, d: U512) -> Result<Self> {
        if curve.is_valid_scalar(&d) {
            Ok(SecretKey { d })
        } else {
            Err(Error::InvalidSecretKey)
        }
    }

    /// Decode a big-endian scalar of `coordinate_len()` bytes.
    pub fn from_bytes_be(curve: &Curve, bytes: &[u8]) -> Result<Self> {
        check_len(bytes, curve.coordinate_len())?;
        Self::from_scalar(curve, from_be_bytes(bytes))
    }

    /// Generate a uniformly random key.
    pub fn random<R: CryptoRng + ?Sized>(curve: &Curve, rng: &mut R) -> Result<Self> {
        let d = random_scalar(curve, rng)?;
        Ok(SecretKey { d })
    }

    /// The scalar `d`.
    pub fn scalar(&self) -> &U512 {
        &self.d
    }

    /// Big-endian encoding of `d`, `coordinate_len()` bytes.
    pub fn to_bytes_be(&self, curve: &Curve) -> Vec<u8> {
        to_be_bytes(&self.d, curve.coordinate_len())
    }

    /// Derive `Q = d·G`.
    pub fn public_key(&self, curve: &Curve) -> PublicKey {
        PublicKey {
            point: curve.mul_generator(&self.d),
        }
    }
}

/// Uniform scalar in `[1, q-1]`: 512 random bits reduced modulo `q`
/// (bias ≤ 2^-256 for the 256-bit curves, ≤ 2^-480 for the 512-bit one).
fn random_scalar<R: CryptoRng + ?Sized>(curve: &Curve, rng: &mut R) -> Result<U512> {
    let mut buf = [0u8; 64];
    for _ in 0..64 {
        rng.fill_bytes(&mut buf);
        let v = curve.reduce_scalar(&U512::from_be_slice(&buf));
        buf.zeroize();
        if curve.is_valid_scalar(&v) {
            return Ok(v);
        }
    }
    Err(Error::RngExhausted)
}

/// GOST R 34.10-2012 §6.1 steps 3–6 for a given nonce `k`.
/// Returns `None` if `r == 0` or `s == 0` (the caller picks a new `k`).
fn sign_core(curve: &Curve, d: &U512, e: &U512, k: &U512) -> Option<Signature> {
    let c = curve.mul_generator(k);
    let (xc, _) = c.coordinates()?;
    let r = curve.reduce_scalar(xc);
    if bool::from(r.is_zero()) {
        return None;
    }
    let fq = curve.fq();
    let rm = FixedMontyForm::new(&r, fq);
    let dm = FixedMontyForm::new(d, fq);
    let km = FixedMontyForm::new(k, fq);
    let em = FixedMontyForm::new(e, fq);
    let s = rm.mul(&dm).add(&km.mul(&em)).retrieve();
    if bool::from(s.is_zero()) {
        return None;
    }
    Some(Signature { r, s })
}

/// Sign a digest with an explicit nonce `k` (GOST R 34.10-2012 §6.1 with
/// step 3 replaced by the caller's `k`).
///
/// **Only for test vectors.**  Reusing or leaking `k` reveals `d`.
/// Returns [`Error::InvalidSignature`] if `k` is outside `[1, q-1]` or the
/// resulting `r` or `s` is zero.
pub fn sign_with_k(curve: &Curve, key: &SecretKey, digest: &[u8], k: &U512) -> Result<Signature> {
    if !curve.is_valid_scalar(k) {
        return Err(Error::InvalidSignature);
    }
    let e = curve.e_from_digest(digest);
    sign_core(curve, key.scalar(), &e, k).ok_or(Error::InvalidSignature)
}

/// Sign a digest with a nonce drawn from `rng` (GOST R 34.10-2012 §6.1).
///
/// `digest` is the raw output of the hash function (see
/// [`crate::hash`] for the byte-order convention).
pub fn sign<R: CryptoRng + ?Sized>(
    curve: &Curve,
    key: &SecretKey,
    digest: &[u8],
    rng: &mut R,
) -> Result<Signature> {
    let e = curve.e_from_digest(digest);
    for _ in 0..64 {
        let mut k = random_scalar(curve, rng)?;
        let sig = sign_core(curve, key.scalar(), &e, &k);
        k.zeroize();
        if let Some(sig) = sig {
            return Ok(sig);
        }
    }
    Err(Error::RngExhausted)
}

/// Sign a digest with a deterministic nonce derived from `(d, e)` by an
/// RFC 6979-style HMAC-DRBG over Streebog-256/512 (not an interoperability
/// format: no standard defines RFC 6979 for GOST; it only removes the
/// dependency on the system RNG).
pub fn sign_deterministic(curve: &Curve, key: &SecretKey, digest: &[u8]) -> Signature {
    let e = curve.e_from_digest(digest);
    let mut gen = NonceGen::new(curve, key.scalar(), &e);
    loop {
        let mut k = gen.next_k();
        let sig = sign_core(curve, key.scalar(), &e, &k);
        k.zeroize();
        if let Some(sig) = sig {
            return sig;
        }
    }
}

/// Verify a signature (GOST R 34.10-2012 §6.2).  Returns `false` for any
/// malformed input instead of panicking.
pub fn verify(curve: &Curve, key: &PublicKey, digest: &[u8], sig: &Signature) -> bool {
    if digest.len() > 64 {
        return false;
    }
    // Step 1: 0 < r, s < q.
    if !curve.is_valid_scalar(&sig.r) || !curve.is_valid_scalar(&sig.s) {
        return false;
    }
    // Step 2: e.
    let e = curve.e_from_digest(digest);
    let fq = curve.fq();
    // Step 3: v = e^-1 mod q.
    let Some(v) = FixedMontyForm::new(&e, fq).invert().into_option() else {
        return false;
    };
    // Step 4: z1 = s·v, z2 = -r·v.
    let z1 = FixedMontyForm::new(&sig.s, fq).mul(&v).retrieve();
    let z2 = FixedMontyForm::new(&sig.r, fq).mul(&v).neg().retrieve();
    // Step 5: C = z1·G + z2·Q, R = x_C mod q.
    let q_jac = curve.to_jacobian(key.point());
    let c = curve.add(
        &curve.mul(curve.generator_jac(), &z1),
        &curve.mul(&q_jac, &z2),
    );
    let Some((xc, _)) = curve.to_affine(&c).coordinates().map(|(x, y)| (*x, *y)) else {
        return false;
    };
    // Step 6.
    curve.reduce_scalar(&xc) == sig.r
}
