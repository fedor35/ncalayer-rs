//! Hash functions paired with the signature parameter sets, and the
//! digest → integer conversion of GOST R 34.10-2012 §6.1 step 2.
//!
//! Hashing itself is delegated to the RustCrypto crates [`streebog`] and
//! [`gost94`]; nothing is reimplemented here.
//!
//! # Digest byte order
//!
//! The `streebog` and `gost94` crates output the digest in the same byte
//! order as CryptoPro CSP, gost-engine (OpenSSL) and KalkanCrypt, i.e. the
//! order found in CMS `MessageDigest` attributes.  This is the *reverse* of
//! the way GOST R 34.11-2012 prints its examples as numbers.  Consequently
//! the standard's integer `α` is obtained by reading those bytes as a
//! **little-endian** integer (RFC 4490 §2.2.1; checked against a real NCA
//! root certificate in this crate's tests).  [`Curve::e_from_digest`] does
//! exactly that and then applies `e = α mod q; if e == 0 { e = 1 }`.

use digest::Digest;

use crate::curve::{from_le_bytes, Curve};
use crate::U512;

/// Hash algorithms used with GOST signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// GOST R 34.11-2012, 256-bit output (Streebog-256).
    Streebog256,
    /// GOST R 34.11-2012, 512-bit output (Streebog-512).
    Streebog512,
    /// GOST R 34.11-94 with the CryptoPro parameter set (RFC 4357 §11.2).
    Gost94CryptoPro,
}

impl HashAlg {
    /// Output size in bytes.
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Streebog256 | HashAlg::Gost94CryptoPro => 32,
            HashAlg::Streebog512 => 64,
        }
    }

    /// Hash a message.
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Streebog256 => streebog::Streebog256::digest(msg).to_vec(),
            HashAlg::Streebog512 => streebog::Streebog512::digest(msg).to_vec(),
            HashAlg::Gost94CryptoPro => gost94::Gost94CryptoPro::digest(msg).to_vec(),
        }
    }

    /// Russian OID of the hash algorithm.
    pub fn oid_ru(self) -> &'static str {
        match self {
            HashAlg::Streebog256 => "1.2.643.7.1.1.2.2",
            HashAlg::Streebog512 => "1.2.643.7.1.1.2.3",
            HashAlg::Gost94CryptoPro => "1.2.643.2.2.9",
        }
    }
}

/// Hash `msg` with the algorithm that belongs to `curve`
/// (Streebog-512 for the 512-bit curve, Streebog-256 for the 2012 256-bit
/// curve, GOST R 34.11-94/CryptoPro for the 2001 curve).
pub fn digest_for_curve(curve: crate::NamedCurve, msg: &[u8]) -> Vec<u8> {
    curve.hash_alg().digest(msg)
}

impl Curve {
    /// GOST R 34.10-2012 §6.1 step 2: interpret the digest as a
    /// little-endian integer `α`, compute `e = α mod q` and replace `0` by
    /// `1`.
    ///
    /// Panics if the digest is longer than 64 bytes.
    pub fn e_from_digest(&self, digest: &[u8]) -> U512 {
        assert!(digest.len() <= 64, "digest longer than 512 bits");
        let alpha = from_le_bytes(digest);
        let e = self.reduce_scalar(&alpha);
        if bool::from(e.is_zero()) {
            U512::ONE
        } else {
            e
        }
    }
}
