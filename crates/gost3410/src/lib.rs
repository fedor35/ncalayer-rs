//! Pure-Rust implementation of the GOST R 34.10-2012 digital signature
//! scheme ([RFC 7091]) over short Weierstrass curves `y^2 = x^3 + ax + b`
//! over a prime field `F_p`.
//!
//! The crate exists for an open replacement of NCALayer, so it ships the
//! three parameter sets used by the Kazakhstan National Certification
//! Authority (НУЦ РК) as [`NamedCurve`] constants (see [`curve`] for the
//! OIDs), plus a generic [`Curve::from_params`] constructor for anything else.
//!
//! # What is implemented
//!
//! * Field and scalar arithmetic on top of [`crypto_bigint`] (`U512`,
//!   Montgomery form via [`crypto_bigint::modular::FixedMontyForm`]).  Every
//!   curve, including the 256-bit ones, is computed at a uniform 512-bit
//!   width; this is slower than a dedicated `U256` backend but keeps a single
//!   non-generic API.
//! * Jacobian point arithmetic and scalar multiplication by a Montgomery
//!   ladder (see [`curve`] for the exact side-channel properties — in short:
//!   field arithmetic is constant-time, the scalar-bit loop is **not**).
//! * [`sign`] / [`verify`] exactly as in GOST R 34.10-2012 §6.1 / §6.2
//!   (RFC 7091 §6), both with an external [`rand_core::CryptoRng`] and with
//!   deterministic nonces derived with an RFC 6979-style HMAC-DRBG over
//!   Streebog ([`sign_deterministic`]).
//! * The hash functions (Streebog-256/512 for 2012 keys, GOST R 34.11-94
//!   with the CryptoPro S-box for 2001 keys) via the RustCrypto crates;
//!   see [`hash`].
//! * Byte encodings used by X.509 / CMS (RFC 4490 §2.2.2, RFC 4491
//!   §2.2.2 / §2.3.2, RFC 9215 §2 / §4.3) and by the standard itself; see
//!   [`Signature`] and [`PublicKey`].
//!
//! # Byte orders (the part everybody gets wrong)
//!
//! | Object | Encoding | Reference |
//! |---|---|---|
//! | digest → integer `e` | the digest bytes **as produced by the `streebog`/`gost94` crates** (which match CryptoPro / gost-engine / KalkanCrypt output) are read as a **little-endian** integer | RFC 4490 §2.2.1 ("little-endian" digest); verified against NCA certificates |
//! | signature in the GOST text | `r ‖ s`, each big-endian | GOST R 34.10-2012 §6.1 step 7 (`ζ = r̄ ‖ s̄`); [`Signature::to_bytes_gost`] |
//! | signature in X.509 / CMS, Russian profile | `s ‖ r`, each big-endian, fixed width (32 or 64 bytes) | RFC 4490 §2.2.2, RFC 4491 §2.2.2, RFC 9215 §2; [`Signature::to_bytes_rfc4491`] |
//! | signature in X.509 issued by the Kazakhstan NCA | `r ‖ s`, each **little-endian** — the byte reversal of the RFC layout | no RFC; verified on `root_gost_2022.cer` / `nca_gost_2022.cer`; [`Signature::to_bytes_kz`] |
//! | public key in X.509 | `x ‖ y`, each **little-endian** | RFC 4491 §2.3.2, RFC 9215 §4.3; [`PublicKey::to_bytes_x509`] — the NCA follows this one |
//!
//! [RFC 7091]: https://www.rfc-editor.org/rfc/rfc7091

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod curve;
mod det;
mod error;
pub mod hash;
mod sign;

pub use crypto_bigint::U512;
pub use curve::{AffinePoint, Curve, NamedCurve};
pub use error::Error;
pub use hash::{digest_for_curve, HashAlg};
pub use sign::{sign, sign_deterministic, sign_with_k, verify, PublicKey, SecretKey, Signature};

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
