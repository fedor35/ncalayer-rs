#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Key containers and certificates of the Kazakhstan NCA (НУЦ РК).
//!
//! The crate reads legacy PKCS#12 files as written by Kalkan / BouncyCastle,
//! extracts GOST R 34.10-2015 / 34.10-2004 / RSA private keys and exposes the
//! certificate fields NCALayer's `getKeyInfo` reports.

pub mod ber;
pub mod cert;
pub mod error;
pub mod key;
pub mod oid;
pub mod pbe;
pub mod pkcs12;

pub use cert::{Cert, KeyUsageType};
pub use error::{Error, Result};
pub use key::{Gost2015Curve, PrivateKey, PublicKey};
pub use pkcs12::{Entry, KeyStore};
