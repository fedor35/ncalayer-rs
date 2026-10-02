//! CMS `SignedData` / CAdES-BES / CAdES-T for an open NCALayer replacement
//! (Kazakhstan NCA, НУЦ РК).
//!
//! The crate reproduces what NCALayer's `CMSUtil.createCAdES` (Kalkan, a
//! BouncyCastle fork) does, byte for byte:
//!
//! * [`mod@sign`] — [`SignedDataBuilder`], [`create_cades_bes`],
//!   [`create_cades_bes_from_hash`] and [`add_signer`] build attached /
//!   detached / hash-only messages with GOST R 34.10-2015 (256/512),
//!   GOST R 34.10-2004 or RSA (`sha256WithRSA`) signers from a
//!   [`kz_pki::Entry`];
//! * [`mod@verify`] — checks `messageDigest` and the signature of every signer
//!   with the certificate carried in the message (or supplied by the caller);
//! * [`tsp`] — RFC 3161 requests to `http://tsp.pki.gov.kz` and the
//!   `signatureTimeStampToken` attribute (CAdES-T).
//!
//! # Byte orders
//!
//! Kalkan writes the GOST `SignerInfo.signature` as `r ‖ s`, each
//! little-endian — the same layout as in NCA X.509 certificates
//! ([`gost3410::Signature::to_bytes_kz`]), *not* the RFC 4490/4491 `s ‖ r`
//! layout.  This was established against the Kalkan-produced fixtures in
//! `tests/fixtures` and is what [`fn@verify`] expects and [`mod@sign`] produces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algo;
mod der_util;
pub mod error;
pub mod oid;
pub mod parse;
pub mod sign;
pub mod tsp;
pub mod verify;

pub use algo::{Nonce, SignerAlgorithm};
pub use error::{Error, Result};
pub use parse::{SignedData, SignerInfo};
pub use sign::{add_signer, create_cades_bes, create_cades_bes_from_hash, SignedDataBuilder};
pub use tsp::{add_cades_t, add_timestamp_token, TimeStampRequest, TimeStampToken, TsaClient};
pub use verify::{verify, Content, SignerReport};
