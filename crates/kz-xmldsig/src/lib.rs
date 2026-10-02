//! XML Signature (XMLDSig) for an open NCALayer replacement (Kazakhstan NCA,
//! НУЦ РК): what `signXml` / `signXmls` / `basics.sign(format="xml")` and
//! `verifyXml` do in the original, i.e.
//! `kz.gov.pki.provider.utils.XMLUtil.createXmlSignature` (Apache Santuario
//! with Kalkan's GOST algorithms).
//!
//! * [`sign_enveloped`] — `Reference URI=""`, enveloped-signature +
//!   `c14n#WithComments` transforms, inclusive C14N of `SignedInfo`, the
//!   `ds:Signature` appended as the last child of the root element;
//! * [`sign_by_id`] — `signXml` with `tbsElementXPath` /
//!   `signatureParentElementXPath`: `Reference URI="#Id"`, single transform
//!   `c14n#WithComments`, Exclusive C14N of `SignedInfo`, the signature
//!   appended to the parent element;
//! * [`verify()`] — checks every `DigestValue` and `SignatureValue` of every
//!   `ds:Signature` in the document with the certificate from `KeyInfo`;
//! * [`c14n`] — Canonical XML 1.0 (with / without comments) and Exclusive
//!   C14N 1.0, usable on their own.
//!
//! Signers: GOST R 34.10-2015 (256 / 512, Streebog), GOST R 34.10-2004
//! (GOST 34.311-95) and RSA (`rsa-sha256`); the families are those of
//! [`kz_cms::SignerAlgorithm`].
//!
//! # Byte order of `SignatureValue`
//!
//! For GOST, Kalkan writes `r ‖ s` with each number **little-endian**
//! ([`gost3410::Signature::to_bytes_kz`]) — exactly as in CMS and X.509 —
//! established against the Kalkan-produced fixtures in `tests/fixtures`.
//!
//! # Text layout
//!
//! The caller's XML is returned byte for byte with the `ds:Signature` spliced
//! in before the parent's end tag; the signature itself is laid out like
//! Santuario's (`\n` between elements, base64 in 76-character lines joined
//! by CR LF, `SignatureValue` / `X509Certificate` wrapped in newlines).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algo;
pub mod c14n;
pub mod dom;
pub mod error;
pub mod sign;
pub mod verify;

pub use algo::XmlAlgorithm;
pub use c14n::{canonicalize, canonicalize_str, Method};
pub use error::{Error, Result};
pub use kz_cms::SignerAlgorithm;
pub use sign::{sign_by_id, sign_enveloped, sign_enveloped_many};
pub use verify::{verify, verify_with, VerifyReport};
