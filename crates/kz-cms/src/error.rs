//! Error type of the crate.

use der::asn1::ObjectIdentifier;

/// Errors produced while building, parsing or verifying CMS structures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed DER / unexpected CMS structure.
    #[error("CMS structure error: {0}")]
    Structure(String),

    /// A `der`-crate error.
    #[error("DER error: {0}")]
    Der(#[from] der::Error),

    /// An error from `kz-pki` (certificate / key handling).
    #[error("PKI error: {0}")]
    Pki(#[from] kz_pki::Error),

    /// An error from `gost3410`.
    #[error("GOST R 34.10 error: {0}")]
    Gost(#[from] gost3410::Error),

    /// An RSA error.
    #[error("RSA error: {0}")]
    Rsa(String),

    /// Unsupported algorithm OID.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),

    /// The signer's certificate was not found in the CMS nor supplied by the caller.
    #[error("signer certificate not found (serial {0})")]
    SignerCertificateNotFound(String),

    /// The content is needed to verify a detached signature but was not supplied.
    #[error("detached signature: content not supplied")]
    ContentRequired,

    /// The `messageDigest` attribute does not match the content.
    #[error("messageDigest attribute does not match the content")]
    DigestMismatch,

    /// The `messageDigest` attribute is missing.
    #[error("messageDigest attribute is missing")]
    DigestMissing,

    /// Signed attributes are missing (not a CAdES signature).
    #[error("signedAttrs are missing")]
    SignedAttrsMissing,

    /// The signature does not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// The content supplied to the builder is missing.
    #[error("content required to compute messageDigest")]
    ContentMissing,

    /// A time-stamp request / response problem.
    #[error("time-stamp error: {0}")]
    Tsp(String),

    /// HTTP transport error of the TSA client.
    #[error("TSA transport error: {0}")]
    Transport(String),
}

/// Result alias of the crate.
pub type Result<T> = std::result::Result<T, Error>;
