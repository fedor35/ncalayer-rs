//! Error type of the crate.

use der::asn1::ObjectIdentifier;

/// Errors produced while reading key stores and certificates.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The PKCS#12 MAC does not match: the password is wrong (or the file is corrupt).
    ///
    /// Mirrors Java's `PKCS12 key store mac invalid - wrong password`.
    #[error("PKCS#12 key store MAC invalid - wrong password")]
    WrongPassword,

    /// Malformed BER/DER structure.
    #[error("ASN.1 structure error: {0}")]
    Asn1(String),

    /// A `der`-crate decoding error.
    #[error("DER decoding error: {0}")]
    Der(#[from] der::Error),

    /// An algorithm or structure the crate does not support.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// An unsupported algorithm OID.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),

    /// Password-based decryption failed (bad padding, truncated data...).
    #[error("decryption failed: {0}")]
    Decrypt(String),

    /// Private-key-specific decoding failure.
    #[error("private key error: {0}")]
    PrivateKey(String),

    /// The container holds no usable key entry.
    #[error("key store contains no private key entries")]
    NoKeys,

    /// I/O error while reading a file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias of the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<pkcs5::Error> for Error {
    fn from(e: pkcs5::Error) -> Self {
        Error::Decrypt(e.to_string())
    }
}

impl From<pkcs8::Error> for Error {
    fn from(e: pkcs8::Error) -> Self {
        Error::PrivateKey(e.to_string())
    }
}
