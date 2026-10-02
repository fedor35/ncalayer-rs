//! Error type of the crate.

/// Errors produced while canonicalizing, signing or verifying XML.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The document is not well-formed XML.
    #[error("XML parse error: {0}")]
    Parse(#[from] roxmltree::Error),

    /// The XPath (only absolute `/a/b[n]` paths are supported) selected nothing.
    #[error("XPath {0:?} matched no element")]
    XPathNoMatch(String),

    /// The XPath has a form this crate does not understand.
    #[error("unsupported XPath {0:?}: only absolute paths like /root/a[1] are accepted")]
    XPathUnsupported(String),

    /// The element selected for signing has no `Id` attribute (same wording as NCALayer).
    #[error("Указанный для подписи элемент не содержит атрибут 'Id'")]
    MissingId,

    /// The element selected for signing is the signature parent (same wording as NCALayer).
    #[error("элемент подписи не может быть родительским элементом подписи")]
    TbsIsParent,

    /// The signature parent lies inside the signed element.
    #[error("the signature parent element lies inside the signed element")]
    ParentInsideTbs,

    /// The signed document has an unexpected `ds:Signature` structure.
    #[error("XMLDSig structure error: {0}")]
    Structure(String),

    /// An algorithm URI (canonicalization, transform, digest, signature) is not supported.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),

    /// A `Reference` URI that cannot be dereferenced.
    #[error("cannot dereference Reference URI {0:?}")]
    BadReferenceUri(String),

    /// A `DigestValue` does not match the referenced content.
    #[error("DigestValue of Reference {0:?} does not match")]
    DigestMismatch(String),

    /// The `SignatureValue` does not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// No certificate in `KeyInfo` and none supplied by the caller.
    #[error("signer certificate not found")]
    CertificateNotFound,

    /// Malformed base64.
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// An error from `kz-pki` (certificate / key handling).
    #[error("PKI error: {0}")]
    Pki(#[from] kz_pki::Error),

    /// An error from `kz-cms` (algorithm families).
    #[error("CMS error: {0}")]
    Cms(#[from] kz_cms::Error),

    /// An error from `gost3410`.
    #[error("GOST R 34.10 error: {0}")]
    Gost(#[from] gost3410::Error),

    /// An RSA error.
    #[error("RSA error: {0}")]
    Rsa(String),
}

/// Result alias of the crate.
pub type Result<T> = std::result::Result<T, Error>;
