//! Verification of `ds:Signature` elements found in a document.

use kz_cms::SignerAlgorithm;
use kz_pki::Cert;

use crate::algo::{base64_decode, verify_raw, XmlAlgorithm, DSIG_NS, ENVELOPED};
use crate::c14n::{canonicalize, Method};
use crate::dom::{Document, NodeId};
use crate::error::{Error, Result};

/// Outcome of verifying one `ds:Signature`.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// The signer's certificate (from `KeyInfo` or supplied by the caller).
    pub cert: Cert,
    /// Algorithm family of `SignatureMethod`.
    pub algorithm: SignerAlgorithm,
    /// `Reference/@URI` of every reference (all verified).
    pub references: Vec<String>,
    /// `CanonicalizationMethod` of `SignedInfo`.
    pub canonicalization: Method,
}

/// Verify every `ds:Signature` in the document, taking the certificate from
/// `KeyInfo/X509Data/X509Certificate`.  Returns one report per signature;
/// the first failing signature aborts with an error.  Certificate chains
/// and revocation are **not** checked.
pub fn verify(xml: &str) -> Result<Vec<VerifyReport>> {
    verify_with(xml, &[])
}

/// Like [`verify`], but `extra_certs` are used for signatures without a
/// certificate in `KeyInfo` (the first one whose key family matches).
pub fn verify_with(xml: &str, extra_certs: &[Cert]) -> Result<Vec<VerifyReport>> {
    let doc = Document::parse(xml)?;
    let sigs = doc.descendants_named(Some(DSIG_NS), "Signature");
    if sigs.is_empty() {
        return Err(Error::Structure("no ds:Signature element".into()));
    }
    sigs.into_iter()
        .map(|s| verify_signature(&doc, s, extra_certs))
        .collect()
}

fn ds(doc: &Document, parent: NodeId, local: &str) -> Result<NodeId> {
    doc.element(parent, Some(DSIG_NS), local)
        .ok_or_else(|| Error::Structure(format!("ds:{local} is missing")))
}

fn algorithm_attr(doc: &Document, id: NodeId) -> Result<&str> {
    doc.attr(id, "Algorithm")
        .ok_or_else(|| Error::Structure("Algorithm attribute is missing".into()))
}

fn verify_signature(doc: &Document, sig: NodeId, extra_certs: &[Cert]) -> Result<VerifyReport> {
    let signed_info = ds(doc, sig, "SignedInfo")?;
    let c14n_uri = algorithm_attr(doc, ds(doc, signed_info, "CanonicalizationMethod")?)?;
    let method =
        Method::from_uri(c14n_uri).ok_or_else(|| Error::UnsupportedAlgorithm(c14n_uri.into()))?;
    let sig_uri = algorithm_attr(doc, ds(doc, signed_info, "SignatureMethod")?)?;
    let algorithm = SignerAlgorithm::from_signature_uri(sig_uri)?;

    let references = doc.elements(signed_info, Some(DSIG_NS), "Reference");
    if references.is_empty() {
        return Err(Error::Structure("SignedInfo has no Reference".into()));
    }
    let mut uris = Vec::new();
    for r in references {
        uris.push(verify_reference(doc, sig, r)?);
    }

    let signature = base64_decode(&doc.text(ds(doc, sig, "SignatureValue")?))?;
    let cert = find_cert(doc, sig, algorithm, extra_certs)?;
    let canon = canonicalize(doc, signed_info, None, method);
    verify_raw(&cert.public_key()?, algorithm, &canon, &signature)?;

    Ok(VerifyReport {
        cert,
        algorithm,
        references: uris,
        canonicalization: method,
    })
}

fn find_cert(
    doc: &Document,
    sig: NodeId,
    algorithm: SignerAlgorithm,
    extra: &[Cert],
) -> Result<Cert> {
    if let Some(ki) = doc.element(sig, Some(DSIG_NS), "KeyInfo") {
        for x509 in doc.elements(ki, Some(DSIG_NS), "X509Data") {
            if let Some(c) = doc.element(x509, Some(DSIG_NS), "X509Certificate") {
                return Ok(Cert::from_der(&base64_decode(&doc.text(c))?)?);
            }
        }
    }
    for c in extra {
        if c.public_key()
            .map(|k| SignerAlgorithm::for_public_key(&k) == algorithm)
            .unwrap_or(false)
        {
            return Ok(c.clone());
        }
    }
    Err(Error::CertificateNotFound)
}

/// Verify one `Reference`; returns its URI.
fn verify_reference(doc: &Document, sig: NodeId, r: NodeId) -> Result<String> {
    let uri = doc.attr(r, "URI").unwrap_or("").to_string();
    let (root, keeps_comments) = dereference(doc, &uri)?;

    let mut exclude = None;
    let mut method = None;
    if let Some(ts) = doc.element(r, Some(DSIG_NS), "Transforms") {
        for t in doc.elements(ts, Some(DSIG_NS), "Transform") {
            let a = algorithm_attr(doc, t)?;
            if method.is_some() {
                // A canonicalization produces octets; nothing may follow it.
                return Err(Error::UnsupportedAlgorithm(a.into()));
            }
            if a == ENVELOPED {
                exclude = Some(sig);
            } else if let Some(m) = Method::from_uri(a) {
                method = Some(m);
            } else {
                return Err(Error::UnsupportedAlgorithm(a.into()));
            }
        }
    }
    let mut method = method.unwrap_or(Method::INCLUSIVE);
    method.with_comments &= keeps_comments;

    let digest_uri = algorithm_attr(doc, ds(doc, r, "DigestMethod")?)?;
    let alg = SignerAlgorithm::from_digest_uri(digest_uri)?;
    let expected = base64_decode(&doc.text(ds(doc, r, "DigestValue")?))?;
    let canon = canonicalize(doc, root, exclude, method);
    if alg.digest(&canon) != expected {
        return Err(Error::DigestMismatch(uri));
    }
    Ok(uri)
}

/// Resolve a same-document URI to the subtree root and whether the
/// node-set keeps comments (XMLDSig §4.4.3.2: only `#xpointer(...)` does).
fn dereference(doc: &Document, uri: &str) -> Result<(NodeId, bool)> {
    if uri.is_empty() {
        return Ok((0, false));
    }
    let Some(frag) = uri.strip_prefix('#') else {
        return Err(Error::BadReferenceUri(uri.into()));
    };
    if frag == "xpointer(/)" {
        return Ok((0, true));
    }
    if let Some(id) = frag
        .strip_prefix("xpointer(id('")
        .and_then(|s| s.strip_suffix("'))"))
        .or_else(|| {
            frag.strip_prefix("xpointer(id(\"")
                .and_then(|s| s.strip_suffix("\"))"))
        })
    {
        let el = doc
            .element_by_id(id)
            .ok_or_else(|| Error::BadReferenceUri(uri.into()))?;
        return Ok((el, true));
    }
    let el = doc
        .element_by_id(frag)
        .ok_or_else(|| Error::BadReferenceUri(uri.into()))?;
    Ok((el, false))
}
