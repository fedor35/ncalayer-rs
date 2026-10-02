//! Verification of CMS `SignedData` signatures.

use kz_pki::Cert;
use time::OffsetDateTime;

use crate::algo::{verify_raw, SignerAlgorithm};
use crate::der_util::{retag, TAG_SET};
use crate::error::{Error, Result};
use crate::oid;
use crate::parse::{SignedData, SignerInfo};
use crate::tsp::TimeStampToken;

/// What the verifier has for the signed content.
#[derive(Debug, Clone, Copy)]
pub enum Content<'a> {
    /// The content is carried inside the CMS (`eContent`); fails if it is not.
    Attached,
    /// Detached signature: the content is supplied here.  Also accepted for
    /// an attached signature, in which case it must equal `eContent`.
    Detached(&'a [u8]),
    /// Only the digest of the content is known (signature "by hash"); it must
    /// equal the `messageDigest` attribute.
    Digest(&'a [u8]),
}

/// Outcome of verifying one signer.
#[derive(Debug, Clone)]
pub struct SignerReport {
    /// The signer's certificate (as found in the CMS or supplied by the caller).
    pub cert: Cert,
    /// Algorithm family.
    pub algorithm: SignerAlgorithm,
    /// `signingTime` attribute, if present.
    pub signing_time: Option<OffsetDateTime>,
    /// `messageDigest` attribute value.
    pub message_digest: Vec<u8>,
    /// Parsed `signatureTimeStampToken`, if present (its imprint is checked
    /// against the signature; the TSA signature itself is **not** verified).
    pub timestamp: Option<TimeStampToken>,
}

/// Verify every signer of a CMS `SignedData`.
///
/// `extra_certs` are consulted when the signer's certificate is not carried in
/// the message.  Returns one report per signer; the first failing signer
/// aborts with an error.  Certificate chains and revocation are **not**
/// checked here.
pub fn verify(cms: &[u8], content: Content<'_>, extra_certs: &[Cert]) -> Result<Vec<SignerReport>> {
    let sd = SignedData::from_der(cms)?;
    if sd.signer_infos.is_empty() {
        return Err(Error::Structure("no signers".into()));
    }
    sd.signer_infos
        .iter()
        .map(|si| verify_signer(&sd, si, content, extra_certs))
        .collect()
}

/// Verify a single parsed signer against the parsed message.
pub fn verify_signer(
    sd: &SignedData,
    si: &SignerInfo,
    content: Content<'_>,
    extra_certs: &[Cert],
) -> Result<SignerReport> {
    let cert = sd
        .find_signer_cert(si, extra_certs)
        .cloned()
        .ok_or_else(|| Error::SignerCertificateNotFound(si.serial_hex()))?;
    let algorithm = SignerAlgorithm::from_signature_oid(&si.signature_oid)?;
    let digest_alg = SignerAlgorithm::from_digest_oid(&si.digest_oid)?;
    if digest_alg != algorithm {
        return Err(Error::UnsupportedAlgorithm(si.digest_oid));
    }
    let signed_raw = si
        .signed_attrs_raw
        .as_deref()
        .ok_or(Error::SignedAttrsMissing)?;

    // messageDigest vs. content.
    let message_digest = si.message_digest()?;
    let data: Option<&[u8]> = match content {
        Content::Attached => Some(sd.content.as_deref().ok_or(Error::ContentRequired)?),
        Content::Detached(d) => {
            if let Some(inner) = &sd.content {
                if inner.as_slice() != d {
                    return Err(Error::DigestMismatch);
                }
            }
            Some(d)
        }
        Content::Digest(h) => {
            if h != message_digest.as_slice() {
                return Err(Error::DigestMismatch);
            }
            None
        }
    };
    if let Some(data) = data {
        if algorithm.digest(data) != message_digest {
            return Err(Error::DigestMismatch);
        }
    }
    // contentType attribute must name the encapsulated content type (RFC 5652 §11.1).
    if let Some(ct) = si.signed_attr(&oid::CONTENT_TYPE) {
        let got = crate::der_util::Tlv::parse(ct.first()?)?.oid()?;
        if got != sd.content_type {
            return Err(Error::Structure(
                "contentType attribute does not match eContentType".into(),
            ));
        }
    }

    // Signature over the signed attributes re-tagged as SET (RFC 5652 §5.4).
    let signed_bytes = retag(signed_raw, TAG_SET);
    verify_raw(&cert.public_key()?, algorithm, &signed_bytes, &si.signature)?;

    let timestamp = match si.unsigned_attr(&oid::SIGNATURE_TIME_STAMP_TOKEN) {
        Some(a) => {
            let tst = TimeStampToken::from_der(a.first()?)?;
            tst.check_imprint(&si.signature)?;
            Some(tst)
        }
        None => None,
    };

    Ok(SignerReport {
        cert,
        algorithm,
        signing_time: si.signing_time()?,
        message_digest,
        timestamp,
    })
}
