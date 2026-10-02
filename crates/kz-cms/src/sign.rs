//! Building CMS `SignedData` with CAdES-BES signers, byte-compatible with
//! Kalkan's `CMSUtil.createCAdES`.

use der::Encode;
use kz_pki::{Cert, Entry};
use rand_core::CryptoRng;
use time::OffsetDateTime;

use crate::algo::{sign_raw, Nonce, SignerAlgorithm};
use crate::der_util::{
    alg_id_null, attribute, integer_u64, octet_string, oid as enc_oid, retag, sequence, set_of,
    tlv, TAG_CTX0, TAG_CTX1, TAG_SEQUENCE,
};
use crate::error::{Error, Result};
use crate::oid;
use crate::parse::{encode_time, SignedData};

/// Builder of a `ContentInfo { signedData }`.
///
/// The structure written is exactly what Kalkan (NCALayer's
/// `kz.gov.pki.provider.utils.CMSUtil.createCAdES`) produces:
///
/// ```text
/// SignedData {
///   version 1,
///   digestAlgorithms { { digestOid, NULL } },
///   encapContentInfo { id-data, [0] OCTET STRING -- attached only },
///   certificates [0] { signer certificate, chain },
///   signerInfos { SignerInfo {
///     version 1, issuerAndSerialNumber, { digestOid, NULL },
///     signedAttrs [0] { contentType, signingTime, signingCertificateV2, messageDigest },
///     { signatureOid, NULL }, signature } }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SignedDataBuilder {
    version: u64,
    digest_algorithms: Vec<Vec<u8>>,
    content: Option<Vec<u8>>,
    attached: bool,
    certificates: Vec<Vec<u8>>,
    other_certs: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    pub(crate) signer_infos: Vec<Vec<u8>>,
}

impl SignedDataBuilder {
    /// Start a new message over `data`, attached (`eContent` carries the data)
    /// or detached.
    pub fn new(data: &[u8], attached: bool) -> Self {
        SignedDataBuilder {
            version: 1,
            digest_algorithms: Vec::new(),
            content: Some(data.to_vec()),
            attached,
            certificates: Vec::new(),
            other_certs: Vec::new(),
            crls: Vec::new(),
            signer_infos: Vec::new(),
        }
    }

    /// Start a detached message whose content is unknown: signers are added
    /// with [`add_signer_with_digest`](Self::add_signer_with_digest).
    pub fn hash_only() -> Self {
        let mut b = Self::new(&[], false);
        b.content = None;
        b
    }

    /// Continue an existing message: its certificates, CRLs and signers are
    /// kept verbatim.  For a detached message the content must be supplied
    /// with [`content`](Self::content) before [`add_signer`](Self::add_signer).
    pub fn from_cms(cms: &[u8]) -> Result<Self> {
        let sd = SignedData::from_der(cms)?;
        if sd.content_type != oid::ID_DATA {
            return Err(Error::Structure(format!(
                "unsupported eContentType {}",
                sd.content_type
            )));
        }
        Ok(Self::from_parsed(&sd))
    }

    pub(crate) fn from_parsed(sd: &SignedData) -> Self {
        SignedDataBuilder {
            version: sd.version.max(1),
            digest_algorithms: sd.digest_algorithms.clone(),
            attached: sd.content.is_some(),
            content: sd.content.clone(),
            certificates: sd
                .certificates
                .iter()
                .map(|c| c.as_der().to_vec())
                .collect(),
            other_certs: sd.other_certs.clone(),
            crls: sd.crls.clone(),
            signer_infos: sd.signer_infos.iter().map(|s| s.raw.clone()).collect(),
        }
    }

    /// Supply the content of a detached message loaded with
    /// [`from_cms`](Self::from_cms).  For an attached message it must equal
    /// the embedded content.
    pub fn content(&mut self, data: &[u8]) -> Result<&mut Self> {
        if let Some(existing) = &self.content {
            if self.attached && existing.as_slice() != data {
                return Err(Error::DigestMismatch);
            }
        }
        self.content = Some(data.to_vec());
        Ok(self)
    }

    /// Add a certificate to `certificates` (duplicates are ignored).
    pub fn add_certificate(&mut self, cert: &Cert) -> &mut Self {
        let der = cert.as_der().to_vec();
        if !self.certificates.contains(&der) {
            self.certificates.push(der);
        }
        self
    }

    /// Sign the content with `entry` (CAdES-BES) and append the signer.
    pub fn add_signer(
        &mut self,
        entry: &Entry,
        signing_time: OffsetDateTime,
        nonce: Nonce<'_>,
    ) -> Result<&mut Self> {
        let alg = SignerAlgorithm::for_private_key(&entry.key);
        let data = self.content.as_deref().ok_or(Error::ContentMissing)?;
        let digest = alg.digest(data);
        self.add_signer_with_digest(entry, &digest, signing_time, nonce)
    }

    /// Sign with `entry` using a precomputed `messageDigest` (the content
    /// itself is not needed; Kalkan's `createCAdESFromBase64Hash`).
    pub fn add_signer_with_digest(
        &mut self,
        entry: &Entry,
        digest: &[u8],
        signing_time: OffsetDateTime,
        nonce: Nonce<'_>,
    ) -> Result<&mut Self> {
        let alg = SignerAlgorithm::for_private_key(&entry.key);
        if digest.len() != alg.digest_len() {
            return Err(Error::Structure(format!(
                "digest length {} does not match {:?} ({} bytes)",
                digest.len(),
                alg,
                alg.digest_len()
            )));
        }
        let signed_attrs = signed_attributes(&entry.cert, digest, signing_time)?;
        let signed_set = set_of(signed_attrs);
        let signature = sign_raw(&entry.key, &signed_set, nonce)?;
        let signer_info = encode_signer_info(&entry.cert, alg, &signed_set, &signature)?;

        let dalg = alg_id_null(&alg.digest_oid());
        if !self.digest_algorithms.contains(&dalg) {
            self.digest_algorithms.push(dalg);
        }
        self.add_certificate(&entry.cert);
        for c in &entry.chain {
            self.add_certificate(c);
        }
        self.signer_infos.push(signer_info);
        Ok(self)
    }

    /// Encode the message.
    pub fn build(&self) -> Vec<u8> {
        let eci = match (&self.content, self.attached) {
            (Some(data), true) => {
                sequence(&[&enc_oid(&oid::ID_DATA), &tlv(TAG_CTX0, &octet_string(data))])
            }
            _ => sequence(&[&enc_oid(&oid::ID_DATA)]),
        };
        let mut parts: Vec<Vec<u8>> = vec![
            integer_u64(self.version),
            set_of(self.digest_algorithms.clone()),
            eci,
        ];
        if !self.certificates.is_empty() || !self.other_certs.is_empty() {
            let mut all = self.certificates.clone();
            all.extend(self.other_certs.iter().cloned());
            parts.push(retag(&set_of(all), TAG_CTX0));
        }
        if !self.crls.is_empty() {
            parts.push(retag(&set_of(self.crls.clone()), TAG_CTX1));
        }
        parts.push(set_of(self.signer_infos.clone()));
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let sd = sequence(&refs);
        sequence(&[&enc_oid(&oid::ID_SIGNED_DATA), &tlv(TAG_CTX0, &sd)])
    }
}

/// The CAdES-BES signed attributes, each DER-encoded (unsorted).
fn signed_attributes(
    cert: &Cert,
    digest: &[u8],
    signing_time: OffsetDateTime,
) -> Result<Vec<Vec<u8>>> {
    use sha2::Digest;
    let cert_hash = sha2::Sha256::digest(cert.as_der());
    // ESSCertIDv2 with hashAlgorithm omitted (DEFAULT sha256, RFC 5035) and no issuerSerial.
    let ess_cert_id = sequence(&[&octet_string(&cert_hash)]);
    let signing_cert_v2 = sequence(&[&sequence(&[&ess_cert_id])]);
    Ok(vec![
        attribute(&oid::CONTENT_TYPE, vec![enc_oid(&oid::ID_DATA)]),
        attribute(&oid::SIGNING_TIME, vec![encode_time(signing_time)?]),
        attribute(&oid::SIGNING_CERTIFICATE_V2, vec![signing_cert_v2]),
        attribute(&oid::MESSAGE_DIGEST, vec![octet_string(digest)]),
    ])
}

fn encode_signer_info(
    cert: &Cert,
    alg: SignerAlgorithm,
    signed_set: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>> {
    let issuer = cert.issuer().to_der()?;
    let serial = cert.inner().tbs_certificate().serial_number().to_der()?;
    let sid = sequence(&[&issuer, &serial]);
    Ok(sequence(&[
        &integer_u64(1),
        &sid,
        &alg_id_null(&alg.digest_oid()),
        &retag(signed_set, TAG_CTX0),
        &alg_id_null(&alg.signature_oid()),
        &octet_string(signature),
    ]))
}

/// Rebuild a `SignerInfo` with an extra unsigned attribute (DER `Attribute`).
pub(crate) fn signer_info_with_unsigned_attr(signer_info: &[u8], attr: Vec<u8>) -> Result<Vec<u8>> {
    use crate::der_util::Tlv;
    let t = Tlv::parse_tag(signer_info, TAG_SEQUENCE)?;
    let mut body = Vec::new();
    let mut unsigned: Vec<Vec<u8>> = Vec::new();
    for child in t.children()? {
        if child.tag == TAG_CTX1 {
            unsigned = child
                .children()?
                .into_iter()
                .map(|a| a.raw.to_vec())
                .collect();
        } else {
            body.extend_from_slice(child.raw);
        }
    }
    unsigned.push(attr);
    body.extend(retag(&set_of(unsigned), TAG_CTX1));
    Ok(tlv(TAG_SEQUENCE, &body))
}

/// Create a CAdES-BES signature over `data` with a random nonce.
///
/// `attached` embeds the data into the message; otherwise a detached
/// signature is produced.  `certificates` carries the signer's certificate
/// and its chain from `entry`.
pub fn create_cades_bes<R: CryptoRng>(
    entry: &Entry,
    data: &[u8],
    attached: bool,
    signing_time: OffsetDateTime,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut b = SignedDataBuilder::new(data, attached);
    b.add_signer(entry, signing_time, Nonce::Random(rng))?;
    Ok(b.build())
}

/// Create a detached CAdES-BES signature over a precomputed digest
/// (Kalkan's `createCAdESFromBase64Hash`).
pub fn create_cades_bes_from_hash<R: CryptoRng>(
    entry: &Entry,
    digest: &[u8],
    signing_time: OffsetDateTime,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut b = SignedDataBuilder::hash_only();
    b.add_signer_with_digest(entry, digest, signing_time, Nonce::Random(rng))?;
    Ok(b.build())
}

/// Add a signer to an existing message (Kalkan's `createCAdES` with a CMS on
/// input).  `data` is required for a detached message and must match the
/// embedded content of an attached one.
pub fn add_signer<R: CryptoRng>(
    cms: &[u8],
    entry: &Entry,
    data: Option<&[u8]>,
    signing_time: OffsetDateTime,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let mut b = SignedDataBuilder::from_cms(cms)?;
    if let Some(d) = data {
        b.content(d)?;
    }
    b.add_signer(entry, signing_time, Nonce::Random(rng))?;
    Ok(b.build())
}
