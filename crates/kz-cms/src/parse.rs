//! Structural parser of `ContentInfo { signedData }` keeping the original
//! encodings of every component, so that signers can be added and verified
//! without re-encoding anything.

use der::asn1::ObjectIdentifier;
use kz_pki::Cert;
use time::OffsetDateTime;

use crate::der_util::{
    Cursor, Tlv, TAG_CTX0, TAG_CTX1, TAG_GENERALIZED_TIME, TAG_OCTET_STRING, TAG_SEQUENCE, TAG_SET,
    TAG_UTC_TIME,
};
use crate::error::{Error, Result};
use crate::oid;

/// One attribute: type and the DER encodings of its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute type.
    pub oid: ObjectIdentifier,
    /// DER-encoded values (each a complete TLV).
    pub values: Vec<Vec<u8>>,
    /// DER of the whole `Attribute`.
    pub raw: Vec<u8>,
}

impl Attribute {
    /// First value.
    pub fn first(&self) -> Result<&[u8]> {
        self.values
            .first()
            .map(Vec::as_slice)
            .ok_or_else(|| Error::Structure(format!("attribute {} has no value", self.oid)))
    }
}

/// Parse `SET OF Attribute` content (the tag of the container is ignored).
pub(crate) fn parse_attributes(container: &Tlv<'_>) -> Result<Vec<Attribute>> {
    container
        .children()?
        .into_iter()
        .map(|a| {
            let a = a.expect(TAG_SEQUENCE)?;
            let mut c = Cursor::new(&a)?;
            let oid = c.next("attribute type")?.oid()?;
            let set = c.next_tag(TAG_SET, "attribute values")?;
            let values = set
                .children()?
                .into_iter()
                .map(|v| v.raw.to_vec())
                .collect();
            Ok(Attribute {
                oid,
                values,
                raw: a.raw.to_vec(),
            })
        })
        .collect()
}

/// A `SignerInfo` with the fields needed for verification and the raw bytes.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// `version`.
    pub version: u64,
    /// DER of the issuer `Name` (`sid.issuerAndSerialNumber.issuer`).
    pub issuer_der: Vec<u8>,
    /// DER of the serial number `INTEGER`.
    pub serial_der: Vec<u8>,
    /// `digestAlgorithm.algorithm`.
    pub digest_oid: ObjectIdentifier,
    /// Signed attributes (empty if absent).
    pub signed_attrs: Vec<Attribute>,
    /// Raw `[0] IMPLICIT SignedAttributes` encoding, if present.
    pub signed_attrs_raw: Option<Vec<u8>>,
    /// `signatureAlgorithm.algorithm`.
    pub signature_oid: ObjectIdentifier,
    /// `signature` octets.
    pub signature: Vec<u8>,
    /// Unsigned attributes (empty if absent).
    pub unsigned_attrs: Vec<Attribute>,
    /// DER of the whole `SignerInfo`.
    pub raw: Vec<u8>,
}

impl SignerInfo {
    fn parse(t: Tlv<'_>) -> Result<Self> {
        let t = t.expect(TAG_SEQUENCE)?;
        let mut c = Cursor::new(&t)?;
        let version = c.next("SignerInfo.version")?.integer_u64()?;
        let sid = c.next("SignerInfo.sid")?;
        if sid.tag != TAG_SEQUENCE {
            return Err(Error::Structure(
                "only issuerAndSerialNumber signer identifiers are supported".into(),
            ));
        }
        let mut sc = Cursor::new(&sid)?;
        let issuer_der = sc.next_tag(TAG_SEQUENCE, "issuer")?.raw.to_vec();
        let serial_der = sc
            .next_tag(crate::der_util::TAG_INTEGER, "serialNumber")?
            .raw
            .to_vec();
        let digest_oid = alg_oid(c.next_tag(TAG_SEQUENCE, "digestAlgorithm")?)?;
        let signed = c.optional(TAG_CTX0);
        let signed_attrs = match &signed {
            Some(s) => parse_attributes(s)?,
            None => Vec::new(),
        };
        let signature_oid = alg_oid(c.next_tag(TAG_SEQUENCE, "signatureAlgorithm")?)?;
        let signature = c.next_tag(TAG_OCTET_STRING, "signature")?.content.to_vec();
        let unsigned_attrs = match c.optional(TAG_CTX1) {
            Some(u) => parse_attributes(&u)?,
            None => Vec::new(),
        };
        Ok(SignerInfo {
            version,
            issuer_der,
            serial_der,
            digest_oid,
            signed_attrs,
            signed_attrs_raw: signed.map(|s| s.raw.to_vec()),
            signature_oid,
            signature,
            unsigned_attrs,
            raw: t.raw.to_vec(),
        })
    }

    /// Serial number as lowercase hex without leading zeros (Java `BigInteger.toString(16)`).
    pub fn serial_hex(&self) -> String {
        let t = Tlv::parse(&self.serial_der).ok();
        kz_pki::cert::big_int_hex(t.map(|t| t.content).unwrap_or(&[]))
    }

    /// Find a signed attribute by type.
    pub fn signed_attr(&self, o: &ObjectIdentifier) -> Option<&Attribute> {
        self.signed_attrs.iter().find(|a| a.oid == *o)
    }

    /// Find an unsigned attribute by type.
    pub fn unsigned_attr(&self, o: &ObjectIdentifier) -> Option<&Attribute> {
        self.unsigned_attrs.iter().find(|a| a.oid == *o)
    }

    /// Value of the `messageDigest` attribute.
    pub fn message_digest(&self) -> Result<Vec<u8>> {
        let a = self
            .signed_attr(&oid::MESSAGE_DIGEST)
            .ok_or(Error::DigestMissing)?;
        Ok(Tlv::parse_tag(a.first()?, TAG_OCTET_STRING)?
            .content
            .to_vec())
    }

    /// Value of the `signingTime` attribute, if present.
    pub fn signing_time(&self) -> Result<Option<OffsetDateTime>> {
        match self.signed_attr(&oid::SIGNING_TIME) {
            None => Ok(None),
            Some(a) => decode_time(a.first()?).map(Some),
        }
    }

    /// Whether the signer carries a `signatureTimeStampToken` (CAdES-T).
    pub fn has_timestamp(&self) -> bool {
        self.unsigned_attr(&oid::SIGNATURE_TIME_STAMP_TOKEN)
            .is_some()
    }

    /// Does `cert` match this signer's `issuerAndSerialNumber`?
    pub fn matches_cert(&self, cert: &Cert) -> bool {
        let Ok(issuer) = der::Encode::to_der(cert.issuer()) else {
            return false;
        };
        issuer == self.issuer_der && cert.serial_number() == self.serial_hex()
    }
}

/// `UTCTime` or `GeneralizedTime` → [`OffsetDateTime`] (UTC).
pub(crate) fn decode_time(raw: &[u8]) -> Result<OffsetDateTime> {
    use der::Decode;
    let t = Tlv::parse(raw)?;
    let secs = match t.tag {
        TAG_UTC_TIME => der::asn1::UtcTime::from_der(raw)?
            .to_unix_duration()
            .as_secs(),
        TAG_GENERALIZED_TIME => der::asn1::GeneralizedTime::from_der(raw)?
            .to_unix_duration()
            .as_secs(),
        other => {
            return Err(Error::Structure(format!(
                "unexpected time tag 0x{other:02x}"
            )))
        }
    };
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(secs).map_err(|_| Error::Structure("time out of range".into()))?,
    )
    .map_err(|e| Error::Structure(e.to_string()))
}

/// Encode a time as `UTCTime` (years 1950–2049) or `GeneralizedTime`,
/// seconds precision, as CMS requires (RFC 5652 §11.3).
pub(crate) fn encode_time(t: OffsetDateTime) -> Result<Vec<u8>> {
    use der::Encode;
    let utc = t.to_offset(time::UtcOffset::UTC);
    let secs = u64::try_from(utc.unix_timestamp())
        .map_err(|_| Error::Structure("time before 1970".into()))?;
    let d = core::time::Duration::from_secs(secs);
    if (1950..2050).contains(&utc.year()) {
        Ok(der::asn1::UtcTime::from_unix_duration(d)?.to_der()?)
    } else {
        Ok(der::asn1::GeneralizedTime::from_unix_duration(d)?.to_der()?)
    }
}

fn alg_oid(t: Tlv<'_>) -> Result<ObjectIdentifier> {
    let mut c = Cursor::new(&t)?;
    c.next("algorithm")?.oid()
}

/// A parsed `SignedData`.
#[derive(Debug, Clone)]
pub struct SignedData {
    /// `version`.
    pub version: u64,
    /// DER encodings of the `digestAlgorithms` members.
    pub digest_algorithms: Vec<Vec<u8>>,
    /// `encapContentInfo.eContentType`.
    pub content_type: ObjectIdentifier,
    /// `encapContentInfo.eContent` octets (attached content), if present.
    pub content: Option<Vec<u8>>,
    /// Certificates carried in `certificates` (X.509 only; other choices are kept in `other_certs`).
    pub certificates: Vec<Cert>,
    /// Raw encodings of non-X.509 `CertificateChoices`, carried over verbatim.
    pub other_certs: Vec<Vec<u8>>,
    /// Raw encodings of `crls` members.
    pub crls: Vec<Vec<u8>>,
    /// Signers.
    pub signer_infos: Vec<SignerInfo>,
}

impl SignedData {
    /// Parse a DER `ContentInfo { signedData }`.
    pub fn from_der(cms: &[u8]) -> Result<Self> {
        let ci = Tlv::parse_tag(cms, TAG_SEQUENCE)?;
        let mut c = Cursor::new(&ci)?;
        let ct = c.next("contentType")?.oid()?;
        if ct != oid::ID_SIGNED_DATA {
            return Err(Error::Structure(format!("not signedData: {ct}")));
        }
        let wrap = c.next_tag(TAG_CTX0, "content")?;
        let sd = Tlv::parse_tag(wrap.content, TAG_SEQUENCE)?;
        let mut c = Cursor::new(&sd)?;
        let version = c.next("SignedData.version")?.integer_u64()?;
        let digest_algorithms = c
            .next_tag(TAG_SET, "digestAlgorithms")?
            .children()?
            .into_iter()
            .map(|t| t.raw.to_vec())
            .collect();
        let eci = c.next_tag(TAG_SEQUENCE, "encapContentInfo")?;
        let mut ec = Cursor::new(&eci)?;
        let content_type = ec.next("eContentType")?.oid()?;
        let content = match ec.optional(TAG_CTX0) {
            Some(w) => {
                // DER: a single primitive OCTET STRING.  (A constructed one would be BER.)
                let os = Tlv::parse_tag(w.content, TAG_OCTET_STRING)?;
                Some(os.content.to_vec())
            }
            None => None,
        };
        let mut certificates = Vec::new();
        let mut other_certs = Vec::new();
        if let Some(cs) = c.optional(TAG_CTX0) {
            for t in cs.children()? {
                if t.tag == TAG_SEQUENCE {
                    certificates.push(Cert::from_der(t.raw)?);
                } else {
                    other_certs.push(t.raw.to_vec());
                }
            }
        }
        let crls = match c.optional(TAG_CTX1) {
            Some(cr) => cr.children()?.into_iter().map(|t| t.raw.to_vec()).collect(),
            None => Vec::new(),
        };
        let signer_infos = c
            .next_tag(TAG_SET, "signerInfos")?
            .children()?
            .into_iter()
            .map(SignerInfo::parse)
            .collect::<Result<Vec<_>>>()?;
        if !c.is_empty() {
            return Err(Error::Structure(
                "unexpected trailing fields in SignedData".into(),
            ));
        }
        Ok(SignedData {
            version,
            digest_algorithms,
            content_type,
            content,
            certificates,
            other_certs,
            crls,
            signer_infos,
        })
    }

    /// Find the certificate matching a signer among the carried certificates
    /// and `extra`.
    pub fn find_signer_cert<'a>(&'a self, si: &SignerInfo, extra: &'a [Cert]) -> Option<&'a Cert> {
        self.certificates
            .iter()
            .chain(extra.iter())
            .find(|c| si.matches_cert(c))
    }
}
