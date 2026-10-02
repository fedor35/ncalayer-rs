//! X.509 certificate wrapper exposing the fields NCALayer's `getKeyInfo` reports.

use std::fmt::Write as _;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode, EncodePem, Tagged};
use time::{OffsetDateTime, UtcOffset};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, CertificatePolicies, ExtendedKeyUsage};
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::error::{Error, Result};
use crate::key::PublicKey;
use crate::oid;

/// Time zone the NCA tools print dates in (Asia/Almaty, UTC+5, no DST since 2024).
pub const ALMATY_OFFSET: UtcOffset = match UtcOffset::from_hms(5, 0, 0) {
    Ok(o) => o,
    Err(_) => unreachable!(),
};

/// What a certificate is meant for, as NCALayer reports it (`keyUsage` of `KeyInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsageType {
    /// `clientAuth` EKU: the "authentication" (AUTH) certificate.
    Authentication,
    /// `emailProtection` EKU: the "signature" (RSA/GOST) certificate.
    Signature,
}

impl KeyUsageType {
    /// Name used in NCALayer JSON (`AUTHENTICATION` / `SIGNATURE`).
    pub fn as_str(self) -> &'static str {
        match self {
            KeyUsageType::Authentication => "AUTHENTICATION",
            KeyUsageType::Signature => "SIGNATURE",
        }
    }
}

/// A parsed X.509 certificate together with its original DER bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    inner: Certificate,
    der: Vec<u8>,
}

impl Cert {
    /// Parse a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = Certificate::from_der(der)?;
        Ok(Cert {
            inner,
            der: der.to_vec(),
        })
    }

    /// Parse a PEM certificate.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = der::pem::decode_vec(pem.as_bytes())?;
        if label != "CERTIFICATE" {
            return Err(Error::Asn1(format!("unexpected PEM label {label}")));
        }
        Self::from_der(&der)
    }

    /// The decoded certificate.
    pub fn inner(&self) -> &Certificate {
        &self.inner
    }

    /// Original DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// DER encoding of `tbsCertificate` (what the signature covers).
    pub fn tbs_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.tbs_certificate().to_der()?)
    }

    /// Raw signature bytes.
    pub fn signature(&self) -> Result<&[u8]> {
        self.inner
            .signature()
            .as_bytes()
            .ok_or_else(|| Error::Asn1("signature BIT STRING has unused bits".into()))
    }

    /// Signature algorithm OID of the certificate.
    pub fn signature_algorithm_oid(&self) -> ObjectIdentifier {
        self.inner.signature_algorithm().oid
    }

    /// PEM encoding with `-----BEGIN CERTIFICATE-----`, 64-column lines and `\n`.
    pub fn pem(&self) -> Result<String> {
        Ok(self.inner.to_pem(der::pem::LineEnding::LF)?)
    }

    /// Subject name.
    pub fn subject(&self) -> &Name {
        self.inner.tbs_certificate().subject()
    }

    /// Issuer name.
    pub fn issuer(&self) -> &Name {
        self.inner.tbs_certificate().issuer()
    }

    /// Subject DN in Kalkan style: `CN=...,SERIALNUMBER=IIN...,C=KZ`.
    pub fn subject_dn(&self) -> String {
        format_dn(self.subject())
    }

    /// Issuer DN in Kalkan style.
    pub fn issuer_dn(&self) -> String {
        format_dn(self.issuer())
    }

    /// Subject common name.
    pub fn subject_cn(&self) -> Option<String> {
        attribute_value(self.subject(), &oid::AT_CN)
    }

    /// Serial number as Java's `BigInteger.toString(16)`: lowercase hex, no leading zeros.
    pub fn serial_number(&self) -> String {
        let bytes = self.inner.tbs_certificate().serial_number().as_bytes();
        big_int_hex(bytes)
    }

    /// `notBefore`.
    pub fn not_before(&self) -> Result<OffsetDateTime> {
        to_offset_datetime(
            self.inner
                .tbs_certificate()
                .validity()
                .not_before
                .to_unix_duration(),
        )
    }

    /// `notAfter`.
    pub fn not_after(&self) -> Result<OffsetDateTime> {
        to_offset_datetime(
            self.inner
                .tbs_certificate()
                .validity()
                .not_after
                .to_unix_duration(),
        )
    }

    /// `notBefore` formatted as `dd.MM.yyyy HH:mm:ss` in Asia/Almaty.
    pub fn not_before_str(&self) -> Result<String> {
        Ok(format_almaty(self.not_before()?))
    }

    /// `notAfter` formatted as `dd.MM.yyyy HH:mm:ss` in Asia/Almaty.
    pub fn not_after_str(&self) -> Result<String> {
        Ok(format_almaty(self.not_after()?))
    }

    /// Authority key identifier, lowercase hex (empty if absent).
    pub fn authority_key_identifier(&self) -> Result<Option<String>> {
        let ext = self
            .inner
            .tbs_certificate()
            .get_extension::<AuthorityKeyIdentifier>()?;
        Ok(ext
            .and_then(|(_, aki)| aki.key_identifier)
            .map(|k| hex_lower(k.as_bytes())))
    }

    /// Extended key usage OIDs.
    pub fn extended_key_usage(&self) -> Result<Vec<ObjectIdentifier>> {
        let ext = self
            .inner
            .tbs_certificate()
            .get_extension::<ExtendedKeyUsage>()?;
        Ok(ext.map(|(_, e)| e.0).unwrap_or_default())
    }

    /// Authentication vs. signature certificate, by EKU: `clientAuth` alone
    /// means authentication; anything else (including both or none) is signature.
    pub fn key_usage_type(&self) -> KeyUsageType {
        let eku = self.extended_key_usage().unwrap_or_default();
        let auth = eku.contains(&oid::EKU_CLIENT_AUTH);
        let sign = eku.contains(&oid::EKU_EMAIL_PROTECTION);
        if auth && !sign {
            KeyUsageType::Authentication
        } else {
            KeyUsageType::Signature
        }
    }

    /// Certificate policy OIDs.
    pub fn policies(&self) -> Result<Vec<ObjectIdentifier>> {
        let ext = self
            .inner
            .tbs_certificate()
            .get_extension::<CertificatePolicies>()?;
        Ok(ext
            .map(|(_, p)| p.0.into_iter().map(|pi| pi.policy_identifier).collect())
            .unwrap_or_default())
    }

    /// DER `SubjectPublicKeyInfo`.
    pub fn spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .inner
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?)
    }

    /// Decoded public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(self.inner.tbs_certificate().subject_public_key_info())
    }

    /// Public-key algorithm name as Kalkan's `Key.getAlgorithm()` reports it:
    /// `ECGOST3410-2015-512`, `ECGOST3410-2015-256`, `ECGOST3410` or `RSA`.
    pub fn algorithm(&self) -> Result<&'static str> {
        Ok(self.public_key()?.algorithm())
    }

    /// Public-key algorithm OID.
    pub fn public_key_oid(&self) -> ObjectIdentifier {
        self.inner
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid
    }

    /// IIN (individual identification number) from the subject `SERIALNUMBER=IIN...`.
    pub fn iin(&self) -> Option<String> {
        attribute_value(self.subject(), &oid::AT_SERIAL_NUMBER)
            .and_then(|v| v.strip_prefix("IIN").map(str::to_owned))
    }

    /// BIN (business identification number) from the subject `OU=BIN...`.
    pub fn bin(&self) -> Option<String> {
        self.subject()
            .iter()
            .filter(|atv| atv.oid == oid::AT_OU)
            .filter_map(atv_string)
            .find_map(|v| v.strip_prefix("BIN").map(str::to_owned))
    }
}

fn to_offset_datetime(d: core::time::Duration) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(
        i64::try_from(d.as_secs()).map_err(|_| Error::Asn1("time out of range".into()))?,
    )
    .map_err(|e| Error::Asn1(e.to_string()))
}

/// Format as `dd.MM.yyyy HH:mm:ss` in Asia/Almaty (UTC+5).
pub fn format_almaty(t: OffsetDateTime) -> String {
    let t = t.to_offset(ALMATY_OFFSET);
    format!(
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
        t.day(),
        u8::from(t.month()),
        t.year(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// Lowercase hex of a big-endian magnitude without leading zeros (`BigInteger.toString(16)`).
pub fn big_int_hex(bytes: &[u8]) -> String {
    let s = hex_lower(bytes);
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// First value of attribute `oid` in `name`, if it is a string type.
fn attribute_value(name: &Name, oid: &ObjectIdentifier) -> Option<String> {
    name.iter()
        .filter(|atv| atv.oid == *oid)
        .find_map(atv_string)
}

/// String value of an attribute (any of the usual directory string types).
fn atv_string(atv: &AttributeTypeAndValue) -> Option<String> {
    use der::asn1::{BmpString, Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    use der::Tag;
    let v = &atv.value;
    match v.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(v)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Utf8String => Utf8StringRef::try_from(v)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::Ia5String => Ia5StringRef::try_from(v)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::TeletexString => TeletexStringRef::try_from(v)
            .ok()
            .map(|s| s.as_str().to_owned()),
        Tag::BmpString => v.decode_as::<BmpString>().ok().map(|s| s.chars().collect()),
        _ => None,
    }
}

/// Keyword for an attribute type, following BouncyCastle's `BCStyle` symbols
/// (what Kalkan's `X500Name.toString()` prints).
fn attribute_keyword(oid: &ObjectIdentifier) -> Option<&'static str> {
    Some(match oid.to_string().as_str() {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SURNAME",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.13" => "DESCRIPTION",
        "2.5.4.15" => "BusinessCategory",
        "2.5.4.16" => "PostalAddress",
        "2.5.4.17" => "PostalCode",
        "2.5.4.20" => "TelephoneNumber",
        "2.5.4.41" => "Name",
        "2.5.4.42" => "GIVENNAME",
        "2.5.4.43" => "INITIALS",
        "2.5.4.44" => "GENERATION",
        "2.5.4.45" => "UniqueIdentifier",
        "2.5.4.46" => "DN",
        "2.5.4.65" => "Pseudonym",
        "2.5.4.72" => "ROLE",
        "2.5.4.97" => "organizationIdentifier",
        "1.2.840.113549.1.9.1" => "E",
        "1.2.840.113549.1.9.2" => "unstructuredName",
        "1.2.840.113549.1.9.8" => "unstructuredAddress",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.3.6.1.5.5.7.9.1" => "DateOfBirth",
        "1.3.6.1.5.5.7.9.2" => "PlaceOfBirth",
        "1.3.6.1.5.5.7.9.3" => "Gender",
        "1.3.6.1.5.5.7.9.4" => "CountryOfCitizenship",
        "1.3.6.1.5.5.7.9.5" => "CountryOfResidence",
        "1.3.36.8.3.14" => "NameAtBirth",
        _ => return None,
    })
}

/// Format a name as BouncyCastle's `X500Name.toString()` (BCStyle) does, which
/// is what Kalkan prints: RDNs in encoded order (not reversed as in RFC 2253),
/// `,` separator without spaces, `+` between multi-valued RDN members,
/// backslash escaping of special characters.
pub fn format_dn(name: &Name) -> String {
    let mut out = String::new();
    for (i, rdn) in name.iter_rdn().enumerate() {
        if i > 0 {
            out.push(',');
        }
        for (j, atv) in rdn.iter().enumerate() {
            if j > 0 {
                out.push('+');
            }
            match attribute_keyword(&atv.oid) {
                Some(k) => out.push_str(k),
                None => {
                    let _ = write!(out, "{}", atv.oid);
                }
            }
            out.push('=');
            match atv_string(atv) {
                Some(v) => escape_value(&v, &mut out),
                None => {
                    out.push('#');
                    out.push_str(&hex_lower(&atv.value.to_der().unwrap_or_default()));
                }
            }
        }
    }
    out
}

fn escape_value(v: &str, out: &mut String) {
    let n = v.chars().count();
    for (i, c) in v.chars().enumerate() {
        match c {
            ',' | '"' | '\\' | '+' | '=' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(c);
            }
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i + 1 == n => out.push_str("\\ "),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn serial_hex() {
        assert_eq!(big_int_hex(&[0x00, 0x01, 0xa0]), "1a0");
        assert_eq!(big_int_hex(&[0x00]), "0");
        assert_eq!(big_int_hex(&[0xff, 0x00]), "ff00");
    }

    #[test]
    fn almaty_format() {
        let t = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap(); // 2026-09-21T14:13:20Z
        assert_eq!(format_almaty(t), "21.09.2026 19:13:20");
    }

    #[test]
    fn dn_keywords_and_escaping() {
        // x509-cert parses RFC 4514 strings (reversed), so build the name from
        // a string whose encoded order becomes C, OU, SURNAME, CN.
        let name = Name::from_str("CN=A\\, B,SURNAME=X,OU=BIN123456789012,C=KZ").unwrap();
        assert_eq!(
            format_dn(&name),
            "C=KZ,OU=BIN123456789012,SURNAME=X,CN=A\\, B"
        );
    }
}
