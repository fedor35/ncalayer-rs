//! Object identifiers used by CMS / CAdES and by the NCA time-stamping service.

use der::asn1::ObjectIdentifier;

const fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

/// `id-data` (PKCS#7).
pub const ID_DATA: ObjectIdentifier = oid("1.2.840.113549.1.7.1");
/// `id-signedData` (PKCS#7).
pub const ID_SIGNED_DATA: ObjectIdentifier = oid("1.2.840.113549.1.7.2");
/// `id-contentType` signed attribute.
pub const CONTENT_TYPE: ObjectIdentifier = oid("1.2.840.113549.1.9.3");
/// `id-messageDigest` signed attribute.
pub const MESSAGE_DIGEST: ObjectIdentifier = oid("1.2.840.113549.1.9.4");
/// `id-signingTime` signed attribute.
pub const SIGNING_TIME: ObjectIdentifier = oid("1.2.840.113549.1.9.5");
/// `id-aa-signingCertificateV2` (RFC 5035).
pub const SIGNING_CERTIFICATE_V2: ObjectIdentifier = oid("1.2.840.113549.1.9.16.2.47");
/// `id-aa-signatureTimeStampToken` (RFC 3161 appendix A).
pub const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier = oid("1.2.840.113549.1.9.16.2.14");
/// `id-ct-TSTInfo` (RFC 3161).
pub const ID_CT_TST_INFO: ObjectIdentifier = oid("1.2.840.113549.1.9.16.1.4");
/// `sha256`.
pub const SHA256: ObjectIdentifier = oid("2.16.840.1.101.3.4.2.1");
/// `sha256WithRSAEncryption`.
pub const SHA256_WITH_RSA: ObjectIdentifier = oid("1.2.840.113549.1.1.11");

/// NCA TSA policy for GOST R 34.10-2004 signers (`kz.gov.pki.reference.TSAPolicy`).
pub const TSA_POLICY_GOST2004: ObjectIdentifier = oid("1.2.398.3.3.2.6.1");
/// NCA TSA policy for RSA signers.
pub const TSA_POLICY_RSA: ObjectIdentifier = oid("1.2.398.3.3.2.6.2");
/// NCA TSA policy for GOST R 34.10-2015 signers.
pub const TSA_POLICY_GOST2015: ObjectIdentifier = oid("1.2.398.3.3.2.6.4");
