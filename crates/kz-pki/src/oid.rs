//! Object identifiers of the Kazakhstan NCA (НУЦ РК) and the standard OIDs used by its containers.

use der::asn1::ObjectIdentifier;

const fn oid(s: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(s)
}

// ---------------------------------------------------------------------------
// GOST R 34.10-2015 (КНТ, "GOST-2015") as profiled by the NCA
// ---------------------------------------------------------------------------

/// GOST R 34.10-2015 512-bit public key.
pub const GOST2015_512_KEY: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.2");
/// GOST R 34.10-2015 512-bit parameter set A.
pub const GOST2015_512_PARAM_A: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.2.1");
/// GOST R 34.10-2015 256-bit public key.
pub const GOST2015_256_KEY: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.1");
/// GOST R 34.10-2015 256-bit parameter set A.
pub const GOST2015_256_PARAM_A: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.1.1");
/// GOST R 34.10-2015 512-bit signature with GOST R 34.11-2015 512-bit hash.
pub const GOST2015_512_SIGNATURE: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.3.2");
/// GOST R 34.10-2015 256-bit signature with GOST R 34.11-2015 256-bit hash.
pub const GOST2015_256_SIGNATURE: ObjectIdentifier = oid("1.2.398.3.10.1.1.2.3.1");
/// GOST R 34.11-2015 512-bit hash (Streebog-512).
pub const GOST2015_512_HASH: ObjectIdentifier = oid("1.2.398.3.10.1.3.3");
/// GOST R 34.11-2015 256-bit hash (Streebog-256).
pub const GOST2015_256_HASH: ObjectIdentifier = oid("1.2.398.3.10.1.3.2");

// ---------------------------------------------------------------------------
// Legacy GOST R 34.10-2004 (ГОСТ 34.310-2004 РК)
// ---------------------------------------------------------------------------

/// GOST R 34.10-2004 public key.
pub const GOST2004_KEY: ObjectIdentifier = oid("1.2.398.3.10.1.1.1.1");
/// GOST R 34.10-2004 parameter set A.
pub const GOST2004_PARAM_A: ObjectIdentifier = oid("1.2.398.3.10.1.1.1.1.1");
/// GOST R 34.10-2004 signature with GOST 34.311-95 hash.
pub const GOST2004_SIGNATURE: ObjectIdentifier = oid("1.2.398.3.10.1.1.1.2");
/// GOST 34.311-95 hash.
pub const GOST34311_HASH: ObjectIdentifier = oid("1.2.398.3.10.1.3.1");

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// `rsaEncryption`.
pub const RSA_ENCRYPTION: ObjectIdentifier = oid("1.2.840.113549.1.1.1");
/// `sha256WithRSAEncryption`.
pub const SHA256_WITH_RSA: ObjectIdentifier = oid("1.2.840.113549.1.1.11");

// ---------------------------------------------------------------------------
// Extended key usage
// ---------------------------------------------------------------------------

/// `id-kp-clientAuth`: the NCA "authentication" certificate.
pub const EKU_CLIENT_AUTH: ObjectIdentifier = oid("1.3.6.1.5.5.7.3.2");
/// `id-kp-emailProtection`: the NCA "signature" certificate.
pub const EKU_EMAIL_PROTECTION: ObjectIdentifier = oid("1.3.6.1.5.5.7.3.4");

// ---------------------------------------------------------------------------
// NCA certificate policies (1.2.398.3.3.4.1.*)
// ---------------------------------------------------------------------------

/// Policy: individual (физическое лицо).
pub const POLICY_INDIVIDUAL: ObjectIdentifier = oid("1.2.398.3.3.4.1.1");
/// Policy: legal entity (юридическое лицо).
pub const POLICY_LEGAL_ENTITY: ObjectIdentifier = oid("1.2.398.3.3.4.1.2");
/// Policy: legal entity, chief executive (первый руководитель).
pub const POLICY_LEGAL_CEO: ObjectIdentifier = oid("1.2.398.3.3.4.1.2.1");
/// Policy: legal entity, person with signing authority (право подписи).
pub const POLICY_LEGAL_SIGNER: ObjectIdentifier = oid("1.2.398.3.3.4.1.2.2");
/// Policy: legal entity, finance signing authority (финансы).
pub const POLICY_LEGAL_FINANCE: ObjectIdentifier = oid("1.2.398.3.3.4.1.2.3");
/// Policy: legal entity, HR (кадры).
pub const POLICY_LEGAL_HR: ObjectIdentifier = oid("1.2.398.3.3.4.1.2.4");
/// Policy: legal entity, employee (сотрудник).
pub const POLICY_LEGAL_EMPLOYEE: ObjectIdentifier = oid("1.2.398.3.3.4.1.2.5");

// ---------------------------------------------------------------------------
// NCA key store type extension (1.2.398.3.3.5.*)
// ---------------------------------------------------------------------------

/// Arc of the NCA key store extension.
pub const KEYSTORE_ARC: ObjectIdentifier = oid("1.2.398.3.3.5");
/// Key store type: PKCS#12 file.
pub const KEYSTORE_PKCS12: ObjectIdentifier = oid("1.2.398.3.3.5.1.1");

// ---------------------------------------------------------------------------
// PKCS#7 / PKCS#12 / PKCS#9 plumbing
// ---------------------------------------------------------------------------

/// `pkcs7-data`.
pub const PKCS7_DATA: ObjectIdentifier = oid("1.2.840.113549.1.7.1");
/// `pkcs7-encryptedData`.
pub const PKCS7_ENCRYPTED_DATA: ObjectIdentifier = oid("1.2.840.113549.1.7.6");
/// `keyBag`.
pub const BAG_KEY: ObjectIdentifier = oid("1.2.840.113549.1.12.10.1.1");
/// `pkcs8ShroudedKeyBag`.
pub const BAG_SHROUDED_KEY: ObjectIdentifier = oid("1.2.840.113549.1.12.10.1.2");
/// `certBag`.
pub const BAG_CERT: ObjectIdentifier = oid("1.2.840.113549.1.12.10.1.3");
/// `x509Certificate` cert bag type.
pub const CERT_TYPE_X509: ObjectIdentifier = oid("1.2.840.113549.1.9.22.1");
/// `friendlyName` bag attribute.
pub const ATTR_FRIENDLY_NAME: ObjectIdentifier = oid("1.2.840.113549.1.9.20");
/// `localKeyId` bag attribute.
pub const ATTR_LOCAL_KEY_ID: ObjectIdentifier = oid("1.2.840.113549.1.9.21");

/// `pbeWithSHAAnd3-KeyTripleDES-CBC`.
pub const PBE_SHA1_3DES: ObjectIdentifier = oid("1.2.840.113549.1.12.1.3");
/// `pbeWithSHAAnd2-KeyTripleDES-CBC`.
pub const PBE_SHA1_2DES: ObjectIdentifier = oid("1.2.840.113549.1.12.1.4");
/// `pbeWithSHAAnd128BitRC2-CBC`.
pub const PBE_SHA1_RC2_128: ObjectIdentifier = oid("1.2.840.113549.1.12.1.5");
/// `pbeWithSHAAnd40BitRC2-CBC`.
pub const PBE_SHA1_RC2_40: ObjectIdentifier = oid("1.2.840.113549.1.12.1.6");
/// `PBES2`.
pub const PBES2: ObjectIdentifier = oid("1.2.840.113549.1.5.13");

/// `sha1` digest (MAC of PKCS#12).
pub const SHA1: ObjectIdentifier = oid("1.3.14.3.2.26");
/// `sha256` digest.
pub const SHA256: ObjectIdentifier = oid("2.16.840.1.101.3.4.2.1");

// ---------------------------------------------------------------------------
// X.509 extensions and name attributes used by this crate
// ---------------------------------------------------------------------------

/// `id-ce-certificatePolicies`.
pub const CERTIFICATE_POLICIES: ObjectIdentifier = oid("2.5.29.32");
/// `id-at-commonName`.
pub const AT_CN: ObjectIdentifier = oid("2.5.4.3");
/// `id-at-serialNumber`.
pub const AT_SERIAL_NUMBER: ObjectIdentifier = oid("2.5.4.5");
/// `id-at-organizationalUnitName`.
pub const AT_OU: ObjectIdentifier = oid("2.5.4.11");
