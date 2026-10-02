//! Private and public keys found in NCA containers and certificates.

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use pkcs8::PrivateKeyInfoRef;
use rsa::pkcs8::DecodePrivateKey;
use spki::SubjectPublicKeyInfoOwned;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::oid;

/// Curve (parameter set) of a GOST R 34.10-2015 key as used by the NCA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gost2015Curve {
    /// 256-bit parameter set A (`1.2.398.3.10.1.1.2.1.1`).
    A256,
    /// 512-bit parameter set A (`1.2.398.3.10.1.1.2.2.1`).
    A512,
}

impl Gost2015Curve {
    /// Size of a scalar / coordinate in bytes.
    pub fn scalar_len(self) -> usize {
        match self {
            Gost2015Curve::A256 => 32,
            Gost2015Curve::A512 => 64,
        }
    }

    /// Public-key algorithm OID.
    pub fn key_oid(self) -> ObjectIdentifier {
        match self {
            Gost2015Curve::A256 => oid::GOST2015_256_KEY,
            Gost2015Curve::A512 => oid::GOST2015_512_KEY,
        }
    }

    /// Parameter-set OID.
    pub fn param_oid(self) -> ObjectIdentifier {
        match self {
            Gost2015Curve::A256 => oid::GOST2015_256_PARAM_A,
            Gost2015Curve::A512 => oid::GOST2015_512_PARAM_A,
        }
    }

    /// Signature algorithm OID (with the matching Streebog hash).
    pub fn signature_oid(self) -> ObjectIdentifier {
        match self {
            Gost2015Curve::A256 => oid::GOST2015_256_SIGNATURE,
            Gost2015Curve::A512 => oid::GOST2015_512_SIGNATURE,
        }
    }

    /// Hash algorithm OID.
    pub fn hash_oid(self) -> ObjectIdentifier {
        match self {
            Gost2015Curve::A256 => oid::GOST2015_256_HASH,
            Gost2015Curve::A512 => oid::GOST2015_512_HASH,
        }
    }

    /// Algorithm name as Kalkan's `Key.getAlgorithm()` reports it.
    pub fn java_name(self) -> &'static str {
        match self {
            Gost2015Curve::A256 => "ECGOST3410-2015-256",
            Gost2015Curve::A512 => "ECGOST3410-2015-512",
        }
    }
}

/// A private key extracted from a container.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub enum PrivateKey {
    /// GOST R 34.10-2015 key; `d` is the scalar, big-endian, `curve.scalar_len()` bytes.
    Gost2015 {
        /// Parameter set.
        #[zeroize(skip)]
        curve: Gost2015Curve,
        /// Private scalar, big-endian.
        d: Vec<u8>,
    },
    /// Legacy GOST R 34.10-2004 key; `d` is the 32-byte scalar, big-endian.
    Gost2004 {
        /// Private scalar, big-endian.
        d: Vec<u8>,
    },
    /// RSA key.
    Rsa(#[zeroize(skip)] rsa::RsaPrivateKey),
}

impl PrivateKey {
    /// Parse a DER `PrivateKeyInfo` (PKCS#8).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let pki = PrivateKeyInfoRef::from_der(der)?;
        let alg = pki.algorithm.oid;
        match alg {
            oid::GOST2015_256_KEY | oid::GOST2015_512_KEY => {
                let curve = gost2015_curve(alg, pki.algorithm.parameters.map(|p| p.to_der()).transpose()?.as_deref())?;
                let d = decode_gost_scalar(pki.private_key.as_bytes(), curve.scalar_len())?;
                Ok(PrivateKey::Gost2015 { curve, d })
            }
            oid::GOST2004_KEY => {
                let d = decode_gost_scalar(pki.private_key.as_bytes(), 32)?;
                Ok(PrivateKey::Gost2004 { d })
            }
            oid::RSA_ENCRYPTION => Ok(PrivateKey::Rsa(rsa::RsaPrivateKey::from_pkcs8_der(der)?)),
            other => Err(Error::UnsupportedAlgorithm(other)),
        }
    }

    /// Algorithm name as Kalkan's `Key.getAlgorithm()` reports it.
    pub fn algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Gost2015 { curve, .. } => curve.java_name(),
            PrivateKey::Gost2004 { .. } => "ECGOST3410",
            PrivateKey::Rsa(_) => "RSA",
        }
    }
}

/// A public key taken from a certificate's `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// GOST R 34.10-2015 point; coordinates are big-endian, `curve.scalar_len()` bytes each.
    Gost2015 {
        /// Parameter set.
        curve: Gost2015Curve,
        /// Affine x, big-endian.
        x: Vec<u8>,
        /// Affine y, big-endian.
        y: Vec<u8>,
    },
    /// GOST R 34.10-2004 point; 32-byte big-endian coordinates.
    Gost2004 {
        /// Affine x, big-endian.
        x: Vec<u8>,
        /// Affine y, big-endian.
        y: Vec<u8>,
    },
    /// RSA public key.
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    /// Parse a DER `SubjectPublicKeyInfo`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        Self::from_spki(&SubjectPublicKeyInfoOwned::from_der(der)?)
    }

    /// Convert a decoded `SubjectPublicKeyInfo`.
    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        let alg = spki.algorithm.oid;
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::Asn1("public key BIT STRING has unused bits".into()))?;
        match alg {
            oid::GOST2015_256_KEY | oid::GOST2015_512_KEY => {
                let params = spki.algorithm.parameters.as_ref().map(|p| p.to_der()).transpose()?;
                let curve = gost2015_curve(alg, params.as_deref())?;
                let (x, y) = decode_gost_point(bits, curve.scalar_len())?;
                Ok(PublicKey::Gost2015 { curve, x, y })
            }
            oid::GOST2004_KEY => {
                let (x, y) = decode_gost_point(bits, 32)?;
                Ok(PublicKey::Gost2004 { x, y })
            }
            oid::RSA_ENCRYPTION => {
                use rsa::pkcs8::DecodePublicKey;
                Ok(PublicKey::Rsa(rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?).map_err(|e| Error::PrivateKey(e.to_string()))?))
            }
            other => Err(Error::UnsupportedAlgorithm(other)),
        }
    }

    /// Algorithm name as Kalkan's `Key.getAlgorithm()` reports it.
    pub fn algorithm(&self) -> &'static str {
        match self {
            PublicKey::Gost2015 { curve, .. } => curve.java_name(),
            PublicKey::Gost2004 { .. } => "ECGOST3410",
            PublicKey::Rsa(_) => "RSA",
        }
    }
}

/// Determine the 2015 curve from the key OID and (optionally) the DER-encoded
/// parameters `SEQUENCE { paramSet OID, digest OID OPTIONAL }`.
fn gost2015_curve(key_oid: ObjectIdentifier, params_der: Option<&[u8]>) -> Result<Gost2015Curve> {
    if let Some(der) = params_der {
        let params = GostParams::from_der(der)?;
        return match params.param_set {
            oid::GOST2015_256_PARAM_A => Ok(Gost2015Curve::A256),
            oid::GOST2015_512_PARAM_A => Ok(Gost2015Curve::A512),
            other => Err(Error::UnsupportedAlgorithm(other)),
        };
    }
    match key_oid {
        oid::GOST2015_256_KEY => Ok(Gost2015Curve::A256),
        oid::GOST2015_512_KEY => Ok(Gost2015Curve::A512),
        other => Err(Error::UnsupportedAlgorithm(other)),
    }
}

/// `GostR3410-2012-PublicKeyParameters` (RFC 7836 / RFC 9215).
#[derive(der::Sequence)]
struct GostParams {
    param_set: ObjectIdentifier,
    #[asn1(optional = "true")]
    digest: Option<ObjectIdentifier>,
}

/// Decode the contents of the PKCS#8 `privateKey` OCTET STRING of a GOST key
/// into a big-endian scalar of `len` bytes.
///
/// Three encodings occur in the wild (RFC 4491 / RFC 9215):
/// * `OCTET STRING` of `len` bytes, little-endian (what Kalkan writes);
/// * `INTEGER`, big-endian (older CryptoPro-style containers);
/// * raw `len` bytes without an inner tag, assumed little-endian.
fn decode_gost_scalar(inner: &[u8], len: usize) -> Result<Vec<u8>> {
    let mut d = match inner.first() {
        Some(&crate::ber::TAG_OCTET_STRING) if inner.len() != len => {
            let s = der::asn1::OctetStringRef::from_der(inner)?;
            let mut v = s.as_bytes().to_vec();
            v.reverse();
            v
        }
        Some(&crate::ber::TAG_INTEGER) if inner.len() != len => {
            let i = der::asn1::UintRef::from_der(inner)?;
            i.as_bytes().to_vec()
        }
        Some(_) if inner.len() == len => {
            let mut v = inner.to_vec();
            v.reverse();
            v
        }
        _ => return Err(Error::PrivateKey("unrecognised GOST private key encoding".into())),
    };
    // Normalise to exactly `len` bytes (strip leading zeros / left-pad).
    while d.len() > len && d[0] == 0 {
        d.remove(0);
    }
    if d.len() > len {
        return Err(Error::PrivateKey("GOST private key too long".into()));
    }
    while d.len() < len {
        d.insert(0, 0);
    }
    Ok(d)
}

/// Decode the BIT STRING contents of a GOST public key: `OCTET STRING(x || y)`,
/// both little-endian (RFC 4491), returning big-endian coordinates.
fn decode_gost_point(bits: &[u8], len: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let raw: Vec<u8> = if bits.len() == 2 * len {
        bits.to_vec()
    } else {
        der::asn1::OctetStringRef::from_der(bits)?.as_bytes().to_vec()
    };
    if raw.len() != 2 * len {
        return Err(Error::Asn1(format!("GOST public key: expected {} bytes, got {}", 2 * len, raw.len())));
    }
    let mut x = raw[..len].to_vec();
    let mut y = raw[len..].to_vec();
    x.reverse();
    y.reverse();
    Ok((x, y))
}
