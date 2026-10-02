//! Signature / digest algorithm families of NCA signers and the primitive
//! sign / verify operations on raw bytes.

use der::asn1::ObjectIdentifier;
use gost3410::{HashAlg, NamedCurve};
use kz_pki::oid as pki_oid;
use kz_pki::{Gost2015Curve, PrivateKey, PublicKey};
use rand_core::CryptoRng;
use rsa::signature::{SignatureEncoding, Signer, Verifier};

use crate::error::{Error, Result};
use crate::oid;

/// The algorithm family of a signer, which fixes the digest, signature and
/// TSA policy OIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerAlgorithm {
    /// GOST R 34.10-2015 512-bit with Streebog-512 (`1.2.398.3.10.1.1.2.3.2`).
    Gost2015_512,
    /// GOST R 34.10-2015 256-bit with Streebog-256 (`1.2.398.3.10.1.1.2.3.1`).
    Gost2015_256,
    /// GOST R 34.10-2004 with GOST 34.311-95 (`1.2.398.3.10.1.1.1.2`).
    Gost2004,
    /// RSA PKCS#1 v1.5 with SHA-256 (`sha256WithRSAEncryption`).
    RsaSha256,
}

impl SignerAlgorithm {
    /// Digest algorithm OID (`digestAlgorithm` of `SignerInfo`).
    pub fn digest_oid(self) -> ObjectIdentifier {
        match self {
            SignerAlgorithm::Gost2015_512 => pki_oid::GOST2015_512_HASH,
            SignerAlgorithm::Gost2015_256 => pki_oid::GOST2015_256_HASH,
            SignerAlgorithm::Gost2004 => pki_oid::GOST34311_HASH,
            SignerAlgorithm::RsaSha256 => oid::SHA256,
        }
    }

    /// Signature algorithm OID (`signatureAlgorithm` of `SignerInfo`).
    pub fn signature_oid(self) -> ObjectIdentifier {
        match self {
            SignerAlgorithm::Gost2015_512 => pki_oid::GOST2015_512_SIGNATURE,
            SignerAlgorithm::Gost2015_256 => pki_oid::GOST2015_256_SIGNATURE,
            SignerAlgorithm::Gost2004 => pki_oid::GOST2004_SIGNATURE,
            SignerAlgorithm::RsaSha256 => oid::SHA256_WITH_RSA,
        }
    }

    /// NCA TSA policy OID (`kz.gov.pki.reference.TSAPolicy`).
    pub fn tsa_policy_oid(self) -> ObjectIdentifier {
        match self {
            SignerAlgorithm::Gost2015_512 | SignerAlgorithm::Gost2015_256 => {
                oid::TSA_POLICY_GOST2015
            }
            SignerAlgorithm::Gost2004 => oid::TSA_POLICY_GOST2004,
            SignerAlgorithm::RsaSha256 => oid::TSA_POLICY_RSA,
        }
    }

    /// Digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            SignerAlgorithm::Gost2015_512 => 64,
            _ => 32,
        }
    }

    /// Hash a message with the family's digest algorithm.
    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            SignerAlgorithm::Gost2015_512 => HashAlg::Streebog512.digest(msg),
            SignerAlgorithm::Gost2015_256 => HashAlg::Streebog256.digest(msg),
            SignerAlgorithm::Gost2004 => HashAlg::Gost94CryptoPro.digest(msg),
            SignerAlgorithm::RsaSha256 => {
                use sha2::Digest;
                sha2::Sha256::digest(msg).to_vec()
            }
        }
    }

    /// The GOST curve of the family (`None` for RSA).
    pub fn curve(self) -> Option<NamedCurve> {
        match self {
            SignerAlgorithm::Gost2015_512 => Some(NamedCurve::Tc26Gost3410_12_512ParamSetA),
            SignerAlgorithm::Gost2015_256 => Some(NamedCurve::Tc26Gost3410_2012_256ParamSetA),
            SignerAlgorithm::Gost2004 => Some(NamedCurve::GostR3410_2001_CryptoPro_A),
            SignerAlgorithm::RsaSha256 => None,
        }
    }

    /// Family of a private key.
    pub fn for_private_key(key: &PrivateKey) -> Self {
        match key {
            PrivateKey::Gost2015 {
                curve: Gost2015Curve::A512,
                ..
            } => SignerAlgorithm::Gost2015_512,
            PrivateKey::Gost2015 {
                curve: Gost2015Curve::A256,
                ..
            } => SignerAlgorithm::Gost2015_256,
            PrivateKey::Gost2004 { .. } => SignerAlgorithm::Gost2004,
            PrivateKey::Rsa(_) => SignerAlgorithm::RsaSha256,
        }
    }

    /// Family of a public key.
    pub fn for_public_key(key: &PublicKey) -> Self {
        match key {
            PublicKey::Gost2015 {
                curve: Gost2015Curve::A512,
                ..
            } => SignerAlgorithm::Gost2015_512,
            PublicKey::Gost2015 {
                curve: Gost2015Curve::A256,
                ..
            } => SignerAlgorithm::Gost2015_256,
            PublicKey::Gost2004 { .. } => SignerAlgorithm::Gost2004,
            PublicKey::Rsa(_) => SignerAlgorithm::RsaSha256,
        }
    }

    /// Family by the signature algorithm OID found in a `SignerInfo`.
    pub fn from_signature_oid(o: &ObjectIdentifier) -> Result<Self> {
        Ok(match *o {
            pki_oid::GOST2015_512_SIGNATURE => SignerAlgorithm::Gost2015_512,
            pki_oid::GOST2015_256_SIGNATURE => SignerAlgorithm::Gost2015_256,
            pki_oid::GOST2004_SIGNATURE => SignerAlgorithm::Gost2004,
            oid::SHA256_WITH_RSA | pki_oid::RSA_ENCRYPTION => SignerAlgorithm::RsaSha256,
            other => return Err(Error::UnsupportedAlgorithm(other)),
        })
    }

    /// Family by a digest algorithm OID (used for `digestAlgorithms` and
    /// TSA `messageImprint`).
    pub fn from_digest_oid(o: &ObjectIdentifier) -> Result<Self> {
        Ok(match *o {
            pki_oid::GOST2015_512_HASH => SignerAlgorithm::Gost2015_512,
            pki_oid::GOST2015_256_HASH => SignerAlgorithm::Gost2015_256,
            pki_oid::GOST34311_HASH => SignerAlgorithm::Gost2004,
            oid::SHA256 => SignerAlgorithm::RsaSha256,
            other => return Err(Error::UnsupportedAlgorithm(other)),
        })
    }
}

/// Where the signature nonce comes from.
pub enum Nonce<'r> {
    /// Draw `k` from a cryptographic RNG (GOST); RSA PKCS#1 v1.5 ignores it.
    Random(&'r mut dyn CryptoRng),
    /// Derive `k` deterministically from the key and digest
    /// (RFC 6979-style HMAC-DRBG, see [`gost3410::sign_deterministic`]).
    Deterministic,
}

fn gost_secret(
    alg: SignerAlgorithm,
    d: &[u8],
) -> Result<(&'static gost3410::Curve, gost3410::SecretKey)> {
    let curve = alg
        .curve()
        .ok_or(Error::UnsupportedAlgorithm(alg.signature_oid()))?
        .curve();
    let key = gost3410::SecretKey::from_bytes_be(curve, d)?;
    Ok((curve, key))
}

/// Public key of a GOST family from a certificate's decoded key
/// (`kz-pki` stores big-endian coordinates, `gost3410` reads little-endian).
pub(crate) fn gost_public(
    alg: SignerAlgorithm,
    x: &[u8],
    y: &[u8],
) -> Result<(&'static gost3410::Curve, gost3410::PublicKey)> {
    let curve = alg
        .curve()
        .ok_or(Error::UnsupportedAlgorithm(alg.signature_oid()))?
        .curve();
    let mut le = x.to_vec();
    le.reverse();
    let mut yle = y.to_vec();
    yle.reverse();
    le.extend(yle);
    let pk = gost3410::PublicKey::from_bytes_x509(curve, &le)?;
    Ok((curve, pk))
}

/// Produce the raw `SignerInfo.signature` bytes over `signed_bytes`
/// (the DER `SET` of signed attributes).
///
/// GOST signatures are written as `r ‖ s`, each **little-endian**
/// ([`gost3410::Signature::to_bytes_kz`]), which is what Kalkan puts into
/// CMS as well as into X.509 (verified against the Kalkan-produced fixtures).
pub(crate) fn sign_raw(key: &PrivateKey, signed_bytes: &[u8], nonce: Nonce<'_>) -> Result<Vec<u8>> {
    let alg = SignerAlgorithm::for_private_key(key);
    match key {
        PrivateKey::Gost2015 { d, .. } | PrivateKey::Gost2004 { d } => {
            let (curve, sk) = gost_secret(alg, d)?;
            let digest = alg.digest(signed_bytes);
            let sig = match nonce {
                Nonce::Random(rng) => gost3410::sign(curve, &sk, &digest, rng)?,
                Nonce::Deterministic => gost3410::sign_deterministic(curve, &sk, &digest),
            };
            Ok(sig.to_bytes_kz(curve))
        }
        PrivateKey::Rsa(priv_key) => {
            let sk = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(priv_key.clone());
            let sig = sk
                .try_sign(signed_bytes)
                .map_err(|e| Error::Rsa(e.to_string()))?;
            Ok(sig.to_vec())
        }
    }
}

/// Verify raw `SignerInfo.signature` bytes over `signed_bytes` with a
/// certificate's public key.
pub(crate) fn verify_raw(
    key: &PublicKey,
    alg: SignerAlgorithm,
    signed_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    match key {
        PublicKey::Gost2015 { x, y, .. } | PublicKey::Gost2004 { x, y } => {
            let key_alg = SignerAlgorithm::for_public_key(key);
            if key_alg != alg {
                return Err(Error::UnsupportedAlgorithm(alg.signature_oid()));
            }
            let (curve, pk) = gost_public(alg, x, y)?;
            let digest = alg.digest(signed_bytes);
            let sig = gost3410::Signature::from_bytes_kz(curve, signature)
                .map_err(|_| Error::BadSignature)?;
            if gost3410::verify(curve, &pk, &digest, &sig) {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
        PublicKey::Rsa(pub_key) => {
            if alg != SignerAlgorithm::RsaSha256 {
                return Err(Error::UnsupportedAlgorithm(alg.signature_oid()));
            }
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pub_key.clone());
            let sig =
                rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| Error::BadSignature)?;
            vk.verify(signed_bytes, &sig)
                .map_err(|_| Error::BadSignature)
        }
    }
}
