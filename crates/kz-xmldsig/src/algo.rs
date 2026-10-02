//! XMLDSig algorithm URIs of the NCA signer families and the raw sign /
//! verify primitives (the family itself — digest, curve, OIDs — is
//! [`kz_cms::SignerAlgorithm`]).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use kz_cms::SignerAlgorithm;
use kz_pki::{PrivateKey, PublicKey};
use rand_core::CryptoRng;
use rsa::signature::{SignatureEncoding, Signer, Verifier};

use crate::error::{Error, Result};

/// Namespace of XML Signature.
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The enveloped-signature transform.
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Algorithm URIs of a family.
pub trait XmlAlgorithm {
    /// `SignatureMethod/@Algorithm`.
    fn signature_uri(self) -> &'static str;
    /// `DigestMethod/@Algorithm`.
    fn digest_uri(self) -> &'static str;
    /// Family by `SignatureMethod/@Algorithm`.
    fn from_signature_uri(u: &str) -> Result<Self>
    where
        Self: Sized;
    /// Family by `DigestMethod/@Algorithm`.
    fn from_digest_uri(u: &str) -> Result<Self>
    where
        Self: Sized;
}

impl XmlAlgorithm for SignerAlgorithm {
    fn signature_uri(self) -> &'static str {
        match self {
            SignerAlgorithm::Gost2015_512 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512"
            }
            SignerAlgorithm::Gost2015_256 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256"
            }
            SignerAlgorithm::Gost2004 => {
                "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"
            }
            SignerAlgorithm::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        }
    }

    fn digest_uri(self) -> &'static str {
        match self {
            SignerAlgorithm::Gost2015_512 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512"
            }
            SignerAlgorithm::Gost2015_256 => {
                "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256"
            }
            SignerAlgorithm::Gost2004 => "http://www.w3.org/2001/04/xmldsig-more#gost34311",
            SignerAlgorithm::RsaSha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        }
    }

    fn from_signature_uri(u: &str) -> Result<Self> {
        [
            SignerAlgorithm::Gost2015_512,
            SignerAlgorithm::Gost2015_256,
            SignerAlgorithm::Gost2004,
            SignerAlgorithm::RsaSha256,
        ]
        .into_iter()
        .find(|a| a.signature_uri() == u)
        .ok_or_else(|| Error::UnsupportedAlgorithm(u.into()))
    }

    fn from_digest_uri(u: &str) -> Result<Self> {
        [
            SignerAlgorithm::Gost2015_512,
            SignerAlgorithm::Gost2015_256,
            SignerAlgorithm::Gost2004,
            SignerAlgorithm::RsaSha256,
        ]
        .into_iter()
        .find(|a| a.digest_uri() == u)
        .ok_or_else(|| Error::UnsupportedAlgorithm(u.into()))
    }
}

fn gost_curve(alg: SignerAlgorithm) -> Result<&'static gost3410::Curve> {
    alg.curve()
        .map(|c| c.curve())
        .ok_or_else(|| Error::UnsupportedAlgorithm(alg.signature_uri().into()))
}

/// Raw `SignatureValue` bytes over the canonical `SignedInfo`.
///
/// GOST signatures are written as `r ‖ s`, each **little-endian**
/// ([`gost3410::Signature::to_bytes_kz`]) — the same layout Kalkan uses in
/// CMS and X.509; verified against the Kalkan-produced XML fixtures.
pub fn sign_raw<R: CryptoRng + ?Sized>(
    key: &PrivateKey,
    data: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let alg = SignerAlgorithm::for_private_key(key);
    match key {
        PrivateKey::Gost2015 { d, .. } | PrivateKey::Gost2004 { d } => {
            let curve = gost_curve(alg)?;
            let sk = gost3410::SecretKey::from_bytes_be(curve, d)?;
            let sig = gost3410::sign(curve, &sk, &alg.digest(data), rng)?;
            Ok(sig.to_bytes_kz(curve))
        }
        PrivateKey::Rsa(priv_key) => {
            let sk = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(priv_key.clone());
            let sig = sk.try_sign(data).map_err(|e| Error::Rsa(e.to_string()))?;
            Ok(sig.to_vec())
        }
    }
}

/// Verify raw `SignatureValue` bytes over the canonical `SignedInfo`.
pub fn verify_raw(
    key: &PublicKey,
    alg: SignerAlgorithm,
    data: &[u8],
    signature: &[u8],
) -> Result<()> {
    if SignerAlgorithm::for_public_key(key) != alg {
        return Err(Error::UnsupportedAlgorithm(alg.signature_uri().into()));
    }
    match key {
        PublicKey::Gost2015 { x, y, .. } | PublicKey::Gost2004 { x, y } => {
            let curve = gost_curve(alg)?;
            let mut le = x.to_vec();
            le.reverse();
            let mut yle = y.to_vec();
            yle.reverse();
            le.extend(yle);
            let pk = gost3410::PublicKey::from_bytes_x509(curve, &le)?;
            let sig = gost3410::Signature::from_bytes_kz(curve, signature)
                .map_err(|_| Error::BadSignature)?;
            if gost3410::verify(curve, &pk, &alg.digest(data), &sig) {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
        PublicKey::Rsa(pub_key) => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pub_key.clone());
            let sig =
                rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| Error::BadSignature)?;
            vk.verify(data, &sig).map_err(|_| Error::BadSignature)
        }
    }
}

/// Base64 as Santuario writes it: lines of 76 characters joined by CR LF.
pub fn base64_wrapped(data: &[u8]) -> String {
    let s = B64.encode(data);
    let lines: Vec<&str> = s
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    lines.join("\r\n")
}

/// Decode base64 ignoring any whitespace.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(B64.decode(clean)?)
}
