//! PKCS#12 (PFX) reader for NCA key containers.
//!
//! Supports the legacy layout produced by Kalkan / BouncyCastle (HMAC-SHA1 MAC,
//! `pkcs8ShroudedKeyBag` under `pbeWithSHAAnd3-KeyTripleDES-CBC`, certificates in
//! `EncryptedData` under `pbeWithSHAAnd40BitRC2-CBC`) as well as SHA-256 MACs and
//! PBES2 (AES) encryption used by newer tools.

use std::path::Path;

use der::asn1::ObjectIdentifier;
use der::Decode;
use digest::Mac;
use hmac::Hmac;
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use spki::AlgorithmIdentifierOwned;
use subtle::ConstantTimeEq;

use crate::ber::{self, Node};
use crate::cert::Cert;
use crate::error::{Error, Result};
use crate::key::PrivateKey;
use crate::{oid, pbe};

/// One key entry of a key store: a private key, its certificate and the rest
/// of the chain found in the container.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Alias (`friendlyName` bag attribute).
    pub alias: String,
    /// The private key.
    pub key: PrivateKey,
    /// End-entity certificate matching the key.
    pub cert: Cert,
    /// Remaining certificates of the chain (issuer first), may be empty.
    pub chain: Vec<Cert>,
}

/// A decoded PKCS#12 key store.
#[derive(Debug, Clone, Default)]
pub struct KeyStore {
    /// Key entries, in container order.
    pub entries: Vec<Entry>,
}

impl KeyStore {
    /// Open a PKCS#12 container from memory.
    pub fn open(bytes: &[u8], password: &str) -> Result<KeyStore> {
        open(bytes, password)
    }

    /// Open a PKCS#12 container from a file.
    pub fn open_file(path: impl AsRef<Path>, password: &str) -> Result<KeyStore> {
        let bytes = std::fs::read(path)?;
        open(&bytes, password)
    }

    /// Look up an entry by alias.
    pub fn entry(&self, alias: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.alias == alias)
    }

    /// Aliases of all entries.
    pub fn aliases(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.alias.as_str())
    }
}

#[derive(Debug)]
struct KeyBag {
    key_der: Vec<u8>,
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
}

#[derive(Debug)]
struct CertBag {
    cert: Cert,
    friendly_name: Option<String>,
    local_key_id: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Bags {
    keys: Vec<KeyBag>,
    certs: Vec<CertBag>,
}

/// Parse and decrypt a PFX.
pub fn open(bytes: &[u8], password: &str) -> Result<KeyStore> {
    let pfx = Node::parse(bytes)?;
    pfx.expect_tag(ber::TAG_SEQUENCE)?;
    let version = pfx.child(0)?.small_int()?;
    if version != 3 {
        return Err(Error::Unsupported(format!("PFX version {version}")));
    }

    // authSafe: ContentInfo { pkcs7-data, [0] OCTET STRING }
    let auth_safe = pfx.child(1)?;
    let (ct, content) = content_info(auth_safe)?;
    if ct != oid::PKCS7_DATA {
        return Err(Error::Unsupported(format!("authSafe content type {ct} (public-key integrity mode)")));
    }
    let auth_safe_bytes = content.octets()?;

    match pfx.children()?.get(2) {
        Some(mac_data) => verify_mac(mac_data, &auth_safe_bytes, password)?,
        None => tracing::warn!("PKCS#12 container has no MAC; password cannot be verified before decryption"),
    }

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    let safes = Node::parse(&auth_safe_bytes)?;
    safes.expect_tag(ber::TAG_SEQUENCE)?;
    let mut bags = Bags::default();
    for ci in safes.children()? {
        let (ct, content) = content_info(ci)?;
        let safe_contents = match ct {
            oid::PKCS7_DATA => content.octets()?,
            oid::PKCS7_ENCRYPTED_DATA => decrypt_encrypted_data(content, password)?,
            other => {
                tracing::warn!("skipping AuthenticatedSafe element of type {other}");
                continue;
            }
        };
        collect_bags(&safe_contents, password, &mut bags)?;
    }

    build_store(bags)
}

/// Split a `ContentInfo` into its type and the node inside `[0] EXPLICIT`.
fn content_info(node: &Node) -> Result<(ObjectIdentifier, &Node)> {
    node.expect_tag(ber::TAG_SEQUENCE)?;
    let ct = node.child(0)?.oid()?;
    let wrapper = node.child(1)?;
    if wrapper.tag() != 0xa0 {
        return Err(Error::Asn1("ContentInfo content is not [0] EXPLICIT".into()));
    }
    Ok((ct, wrapper.child(0)?))
}

fn verify_mac(mac_data: &Node, data: &[u8], password: &str) -> Result<()> {
    // MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }
    mac_data.expect_tag(ber::TAG_SEQUENCE)?;
    let digest_info = mac_data.child(0)?;
    let alg = digest_info.child(0)?.child(0)?.oid()?;
    let expected = digest_info.child(1)?.expect_tag(ber::TAG_OCTET_STRING)?.octets()?;
    let salt = mac_data.child(1)?.expect_tag(ber::TAG_OCTET_STRING)?.octets()?;
    let iterations = match mac_data.children()?.get(2) {
        Some(n) => n.small_int()?,
        None => 1,
    };
    let iterations = i32::try_from(iterations).map_err(|_| Error::Asn1("MAC iteration count out of range".into()))?;

    macro_rules! check {
        ($d:ty) => {{
            let key_len = <$d as digest::OutputSizeUser>::output_size();
            let key = derive_key_utf8::<$d>(password, &salt, Pkcs12KeyType::Mac, iterations, key_len)?;
            let mut mac = <Hmac<$d> as digest::KeyInit>::new_from_slice(&key)
                .map_err(|_| Error::Decrypt("HMAC key length".into()))?;
            Mac::update(&mut mac, data);
            let out = mac.finalize().into_bytes();
            bool::from(out.as_slice().ct_eq(&expected))
        }};
    }
    let ok = match alg {
        oid::SHA1 => check!(sha1::Sha1),
        oid::SHA256 => check!(sha2::Sha256),
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    if ok {
        Ok(())
    } else {
        Err(Error::WrongPassword)
    }
}

/// Decrypt a CMS `EncryptedData` node and return the plaintext `SafeContents`.
fn decrypt_encrypted_data(node: &Node, password: &str) -> Result<Vec<u8>> {
    // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo, ... }
    node.expect_tag(ber::TAG_SEQUENCE)?;
    let eci = node.child(1)?.expect_tag(ber::TAG_SEQUENCE)?;
    let ct = eci.child(0)?.oid()?;
    if ct != oid::PKCS7_DATA {
        return Err(Error::Unsupported(format!("EncryptedData content type {ct}")));
    }
    let alg = AlgorithmIdentifierOwned::from_der(&eci.child(1)?.to_der())?;
    let enc = eci.child(2)?;
    if enc.tag() & 0xdf != 0x80 {
        return Err(Error::Asn1("EncryptedData has no [0] encryptedContent".into()));
    }
    let ciphertext = enc.octets()?;
    pbe::decrypt(&alg, password, &ciphertext)
}

/// Walk a `SafeContents` and collect key and certificate bags.
fn collect_bags(safe_contents: &[u8], password: &str, bags: &mut Bags) -> Result<()> {
    let seq = Node::parse(safe_contents)?;
    seq.expect_tag(ber::TAG_SEQUENCE)?;
    for bag in seq.children()? {
        bag.expect_tag(ber::TAG_SEQUENCE)?;
        let bag_id = bag.child(0)?.oid()?;
        let value = bag.child(1)?;
        if value.tag() != 0xa0 {
            return Err(Error::Asn1("SafeBag value is not [0] EXPLICIT".into()));
        }
        let value = value.child(0)?;
        let (friendly_name, local_key_id) = bag_attributes(bag.children()?.get(2))?;
        match bag_id {
            oid::BAG_KEY => bags.keys.push(KeyBag {
                key_der: value.to_der(),
                friendly_name,
                local_key_id,
            }),
            oid::BAG_SHROUDED_KEY => {
                // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData OCTET STRING }
                let alg = AlgorithmIdentifierOwned::from_der(&value.child(0)?.to_der())?;
                let ciphertext = value.child(1)?.expect_tag(ber::TAG_OCTET_STRING)?.octets()?;
                let key_der = pbe::decrypt(&alg, password, &ciphertext)?;
                bags.keys.push(KeyBag {
                    key_der,
                    friendly_name,
                    local_key_id,
                });
            }
            oid::BAG_CERT => {
                // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
                let cert_id = value.child(0)?.oid()?;
                if cert_id != oid::CERT_TYPE_X509 {
                    tracing::warn!("skipping certBag of type {cert_id}");
                    continue;
                }
                let cert_der = value.child(1)?.child(0)?.octets()?;
                let cert = Cert::from_der(&cert_der)?;
                bags.certs.push(CertBag {
                    cert,
                    friendly_name,
                    local_key_id,
                });
            }
            other => tracing::debug!("skipping SafeBag of type {other}"),
        }
    }
    Ok(())
}

/// Extract `friendlyName` and `localKeyId` from the optional attribute SET.
fn bag_attributes(attrs: Option<&Node>) -> Result<(Option<String>, Option<Vec<u8>>)> {
    let mut name = None;
    let mut id = None;
    let Some(attrs) = attrs else {
        return Ok((name, id));
    };
    for attr in attrs.expect_tag(ber::TAG_SET)?.children()? {
        let ty = attr.child(0)?.oid()?;
        let Some(val) = attr.child(1)?.children()?.first() else {
            continue;
        };
        match ty {
            oid::ATTR_FRIENDLY_NAME => {
                let bytes = val.octets()?;
                let s = der::asn1::BmpString::from_ucs2(bytes)?;
                name = Some(s.chars().collect());
            }
            oid::ATTR_LOCAL_KEY_ID => id = Some(val.octets()?),
            _ => {}
        }
    }
    Ok((name, id))
}

fn build_store(bags: Bags) -> Result<KeyStore> {
    if bags.keys.is_empty() {
        return Err(Error::NoKeys);
    }
    let mut entries = Vec::new();
    for (n, key_bag) in bags.keys.iter().enumerate() {
        let key = PrivateKey::from_pkcs8_der(&key_bag.key_der)?;

        // Match the certificate by localKeyId; fall back to the first
        // certificate that is not an issuer of another one.
        let cert_idx = key_bag
            .local_key_id
            .as_ref()
            .and_then(|id| bags.certs.iter().position(|c| c.local_key_id.as_deref() == Some(id.as_slice())))
            .or_else(|| {
                bags.certs
                    .iter()
                    .position(|c| !bags.certs.iter().any(|o| o.cert.issuer() == c.cert.subject() && o.cert.subject() != c.cert.subject()))
            })
            .or(if bags.certs.is_empty() { None } else { Some(0) })
            .ok_or_else(|| Error::Unsupported("key entry without a certificate".into()))?;
        let cert = bags.certs[cert_idx].cert.clone();
        let alias = key_bag
            .friendly_name
            .clone()
            .or_else(|| bags.certs[cert_idx].friendly_name.clone())
            .unwrap_or_else(|| format!("key{}", n + 1));

        // Build the chain by following issuer names.
        let mut chain = Vec::new();
        let mut current = cert.clone();
        loop {
            if current.issuer() == current.subject() {
                break;
            }
            let next = bags
                .certs
                .iter()
                .map(|c| &c.cert)
                .find(|c| c.subject() == current.issuer() && c.as_der() != current.as_der());
            match next {
                Some(c) if !chain.iter().any(|x: &Cert| x.as_der() == c.as_der()) => {
                    chain.push(c.clone());
                    current = c.clone();
                }
                _ => break,
            }
        }

        entries.push(Entry {
            alias,
            key,
            cert,
            chain,
        });
    }
    Ok(KeyStore { entries })
}
