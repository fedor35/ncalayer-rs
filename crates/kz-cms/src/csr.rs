//! Key generation and PKCS#10 certification requests for `basics.generateCsr`.
//!
//! Mirrors NCALayer's `KeyStoreUtil.genKeyPairAndGetCSR` (bundle `knca_provider_util`) for file
//! storages: a fresh GOST R 34.10-2015 key, the subject built from the site's `{oid: value}` map
//! in natural OID order, an `extensionRequest` with SubjectAlternativeName (if any) and the
//! NCA `keystore_branch` extension `SEQUENCE { storage OID, UTF8String folder }`, signed with
//! the new key. Encodings follow Kalkan (a BouncyCastle fork) byte for byte, checked against
//! `tools/java-oracle/CsrOracle.java`.

use der::asn1::ObjectIdentifier;
use kz_pki::{Gost2015Curve, PrivateKey, PublicKey};

use crate::algo::{sign_raw, Nonce};
use crate::der_util::{null, oid, sequence, set_of, tlv, TAG_CTX0};
use crate::error::{Error, Result};

/// `pkcs-9-at-extensionRequest`.
const EXTENSION_REQUEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");
/// `id-ce-subjectAltName`.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// NCA `keystore_branch` extension (`KNCAObjectIdentifiers.keystore_branch`).
pub const KEYSTORE_BRANCH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.5");
/// Storage OID of a PKCS#12 file (`KNCAObjectIdentifiers.pkcs12`).
pub const KEYSTORE_PKCS12: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.5.1.1");

/// What the site asks for.
#[derive(Debug, Clone)]
pub struct CsrParams {
    /// Subject attributes `{oid: value}` as sent in `args.dn` (any order).
    pub subject: Vec<(ObjectIdentifier, String)>,
    /// `args.email`; becomes an `rfc822Name` in SubjectAlternativeName when non-empty.
    pub email: Option<String>,
    /// `args.subjectAltNames`; each becomes a `dNSName`.
    pub alt_names: Vec<String>,
    /// Folder the key file goes to; written into the `keystore_branch` extension.
    pub keystore_path: String,
}

/// A generated key with its request.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// The new private key.
    pub key: PrivateKey,
    /// Its public key.
    pub public: PublicKey,
    /// Kalkan key id (SHA-1 of the public key bits); NCALayer's alias and file name part.
    pub key_id: Vec<u8>,
    /// The request, PEM (`-----BEGIN CERTIFICATE REQUEST-----`, 64-column lines).
    pub csr_pem: String,
    /// The request, DER.
    pub csr_der: Vec<u8>,
}

/// Generate a GOST R 34.10-2015 key (`curve`) and a request signed with it.
pub fn generate(
    curve: Gost2015Curve,
    params: &CsrParams,
    rng: &mut dyn rand_core::CryptoRng,
) -> Result<GeneratedKey> {
    let named = match curve {
        Gost2015Curve::A512 => gost3410::NamedCurve::Tc26Gost3410_12_512ParamSetA,
        Gost2015Curve::A256 => gost3410::NamedCurve::Tc26Gost3410_2012_256ParamSetA,
    };
    let c = named.curve();
    let sk = gost3410::SecretKey::random(c, rng)?;
    let len = curve.scalar_len();
    let xy = sk.public_key(c).to_bytes_x509(c); // x ‖ y, little-endian
    let be = |s: &[u8]| s.iter().rev().copied().collect::<Vec<u8>>();
    let public = PublicKey::Gost2015 {
        curve,
        x: be(&xy[..len]),
        y: be(&xy[len..2 * len]),
    };
    let key = PrivateKey::Gost2015 {
        curve,
        d: sk.to_bytes_be(c),
    };
    let key_id = public.key_id()?;
    let csr_der = build(&key, &public, params, rng)?;
    Ok(GeneratedKey {
        key,
        public,
        key_id,
        csr_pem: pem(&csr_der),
        csr_der,
    })
}

/// Build and sign the request for an existing key pair.
pub fn build(
    key: &PrivateKey,
    public: &PublicKey,
    params: &CsrParams,
    rng: &mut dyn rand_core::CryptoRng,
) -> Result<Vec<u8>> {
    let PrivateKey::Gost2015 { curve, .. } = key else {
        return Err(Error::UnsupportedAlgorithm(ObjectIdentifier::new_unwrap(
            "1.2.398.3.10.1.1.1.1",
        )));
    };
    let spki = public.to_spki_der()?;

    // Extensions, in insertion order like X509ExtensionsGenerator: SAN, then keystore_branch.
    let mut exts = Vec::new();
    let mut names = Vec::new();
    for n in &params.alt_names {
        names.push(tlv(0x82, n.as_bytes())); // dNSName [2] IMPLICIT IA5String
    }
    // NCALayer tests `email.trim().isEmpty()` but writes the value as given.
    if let Some(e) = params.email.as_deref().filter(|e| !e.trim().is_empty()) {
        names.push(tlv(0x81, e.as_bytes()));
    }
    if !names.is_empty() {
        let gn = sequence(&names.iter().map(Vec::as_slice).collect::<Vec<_>>());
        exts.push(extension(&SUBJECT_ALT_NAME, &gn));
    }
    let ks = sequence(&[
        &oid(&KEYSTORE_PKCS12),
        &tlv(0x0c, params.keystore_path.as_bytes()),
    ]);
    exts.push(extension(&KEYSTORE_BRANCH, &ks));
    let extensions = sequence(&exts.iter().map(Vec::as_slice).collect::<Vec<_>>());
    let attr = sequence(&[&oid(&EXTENSION_REQUEST), &set_of(vec![extensions])]);
    let attrs = tlv(TAG_CTX0, &attr);

    let info = sequence(&[&[0x02, 0x01, 0x00], &name(&params.subject), &spki, &attrs]);
    let sig = sign_raw(key, &info, Nonce::Random(rng))?;
    let mut bits = vec![0u8];
    bits.extend(sig);
    Ok(sequence(&[
        &info,
        &sequence(&[&oid(&curve.signature_oid()), &null()]),
        &tlv(0x03, &bits),
    ]))
}

/// Check a request's self-signature; returns its subject public key.
pub fn verify(csr_der: &[u8]) -> Result<PublicKey> {
    use crate::der_util::{Cursor, Tlv, TAG_SEQUENCE};
    let top = Tlv::parse_tag(csr_der, TAG_SEQUENCE)?;
    let mut c = Cursor::new(&top)?;
    let info = c.next_tag(TAG_SEQUENCE, "certificationRequestInfo")?;
    let alg = c.next_tag(TAG_SEQUENCE, "signatureAlgorithm")?;
    let sig = c.next_tag(0x03, "signature")?;
    let alg_oid = Cursor::new(&alg)?.next_tag(0x06, "algorithm")?.oid()?;
    let mut ic = Cursor::new(&info)?;
    ic.next_tag(0x02, "version")?;
    ic.next_tag(TAG_SEQUENCE, "subject")?;
    let spki = ic.next_tag(TAG_SEQUENCE, "subjectPKInfo")?;
    let public = PublicKey::from_spki_der(spki.raw)?;
    let signer = crate::algo::SignerAlgorithm::from_signature_oid(&alg_oid)?;
    let bits = sig
        .content
        .get(1..)
        .ok_or_else(|| Error::Structure("empty signature".into()))?;
    crate::algo::verify_raw(&public, signer, info.raw, bits)?;
    Ok(public)
}

/// `Extension { extnID, extnValue }` (non-critical: the BOOLEAN is omitted).
fn extension(id: &ObjectIdentifier, value_der: &[u8]) -> Vec<u8> {
    sequence(&[&oid(id), &tlv(0x04, value_der)])
}

/// Subject `Name`: one RDN per attribute, sorted like NCALayer's `NaturalOrderComparator`
/// over the OID strings (numeric runs compare as numbers), values typed like BouncyCastle's
/// `X509DefaultEntryConverter`.
fn name(subject: &[(ObjectIdentifier, String)]) -> Vec<u8> {
    let mut attrs: Vec<&(ObjectIdentifier, String)> = subject.iter().collect();
    attrs.sort_by(|a, b| natural_cmp(&a.0.to_string(), &b.0.to_string()));
    let rdns: Vec<Vec<u8>> = attrs
        .iter()
        .map(|(o, v)| set_of(vec![sequence(&[&oid(o), &directory_string(o, v)])]))
        .collect();
    sequence(&rdns.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

fn directory_string(o: &ObjectIdentifier, v: &str) -> Vec<u8> {
    const PRINTABLE: &[&str] = &["2.5.4.6", "2.5.4.5", "2.5.4.46", "2.5.4.20"];
    const IA5: &[&str] = &["1.2.840.113549.1.9.1", "0.9.2342.19200300.100.1.25"];
    let s = o.to_string();
    if PRINTABLE.contains(&s.as_str()) {
        tlv(0x13, v.as_bytes())
    } else if IA5.contains(&s.as_str()) {
        tlv(0x16, v.as_bytes())
    } else {
        tlv(0x0c, v.as_bytes())
    }
}

/// Natural string order: runs of digits compare by numeric value, the rest by character.
fn natural_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let si = i;
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            let sj = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let x = core::str::from_utf8(&a[si..i])
                .unwrap()
                .trim_start_matches('0');
            let y = core::str::from_utf8(&b[sj..j])
                .unwrap()
                .trim_start_matches('0');
            let o = x.len().cmp(&y.len()).then(x.cmp(y));
            if o != Ordering::Equal {
                return o;
            }
        } else {
            if a[i] != b[j] {
                return a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
    }
    (a.len() - i).cmp(&(b.len() - j))
}

/// PEM as Kalkan's `CSRUtil.getPem`: 64-column base64, trailing newline.
pub fn pem(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE REQUEST-----\n");
    out
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natural_order_of_dn_oids() {
        let mut v = vec![
            "2.5.4.42", "2.5.4.6", "2.5.4.3", "2.5.4.5", "2.5.4.4", "2.5.4.11",
        ];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            v,
            ["2.5.4.3", "2.5.4.4", "2.5.4.5", "2.5.4.6", "2.5.4.11", "2.5.4.42"]
        );
    }

    #[test]
    fn generated_request_verifies() {
        let params = CsrParams {
            subject: vec![
                (ObjectIdentifier::new_unwrap("2.5.4.4"), "ТЕСТОВ".into()),
                (
                    ObjectIdentifier::new_unwrap("2.5.4.3"),
                    "ТЕСТОВ ТЕСТ".into(),
                ),
                (
                    ObjectIdentifier::new_unwrap("2.5.4.5"),
                    "IIN000000000000".into(),
                ),
                (ObjectIdentifier::new_unwrap("2.5.4.6"), "KZ".into()),
            ],
            email: Some("test@example.kz".into()),
            alt_names: vec![],
            keystore_path: "/tmp/keys".into(),
        };
        let g = generate(Gost2015Curve::A512, &params, &mut rand::rng()).unwrap();
        let pk = verify(&g.csr_der).unwrap();
        assert_eq!(pk, g.public);
        assert!(g
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----\nMII"));
        assert_eq!(g.key_id.len(), 20);
    }
}
