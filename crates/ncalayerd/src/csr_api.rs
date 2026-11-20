//! `basics.generateCsr` / `basics.importCertificate` for file storage (PKCS12), as NCALayer's
//! `PKIEssentials` + `KeyStoreUtil` do it:
//!
//! 1. `generateCsr`: a new GOST R 34.10-2015 (512) key goes into
//!    `<folder>/GOST512_<keyId>.p12`, protected with the site's `defaultPassword`, holding only
//!    the key (alias and `localKeyId` = key id); the request carries the folder in the NCA
//!    `keystore_branch` extension. The site gets `{pems: [...]}`.
//! 2. The NCA issues the certificate; the site calls `importCertificate` with it. The key file
//!    is found in the folder by the alias (= the certificate's SubjectKeyIdentifier), the
//!    certificate is added and the container is re-saved under the password the user chose.

use anyhow::{anyhow, bail, Context, Result};
use der::asn1::ObjectIdentifier;
use kz_cms::csr::{self, CsrParams};
use kz_pki::{Cert, Gost2015Curve, PrivateKey, RawCert, RawStore};
use std::path::{Path, PathBuf};

/// Signature algorithm NCALayer accepts for file key generation that we implement.
pub const GOST512_SIGNATURE: &str = "1.2.398.3.10.1.1.2.3.2";

/// `args.dn` (`{"2.5.4.3": "ИВАНОВ ИВАН", …}`) → subject attributes.
pub fn subject_from_json(
    dn: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<(ObjectIdentifier, String)>> {
    dn.iter()
        .map(|(k, v)| {
            let o = ObjectIdentifier::new(k).map_err(|e| anyhow!("dn: bad OID {k}: {e}"))?;
            let v = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            Ok((o, v))
        })
        .collect()
}

/// Lowercase hex, like Kalkan's `Hex.encodeStr`.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Generate a key and request into `folder`. Returns the PEM and the key file path.
pub fn generate(
    folder: &Path,
    default_password: &str,
    algorithm: &str,
    length: u32,
    subject: Vec<(ObjectIdentifier, String)>,
    email: Option<String>,
    alt_names: Vec<String>,
) -> Result<(String, PathBuf)> {
    if algorithm != GOST512_SIGNATURE || length != 512 {
        bail!("UNKNOWN_ALGORITHM: {algorithm}/{length} (поддерживается ГОСТ 34.10-2015 512)");
    }
    if !folder.is_dir() {
        bail!("{} — не папка", folder.display());
    }
    if default_password.is_empty() {
        bail!("defaultPassword пуст");
    }
    let params = CsrParams {
        subject,
        email,
        alt_names,
        keystore_path: folder.to_string_lossy().into_owned(),
    };
    let mut rng = rand::rng();
    let g = csr::generate(Gost2015Curve::A512, &params, &mut rng)?;
    csr::verify(&g.csr_der).context("self-check of the new request")?;
    let alias = hex(&g.key_id);
    let pkcs8 = g.key.to_pkcs8_der()?;
    let bytes = kz_pki::pkcs12::write(
        &[kz_pki::RawKey {
            friendly_name: Some(alias.clone()),
            local_key_id: Some(g.key_id.clone()),
            pkcs8,
        }],
        &[],
        default_password,
        &mut rng,
    )?;
    let path = folder.join(format!("GOST512_{alias}.p12"));
    write_new(&path, &bytes)?;
    // Read back: the container must open with the default password and hold this key.
    let back = kz_pki::pkcs12::open_raw(&std::fs::read(&path)?, default_password)?;
    let ok = back.keys.len() == 1
        && PrivateKey::from_pkcs8_der(&back.keys[0].pkcs8)
            .map(|k| matches!((&k, &g.key), (PrivateKey::Gost2015 { d: a, .. }, PrivateKey::Gost2015 { d: b, .. }) if a == b))
            .unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(&path);
        bail!("key file self-check failed");
    }
    tracing::info!(path = %path.display(), key_id = %alias, "generated key and CSR");
    Ok((g.csr_pem, path))
}

/// NCALayer's rules for the new container password (ImportCertStage + KeyStoreUtil):
/// 6–32 characters from `[0-9a-zA-Z.?#$^+=!*()@%&_-]`, with an upper-case and a lower-case
/// Latin letter and a digit.
pub fn check_new_password(pw: &str) -> Result<(), &'static str> {
    const EXTRA: &str = ".?#$^+=!*()@%&_-";
    let n = pw.chars().count();
    if !(6..=32).contains(&n) {
        return Err("Пароль: от 6 до 32 символов");
    }
    if !pw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || EXTRA.contains(c))
    {
        return Err("Пароль: только латинские буквы, цифры и .?#$^+=!*()@%&_-");
    }
    if !pw.chars().any(|c| c.is_ascii_uppercase())
        || !pw.chars().any(|c| c.is_ascii_lowercase())
        || !pw.chars().any(|c| c.is_ascii_digit())
    {
        return Err("Пароль должен содержать заглавную и строчную латинскую букву и цифру");
    }
    Ok(())
}

/// Parse a certificate given as PEM or base64 DER (what `X509Util.getX509Certificate` accepts).
pub fn parse_cert(s: &str) -> Result<Cert> {
    let t = s.trim();
    if t.starts_with("-----BEGIN") {
        return Ok(Cert::from_pem(t)?);
    }
    let der = crate::cms_api::decode_b64(&t.replace(['\r', '\n'], ""))?;
    Ok(Cert::from_der(&der)?)
}

/// Import `certs` into the matching key files under `folder` and re-protect them with
/// `new_password`. Returns the updated files.
pub fn import(
    folder: &Path,
    default_password: &str,
    certs: &[Cert],
    new_password: &str,
) -> Result<Vec<PathBuf>> {
    check_new_password(new_password).map_err(|e| anyhow!("WRONG_PASSWORD_PATTERN: {e}"))?;
    let mut done: Vec<PathBuf> = Vec::new();
    let mut rng = rand::rng();
    for cert in certs {
        let ski = match cert.subject_key_identifier()? {
            Some(k) => k,
            None => bail!("EXTENSION_NOT_FOUND: в сертификате нет «Идентификатора ключа субъекта»"),
        };
        let alias = hex(&ski);
        if let Some(o) = cert.keystore_oid()? {
            if o != kz_cms::csr::KEYSTORE_PKCS12 {
                bail!("UNSUITED_STORAGE: хранилище ключей не соответствует указанному в сертификате ({o})");
            }
        }
        // Files already re-saved in this call are protected with the new password.
        let (path, mut store, _pw) =
            find_key_file(folder, &alias, &ski, &[default_password, new_password]).with_context(
                || {
                    format!(
                        "KEYSTORE_FILE_NOT_FOUND: в «{}» нет файла с ключом {alias}",
                        folder.display()
                    )
                },
            )?;
        let ki = store
            .keys
            .iter()
            .position(|k| key_matches(k, &alias, &ski))
            .expect("find_key_file checked");
        // The key must belong to the certificate (Kalkan: INAPPROPRIATE_CERT).
        let key = PrivateKey::from_pkcs8_der(&store.keys[ki].pkcs8)?;
        let cert_pub = cert.public_key()?;
        if !public_matches(&key, &cert_pub)? {
            bail!(
                "INAPPROPRIATE_CERT: ключ в {} не соответствует сертификату",
                path.display()
            );
        }
        let lkid = store.keys[ki]
            .local_key_id
            .clone()
            .unwrap_or_else(|| ski.clone());
        store.certs.retain(|c| c.der != cert.as_der());
        store.certs.push(RawCert {
            friendly_name: Some(alias.clone()),
            local_key_id: Some(lkid),
            der: cert.as_der().to_vec(),
        });
        let bytes = kz_pki::pkcs12::write(&store.keys, &store.certs, new_password, &mut rng)?;
        replace(&path, &bytes)?;
        // Must now open as a normal key store with the new password.
        kz_pki::KeyStore::open(&std::fs::read(&path)?, new_password)
            .context("re-open after import")?;
        tracing::info!(path = %path.display(), alias = %alias, "certificate imported");
        if !done.contains(&path) {
            done.push(path);
        }
    }
    Ok(done)
}

fn key_matches(k: &kz_pki::RawKey, alias: &str, ski: &[u8]) -> bool {
    k.friendly_name
        .as_deref()
        .is_some_and(|n| n.eq_ignore_ascii_case(alias))
        || k.local_key_id.as_deref() == Some(ski)
}

fn find_key_file(
    folder: &Path,
    alias: &str,
    ski: &[u8],
    passwords: &[&str],
) -> Result<(PathBuf, RawStore, String)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(folder)
        .with_context(|| folder.display().to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("p12"))
        })
        .collect();
    files.sort();
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else {
            continue;
        };
        for pw in passwords {
            match kz_pki::pkcs12::open_raw(&bytes, pw) {
                Ok(store) if store.keys.iter().any(|k| key_matches(k, alias, ski)) => {
                    return Ok((f, store, pw.to_string()))
                }
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }
    bail!("not found")
}

fn public_matches(key: &PrivateKey, cert_pub: &kz_pki::PublicKey) -> Result<bool> {
    let PrivateKey::Gost2015 { curve, d } = key else {
        bail!("ожидался ключ ГОСТ 2015");
    };
    let named = match curve {
        Gost2015Curve::A512 => gost3410::NamedCurve::Tc26Gost3410_12_512ParamSetA,
        Gost2015Curve::A256 => gost3410::NamedCurve::Tc26Gost3410_2012_256ParamSetA,
    };
    let c = named.curve();
    let sk = gost3410::SecretKey::from_bytes_be(c, d).map_err(|e| anyhow!("{e}"))?;
    let xy = sk.public_key(c).to_bytes_x509(c);
    let len = curve.scalar_len();
    let be = |s: &[u8]| s.iter().rev().copied().collect::<Vec<u8>>();
    Ok(*cert_pub
        == kz_pki::PublicKey::Gost2015 {
            curve: *curve,
            x: be(&xy[..len]),
            y: be(&xy[len..2 * len]),
        })
}

/// Create a new file, refusing to overwrite.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| path.display().to_string())?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replace a file atomically (temp file in the same folder + rename).
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("p12.tmp");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, bytes)?;
    std::fs::rename(&tmp, path).with_context(|| path.display().to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_rules() {
        assert!(check_new_password("Test1234").is_ok());
        assert!(check_new_password("test1234").is_err());
        assert!(check_new_password("TEST1234").is_err());
        assert!(check_new_password("Testtest").is_err());
        assert!(check_new_password("Te1").is_err());
        assert!(check_new_password("Тест1234Aa").is_err());
        assert!(check_new_password("Ab1.?#$^+=!*()@%&_-").is_ok());
    }
}
