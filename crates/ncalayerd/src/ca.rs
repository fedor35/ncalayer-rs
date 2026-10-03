//! Local certificate authority, mkcert-style.
//!
//! The browser only lets an https page talk to `wss://127.0.0.1` when it trusts the server
//! certificate. The original NCALayer ships a certificate issued by the national CA; we instead
//! create a per-machine root (`ca.pem`/`ca.key`), issue a leaf for `127.0.0.1`/`localhost`
//! from it, and register the root in every NSS database we can find.

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::{Duration, OffsetDateTime};

pub const CA_NICKNAME: &str = "ncalayer-rs local CA";
const CA_VALID_YEARS: i64 = 10;
const LEAF_VALID_DAYS: i64 = 398; // browsers reject longer-lived leaves

pub struct Paths {
    pub dir: PathBuf,
}

impl Paths {
    pub fn new(override_dir: Option<PathBuf>) -> Result<Self> {
        let dir = match override_dir {
            Some(d) => d,
            None => directories::ProjectDirs::from("kz", "ncalayer-rs", "ncalayer-rs")
                .context("no home directory")?
                .data_dir()
                .to_path_buf(),
        };
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self { dir })
    }
    pub fn ca_cert(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }
    pub fn ca_key(&self) -> PathBuf {
        self.dir.join("ca.key")
    }
    pub fn server_cert(&self) -> PathBuf {
        self.dir.join("server.pem")
    }
    pub fn server_key(&self) -> PathBuf {
        self.dir.join("server.key")
    }
}

/// PEM material the TLS listener needs (leaf + chain, and the leaf key).
pub struct ServerCerts {
    pub cert_chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Create CA and leaf if missing (or leaf expired), return what the server needs.
pub fn ensure(paths: &Paths) -> Result<ServerCerts> {
    if !paths.ca_cert().exists() || !paths.ca_key().exists() {
        tracing::info!("creating local CA in {}", paths.dir.display());
        create_ca(paths)?;
        let _ = std::fs::remove_file(paths.server_cert());
    }
    if !paths.server_cert().exists() || leaf_expires_within(paths, Duration::days(30))? {
        tracing::info!("issuing server certificate for 127.0.0.1 / localhost");
        issue_leaf(paths)?;
    }
    Ok(ServerCerts {
        cert_chain_pem: std::fs::read(paths.server_cert())?,
        key_pem: std::fs::read(paths.server_key())?,
    })
}

fn create_ca(paths: &Paths) -> Result<()> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NICKNAME);
    dn.push(DnType::OrganizationName, "ncalayer-rs");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * CA_VALID_YEARS);
    let cert = params.self_signed(&key)?;
    write_private(&paths.ca_key(), key.serialize_pem().as_bytes())?;
    std::fs::write(paths.ca_cert(), cert.pem())?;
    Ok(())
}

fn load_ca(paths: &Paths) -> Result<Issuer<'static, KeyPair>> {
    let key = KeyPair::from_pem(&std::fs::read_to_string(paths.ca_key())?)?;
    let ca_pem = std::fs::read_to_string(paths.ca_cert())?;
    Ok(Issuer::from_ca_cert_pem(&ca_pem, key)?)
}

fn issue_leaf(paths: &Paths) -> Result<()> {
    let issuer = load_ca(paths)?;
    let key = KeyPair::generate()?;
    let mut params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "127.0.0.1");
    dn.push(DnType::OrganizationName, "ncalayer-rs");
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(LEAF_VALID_DAYS);
    let cert = params.signed_by(&key, &issuer)?;
    let mut chain = cert.pem();
    chain.push_str(&std::fs::read_to_string(paths.ca_cert())?);
    std::fs::write(paths.server_cert(), chain)?;
    write_private(&paths.server_key(), key.serialize_pem().as_bytes())?;
    Ok(())
}

/// `notAfter` of the first certificate in a PEM file.
fn pem_not_after(path: &Path) -> Result<OffsetDateTime> {
    let pem = std::fs::read(path)?;
    let (_, block) = x509_parser::pem::parse_x509_pem(&pem).map_err(|e| anyhow::anyhow!("{e}"))?;
    let cert = block.parse_x509().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

fn leaf_not_after(paths: &Paths) -> Result<OffsetDateTime> {
    pem_not_after(&paths.server_cert())
}

fn leaf_expires_within(paths: &Paths, window: Duration) -> Result<bool> {
    Ok(leaf_not_after(paths)? <= OffsetDateTime::now_utc() + window)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

/// NSS databases browsers keep in the home directory.
pub fn nss_databases() -> Vec<PathBuf> {
    let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) else {
        return vec![];
    };
    let mut out = vec![];
    // Firefox-family profiles: <root>/<profile>/cert9.db
    for root in [
        ".mozilla/firefox",
        ".librewolf",
        ".waterfox",
        ".thunderbird",
        "snap/firefox/common/.mozilla/firefox",
        ".var/app/org.mozilla.firefox/.mozilla/firefox",
    ] {
        if let Ok(rd) = std::fs::read_dir(home.join(root)) {
            for e in rd.flatten() {
                if e.path().join("cert9.db").exists() {
                    out.push(e.path());
                }
            }
        }
    }
    // Chromium family shares ~/.pki/nssdb
    if home.join(".pki/nssdb/cert9.db").exists() {
        out.push(home.join(".pki/nssdb"));
    }
    out
}

/// Is our root already trusted in this NSS database?
fn nss_has_ca(db: &Path) -> bool {
    Command::new("certutil")
        .args(["-L", "-n", CA_NICKNAME, "-d"])
        .arg(format!("sql:{}", db.display()))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Idempotent start-up step: add the root to every browser profile that lacks it.
/// Returns the databases that were just fixed (the user must restart those browsers).
pub fn install_missing_into_nss(paths: &Paths) -> Vec<PathBuf> {
    if Command::new("certutil").arg("-H").output().is_err() {
        tracing::warn!(
            "certutil не найден — корень CA в браузеры не установлен (пакет nss / libnss3-tools)"
        );
        return vec![];
    }
    let mut fixed = vec![];
    for db in nss_databases() {
        if nss_has_ca(&db) {
            continue;
        }
        let out = Command::new("certutil")
            .args(["-A", "-n", CA_NICKNAME, "-t", "C,,", "-i"])
            .arg(paths.ca_cert())
            .arg("-d")
            .arg(format!("sql:{}", db.display()))
            .output();
        match out {
            Ok(o) if o.status.success() => {
                tracing::info!("CA installed into {}", db.display());
                fixed.push(db);
            }
            Ok(o) => tracing::warn!(
                "certutil {}: {}",
                db.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => tracing::warn!("certutil: {e}"),
        }
    }
    fixed
}

/// Register the local root as a trusted TLS CA in every NSS db found. Needs `certutil` (nss).
pub fn install_into_nss(paths: &Paths) -> Result<String> {
    if Command::new("certutil").arg("-H").output().is_err() {
        bail!("certutil не найден: установите пакет nss (Arch) / libnss3-tools (Debian)");
    }
    let dbs = nss_databases();
    let mut report = String::new();
    if dbs.is_empty() {
        writeln!(report, "NSS-базы не найдены (браузер ещё не запускался?)")?;
    }
    for db in dbs {
        // Replace an older copy of our root first, so re-running after CA rotation works.
        let _ = Command::new("certutil")
            .args(["-D", "-n", CA_NICKNAME, "-d"])
            .arg(format!("sql:{}", db.display()))
            .output();
        let out = Command::new("certutil")
            .args(["-A", "-n", CA_NICKNAME, "-t", "C,,", "-i"])
            .arg(paths.ca_cert())
            .arg("-d")
            .arg(format!("sql:{}", db.display()))
            .output()?;
        if out.status.success() {
            writeln!(report, "✓ {}", db.display())?;
        } else {
            writeln!(
                report,
                "✗ {}: {}",
                db.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )?;
        }
    }
    writeln!(
        report,
        "Перезапустите браузер, чтобы доверие вступило в силу."
    )?;
    Ok(report)
}

pub fn status(paths: &Paths) -> Result<String> {
    let mut s = String::new();
    writeln!(s, "data dir: {}", paths.dir.display())?;
    writeln!(
        s,
        "CA: {}",
        if paths.ca_cert().exists() {
            paths.ca_cert().display().to_string()
        } else {
            "нет".into()
        }
    )?;
    if paths.server_cert().exists() {
        writeln!(
            s,
            "server: {} (до {})",
            paths.server_cert().display(),
            leaf_not_after(paths)?.date()
        )?;
    } else {
        writeln!(s, "server: нет")?;
    }
    for db in nss_databases() {
        let out = Command::new("certutil")
            .args(["-L", "-n", CA_NICKNAME, "-d"])
            .arg(format!("sql:{}", db.display()))
            .output();
        let trusted = matches!(out, Ok(o) if o.status.success());
        writeln!(s, "{} {}", if trusted { "✓" } else { "✗" }, db.display())?;
    }
    Ok(s)
}
