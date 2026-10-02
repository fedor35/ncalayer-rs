//! Key selection flow shared by every API: pick a PKCS#12 file, ask the password, open it,
//! choose the entry matching the requested key type. Mirrors what NCALayer's Swing dialog does,
//! including remembering the last used path (`recentPath` in the original settings.json).

use crate::ui::Ui;
use anyhow::Result;
use kz_pki::{Entry, KeyStore, KeyUsageType};
use nca_protocol::{KeyInfo, KeyType};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    #[serde(rename = "recentPath")]
    pub recent_path: Option<PathBuf>,
    pub locale: Option<String>,
}

impl Settings {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }
    pub fn save(&self, path: &Path) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, s);
        }
    }
}

pub enum Selection {
    Chosen(Entry),
    Cancelled,
}

const PASSWORD_ATTEMPTS: usize = 3;

/// Interactive selection. Only PKCS12 storage is supported in v1.
pub async fn select_entry(ui: &dyn Ui, settings_path: &Path, storage: &str, key_type: Option<KeyType>) -> Result<Selection> {
    if storage != "PKCS12" {
        anyhow::bail!("UNKNOWN_STORAGE");
    }
    let mut settings = Settings::load(settings_path);
    let start = settings.recent_path.as_deref().and_then(Path::parent);
    let Some(file) = ui.choose_key_file(start).await else {
        return Ok(Selection::Cancelled);
    };
    let bytes = std::fs::read(&file)?;
    let name = file.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let mut store = None;
    for attempt in 0..PASSWORD_ATTEMPTS {
        let prompt = if attempt == 0 { format!("Пароль от {name}") } else { format!("Неверный пароль. Пароль от {name}") };
        let Some(pw) = ui.ask_password("ncalayer-rs", &prompt).await else {
            return Ok(Selection::Cancelled);
        };
        match KeyStore::open(&bytes, &pw) {
            Ok(ks) => {
                store = Some(ks);
                break;
            }
            Err(kz_pki::Error::WrongPassword) => continue,
            Err(e) => {
                ui.error(&format!("Не удалось открыть {name}: {e}")).await;
                anyhow::bail!("KEYSTORE_FILE_NOT_FOUND");
            }
        }
    }
    let Some(store) = store else {
        return Ok(Selection::Cancelled);
    };
    settings.recent_path = Some(file.clone());
    settings.save(settings_path);

    let wanted = key_type.map(|k| match k {
        KeyType::Authentication => KeyUsageType::Authentication,
        KeyType::Signature => KeyUsageType::Signature,
    });
    let mut entries = store.entries;
    // Prefer an entry whose EKU matches; GOST-2015 keys carry both usages, so fall back to any.
    let idx = entries
        .iter()
        .position(|e| wanted.is_none_or(|w| e.cert.key_usage_type() == w || e.cert.extended_key_usage().map(|v| v.len() > 1).unwrap_or(false)))
        .or_else(|| (!entries.is_empty()).then_some(0));
    match idx {
        Some(i) => Ok(Selection::Chosen(entries.swap_remove(i))),
        None => {
            ui.error("В хранилище нет подходящих ключей").await;
            anyhow::bail!("EMPTY_KEY_LIST")
        }
    }
}

/// `responseObject` of `getKeyInfo`, field for field as the Java `KeyInfo` bean.
pub fn key_info(entry: &Entry) -> Result<KeyInfo> {
    let c = &entry.cert;
    Ok(KeyInfo {
        alias: entry.alias.clone(),
        key_id: entry.alias.clone(),
        algorithm: c.algorithm()?.to_string(),
        subject_cn: c.subject_cn().unwrap_or_default(),
        subject_dn: c.subject_dn(),
        issuer_cn: issuer_cn(c),
        issuer_dn: c.issuer_dn(),
        serial_number: c.serial_number(),
        cert_not_after: c.not_after_str()?,
        cert_not_before: c.not_before_str()?,
        authority_key_identifier: c.authority_key_identifier()?.unwrap_or_default(),
        pem: c.pem()?,
    })
}

fn issuer_cn(c: &kz_pki::Cert) -> String {
    c.issuer_dn()
        .split(',')
        .find_map(|rdn| rdn.strip_prefix("CN="))
        .unwrap_or_default()
        .to_string()
}
