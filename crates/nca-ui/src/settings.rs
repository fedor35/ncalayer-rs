//! `settings.json` in the data directory. Field names follow the original NCALayer where it
//! had an equivalent (`recentPath`), so an existing file is picked up on first run.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How many recently used containers are remembered.
pub const MAX_RECENT: usize = 10;

/// Persisted user preferences.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// Recently used PKCS#12 containers, newest first, at most [`MAX_RECENT`].
    pub recent: Vec<PathBuf>,
    /// Legacy single entry of the original NCALayer; migrated into `recent` on load.
    #[serde(rename = "recentPath", skip_serializing_if = "Option::is_none")]
    pub recent_path: Option<PathBuf>,
    /// Interface language: `ru`, `kk` or `en`.
    pub locale: Option<String>,
    /// Do not show the main window at start-up; only the tray icon.
    #[serde(rename = "startMinimized")]
    pub start_minimized: bool,
}

impl Settings {
    /// Read the file; a missing or broken file yields defaults.
    pub fn load(path: &Path) -> Self {
        let mut s: Self = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if let Some(p) = s.recent_path.take() {
            if !s.recent.contains(&p) {
                s.recent.push(p);
            }
        }
        s.recent.truncate(MAX_RECENT);
        s
    }

    /// Write the file (errors are ignored: settings are a convenience, not state).
    pub fn save(&self, path: &Path) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, s);
        }
    }

    /// Move `path` to the front of the recent list, deduplicated and capped.
    pub fn push_recent(&mut self, path: PathBuf) {
        self.recent.retain(|p| *p != path);
        self.recent.insert(0, path);
        self.recent.truncate(MAX_RECENT);
    }

    /// Forget one entry.
    pub fn remove_recent(&mut self, path: &Path) {
        self.recent.retain(|p| p != path);
    }

    /// Parsed locale, defaulting to Russian.
    pub fn locale(&self) -> crate::Locale {
        self.locale
            .as_deref()
            .and_then(crate::Locale::parse)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Locale;

    #[test]
    fn recent_is_deduplicated_and_capped() {
        let mut s = Settings::default();
        for i in 0..15 {
            s.push_recent(PathBuf::from(format!("/k/{i}.p12")));
        }
        s.push_recent(PathBuf::from("/k/14.p12"));
        s.push_recent(PathBuf::from("/k/7.p12"));
        assert_eq!(s.recent.len(), MAX_RECENT);
        assert_eq!(s.recent[0], PathBuf::from("/k/7.p12"));
        assert_eq!(s.recent[1], PathBuf::from("/k/14.p12"));
        assert_eq!(
            s.recent
                .iter()
                .filter(|p| p.as_path() == Path::new("/k/7.p12"))
                .count(),
            1
        );
    }

    #[test]
    fn legacy_recent_path_is_migrated() {
        let dir = std::env::temp_dir().join(format!("nca-ui-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.json");
        std::fs::write(&file, r#"{"recentPath":"/old/key.p12","locale":"kk"}"#).unwrap();
        let s = Settings::load(&file);
        assert_eq!(s.recent, vec![PathBuf::from("/old/key.p12")]);
        assert_eq!(s.locale(), Locale::Kk);
        s.save(&file);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(!text.contains("recentPath"));
        assert_eq!(Settings::load(&file), s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
