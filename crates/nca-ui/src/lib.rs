//! User-interface boundary of `ncalayerd`.
//!
//! The daemon never talks to a toolkit directly: everything it needs from a user interface
//! is behind the [`Ui`] trait. Frontends live in their own crates (`nca-ui-slint`, …) and
//! implement it; this crate also carries the zero-dependency fallbacks:
//!
//! * [`DialogUi`] shells out to `kdialog` (KDE) or `zenity` (GTK);
//! * [`FixedUi`] is headless (`NCALAYER_TEST_KEY=<path>:<password>`) for tests and CI.
//!
//! Shared pieces every frontend needs are here too: the persisted [`Settings`]
//! (`settings.json`) and the [`i18n`] string table for ru/kk/en.
#![forbid(unsafe_code)]

pub mod i18n;
mod settings;

pub use i18n::{Locale, Strings};
pub use settings::{Settings, MAX_RECENT};

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tokio::process::Command;

/// Everything the daemon asks a frontend for. All methods are called from tokio tasks;
/// implementations that own a UI thread must hop onto it themselves.
#[async_trait]
pub trait Ui: Send + Sync {
    /// Switch the interface language (`ru`, `kk`, `en`); unknown codes are ignored.
    /// Called for `commonUtils.changeLocale` and when settings change.
    fn set_locale(&self, _locale: &str) {}

    /// Let the user pick a PKCS#12 container for the site `origin`.
    /// `recent` is the most-recently-used list (newest first). `None` = cancelled.
    async fn choose_key_file(&self, origin: &str, recent: &[PathBuf]) -> Option<PathBuf>;

    /// Generic file picker for `commonUtils.showFileChooser(ext, currentDir)`;
    /// `ext` is a comma-separated list like `"pdf,xml"` or `"ALL"`.
    async fn choose_file(&self, ext: &str, start_dir: Option<&Path>) -> Option<PathBuf>;

    /// Ask for the password of the container `file_name` requested by `origin`.
    /// `retry` is true after a wrong password. `None` = cancelled.
    async fn ask_password(&self, origin: &str, file_name: &str, retry: bool) -> Option<String>;

    /// Modal error; returns when the user dismissed it.
    async fn error(&self, text: &str);

    /// Non-blocking notification (tray / desktop).
    async fn notify(&self, title: &str, text: &str);
}

#[derive(Clone, Copy, Debug)]
enum Tool {
    Kdialog,
    Zenity,
}

/// `kdialog` / `zenity` backed implementation.
pub struct DialogUi {
    tool: Tool,
    locale: RwLock<Locale>,
}

impl DialogUi {
    /// Prefer kdialog on KDE sessions, otherwise whichever exists.
    pub fn detect() -> anyhow::Result<Self> {
        let has = |b: &str| which(b);
        let kde = std::env::var("XDG_CURRENT_DESKTOP")
            .map(|d| d.to_uppercase().contains("KDE"))
            .unwrap_or(false);
        let tool = match (has("kdialog"), has("zenity")) {
            (true, _) if kde => Tool::Kdialog,
            (_, true) => Tool::Zenity,
            (true, false) => Tool::Kdialog,
            _ => anyhow::bail!("ни kdialog, ни zenity не найдены — установите один из них"),
        };
        tracing::info!(?tool, "dialog backend");
        Ok(Self {
            tool,
            locale: RwLock::new(Locale::default()),
        })
    }

    fn strings(&self) -> &'static Strings {
        self.locale
            .read()
            .map(|l| l.strings())
            .unwrap_or_else(|_| Locale::default().strings())
    }

    async fn run(&self, args: &[&str]) -> Option<String> {
        let bin = match self.tool {
            Tool::Kdialog => "kdialog",
            Tool::Zenity => "zenity",
        };
        let out = Command::new(bin).args(args).output().await.ok()?;
        if !out.status.success() {
            return None; // cancelled
        }
        Some(
            String::from_utf8_lossy(&out.stdout)
                .trim_end_matches('\n')
                .to_string(),
        )
    }

    async fn pick(
        &self,
        title: &str,
        dir: &str,
        globs: &[String],
        filter_label: &str,
    ) -> Option<PathBuf> {
        let s = match self.tool {
            Tool::Kdialog => {
                let filter = format!("{}|{filter_label} ({})", globs.join(" "), globs.join(", "));
                self.run(&["--title", title, "--getopenfilename", dir, &filter])
                    .await?
            }
            Tool::Zenity => {
                let filename = format!("--filename={}/", dir.trim_end_matches('/'));
                let t = format!("--title={title}");
                let filter = format!("--file-filter={filter_label} | {}", globs.join(" "));
                self.run(&["--file-selection", &t, &filename, &filter])
                    .await?
            }
        };
        if s.is_empty() {
            None
        } else {
            Some(PathBuf::from(s))
        }
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// Turn `showFileChooser`'s `ext` argument into shell globs.
pub fn ext_globs(ext: &str) -> Vec<String> {
    if ext.trim().is_empty() || ext.eq_ignore_ascii_case("ALL") {
        vec!["*".into()]
    } else {
        ext.split(',')
            .map(|e| format!("*.{}", e.trim().trim_start_matches('.')))
            .collect()
    }
}

#[async_trait]
impl Ui for DialogUi {
    fn set_locale(&self, locale: &str) {
        if let Some(l) = Locale::parse(locale) {
            if let Ok(mut cur) = self.locale.write() {
                *cur = l;
            }
        }
    }

    async fn choose_key_file(&self, origin: &str, recent: &[PathBuf]) -> Option<PathBuf> {
        let s = self.strings();
        let dir = recent
            .first()
            .and_then(|p| p.parent())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~".into());
        let title = if origin.is_empty() {
            s.choose_key_title.to_string()
        } else {
            format!("{} — {}", s.choose_key_title, origin)
        };
        self.pick(
            &title,
            &dir,
            &["*.p12".into(), "*.pfx".into()],
            s.p12_filter,
        )
        .await
    }

    async fn choose_file(&self, ext: &str, start_dir: Option<&Path>) -> Option<PathBuf> {
        let s = self.strings();
        let dir = start_dir
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~".into());
        self.pick(s.choose_file_title, &dir, &ext_globs(ext), s.files_filter)
            .await
    }

    async fn ask_password(&self, origin: &str, file_name: &str, retry: bool) -> Option<String> {
        let s = self.strings();
        let mut prompt = s.password_prompt.replace("{file}", file_name);
        if retry {
            prompt = format!("{}. {prompt}", s.wrong_password);
        }
        let title = if origin.is_empty() {
            "ncalayer-rs".to_string()
        } else {
            format!("ncalayer-rs — {origin}")
        };
        match self.tool {
            Tool::Kdialog => self.run(&["--title", &title, "--password", &prompt]).await,
            Tool::Zenity => {
                let t = format!("--title={title}");
                let p = format!("--text={prompt}");
                self.run(&["--password", &t, &p]).await
            }
        }
    }

    async fn error(&self, text: &str) {
        match self.tool {
            Tool::Kdialog => self.run(&["--title", "ncalayer-rs", "--error", text]).await,
            Tool::Zenity => {
                self.run(&["--error", "--title=ncalayer-rs", &format!("--text={text}")])
                    .await
            }
        };
    }

    async fn notify(&self, title: &str, text: &str) {
        let _ = Command::new("notify-send")
            .args(["-a", "ncalayer-rs", title, text])
            .output()
            .await;
    }
}

/// Headless implementation for tests and CI: always "chooses" the given file and password.
/// Enabled with `NCALAYER_TEST_KEY=<path>:<password>`.
pub struct FixedUi {
    pub file: PathBuf,
    pub password: String,
}

impl FixedUi {
    /// Read `NCALAYER_TEST_KEY`; `None` when unset or malformed.
    pub fn from_env() -> Option<Self> {
        let v = std::env::var("NCALAYER_TEST_KEY").ok()?;
        let (file, password) = v.rsplit_once(':')?;
        Some(Self {
            file: PathBuf::from(file),
            password: password.to_string(),
        })
    }
}

#[async_trait]
impl Ui for FixedUi {
    async fn choose_key_file(&self, _origin: &str, _recent: &[PathBuf]) -> Option<PathBuf> {
        Some(self.file.clone())
    }
    async fn choose_file(&self, _ext: &str, _start_dir: Option<&Path>) -> Option<PathBuf> {
        Some(self.file.clone())
    }
    async fn ask_password(&self, _origin: &str, _file_name: &str, _retry: bool) -> Option<String> {
        Some(self.password.clone())
    }
    async fn error(&self, text: &str) {
        tracing::error!("ui error: {text}");
    }
    async fn notify(&self, title: &str, text: &str) {
        tracing::info!("notify: {title}: {text}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert_eq!(ext_globs("ALL"), vec!["*"]);
        assert_eq!(ext_globs(""), vec!["*"]);
        assert_eq!(ext_globs("pdf, .xml"), vec!["*.pdf", "*.xml"]);
    }
}
