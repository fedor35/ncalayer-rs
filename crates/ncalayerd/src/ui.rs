//! The daemon never talks to a toolkit directly: everything it needs from a user interface
//! is behind [`Ui`]. Frontends (Slint, syngui, …) implement it; [`DialogUi`] is the
//! zero-dependency fallback that shells out to `kdialog` (KDE) or `zenity` (GTK), which already
//! gives native-looking dialogs on Plasma today.

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[async_trait]
pub trait Ui: Send + Sync {
    /// Let the user pick a PKCS#12 file. `None` = cancelled.
    async fn choose_key_file(&self, start_dir: Option<&Path>) -> Option<PathBuf>;
    /// Ask for the container password. `None` = cancelled.
    async fn ask_password(&self, title: &str, prompt: &str) -> Option<String>;
    /// Modal error.
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
}

impl DialogUi {
    /// Prefer kdialog on KDE sessions, otherwise whichever exists.
    pub fn detect() -> anyhow::Result<Self> {
        let has = |b: &str| which(b);
        let kde = std::env::var("XDG_CURRENT_DESKTOP").map(|d| d.to_uppercase().contains("KDE")).unwrap_or(false);
        let tool = match (has("kdialog"), has("zenity")) {
            (true, _) if kde => Tool::Kdialog,
            (_, true) => Tool::Zenity,
            (true, false) => Tool::Kdialog,
            _ => anyhow::bail!("ни kdialog, ни zenity не найдены — установите один из них"),
        };
        tracing::info!(?tool, "dialog backend");
        Ok(Self { tool })
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
        Some(String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string())
    }
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

#[async_trait]
impl Ui for DialogUi {
    async fn choose_key_file(&self, start_dir: Option<&Path>) -> Option<PathBuf> {
        let dir = start_dir.map(|p| p.display().to_string()).unwrap_or_else(|| "~".into());
        let s = match self.tool {
            Tool::Kdialog => {
                self.run(&["--title", "Выберите ключ ЭЦП", "--getopenfilename", &dir, "*.p12 *.pfx|Хранилище PKCS#12 (*.p12)"]).await?
            }
            Tool::Zenity => {
                let filename = format!("--filename={}/", dir.trim_end_matches('/'));
                self.run(&["--file-selection", "--title=Выберите ключ ЭЦП", &filename, "--file-filter=Хранилище PKCS#12 | *.p12 *.pfx"]).await?
            }
        };
        if s.is_empty() { None } else { Some(PathBuf::from(s)) }
    }

    async fn ask_password(&self, title: &str, prompt: &str) -> Option<String> {
        match self.tool {
            Tool::Kdialog => self.run(&["--title", title, "--password", prompt]).await,
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
            Tool::Zenity => self.run(&["--error", "--title=ncalayer-rs", &format!("--text={text}")]).await,
        };
    }

    async fn notify(&self, title: &str, text: &str) {
        let _ = Command::new("notify-send").args(["-a", "ncalayer-rs", title, text]).output().await;
    }
}

/// Headless implementation for tests and CI: always "chooses" the given file and password.
/// Enabled with `NCALAYER_TEST_KEY=<path>:<password>`.
pub struct FixedUi {
    pub file: PathBuf,
    pub password: String,
}

impl FixedUi {
    pub fn from_env() -> Option<Self> {
        let v = std::env::var("NCALAYER_TEST_KEY").ok()?;
        let (file, password) = v.rsplit_once(':')?;
        Some(Self { file: PathBuf::from(file), password: password.to_string() })
    }
}

#[async_trait]
impl Ui for FixedUi {
    async fn choose_key_file(&self, _start_dir: Option<&Path>) -> Option<PathBuf> {
        Some(self.file.clone())
    }
    async fn ask_password(&self, _title: &str, _prompt: &str) -> Option<String> {
        Some(self.password.clone())
    }
    async fn error(&self, text: &str) {
        tracing::error!("ui error: {text}");
    }
    async fn notify(&self, title: &str, text: &str) {
        tracing::info!("notify: {title}: {text}");
    }
}
