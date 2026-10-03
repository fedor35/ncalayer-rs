//! ncalayerd — NCALayer-compatible local signing daemon.
//!
//! Threading: with the `ui-slint` feature the main thread belongs to the Slint event loop
//! (Qt and winit both insist on it), while the tokio runtime that drives the wss server runs
//! on a second thread. Without the feature the server simply blocks the main thread, as before.
#![forbid(unsafe_code)]

mod ca;
mod cms_api;
mod keys;
mod server;

use anyhow::Result;
use clap::{Parser, Subcommand};
use nca_ui::Ui;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "ncalayerd",
    version,
    about = "Открытая замена NCALayer (wss://127.0.0.1:13579)"
)]
struct Cli {
    /// Каталог с CA и сертификатом сервера (по умолчанию ~/.local/share/ncalayer-rs)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Запустить сервер (по умолчанию)
    Run {
        /// Порт; оригинал слушает 13579 и умеет NCALAYERPORT
        #[arg(long, env = "NCALAYERPORT", default_value_t = 13579)]
        port: u16,
    },
    /// Создать локальный CA (если нет) и прописать его в NSS-базы Firefox/Chromium
    InstallCa,
    /// Показать пути и состояние сертификатов
    Status,
}

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ncalayerd=info".parse().expect("valid filter"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();
    let paths = ca::Paths::new(cli.data_dir)?;
    match cli.cmd.unwrap_or(Cmd::Run { port: 13579 }) {
        Cmd::Run { port } => run(port, &paths),
        Cmd::InstallCa => {
            ca::ensure(&paths)?;
            let report = ca::install_into_nss(&paths)?;
            println!("{report}");
            Ok(())
        }
        Cmd::Status => {
            println!("{}", ca::status(&paths)?);
            Ok(())
        }
    }
}

fn run(port: u16, paths: &ca::Paths) -> Result<()> {
    // Single instance / clash with the Java NCALayer: fail early with a human-readable message.
    if let Err(e) = std::net::TcpListener::bind(("127.0.0.1", port)) {
        let msg = format!(
            "Порт {port} уже занят ({e}). Вероятно, запущен другой экземпляр ncalayer-rs или оригинальный NCALayer — закройте его."
        );
        tracing::error!("{msg}");
        #[cfg(feature = "ui-slint")]
        {
            if let Ok(d) = nca_ui::DialogUi::detect() {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(d.error(&msg));
            }
        }
        anyhow::bail!("{msg}");
    }
    let certs = ca::ensure(paths)?;
    // Zero-configuration trust: browsers installed later, or new profiles, get the root on next start.
    let fixed = ca::install_missing_into_nss(paths);
    let settings_path = paths.dir.join("settings.json");
    let settings = nca_ui::Settings::load(&settings_path);
    let runtime = tokio::runtime::Runtime::new()?;

    if let Some(fixed) = nca_ui::FixedUi::from_env() {
        tracing::warn!("NCALAYER_TEST_KEY set: headless test UI, no dialogs");
        return runtime.block_on(server::run(port, certs, Arc::new(fixed), settings_path));
    }

    #[cfg(feature = "ui-slint")]
    {
        // Slint owns the main thread; the server lives on a tokio thread and reaches the UI
        // through `slint::invoke_from_event_loop` (see nca-ui-slint).
        let gui = nca_ui_slint::SlintUi::new(settings_path.clone(), port)?;
        gui.set_locale(settings.locale().code());
        let ui: Arc<dyn Ui> = Arc::new(gui.clone());
        if !fixed.is_empty() {
            let ui_n = ui.clone();
            let n = fixed.len();
            runtime.spawn(async move {
                ui_n.notify(
                    "ncalayer-rs готов",
                    &format!("Сертификат доверия установлен в {n} профил. браузера. Перезапустите браузер, если он был открыт."),
                )
                .await;
            });
        }
        std::thread::Builder::new()
            .name("tokio".into())
            .spawn(move || {
                if let Err(e) = runtime.block_on(server::run(port, certs, ui, settings_path)) {
                    tracing::error!("server stopped: {e:#}");
                }
                nca_ui_slint::quit();
            })?;
        gui.run(!settings.start_minimized)?;
        // The server thread is blocked in accept(); no graceful shutdown is needed.
        std::process::exit(0);
    }

    #[cfg(not(feature = "ui-slint"))]
    {
        let dialog = nca_ui::DialogUi::detect()?;
        dialog.set_locale(settings.locale().code());
        if !fixed.is_empty() {
            runtime.block_on(dialog.notify(
                "ncalayer-rs готов",
                "Сертификат доверия установлен в браузеры. Перезапустите браузер.",
            ));
        }
        runtime.block_on(server::run(port, certs, Arc::new(dialog), settings_path))
    }
}
