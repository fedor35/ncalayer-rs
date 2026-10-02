//! ncalayerd — NCALayer-compatible local signing daemon.
#![forbid(unsafe_code)]

mod ca;
mod cms_api;
mod keys;
mod server;
mod ui;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ncalayerd", version, about = "Открытая замена NCALayer (wss://127.0.0.1:13579)")]
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("ncalayerd=info".parse()?))
        .init();
    let cli = Cli::parse();
    let paths = ca::Paths::new(cli.data_dir)?;
    match cli.cmd.unwrap_or(Cmd::Run { port: 13579 }) {
        Cmd::Run { port } => {
            let certs = ca::ensure(&paths)?;
            let ui: std::sync::Arc<dyn ui::Ui> = match ui::FixedUi::from_env() {
                Some(fixed) => {
                    tracing::warn!("NCALAYER_TEST_KEY set: headless test UI, no dialogs");
                    std::sync::Arc::new(fixed)
                }
                None => std::sync::Arc::new(ui::DialogUi::detect()?),
            };
            server::run(port, certs, ui, paths.dir.join("settings.json")).await
        }
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
