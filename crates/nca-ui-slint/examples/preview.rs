//! Shows every window of the frontend with sample data, for design work and screenshots:
//!
//! ```text
//! cargo run -p nca-ui-slint --example preview -- [ru|kk|en] [snapshot-dir]
//! ```
//!
//! With a snapshot directory the windows are rendered, written as PNG files and the program
//! exits; without it they stay open until closed.

use nca_ui_slint::generated::{ErrorDialog, KeyChooser, PasswordDialog, SettingsWindow};
use nca_ui_slint::texts_for;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let locale = args
        .next()
        .and_then(|a| nca_ui::Locale::parse(&a))
        .unwrap_or_default();
    let snapshot_dir = args.next();
    let origin = "https://egov.kz";
    let file = "GOST512_1234567890_abcdef.p12";

    let chooser = KeyChooser::new()?;
    chooser.set_t(texts_for(locale, origin, file));
    let recent = [
        "/home/user/keys/GOST512_1234567890_abcdef.p12",
        "/home/user/keys/RSA256_0987654321_fedcba.p12",
    ];
    chooser.set_recent(ModelRc::new(VecModel::from(
        recent
            .iter()
            .map(|p| slint::language::StandardListViewItem::from(SharedString::from(*p)))
            .collect::<Vec<_>>(),
    )));
    chooser.set_selected(0);
    chooser.show()?;

    let password = PasswordDialog::new()?;
    password.set_t(texts_for(locale, origin, file));
    password.set_origin(origin.into());
    password.set_retry(true);
    password.show()?;

    let error = ErrorDialog::new()?;
    error.set_t(texts_for(locale, origin, file));
    error.set_message(
        "Не удалось открыть GOST512_1234567890_abcdef.p12: файл повреждён (MAC не сходится)".into(),
    );
    error.show()?;

    let settings = SettingsWindow::new()?;
    settings.set_t(texts_for(locale, origin, file));
    settings.set_languages(ModelRc::new(VecModel::from(
        nca_ui::Locale::ALL
            .iter()
            .map(|l| SharedString::from(l.native_name()))
            .collect::<Vec<_>>(),
    )));
    settings.set_language_index(locale.index() as i32);
    settings.set_recent(ModelRc::new(VecModel::from(
        recent
            .iter()
            .map(|p| SharedString::from(*p))
            .collect::<Vec<_>>(),
    )));
    settings.set_status_line("ncalayer-rs 0.1.0 — https://127.0.0.1:13579/".into());
    settings.show()?;

    if let Some(dir) = snapshot_dir {
        let dir = Path::new(&dir).to_path_buf();
        std::fs::create_dir_all(&dir)?;
        // Give the compositor a moment to map the windows, then snapshot. The snapshot is
        // posted as a separate event: taking it inside the timer callback re-enters the
        // timer machinery on the Qt backend ("Recursion in timer code").
        let (c, p, e, s) = (
            chooser.as_weak(),
            password.as_weak(),
            error.as_weak(),
            settings.as_weak(),
        );
        slint::Timer::single_shot(std::time::Duration::from_millis(1500), move || {
            let (c, p, e, s, dir) = (c.clone(), p.clone(), e.clone(), s.clone(), dir.clone());
            let _ = slint::invoke_from_event_loop(move || {
                let windows = [
                    ("chooser", c.upgrade().map(|w| w.window().take_snapshot())),
                    ("password", p.upgrade().map(|w| w.window().take_snapshot())),
                    ("error", e.upgrade().map(|w| w.window().take_snapshot())),
                    ("settings", s.upgrade().map(|w| w.window().take_snapshot())),
                ];
                for (name, shot) in windows {
                    match shot {
                        Some(Ok(px)) => {
                            if let Err(e) = write_png(
                                &dir.join(format!("{name}.png")),
                                px.width(),
                                px.height(),
                                px.as_bytes(),
                            ) {
                                eprintln!("{name}: {e}");
                            }
                        }
                        Some(Err(e)) => eprintln!("{name}: snapshot failed: {e}"),
                        None => eprintln!("{name}: window gone"),
                    }
                }
                let _ = slint::quit_event_loop();
            });
        });
        slint::run_event_loop()?;
    } else {
        slint::run_event_loop()?;
    }
    Ok(())
}

fn write_png(path: &Path, w: u32, h: u32, rgba: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::File::create(path)?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(rgba)?;
    println!("wrote {}", path.display());
    Ok(())
}
