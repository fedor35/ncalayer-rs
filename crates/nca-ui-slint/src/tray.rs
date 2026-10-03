//! StatusNotifierItem tray icon through `ksni` (native on Plasma; GNOME needs the
//! AppIndicator extension). The service runs on its own thread; menu actions hop to the
//! Slint thread with `invoke_from_event_loop`.

use crate::Shared;
use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};
use nca_ui::Locale;
use std::sync::{Arc, Weak};

pub(crate) type Handle = ksni::blocking::Handle<TrayIcon>;

static ICON_64: &[u8] = include_bytes!("../assets/ncalayer-rs-64.png");
static ICON_128: &[u8] = include_bytes!("../assets/ncalayer-rs-128.png");

pub(crate) struct TrayIcon {
    pub locale: Locale,
    shared: Weak<Shared>,
    icons: Vec<ksni::Icon>,
}

/// Register the item on the session bus. Fails when no StatusNotifierWatcher is running
/// (plain GNOME, headless); the daemon keeps working without a tray.
pub(crate) fn spawn(shared: Weak<Shared>) -> Result<Handle, ksni::Error> {
    let icons = [ICON_64, ICON_128]
        .iter()
        .filter_map(|png| decode_png(png))
        .collect();
    let locale = shared.upgrade().map(|s| s.locale()).unwrap_or_default();
    TrayIcon {
        locale,
        shared,
        icons,
    }
    .spawn()
}

/// PNG → ARGB32 in network byte order, as the SNI spec wants it.
fn decode_png(bytes: &[u8]) -> Option<ksni::Icon> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(bytes));
    decoder.set_transformations(
        png::Transformations::normalize_to_color8() | png::Transformations::ALPHA,
    );
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgba {
        return None;
    }
    let data = buf[..info.buffer_size()]
        .as_chunks::<4>()
        .0
        .iter()
        .flat_map(|px| [px[3], px[0], px[1], px[2]])
        .collect();
    Some(ksni::Icon {
        width: info.width as i32,
        height: info.height as i32,
        data,
    })
}

impl TrayIcon {
    fn on_ui(&self, f: impl FnOnce(Arc<Shared>) + Send + 'static) {
        if let Some(shared) = self.shared.upgrade() {
            let _ = slint::invoke_from_event_loop(move || f(shared));
        }
    }

    fn open_status_page(&self) {
        if let Some(shared) = self.shared.upgrade() {
            let url = shared.status_url();
            if let Err(e) = std::process::Command::new("xdg-open").arg(&url).spawn() {
                tracing::warn!("xdg-open {url}: {e}");
            }
        }
    }
}

impl ksni::Tray for TrayIcon {
    fn id(&self) -> String {
        "ncalayer-rs".into()
    }

    fn title(&self) -> String {
        "ncalayer-rs".into()
    }

    fn icon_name(&self) -> String {
        // Deliberately empty: XDG icon lookup falls back from "ncalayer-rs" to "ncalayer",
        // which on machines with the Java NCALayer installed is *its* icon. The embedded
        // pixmaps below are always ours.
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icons.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "ncalayer-rs".into(),
            description: self.locale.strings().tray_tooltip.into(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.on_ui(crate::show_settings);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let s = self.locale.strings();
        vec![
            StandardItem {
                label: s.tray_status_page.into(),
                icon_name: "internet-web-browser".into(),
                activate: Box::new(|t: &mut Self| t.open_status_page()),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: s.tray_settings.into(),
                icon_name: "configure".into(),
                activate: Box::new(|t: &mut Self| t.on_ui(crate::show_settings)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: s.tray_quit.into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| crate::quit()),
                ..Default::default()
            }
            .into(),
        ]
    }
}
