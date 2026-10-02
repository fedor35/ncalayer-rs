//! Slint frontend for `ncalayerd`: key chooser, password prompt, error box, settings window,
//! a StatusNotifierItem tray icon ([`tray`]) and desktop notifications.
//!
//! # Threads
//!
//! Slint (Qt or winit underneath) must own the main thread and its event loop; the daemon's
//! tokio runtime lives on another thread. Every [`Ui`] method is therefore a small bridge:
//! the tokio side creates a [`tokio::sync::oneshot`] channel, ships a closure to the UI thread
//! with [`slint::invoke_from_event_loop`], the closure builds a window whose callbacks answer
//! through the channel, and the tokio task awaits the receiver. Dropping the window (the user
//! closed it from the window manager) drops the sender, which the caller reads as "cancelled".
//!
//! Usage: [`SlintUi::new`] on the main thread, hand a clone to the server, then [`SlintUi::run`]
//! blocks the main thread in the event loop until [`quit`] is called.
// `forbid` is impossible here: the code Slint generates from `ui/app.slint` carries its own
// `allow(unsafe_code)` for item vtables. Hand-written code stays unsafe-free.
#![deny(unsafe_code)]

mod files;
mod tray;

/// Components compiled from `ui/app.slint` by `build.rs`. Public only for
/// `examples/preview.rs`; not part of the stable API.
#[doc(hidden)]
#[allow(unsafe_code, clippy::all)]
pub mod generated {
    slint::include_modules!();
}
use generated::{ErrorDialog, KeyChooser, PasswordDialog, SettingsWindow, Texts};

/// Fill a [`Texts`] table for `locale`; `origin`/`file` are substituted into the templates.
#[doc(hidden)]
pub fn texts_for(locale: Locale, origin: &str, file: &str) -> Texts {
    texts(locale.strings(), origin, file)
}

use async_trait::async_trait;
use nca_ui::{Locale, Settings, Strings, Ui};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// Stop the Slint event loop; [`SlintUi::run`] then returns. Safe from any thread.
pub fn quit() {
    let _ = slint::quit_event_loop();
}

/// The frontend handle. Cheap to clone; all clones share one state.
#[derive(Clone)]
pub struct SlintUi {
    shared: Arc<Shared>,
}

pub(crate) struct Shared {
    settings_path: PathBuf,
    port: u16,
    locale: Mutex<Locale>,
    tray: Mutex<Option<Arc<tray::Handle>>>,
}

impl Shared {
    pub(crate) fn locale(&self) -> Locale {
        self.locale.lock().map(|l| *l).unwrap_or_default()
    }

    fn strings(&self) -> &'static Strings {
        self.locale().strings()
    }

    /// Switch language everywhere (dialogs read it on creation; the tray is told explicitly).
    pub(crate) fn set_locale(&self, locale: Locale) {
        if let Ok(mut l) = self.locale.lock() {
            *l = locale;
        }
        let handle = self.tray.lock().ok().and_then(|t| t.clone());
        if let Some(h) = handle {
            // `blocking::Handle::update` drives its own runtime; it must not run on a tokio
            // worker ("Cannot start a runtime from within a runtime"), so hop off the caller.
            std::thread::spawn(move || {
                h.update(|t| t.locale = locale);
            });
        }
    }

    pub(crate) fn status_url(&self) -> String {
        format!("https://127.0.0.1:{}/", self.port)
    }
}

impl SlintUi {
    /// Initialise the toolkit on the *current* thread (must be the main thread) and show the
    /// tray icon. The event loop is not started yet; call [`SlintUi::run`] for that.
    pub fn new(settings_path: PathBuf, port: u16) -> anyhow::Result<Self> {
        // Creating the backend here, before any other thread touches Slint, pins the Qt/winit
        // event loop to this thread and installs the event-loop proxy that
        // `invoke_from_event_loop` needs (the proxy exists only once a platform is selected).
        // The default choice is Qt when it was found at build time, winit otherwise;
        // `SLINT_BACKEND=winit` overrides.
        // Wayland app_id = name of the .desktop file, so the shell can show the right icon.
        let _ = slint::set_xdg_app_id("ncalayer-rs");
        slint::BackendSelector::new()
            .select()
            .map_err(|e| anyhow::anyhow!("Slint backend: {e}"))?;
        let shared = Arc::new(Shared {
            settings_path,
            port,
            locale: Mutex::new(Locale::default()),
            tray: Mutex::new(None),
        });
        match tray::spawn(Arc::downgrade(&shared)) {
            Ok(h) => {
                if let Ok(mut t) = shared.tray.lock() {
                    *t = Some(Arc::new(h));
                }
            }
            Err(e) => tracing::warn!("no system tray (StatusNotifierItem): {e}"),
        }
        Ok(Self { shared })
    }

    /// Run the event loop on this thread until [`quit`]. `show_window` opens the settings window
    /// first (the "start minimised" preference is the caller's).
    pub fn run(&self, show_window: bool) -> anyhow::Result<()> {
        if show_window {
            let shared = self.shared.clone();
            let _ = slint::invoke_from_event_loop(move || show_settings(shared));
        }
        slint::run_event_loop_until_quit().map_err(|e| anyhow::anyhow!("Slint event loop: {e}"))
    }
}

/// One-shot reply handle usable from several `Fn` callbacks of a window.
struct Reply<T>(Rc<RefCell<Option<oneshot::Sender<T>>>>);

impl<T> Clone for Reply<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Reply<T> {
    fn new(tx: oneshot::Sender<T>) -> Self {
        Self(Rc::new(RefCell::new(Some(tx))))
    }
    fn send(&self, value: T) {
        if let Some(tx) = self.0.borrow_mut().take() {
            let _ = tx.send(value);
        }
    }
}

/// Run `build` on the UI thread and wait for the answer. `None` when the window was closed
/// without answering or the event loop is gone.
async fn on_ui<T: Send + 'static>(
    build: impl FnOnce(Reply<T>) -> Result<(), slint::PlatformError> + Send + 'static,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    slint::invoke_from_event_loop(move || {
        if let Err(e) = build(Reply::new(tx)) {
            tracing::error!("cannot create window: {e}");
        }
    })
    .ok()?;
    rx.await.ok()
}

fn hide<C: ComponentHandle + 'static>(w: &slint::Weak<C>) {
    if let Some(w) = w.upgrade() {
        let _ = w.hide();
    }
}

fn texts(s: &Strings, origin: &str, file: &str) -> Texts {
    let origin_line = if origin.is_empty() {
        s.choose_key_title.to_string()
    } else {
        s.choose_key_for.replace("{origin}", origin)
    };
    Texts {
        title: s.choose_key_title.into(),
        origin_line: origin_line.into(),
        recent: s.recent_containers.into(),
        no_recent: s.no_recent.into(),
        open_file: s.open_file.into(),
        cancel: s.cancel.into(),
        select: s.select.into(),
        ok: s.ok.into(),
        close: s.close.into(),
        password_title: s.password_title.into(),
        password_prompt: s.password_prompt.replace("{file}", file).into(),
        wrong_password: s.wrong_password.into(),
        show_password: s.show_password.into(),
        error_title: s.error_title.into(),
        settings_title: s.settings_title.into(),
        language: s.language.into(),
        recent_keys: s.recent_keys.into(),
        remove: s.remove.into(),
        start_minimized: s.start_minimized.into(),
    }
}

enum KeyChoice {
    Recent(usize),
    Browse,
    Cancel,
}

#[async_trait]
impl Ui for SlintUi {
    fn set_locale(&self, locale: &str) {
        if let Some(l) = Locale::parse(locale) {
            self.shared.set_locale(l);
        }
    }

    async fn choose_key_file(&self, origin: &str, recent: &[PathBuf]) -> Option<PathBuf> {
        let locale = self.shared.locale();
        let s = locale.strings();
        loop {
            let origin = origin.to_string();
            let items: Vec<slint::language::StandardListViewItem> = recent
                .iter()
                .map(|p| {
                    slint::language::StandardListViewItem::from(SharedString::from(
                        p.display().to_string(),
                    ))
                })
                .collect();
            let choice = on_ui(move |reply: Reply<KeyChoice>| {
                let w = KeyChooser::new()?;
                w.set_t(texts(s, &origin, ""));
                w.set_recent(ModelRc::new(VecModel::from(items)));
                let weak = w.as_weak();
                let r = reply.clone();
                w.on_confirm(move |i| {
                    r.send(KeyChoice::Recent(i.max(0) as usize));
                    hide(&weak);
                });
                let weak = w.as_weak();
                let r = reply.clone();
                w.on_open_file(move || {
                    r.send(KeyChoice::Browse);
                    hide(&weak);
                });
                let weak = w.as_weak();
                w.on_cancel(move || {
                    reply.send(KeyChoice::Cancel);
                    hide(&weak);
                });
                w.show()
            })
            .await;
            match choice {
                Some(KeyChoice::Recent(i)) => return recent.get(i).cloned(),
                Some(KeyChoice::Browse) => {
                    let start = recent
                        .first()
                        .and_then(|p| p.parent())
                        .map(Path::to_path_buf);
                    if let Some(p) = files::pick(
                        s.choose_key_title,
                        s.p12_filter,
                        &["*.p12".into(), "*.pfx".into()],
                        start.as_deref(),
                    )
                    .await
                    {
                        return Some(p);
                    }
                    // File dialog cancelled: back to the chooser.
                }
                Some(KeyChoice::Cancel) | None => return None,
            }
        }
    }

    async fn choose_file(&self, ext: &str, start_dir: Option<&Path>) -> Option<PathBuf> {
        let s = self.shared.strings();
        files::pick(
            s.choose_file_title,
            s.files_filter,
            &nca_ui::ext_globs(ext),
            start_dir,
        )
        .await
    }

    async fn ask_password(&self, origin: &str, file_name: &str, retry: bool) -> Option<String> {
        let s = self.shared.strings();
        let origin = origin.to_string();
        let file_name = file_name.to_string();
        on_ui(move |reply: Reply<String>| {
            let w = PasswordDialog::new()?;
            w.set_t(texts(s, &origin, &file_name));
            w.set_origin(origin.into());
            w.set_retry(retry);
            let weak = w.as_weak();
            let r = reply.clone();
            w.on_confirm(move |pw| {
                r.send(pw.to_string());
                hide(&weak);
            });
            let weak = w.as_weak();
            w.on_cancel(move || {
                // Dropping the sender without a value reads as "cancelled" on the other side.
                drop(reply.0.borrow_mut().take());
                hide(&weak);
            });
            w.show()
        })
        .await
    }

    async fn error(&self, text: &str) {
        let s = self.shared.strings();
        let text = text.to_string();
        tracing::error!("ui error: {text}");
        on_ui(move |reply: Reply<()>| {
            let w = ErrorDialog::new()?;
            w.set_t(texts(s, "", ""));
            w.set_message(text.into());
            let weak = w.as_weak();
            w.on_dismiss(move || {
                reply.send(());
                hide(&weak);
            });
            w.show()
        })
        .await;
    }

    async fn notify(&self, title: &str, text: &str) {
        tracing::info!("notify: {title}: {text}");
        let r = notify_rust::Notification::new()
            .appname("ncalayer-rs")
            .summary(title)
            .body(text)
            .icon("ncalayer-rs")
            .show_async()
            .await;
        if let Err(e) = r {
            tracing::warn!("desktop notification failed: {e}");
        }
    }
}

thread_local! {
    static SETTINGS_WINDOW: RefCell<Option<slint::Weak<SettingsWindow>>> = const { RefCell::new(None) };
}

/// Open (or raise) the settings window. UI thread only.
pub(crate) fn show_settings(shared: Arc<Shared>) {
    if let Some(w) = SETTINGS_WINDOW.with(|c| c.borrow().as_ref().and_then(slint::Weak::upgrade)) {
        let _ = w.show();
        return;
    }
    let w = match SettingsWindow::new() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("cannot create settings window: {e}");
            return;
        }
    };
    let settings = Settings::load(&shared.settings_path);
    let locale = shared.locale();
    let s = locale.strings();
    w.set_t(texts(s, "", ""));
    w.set_languages(ModelRc::new(VecModel::from(
        Locale::ALL
            .iter()
            .map(|l| SharedString::from(l.native_name()))
            .collect::<Vec<_>>(),
    )));
    w.set_language_index(locale.index() as i32);
    w.set_start_minimized(settings.start_minimized);
    w.set_status_line(
        format!(
            "ncalayer-rs {} — {}",
            env!("CARGO_PKG_VERSION"),
            shared.status_url()
        )
        .into(),
    );
    let recent_model = Rc::new(VecModel::from(
        settings
            .recent
            .iter()
            .map(|p| SharedString::from(p.display().to_string()))
            .collect::<Vec<_>>(),
    ));
    w.set_recent(ModelRc::from(recent_model.clone()));

    let sh = shared.clone();
    let weak = w.as_weak();
    w.on_language_changed(move |i| {
        let Some(l) = Locale::ALL.get(i.max(0) as usize).copied() else {
            return;
        };
        sh.set_locale(l);
        let mut settings = Settings::load(&sh.settings_path);
        settings.locale = Some(l.code().to_string());
        settings.save(&sh.settings_path);
        if let Some(w) = weak.upgrade() {
            w.set_t(texts(l.strings(), "", ""));
        }
    });
    let sh = shared.clone();
    let model = recent_model.clone();
    w.on_remove_recent(move |i| {
        let i = i.max(0) as usize;
        if i < model.row_count() {
            let path = PathBuf::from(model.row_data(i).map(|s| s.to_string()).unwrap_or_default());
            model.remove(i);
            let mut settings = Settings::load(&sh.settings_path);
            settings.remove_recent(&path);
            settings.save(&sh.settings_path);
        }
    });
    let sh = shared.clone();
    w.on_start_minimized_changed(move |on| {
        let mut settings = Settings::load(&sh.settings_path);
        settings.start_minimized = on;
        settings.save(&sh.settings_path);
    });
    let weak = w.as_weak();
    w.on_dismiss(move || hide(&weak));
    SETTINGS_WINDOW.with(|c| *c.borrow_mut() = Some(w.as_weak()));
    if let Err(e) = w.show() {
        tracing::error!("cannot show settings window: {e}");
    }
}
