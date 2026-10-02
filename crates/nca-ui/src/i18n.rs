//! Interface strings for Russian, Kazakh and English. `commonUtils.changeLocale` switches the
//! language at run time, so frontends look strings up through [`Locale::strings`] on every
//! dialog instead of baking them in.

/// Interface language. The original NCALayer offers the same three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Locale {
    #[default]
    Ru,
    Kk,
    En,
}

impl Locale {
    /// All locales in menu order.
    pub const ALL: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];

    /// Accepts `ru`, `kk`/`kz`, `en` and longer tags like `ru_RU`; case-insensitive.
    pub fn parse(code: &str) -> Option<Self> {
        let c = code.trim().to_ascii_lowercase();
        let base = c.split(['_', '-']).next().unwrap_or("");
        match base {
            "ru" => Some(Locale::Ru),
            "kk" | "kz" => Some(Locale::Kk),
            "en" => Some(Locale::En),
            _ => None,
        }
    }

    /// ISO 639-1 code as stored in `settings.json`.
    pub fn code(self) -> &'static str {
        match self {
            Locale::Ru => "ru",
            Locale::Kk => "kk",
            Locale::En => "en",
        }
    }

    /// Native name for the language menu.
    pub fn native_name(self) -> &'static str {
        match self {
            Locale::Ru => "Русский",
            Locale::Kk => "Қазақша",
            Locale::En => "English",
        }
    }

    /// Position in [`Locale::ALL`].
    pub fn index(self) -> usize {
        Locale::ALL.iter().position(|l| *l == self).unwrap_or(0)
    }

    /// The string table.
    pub fn strings(self) -> &'static Strings {
        match self {
            Locale::Ru => &RU,
            Locale::Kk => &KK,
            Locale::En => &EN,
        }
    }
}

/// Every user-visible string. `{origin}` / `{file}` are substituted by the caller.
#[derive(Debug)]
pub struct Strings {
    pub app_name: &'static str,
    pub choose_key_title: &'static str,
    /// "{origin} asks for a signing key"
    pub choose_key_for: &'static str,
    pub recent_containers: &'static str,
    pub no_recent: &'static str,
    pub open_file: &'static str,
    pub cancel: &'static str,
    pub select: &'static str,
    pub ok: &'static str,
    pub close: &'static str,
    pub p12_filter: &'static str,
    pub files_filter: &'static str,
    pub choose_file_title: &'static str,
    pub password_title: &'static str,
    /// "Password for {file}"
    pub password_prompt: &'static str,
    pub wrong_password: &'static str,
    pub show_password: &'static str,
    pub error_title: &'static str,
    pub settings_title: &'static str,
    pub language: &'static str,
    pub recent_keys: &'static str,
    pub remove: &'static str,
    pub start_minimized: &'static str,
    pub tray_status_page: &'static str,
    pub tray_settings: &'static str,
    pub tray_quit: &'static str,
    pub tray_tooltip: &'static str,
}

pub static RU: Strings = Strings {
    app_name: "ncalayer-rs",
    choose_key_title: "Выберите ключ ЭЦП",
    choose_key_for: "{origin} запрашивает ключ ЭЦП",
    recent_containers: "Недавние контейнеры",
    no_recent: "Недавних контейнеров нет — нажмите «Открыть файл…»",
    open_file: "Открыть файл…",
    cancel: "Отмена",
    select: "Выбрать",
    ok: "ОК",
    close: "Закрыть",
    p12_filter: "Хранилище PKCS#12",
    files_filter: "Файлы",
    choose_file_title: "Выберите файл",
    password_title: "Пароль ключа",
    password_prompt: "Пароль от {file}",
    wrong_password: "Неверный пароль",
    show_password: "Показать пароль",
    error_title: "Ошибка",
    settings_title: "Настройки ncalayer-rs",
    language: "Язык",
    recent_keys: "Недавние ключи",
    remove: "Удалить",
    start_minimized: "Запускать свёрнутым (только значок в трее)",
    tray_status_page: "Открыть страницу состояния",
    tray_settings: "Настройки",
    tray_quit: "Выход",
    tray_tooltip: "ncalayer-rs — сервис подписи ЭЦП",
};

pub static KK: Strings = Strings {
    app_name: "ncalayer-rs",
    choose_key_title: "ЭЦҚ кілтін таңдаңыз",
    choose_key_for: "{origin} ЭЦҚ кілтін сұрайды",
    recent_containers: "Соңғы контейнерлер",
    no_recent: "Соңғы контейнерлер жоқ — «Файлды ашу…» басыңыз",
    open_file: "Файлды ашу…",
    cancel: "Болдырмау",
    select: "Таңдау",
    ok: "ОК",
    close: "Жабу",
    p12_filter: "PKCS#12 қоймасы",
    files_filter: "Файлдар",
    choose_file_title: "Файлды таңдаңыз",
    password_title: "Кілт құпиясөзі",
    password_prompt: "{file} құпиясөзі",
    wrong_password: "Құпиясөз қате",
    show_password: "Құпиясөзді көрсету",
    error_title: "Қате",
    settings_title: "ncalayer-rs баптаулары",
    language: "Тіл",
    recent_keys: "Соңғы кілттер",
    remove: "Жою",
    start_minimized: "Жасырын күйде іске қосу (тек трейдегі белгіше)",
    tray_status_page: "Күй бетін ашу",
    tray_settings: "Баптаулар",
    tray_quit: "Шығу",
    tray_tooltip: "ncalayer-rs — ЭЦҚ қол қою қызметі",
};

pub static EN: Strings = Strings {
    app_name: "ncalayer-rs",
    choose_key_title: "Choose a signing key",
    choose_key_for: "{origin} asks for a signing key",
    recent_containers: "Recent containers",
    no_recent: "No recent containers — press “Open file…”",
    open_file: "Open file…",
    cancel: "Cancel",
    select: "Select",
    ok: "OK",
    close: "Close",
    p12_filter: "PKCS#12 keystore",
    files_filter: "Files",
    choose_file_title: "Choose a file",
    password_title: "Key password",
    password_prompt: "Password for {file}",
    wrong_password: "Wrong password",
    show_password: "Show password",
    error_title: "Error",
    settings_title: "ncalayer-rs settings",
    language: "Language",
    recent_keys: "Recent keys",
    remove: "Remove",
    start_minimized: "Start minimised (tray icon only)",
    tray_status_page: "Open status page",
    tray_settings: "Settings",
    tray_quit: "Quit",
    tray_tooltip: "ncalayer-rs — digital signature service",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_codes() {
        assert_eq!(Locale::parse("ru"), Some(Locale::Ru));
        assert_eq!(Locale::parse("KZ"), Some(Locale::Kk));
        assert_eq!(Locale::parse("kk_KZ"), Some(Locale::Kk));
        assert_eq!(Locale::parse("en-US"), Some(Locale::En));
        assert_eq!(Locale::parse("de"), None);
    }
}
