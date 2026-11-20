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
    /// Folder picker title for `basics.generateCsr`.
    pub new_key_folder: &'static str,
    /// Folder picker title for `basics.importCertificate`.
    pub import_folder: &'static str,
    pub new_password_title: &'static str,
    /// "Come up with a password for {file}"
    pub new_password_prompt: &'static str,
    pub new_password_rules: &'static str,
    pub repeat_password: &'static str,
    pub passwords_mismatch: &'static str,
    /// Notification after a successful import; "{file}".
    pub key_saved: &'static str,
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
    new_key_folder: "Папка для нового ключа ЭЦП",
    import_folder: "Папка с ключом, созданным при подаче заявки",
    new_password_title: "Пароль для ключа ЭЦП",
    new_password_prompt:
        "Придумайте пароль для ключа {file}. Он понадобится при каждой подписи — запишите его.",
    new_password_rules:
        "6–32 символа: латинские заглавная и строчная буквы и цифра; можно .?#$^+=!*()@%&_-",
    repeat_password: "Повторите пароль",
    passwords_mismatch: "Пароли не совпадают",
    key_saved: "Ключ ЭЦП сохранён: {file}",
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
    new_key_folder: "Жаңа ЭЦҚ кілтіне арналған қалта",
    import_folder: "Өтінім берген кезде жасалған кілт бар қалта",
    new_password_title: "ЭЦҚ кілтінің құпиясөзі",
    new_password_prompt: "{file} кілті үшін құпиясөз ойлап табыңыз. Ол әр қол қойған сайын қажет болады — жазып алыңыз.",
    new_password_rules: "6–32 таңба: латынның бас және кіші әрпі және цифр; .?#$^+=!*()@%&_- болады",
    repeat_password: "Құпиясөзді қайталаңыз",
    passwords_mismatch: "Құпиясөздер сәйкес келмейді",
    key_saved: "ЭЦҚ кілті сақталды: {file}",
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
    new_key_folder: "Folder for the new signing key",
    import_folder: "Folder with the key created when you applied",
    new_password_title: "Signing key password",
    new_password_prompt: "Choose a password for the key {file}. You will need it for every signature — write it down.",
    new_password_rules: "6–32 characters: an upper- and a lower-case Latin letter and a digit; .?#$^+=!*()@%&_- allowed",
    repeat_password: "Repeat the password",
    passwords_mismatch: "Passwords do not match",
    key_saved: "Signing key saved: {file}",
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
