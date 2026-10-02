# nca-ui-slint

Графический фронтенд `ncalayerd` на [Slint](https://slint.dev): реализация трейта `nca_ui::Ui`.

## Что внутри

| Окно / элемент | Чем сделано |
|---|---|
| Выбор ключа (`choose_key_file`) — список недавних контейнеров, «Открыть файл…», заголовок с сайтом-инициатором | Slint `KeyChooser`; файл — XDG-портал `org.freedesktop.portal.FileChooser` (`ashpd`), запасной вариант `rfd` (GTK3), если портала нет |
| Пароль (`ask_password`) — имя файла, «Неверный пароль» при повторе, Enter = ОК, «Показать пароль» | Slint `PasswordDialog` |
| Ошибка (`error`) | Slint `ErrorDialog` |
| Настройки — язык, недавние ключи с удалением, «Запускать свёрнутым» | Slint `SettingsWindow`; пишет `settings.json` через `nca_ui::Settings` |
| Трей — значок, меню «Открыть страницу состояния» / «Настройки» / «Выход», клик = настройки | `ksni` (StatusNotifierItem: родной в Plasma, в GNOME нужен AppIndicator) — без трея не падаем |
| Уведомления (`notify`) | `notify-rust` по D-Bus `org.freedesktop.Notifications` |
| Язык ru/kk/en, смена на лету (`changeLocale`) | строки из `nca_ui::i18n`, передаются в окна структурой `Texts` |

Описание окон — `ui/app.slint`, собирается `build.rs` (`slint-build`). Иконка — `assets/ncalayer-rs.svg`
(+ PNG 64/128 для трея и окон).

## Бэкенд Slint

Включены `backend-qt` и `backend-winit`. Если при сборке найден Qt (≥ 5.15 или 6.x, по `qmake` в PATH
или `QMAKE=/usr/lib/qt6/bin/qmake6`), по умолчанию используется Qt: окна в стиле и теме Plasma (Breeze,
тёмная/светлая). Без Qt dev-пакетов сборка не ломается — остаётся winit (Wayland/X11) со стилем fluent.
Переключить на лету: `SLINT_BACKEND=winit` или `SLINT_BACKEND=qt`. Отключить Qt при сборке: `SLINT_NO_QT=1`.

## Потоки

Slint требует главный поток под свой цикл событий, сервер живёт на tokio в другом потоке.
Каждый метод `Ui` — мостик: tokio-задача создаёт `tokio::sync::oneshot`, через
`slint::invoke_from_event_loop` отправляет в UI-поток замыкание, которое строит окно и в колбэках
отвечает в канал; задача ждёт `rx.await`. Закрытие окна крестиком роняет отправитель — вызывающая
сторона читает это как «отмена» (`action.canceled`). Порядок запуска: `SlintUi::new` (в главном потоке,
выбирает бэкенд и поднимает трей) → сервер в `std::thread` с `tokio::runtime::Runtime` →
`SlintUi::run` блокирует главный поток до `quit()`.

## Посмотреть окна без демона

```
cargo run -p nca-ui-slint --example preview -- ru            # открыть все окна с примерными данными
cargo run -p nca-ui-slint --example preview -- kk /tmp/shots # то же + PNG-снимки каждого окна
```
