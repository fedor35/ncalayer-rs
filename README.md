# ncalayer-rs

Открытая замена [NCALayer](https://pki.gov.kz) на Rust: локальный сервис `wss://127.0.0.1:13579`, через который
сайты госорганов Казахстана (egov.kz, cabinet.salyk.kz, stat.gov.kz, knp.kgd.gov.kz) подписывают документы
ЭЦП НУЦ РК. Без Java, без Felix, нативно под Wayland.

## Статус

| Готово | Проверено |
|---|---|
| wss-сервер, локальный CA с установкой в Firefox/Chromium | подключение из браузера |
| ГОСТ Р 34.10-2012 на кривых НУЦ (`gost3410`) | тест-векторы стандарта, сертификаты НУЦ, Kalkan ⇄ Rust |
| Чтение PKCS#12 НУЦ (`kz-pki`) | боевые контейнеры GOST512 |
| CAdES-BES / CAdES-T с меткой TSA НУЦ (`kz-cms`) | DER байт-в-байт как Kalkan; **cabinet.stat.gov.kz принял подпись** |
| `commonUtils`: getKeyInfo, createCMSSignature*/createCAdES*, applyCAdEST, showFileChooser; `basics.sign(cms)` | по сокету, оракул Kalkan |

| XMLDSig (`kz-xmldsig`), `signXml`/`signXmls`, `basics.sign(xml)` | **egov.kz: вход боевым ключом** |

Проверено на боевых порталах с действующим ключом НУЦ: **cabinet.stat.gov.kz**, **egov.kz**, **knp.kgd.gov.kz** (кабинет налогоплательщика).

GUI: Slint с Qt-бэкендом (стиль KDE), трей StatusNotifier, выбор файла через XDG-портал, языки ru/kk/en
(фича `ui-slint`, по умолчанию; `--no-default-features` — диалоги kdialog/zenity). В работе: упаковка deb/AppImage,
фронтенд на syngui, шимы сторонних модулей. План и факты — в [docs/PLAN.md](docs/PLAN.md).

## Установка

Пакеты в [Releases](https://github.com/fedor35/ncalayer-rs/releases): `.deb` (Ubuntu/Debian/Mint), `.pkg.tar.zst` (Arch), `.AppImage`.
После установки ничего настраивать не нужно: демон стартует при входе в сессию (`/etc/xdg/autostart`), при старте сам
прописывает свой корневой сертификат в профили Firefox и Chromium и сообщает, если браузер надо перезапустить.
Оригинальный NCALayer должен быть выключен — порт 13579 один на двоих, демон об этом предупредит.
Проверка: открыть `https://127.0.0.1:13579/`. Из исходников: `cargo build --release -p ncalayerd && ./target/release/ncalayerd run`.

## Эталон и тесты

`tools/java-oracle` гоняет настоящий KalkanCrypt из установленного NCALayer (в репозиторий он не входит):
генерирует тестовые ключи и подписи, проверяет наши. Фикстуры в `tests/fixtures` — тестовый ключ, не ЭЦП.

Дисклеймер: проект не аффилирован с НУЦ РК / АО «НИТ». Криптография не сертифицирована по СТ РК 1073.
Лицензия: MIT OR Apache-2.0.
