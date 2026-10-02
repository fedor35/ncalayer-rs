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

В работе: GUI на Slint/syngui (сейчас — kdialog/zenity),
упаковка. План и факты — в [docs/PLAN.md](docs/PLAN.md).

## Попробовать

```
cargo build --release -p ncalayerd
./target/release/ncalayerd install-ca   # корень в NSS-базы Firefox/Chromium; перезапустить браузер
./target/release/ncalayerd run          # оригинальный NCALayer должен быть выключен
```
Открыть `https://127.0.0.1:13579/` — страница покажет, отвечает ли WebSocket. Автозапуск: `packaging/ncalayerd.service`.

## Эталон и тесты

`tools/java-oracle` гоняет настоящий KalkanCrypt из установленного NCALayer (в репозиторий он не входит):
генерирует тестовые ключи и подписи, проверяет наши. Фикстуры в `tests/fixtures` — тестовый ключ, не ЭЦП.

Дисклеймер: проект не аффилирован с НУЦ РК / АО «НИТ». Криптография не сертифицирована по СТ РК 1073.
Лицензия: MIT OR Apache-2.0.
