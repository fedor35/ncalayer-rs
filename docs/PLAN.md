# ncalayer-rs — открытая замена NCALayer на Rust

Рабочее название. Цель: нативный Linux-демон (и потом Windows/macOS), который сайты
egov.kz / cabinet.salyk.kz / knp.kgd.gov.kz / stat.gov.kz / nca.pki.gov.kz видят как NCALayer,
без Java 8, с нормальным GUI под Wayland и с переключаемым языком.

## 0. Что выяснено в разведке (02.10.2026)

Источники: распаковка ncalayer.jar + бандлов (`~/.config/NCALayer/ncalayer-cache`), веб-поиск.

**Протокол.** `wss://127.0.0.1:13579/`, принимаются только соединения с 127.0.0.1.
При открытии сервер шлёт `{"result":{"version":"1.4"}}`, на `--heartbeat--` отвечает тем же.
Запрос — JSON с полем `module` (по умолчанию legacy `kz.gov.pki.knca.applet.Applet`).
Три API, нужны все (порталы до сих пор зовут commonUtils):

| module | стиль | методы |
|---|---|---|
| `kz.gov.pki.knca.commonUtils` | `{method, args:[…], uuid?}` → `{code:"200"\|"500", message, responseObject, uuid?}` | getActiveTokens, getKeyInfo(storage), signXml(storage,keyType,xml,tbsXPath,parentXPath), signXmls, createCMSSignatureFromBase64(storage,keyType,b64,attach), createCMSSignatureFromFile, createCAdESFromBase64, createCAdESFromFile, createCAdESFromBase64Hash, applyCAdEST, showFileChooser, changeLocale |
| `kz.gov.pki.knca.basics` | `{method:"sign", args:{allowedStorages, format:"cms"\|"xml", data, signingParams{decode,encapsulate,digested,tsaProfile}, signerParams{extKeyUsageOids,iin,bin,serialNumber,chain}, locale}}` → `{status, code, message, body:{result:{signatures[],certificate}}}` | sign, generateCsr, importCertificate |
| `kz.gov.pki.knca.applet.Applet` | `{method, args:[…]}` → `{result, secondResult, errorCode}` | legacy; НУЦ отключил MainApplet 14.10.2024 — реализовать только MODULE_NOT_FOUND-совместимый ответ |
| `kz.gov.pki.ncalayerservices.accessory` | getBundles/getServices/installBundle | служебный, можно отвечать пустыми списками |

keyType: `AUTHENTICATION` / `SIGNATURE`. Пароль от ключа запрашивает сам NCALayer своим окном, сайту не передаётся.
`responseObject` для getKeyInfo = `{alias,keyId,algorithm,subjectCn,subjectDn,issuerCn,issuerDn,serialNumber,certNotAfter,certNotBefore,authorityKeyIdentifier,pem}`, даты `dd.MM.yyyy HH:mm:ss` (Asia/Almaty).
Отмена пользователем: commonUtils → code 500 + `action.canceled`; basics → status:true без body.result.
Клиент-референс: github.com/sigex-kz/ncalayer-js-client, мок: sigex-kz/ncalayer-mocker, оф. wiki: github.com/pkigovkz/sdkinfo/wiki/KNCA-Basics-Module.

**TLS на 13579.** Сертификат `CN=127.0.0.1, O=ҰКО, C=KZ` (RSA-2048, SAN localhost/127.0.0.1) выдан
«ҰКО (RSA) 2022» ← корень «НЕГІЗГІ КО (RSA)». Ключ и цепочка вшиты в бандл websocket
(`keystore.jks`, пароль `nb1B3dau`, alias `ncalayer`), ротируется раз в ~год через обновление бандла
(текущий до 03.04.2027). Браузер доверяет корню НУЦ, который NCALayer ставит в NSS (`certutil`).
Варианты для нас: (а) переиспользовать ключ из бандла — нулевая настройка у пользователя, но чужой ключ и
зависимость от ротации; (б) свой локальный CA + серт на 127.0.0.1, ставим в NSS/системное хранилище сами
(как mkcert) — честно и автономно. Решение: (б) по умолчанию, (а) как опция `--borrow-nca-cert` для тех,
у кого уже стоит NCALayer. Требует решения пользователя.

**Криптография.** Kalkan — чистая Java (форк BouncyCastle), нативных библиотек нет. Параметры кривых
вытащены из `ECGOST3410NamedCurves` и сверены:

| Имя в Kalkan | OID параметров | Совпадает с |
|---|---|---|
| Gost3410-2015-512-ParamSetA | 1.2.398.3.10.1.1.2.2.1 | id-tc26-gost-3410-12-512-paramSetA (RFC 7836) — p,q,a,b,x,y идентичны |
| Gost3410-2015-256-ParamSetA | 1.2.398.3.10.1.1.2.1.1 | id-tc26-gost-3410-2012-256-paramSetA |
| Gost34310-2004-PKIGOVKZ-A | 1.2.398.3.10.1.1.1.1.1 | GostR3410-2001-CryptoPro-A (p=2^256−617, b=166) |
| Gost34310_2004_384 | ? | своя 384-битная кривая, в выдаче НУЦ не встречается — вне scope |

OID подписи: `1.2.398.3.10.1.1.2.3.2` (34.10-2015-512 + 34.11-2015-512), ключ `1.2.398.3.10.1.1.2.2`,
хэш `1.2.398.3.10.1.3.3`; legacy 2004: подпись `1.2.398.3.10.1.1.1.2`, хэш 34.311-95 `1.2.398.3.10.1.3.1`
(S-box «Параметр 1» — ещё не сверен с CryptoPro-набором; актуально только для ключей до 04.2024).
С 28.04.2024 НУЦ выпускает только ГОСТ 2015/512 (файлы `GOST512_*.p12`), плюс RSA-2048/SHA-256 у старых комплектов.
XMLDSig URI: `urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512` /
`…:gostr34112015-512`; 2004: `http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311` / `#gost34311`.
Хранилища: PKCS12 (обязательно), JKS; токены (Kaztoken, ID-карта, eToken, JaCarta) идут по PC/SC APDU —
вне первого релиза.
PKCS#12 НУЦ — стандартный: MAC sha1, ключ pbeWithSHA1And3-KeyTripleDES-CBC, серты RC2-40.
Пароль по regex `^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{6,32}$`.
Сервисы НУЦ: TSP `http://tsp.pki.gov.kz` (политика 1.2.398.3.3.2.6.4 для gost2015), OCSP `http://ocsp.pki.gov.kz/`,
CRL `http://crl.pki.gov.kz/nca_gost.crl`. Правила проверки (с 06.09.2026): TSP необязателен, OCSP или CRL.

**Rust-экосистема.** Есть: `streebog`, `gost94` (RustCrypto), `der`/`x509-cert`/`cms`/`pkcs12`/`pkcs8`,
`rcgen`, `rustls`, `tokio-tungstenite`. Нет: подписи ГОСТ Р 34.10-2012 — писать свой крейт
над `crypto-bigint`/`primeorder` (кривые Вейерштрасса, ~400 строк + тест-векторы RFC 7836), и
XMLDSig с каноникализацией C14N (нет зрелого крейта — писать exclusive C14N 1.0 самим или через libxml2).

**Юридически.** Закон 370-II не требует сертификации средства формирования подписи на стороне клиента;
НУЦ на форуме: «NCALayer не криптопровайдер, сертифицирован только KalkanCrypt». Прецедент: Doodocs Sign
(своя крипта в WASM, с марта 2026, работает на egov/eSalyk). Риск принимаем, в README — дисклеймер.

## 1. Архитектура

```
ncalayer-rs/
  crates/
    gost3410/      подпись ГОСТ Р 34.10-2012 (256/512) + CryptoPro-A; тест-векторы RFC 7836; no_std-совместимо
    kz-pki/        OID НУЦ, разбор сертификатов/p12, построение цепочки, OCSP/CRL/TSP-клиенты
    kz-cms/        CMS SignedData / CAdES-BES/-T (attached/detached, digested) для ГОСТ и RSA
    kz-xmldsig/    XMLDSig enveloped + C14N, ГОСТ/RSA URI
    nca-protocol/  JSON-типы трёх модулей, диспетчер, коды ошибок — чистые типы, без I/O
    ncalayerd/     демон: tokio + rustls wss на 13579, фильтр 127.0.0.1, трей, GUI-диалоги
  tools/
    mkcert-nca/    генерация локального CA и установка в NSS/ca-certificates
  tests/
    fixtures/      тестовые p12 (сгенерить свои на тех же кривых), эталонные CMS/XML от настоящего NCALayer
```

GUI: Slint (уже знаком по vega-bs-config, рендерится под Wayland без X11) — окно выбора ключа/пароля,
трей через `ksni`/StatusNotifier, язык ru/kk/en переключается на лету (changeLocale).

## 2. Этапы

| # | Этап | Критерий готовности |
|---|---|---|
| 0 | Скелет: wss на 13579 с локальным CA, фильтр 127.0.0.1, version/heartbeat, MODULE_NOT_FOUND | `ncalayer-client.js` подключается из Firefox, mocker-тесты sigex проходят |
| 1 | `gost3410`: подпись/проверка 512-A и 256-A, Стрибог; RSA через `rsa` | тест-векторы RFC 7836; проверка подписи настоящего серта НУЦ (цепочка ҰКО GOST 2022) |
| 2 | `kz-pki`: чтение p12 НУЦ (3DES/RC2-40 PBE), KeyInfo как у оригинала, выбор по keyType/EKU | `getKeyInfo` отдаёт байт-в-байт такой же JSON, как Java (сверка на своих ключах) |
| 3 | `kz-cms`: CAdES-BES attached/detached, +TSP → CAdES-T | подпись проверяется NCANode/Kalkan и принимается cabinet.stat.gov.kz (там CMS) |
| 4 | commonUtils полностью + basics.sign(cms) | сдача формы на knp.kgd.gov.kz / cabinet.salyk.kz реальным ключом |
| 5 | `kz-xmldsig` + signXml/signXmls + basics.sign(xml) | egov.kz авторизация и подпись заявления |
| 6 | GUI: диалоги Slint, трей, локаль, настройки (прокси, недавние ключи как в settings.json) | работает в Plasma Wayland и GNOME без X11 |
| 7 | Упаковка: PKGBUILD/AUR, deb, AppImage; systemd --user unit; установка CA | «один пакет и работает» на Arch и Ubuntu |
| 8 | Позже: legacy ГОСТ-2004 (S-box сверить), токены по PC/SC, Windows/macOS, generateCsr/importCertificate | — |

Этапы 1–3 и 5 — чистые библиотеки, их можно делать параллельно и тестировать без браузера.

## 3. Как тестировать без риска

- Эталоны: настоящий NCALayer на ноуте (Java) — через `ncalayer-client.js` снять ответы getKeyInfo/CMS/XML на
  **своих** ключах и положить в fixtures (ключи в репо не класть, только выходы без секретов).
- Проверка CMS/XML: NCANode (Java, MIT) локально в Docker как независимый верификатор; плюс
  `openssl cms -verify` с gost-engine для ГОСТ-2012 (OID подменять на российские при проверке).
- Боевой прогон: stat.gov.kz (наименее рискованный), затем КНП.

## 4. Решения (приняты 02.10.2026)

1. Название `ncalayer-rs` (рабочее), лицензия MIT OR Apache-2.0, публичный GitHub с первого релиза этапа 0.
2. TLS: свой локальный CA по умолчанию (как mkcert: корень → NSS Firefox/Chromium + /etc/ca-certificates),
   опция `--borrow-nca-cert` для заимствования ключа из бандла установленного NCALayer.
3. Scope v1: PKCS12 + ГОСТ-2015 (256/512-A) + RSA. Токены и ГОСТ-2004 — этап 8.
4. GUI: **Slint с Qt-бэкендом** (на Plasma — стиль и тема KDE), трей через StatusNotifierItem (`ksni`),
   файловые диалоги через XDG-портал (`ashpd`) → родной диалог KDE/GNOME. Fallback — winit-бэкенд Slint.

## 5. Сторонние модули (bundles)

Оригинал подгружает ~42 подписанных НУЦ Java-бандла (КНП, ЭСФ, Госзакуп NurSign, eZsigner, Doodocs, uchet,
documentolog, idocs…) — список `https://pki.gov.kz/docs/nl_ru/bundles/`, манифест `http://crl.pki.gov.kz/updates/ncalayer.der`
(CMS с JSON: name, symname, version, url, hash, required). Выполнять Java-код мы не будем; большинство модулей —
тонкие обёртки над теми же sign/getKeyInfo со своим `module`-именем и форматом аргументов.
План: этап 7а — скачать все бандлы из манифеста, разобрать javap'ом API каждого (module-name, методы, JSON),
реализовать совместимые шимы для популярных (КНП, ЭСФ, Госзакуп, eZsigner) на общем ядре подписи; в GUI —
окно «Модули» с каталогом из манифеста НУЦ и статусом «поддерживается / в планах», чтобы пользователь понимал,
почему сайт просит модуль. Неизвестный модуль → `MODULE_NOT_FOUND` + уведомление в трее с именем модуля
(чтобы собирать запросы на шимы через issues).

## 6. Интеграция с браузерами

- Автоустановка корня в NSS (`certutil`, профили Firefox/Librewolf/Chromium/Chrome/Brave/Yandex) и в
  `/etc/ca-certificates/trust-source` (через pkexec), проверка на старте с подсказкой в трее, если доверия нет.
- Страница состояния `https://127.0.0.1:13579/` (оригинал тоже отдаёт `/basics/index.html`): версия, список ключей
  без секретов, индикатор «браузер доверяет сертификату», кнопка самопроверки подписи — заменяет «Проверить NCALayer»
  на pki.gov.kz.
- Firefox enterprise policy (`policies.json` → `Certificates.Install`) как альтернатива certutil для флатпак/снап-браузеров.
- Позже: WebExtension (как у Doodocs) не нужен, пока сайты ходят на wss напрямую; держим в уме как план Б,
  если НУЦ сменит транспорт.
