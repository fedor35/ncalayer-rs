# java-oracle

Эталон на проприетарном KalkanProvider из установленного NCALayer (jar в репозиторий не кладём).
`./run.sh gen <dir> <password>` — тестовый ключ ГОСТ-2015-512 (ParamSetA), самоподписанный сертификат,
PKCS#12 и файл `.vectors` (digest, d, Q, подпись, SPKI, TBS и подпись сертификата).
`./run.sh verify <cert.pem> <msg> <sig-hex>` — проверить подпись, сделанную Rust-кодом.

`tests/fixtures/test_gost512.*` сгенерированы им 02.10.2026, пароль `Test1234`. Это тестовый ключ, не ЭЦП.
