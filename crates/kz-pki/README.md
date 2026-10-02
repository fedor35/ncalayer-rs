# kz-pki

Чтение контейнеров ключей ЭЦП НУЦ РК (PKCS#12) и сертификатов для открытой
замены NCALayer.

## Что умеет

* **OID НУЦ** (`oid.rs`): ключи/подписи/хэши ГОСТ-2015 (256/512), legacy
  ГОСТ-2004, RSA, EKU (`clientAuth` = аутентификация, `emailProtection` = подпись),
  политики `1.2.398.3.3.4.1.*`, расширение типа хранилища `1.2.398.3.3.5.*`.
* **PKCS#12** (`pkcs12.rs`): контейнеры в том виде, как их пишут Kalkan и
  BouncyCastle — BER с неопределёнными длинами, MAC HMAC-SHA1/SHA-256,
  `pkcs8ShroudedKeyBag` под `pbeWithSHAAnd3-KeyTripleDES-CBC`, сертификаты в
  `EncryptedData` под `pbeWithSHAAnd40BitRC2-CBC`; дополнительно PBES2 (AES)
  через `pkcs5`. Неверный пароль → `Error::WrongPassword` (проверка MAC до
  расшифровки).
* **Ключи** (`key.rs`): `PrivateKey::{Gost2015, Gost2004, Rsa}`; скаляр ГОСТ
  отдаётся big-endian. Поддержаны все три кодировки `privateKey` в PKCS#8:
  `OCTET STRING` little-endian (так пишет Kalkan), `INTEGER` big-endian и
  «сырые» 32/64 байта. Публичный ключ из SPKI (`x||y` little-endian по RFC 4491)
  отдаётся как big-endian `x`, `y`.
* **Сертификат** (`cert.rs`): поля для ответа `getKeyInfo` — `subject_dn()` /
  `issuer_dn()` в стиле BouncyCastle (`CN=...,SERIALNUMBER=IIN...,C=KZ`, порядок
  как в сертификате), `serial_number()` как `BigInteger.toString(16)`,
  даты `dd.MM.yyyy HH:mm:ss` в Asia/Almaty (+05:00), `key_usage_type()`,
  `algorithm()` (`ECGOST3410-2015-512` / `ECGOST3410` / `RSA`), `pem()`,
  `policies()`, `iin()`, `bin()`, `authority_key_identifier()`.

## Пример

```rust
let ks = kz_pki::KeyStore::open_file("GOST512_xxx.p12", "пароль")?;
let e = &ks.entries[0];
println!("{} {} {}", e.alias, e.cert.subject_dn(), e.cert.not_after_str()?);
```

`cargo run -p kz-pki --example dump -- file.p12 пароль` печатает содержимое контейнера.

## Тесты

`cargo test -p kz-pki` — фикстура `tests/fixtures/test_gost512.p12` (пароль
`Test1234`, alias `test`) и векторы из `test_gost512.vectors`.
