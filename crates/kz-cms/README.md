# kz-cms

CMS `SignedData` / CAdES-BES / CAdES-T для открытой замены NCALayer (НУЦ РК).
Воспроизводит байт-в-байт то, что делает `kz.gov.pki.provider.utils.CMSUtil.createCAdES`
из бандла NCALayer (Kalkan — форк BouncyCastle).

## Что умеет

* **Подпись** (`sign`): `SignedDataBuilder`, `create_cades_bes` (attached/detached),
  `create_cades_bes_from_hash` (по готовому хэшу, аналог `createCAdESFromBase64Hash`),
  `add_signer` (дописать подписанта в существующий CMS — старые `SignerInfo` переносятся
  без перекодирования). Подписанты: ГОСТ Р 34.10-2015 (256/512, Стрибог),
  ГОСТ Р 34.10-2004 (ГОСТ 34.311-95), RSA (`sha256WithRSA`, PKCS#1 v1.5).
  Подписанные атрибуты: `contentType`, `signingTime`, `signingCertificateV2`
  (ESSCertIDv2 = SHA-256 сертификата, hashAlgorithm опущен), `messageDigest`.
  `certificates` = сертификат подписанта + цепочка из `kz_pki::Entry`.
* **Проверка** (`verify`): `messageDigest` против данных (attached, detached или только хэш),
  подпись над DER подписанных атрибутов (с тегом SET), сертификат — из CMS по
  `issuerAndSerialNumber` или переданный. Цепочку и отзыв не проверяет.
* **CAdES-T** (`tsp`): запрос RFC 3161 к `http://tsp.pki.gov.kz` (политики
  `1.2.398.3.3.2.6.{1,2,4}` по алгоритму подписанта), вставка `signatureTimeStampToken`
  как unsigned-атрибута. Ответ TSA проверяется минимально: статус granted,
  `messageImprint` и nonce совпадают; подпись самого токена не проверяется.

## Порядок байт подписи

Kalkan пишет `SignerInfo.signature` для ГОСТ как `r ‖ s`, каждое число little-endian —
так же, как в сертификатах НУЦ (`gost3410::Signature::to_bytes_kz`), а **не** по RFC 4490/4491
(`s ‖ r` big-endian). Установлено по эталонным файлам `tests/fixtures/test_gost512.*`.

## Тесты

```sh
cargo test -p kz-cms                # эталоны Kalkan, байт-в-байт, round-trip, оракул (если есть JDK + NCALayer)
cargo test -p kz-cms -- --ignored   # живой запрос к tsp.pki.gov.kz
```

Перекрёстная проверка `tools/java-oracle/run.sh verifycms` пропускается с сообщением,
если нет `~/.config/NCALayer/.../bundle.jar` или `java`.
