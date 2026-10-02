# kz-xmldsig

XML Signature (XMLDSig) для открытой замены NCALayer (НУЦ РК): то, что делают
`signXml`, `signXmls`, `basics.sign(format="xml")` и `verifyXml` оригинала —
`kz.gov.pki.provider.utils.XMLUtil.createXmlSignature` (Apache Santuario + ГОСТ-алгоритмы Kalkan).

## Что умеет

* **`sign_enveloped`** — enveloped-подпись: `Reference URI=""`, трансформы
  `enveloped-signature` + `c14n#WithComments`, `SignedInfo` канонизируется inclusive C14N 1.0,
  `ds:Signature` дописывается последним ребёнком корня. Текст вызывающего возвращается
  байт-в-байт, подпись вклеивается перед закрывающим тегом (XML-декларация сохраняется —
  Santuario её выбрасывает).
* **`sign_by_id`** — `signXml` с `tbsElementXPath` / `signatureParentElementXPath`:
  `Reference URI="#Id"` по атрибуту `Id` (без него — ошибка с текстом оригинала), единственный
  трансформ `c14n#WithComments`, `SignedInfo` — Exclusive C14N, подпись вставляется в родителя.
  XPath только абсолютный вида `/root/a` или `/root/a[2]` — ровно то, что присылают сайты.
* **`sign_enveloped_many`** — `signXmls`, map по массиву.
* **`verify`** — находит все `ds:Signature`, проверяет каждый `DigestValue`
  (`URI=""` с enveloped, `#Id`, `#xpointer(/)`, `#xpointer(id('…'))`) и `SignatureValue`
  сертификатом из `KeyInfo` (или переданным в `verify_with`). Цепочку и отзыв не проверяет.
* **`c14n`** — Canonical XML 1.0 (с комментариями и без) и Exclusive C14N 1.0
  (без `InclusiveNamespaces`), самостоятельно пригодные. Тесты — примеры §3 спецификации W3C.

Подписанты: ГОСТ Р 34.10-2015 (256/512), ГОСТ Р 34.10-2004, RSA (`rsa-sha256`) —
семейства `kz_cms::SignerAlgorithm`; URI алгоритмов в `algo.rs`.

## Порядок байт подписи

Для ГОСТ Kalkan пишет `SignatureValue` как `r ‖ s`, каждое число little-endian
(`gost3410::Signature::to_bytes_kz`) — так же, как в CMS и сертификатах НУЦ, не по RFC 4491.
Установлено по эталонам `tests/fixtures/test_gost512.xml_*.xml`; обратные варианты не проходят
(`tests/kalkan.rs::kalkan_signature_value_byte_order`).

## Проверка

`cargo test -p kz-xmldsig`. Тест `kalkan_oracle_verifies_our_xml` прогоняет наши подписи через
`tools/java-oracle/run.sh verifyxml` (нужны JDK 8 и кэш NCALayer); без них пропускается.
`cargo run -p kz-xmldsig --example sign_fixture -- <dir>` кладёт подписанные эталонные входы
для ручного сравнения.
