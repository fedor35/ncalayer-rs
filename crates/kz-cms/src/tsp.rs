//! RFC 3161 time-stamping against the NCA TSA (`http://tsp.pki.gov.kz`) and
//! the CAdES-T `signatureTimeStampToken` unsigned attribute.
//!
//! Only the parts needed to upgrade a CAdES-BES to CAdES-T are implemented:
//! request building, a blocking HTTP client, response parsing and a
//! *minimal* check of the token (status granted, `messageImprint` matches,
//! nonce echoed).  The TSA's own signature is not verified.

use std::time::Duration;

use der::asn1::ObjectIdentifier;
use rand_core::CryptoRng;
use time::OffsetDateTime;

use crate::algo::SignerAlgorithm;
use crate::der_util::{
    alg_id_null, attribute, integer_be, integer_u64, octet_string, oid as enc_oid, sequence,
    Cursor, Tlv, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE,
};
use crate::error::{Error, Result};
use crate::oid;
use crate::parse::{decode_time, SignedData};
use crate::sign::{signer_info_with_unsigned_attr, SignedDataBuilder};

/// Public URL of the NCA time-stamping service.
pub const NCA_TSA_URL: &str = "http://tsp.pki.gov.kz";

/// An RFC 3161 `TimeStampReq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampRequest {
    /// Hash algorithm of the imprint.
    pub digest_algorithm: SignerAlgorithm,
    /// `messageImprint.hashedMessage`.
    pub imprint: Vec<u8>,
    /// `reqPolicy`.
    pub policy: Option<ObjectIdentifier>,
    /// `nonce` as an unsigned big-endian integer.
    pub nonce: Option<Vec<u8>>,
    /// `certReq`.
    pub cert_req: bool,
}

impl TimeStampRequest {
    /// Request for a signature time stamp: imprint = digest of the
    /// `signature` octets with the signer family's hash, policy = the NCA
    /// policy of that family, `certReq = true`.
    pub fn for_signature(alg: SignerAlgorithm, signature: &[u8], nonce: Option<Vec<u8>>) -> Self {
        TimeStampRequest {
            digest_algorithm: alg,
            imprint: alg.digest(signature),
            policy: Some(alg.tsa_policy_oid()),
            nonce,
            cert_req: true,
        }
    }

    /// Random 8-byte nonce.
    pub fn random_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> Vec<u8> {
        let mut n = [0u8; 8];
        rng.fill_bytes(&mut n);
        n[0] &= 0x7f;
        n.to_vec()
    }

    /// DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        let imprint = sequence(&[
            &alg_id_null(&self.digest_algorithm.digest_oid()),
            &octet_string(&self.imprint),
        ]);
        let mut parts: Vec<Vec<u8>> = vec![integer_u64(1), imprint];
        if let Some(p) = &self.policy {
            parts.push(enc_oid(p));
        }
        if let Some(n) = &self.nonce {
            parts.push(integer_be(n));
        }
        if self.cert_req {
            parts.push(vec![0x01, 0x01, 0xff]);
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        sequence(&refs)
    }
}

/// A parsed `TimeStampToken` (a `ContentInfo { signedData }` whose content is `TSTInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampToken {
    /// DER of the whole token (`ContentInfo`).
    pub der: Vec<u8>,
    /// `TSTInfo.policy`.
    pub policy: ObjectIdentifier,
    /// `TSTInfo.messageImprint.hashAlgorithm.algorithm`.
    pub imprint_algorithm: ObjectIdentifier,
    /// `TSTInfo.messageImprint.hashedMessage`.
    pub imprint: Vec<u8>,
    /// `TSTInfo.serialNumber` content octets.
    pub serial: Vec<u8>,
    /// `TSTInfo.genTime`.
    pub gen_time: OffsetDateTime,
    /// `TSTInfo.nonce` as unsigned big-endian bytes (leading zero stripped).
    pub nonce: Option<Vec<u8>>,
}

impl TimeStampToken {
    /// Parse a DER token.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let sd = SignedData::from_der(der)?;
        if sd.content_type != oid::ID_CT_TST_INFO {
            return Err(Error::Tsp(format!(
                "token content is {}, not TSTInfo",
                sd.content_type
            )));
        }
        let tst_der = sd
            .content
            .ok_or_else(|| Error::Tsp("token has no TSTInfo".into()))?;
        let tst = Tlv::parse_tag(&tst_der, TAG_SEQUENCE)?;
        let mut c = Cursor::new(&tst)?;
        let _version = c.next("TSTInfo.version")?.integer_u64()?;
        let policy = c.next("TSTInfo.policy")?.oid()?;
        let imprint_seq = c.next_tag(TAG_SEQUENCE, "messageImprint")?;
        let mut ic = Cursor::new(&imprint_seq)?;
        let alg = ic.next_tag(TAG_SEQUENCE, "hashAlgorithm")?;
        let imprint_algorithm = Cursor::new(&alg)?.next("algorithm")?.oid()?;
        let imprint = ic
            .next_tag(TAG_OCTET_STRING, "hashedMessage")?
            .content
            .to_vec();
        let serial = c.next_tag(TAG_INTEGER, "serialNumber")?.content.to_vec();
        let gen_time = decode_time(c.next("genTime")?.raw)?;
        let _accuracy = c.optional(TAG_SEQUENCE);
        let _ordering = c.optional(0x01);
        let nonce = c
            .optional(TAG_INTEGER)
            .map(|n| strip_leading_zero(n.content));
        Ok(TimeStampToken {
            der: der.to_vec(),
            policy,
            imprint_algorithm,
            imprint,
            serial,
            gen_time,
            nonce,
        })
    }

    /// Check that the token's imprint is the digest of `signature`.
    pub fn check_imprint(&self, signature: &[u8]) -> Result<()> {
        let alg = SignerAlgorithm::from_digest_oid(&self.imprint_algorithm)?;
        if alg.digest(signature) == self.imprint {
            Ok(())
        } else {
            Err(Error::Tsp(
                "messageImprint does not match the signature".into(),
            ))
        }
    }

    /// The `signatureTimeStampToken` unsigned attribute, DER-encoded.
    pub fn to_attribute(&self) -> Vec<u8> {
        attribute(&oid::SIGNATURE_TIME_STAMP_TOKEN, vec![self.der.clone()])
    }
}

fn strip_leading_zero(b: &[u8]) -> Vec<u8> {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[i..].to_vec()
}

/// A parsed `TimeStampResp`.
#[derive(Debug, Clone)]
pub struct TimeStampResponse {
    /// `status.status` (0 granted, 1 grantedWithMods, 2 rejection, ...).
    pub status: u64,
    /// `status.statusString` texts.
    pub status_text: Vec<String>,
    /// The token, when granted.
    pub token: Option<TimeStampToken>,
}

impl TimeStampResponse {
    /// Parse a DER response.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let resp = Tlv::parse_tag(der, TAG_SEQUENCE)?;
        let mut c = Cursor::new(&resp)?;
        let status_info = c.next_tag(TAG_SEQUENCE, "PKIStatusInfo")?;
        let mut sc = Cursor::new(&status_info)?;
        let status = sc.next("status")?.integer_u64()?;
        let status_text = match sc.optional(TAG_SEQUENCE) {
            Some(texts) => texts
                .children()?
                .iter()
                .map(|t| String::from_utf8_lossy(t.content).into_owned())
                .collect(),
            None => Vec::new(),
        };
        let token = match c.optional(TAG_SEQUENCE) {
            Some(t) => Some(TimeStampToken::from_der(t.raw)?),
            None => None,
        };
        Ok(TimeStampResponse {
            status,
            status_text,
            token,
        })
    }

    /// The token if the status is `granted` / `grantedWithMods`.
    pub fn granted(self) -> Result<TimeStampToken> {
        match (self.status, self.token) {
            (0 | 1, Some(t)) => Ok(t),
            (s, _) => Err(Error::Tsp(format!(
                "TSA status {s}: {}",
                self.status_text.join("; ")
            ))),
        }
    }
}

/// Blocking HTTP client of an RFC 3161 TSA.
#[derive(Debug, Clone)]
pub struct TsaClient {
    url: String,
    timeout: Duration,
}

impl TsaClient {
    /// Client of `url`.
    pub fn new(url: impl Into<String>) -> Self {
        TsaClient {
            url: url.into(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Client of the NCA service ([`NCA_TSA_URL`]).
    pub fn nca() -> Self {
        Self::new(NCA_TSA_URL)
    }

    /// Overall request timeout (default 30 s).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// POST a DER `TimeStampReq` and return the raw DER `TimeStampResp`.
    pub fn send_raw(&self, request_der: &[u8]) -> Result<Vec<u8>> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .build()
            .into();
        let mut resp = agent
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .send(request_der)
            .map_err(|e| Error::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::Transport(format!("HTTP {status}")));
        }
        resp.body_mut()
            .read_to_vec()
            .map_err(|e| Error::Transport(e.to_string()))
    }

    /// Send a request and return the granted token after checking the
    /// imprint and the nonce.
    pub fn request(&self, req: &TimeStampRequest) -> Result<TimeStampToken> {
        let resp = TimeStampResponse::from_der(&self.send_raw(&req.to_der())?)?;
        let token = resp.granted()?;
        if token.imprint != req.imprint {
            return Err(Error::Tsp("TSA returned a different messageImprint".into()));
        }
        if let Some(n) = &req.nonce {
            if token.nonce.as_deref() != Some(strip_leading_zero(n).as_slice()) {
                return Err(Error::Tsp("TSA did not echo the nonce".into()));
            }
        }
        Ok(token)
    }
}

/// Insert `token` as `signatureTimeStampToken` of signer `signer_index`.
pub fn add_timestamp_token(
    cms: &[u8],
    signer_index: usize,
    token: &TimeStampToken,
) -> Result<Vec<u8>> {
    let sd = SignedData::from_der(cms)?;
    let si = sd
        .signer_infos
        .get(signer_index)
        .ok_or_else(|| Error::Structure(format!("no signer #{signer_index}")))?;
    token.check_imprint(&si.signature)?;
    let mut b = SignedDataBuilder::from_parsed(&sd);
    b.signer_infos[signer_index] = signer_info_with_unsigned_attr(&si.raw, token.to_attribute())?;
    Ok(b.build())
}

/// Upgrade every signer without a time stamp to CAdES-T using `client`.
pub fn add_cades_t<R: CryptoRng + ?Sized>(
    cms: &[u8],
    client: &TsaClient,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let sd = SignedData::from_der(cms)?;
    let mut out = cms.to_vec();
    for (i, si) in sd.signer_infos.iter().enumerate() {
        if si.has_timestamp() {
            continue;
        }
        let alg = SignerAlgorithm::from_signature_oid(&si.signature_oid)?;
        let req = TimeStampRequest::for_signature(
            alg,
            &si.signature,
            Some(TimeStampRequest::random_nonce(rng)),
        );
        let token = client.request(&req)?;
        out = add_timestamp_token(&out, i, &token)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der_util::{retag, set_of, tlv, TAG_CTX0};

    fn alg() -> SignerAlgorithm {
        SignerAlgorithm::Gost2015_512
    }

    #[test]
    fn request_der_layout() {
        let sig = [0xabu8; 128];
        let req = TimeStampRequest::for_signature(alg(), &sig, Some(vec![0x12, 0x34]));
        assert_eq!(req.policy, Some(oid::TSA_POLICY_GOST2015));
        assert_eq!(req.imprint, alg().digest(&sig));
        let der = req.to_der();
        let t = Tlv::parse_tag(&der, TAG_SEQUENCE).unwrap();
        let kids = t.children().unwrap();
        assert_eq!(kids.len(), 5);
        assert_eq!(kids[0].integer_u64().unwrap(), 1);
        let imprint = kids[1].children().unwrap();
        let hash_alg = imprint[0].children().unwrap();
        assert_eq!(hash_alg[0].oid().unwrap(), kz_pki::oid::GOST2015_512_HASH);
        assert_eq!(hash_alg[1].raw, &[0x05, 0x00]);
        assert_eq!(imprint[1].content, req.imprint.as_slice());
        assert_eq!(kids[2].oid().unwrap(), oid::TSA_POLICY_GOST2015);
        assert_eq!(kids[3].raw, &[0x02, 0x02, 0x12, 0x34]);
        assert_eq!(kids[4].raw, &[0x01, 0x01, 0xff]);
        // Policies of the other families.
        assert_eq!(
            SignerAlgorithm::RsaSha256.tsa_policy_oid(),
            oid::TSA_POLICY_RSA
        );
        assert_eq!(
            SignerAlgorithm::Gost2004.tsa_policy_oid(),
            oid::TSA_POLICY_GOST2004
        );
        assert_eq!(
            SignerAlgorithm::Gost2015_256.tsa_policy_oid(),
            oid::TSA_POLICY_GOST2015
        );
        // Without policy / nonce / certReq the request is just version + imprint.
        let bare = TimeStampRequest {
            policy: None,
            nonce: None,
            cert_req: false,
            ..req
        };
        assert_eq!(
            Tlv::parse(&bare.to_der())
                .unwrap()
                .children()
                .unwrap()
                .len(),
            2
        );
    }

    /// A syntactically valid (unsigned) token over `imprint` for `nonce`.
    fn fake_token(imprint: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
        let mut tst: Vec<Vec<u8>> = vec![
            integer_u64(1),
            enc_oid(&oid::TSA_POLICY_GOST2015),
            sequence(&[
                &alg_id_null(&kz_pki::oid::GOST2015_512_HASH),
                &octet_string(imprint),
            ]),
            integer_u64(42),
            tlv(0x18, b"20261002120000Z"),
            sequence(&[&tlv(0x80, &[0x01])]), // accuracy
        ];
        if let Some(n) = nonce {
            tst.push(integer_be(n));
        }
        let refs: Vec<&[u8]> = tst.iter().map(Vec::as_slice).collect();
        let tst_info = sequence(&refs);
        let eci = sequence(&[
            &enc_oid(&oid::ID_CT_TST_INFO),
            &tlv(TAG_CTX0, &octet_string(&tst_info)),
        ]);
        let sd = sequence(&[
            &integer_u64(3),
            &set_of(vec![alg_id_null(&kz_pki::oid::GOST2015_512_HASH)]),
            &eci,
            &retag(&set_of(vec![]), crate::der_util::TAG_CTX1), // empty crls, to exercise the [1] path
            &set_of(vec![]),
        ]);
        sequence(&[&enc_oid(&oid::ID_SIGNED_DATA), &tlv(TAG_CTX0, &sd)])
    }

    fn response(status: u64, token: Option<Vec<u8>>) -> Vec<u8> {
        let mut status_info = vec![integer_u64(status)];
        if status != 0 {
            status_info.push(sequence(&[&tlv(0x0c, b"nope")]));
        }
        let refs: Vec<&[u8]> = status_info.iter().map(Vec::as_slice).collect();
        let mut parts = vec![sequence(&refs)];
        parts.extend(token);
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        sequence(&refs)
    }

    #[test]
    fn token_parsing_and_imprint_check() {
        let sig = [7u8; 128];
        let imprint = alg().digest(&sig);
        let tok = TimeStampToken::from_der(&fake_token(&imprint, Some(&[0x05]))).unwrap();
        assert_eq!(tok.policy, oid::TSA_POLICY_GOST2015);
        assert_eq!(tok.serial, vec![42]);
        assert_eq!(tok.nonce, Some(vec![5]));
        assert_eq!(tok.gen_time.unix_timestamp(), 1_790_942_400);
        tok.check_imprint(&sig).unwrap();
        assert!(tok.check_imprint(&[8u8; 128]).is_err());
    }

    #[test]
    fn response_status_handling() {
        let imprint = alg().digest(&[1u8; 128]);
        let granted =
            TimeStampResponse::from_der(&response(0, Some(fake_token(&imprint, None)))).unwrap();
        assert_eq!(granted.status, 0);
        assert!(granted.granted().is_ok());
        let rejected = TimeStampResponse::from_der(&response(2, None)).unwrap();
        assert_eq!(rejected.status_text, vec!["nope".to_string()]);
        assert!(matches!(rejected.granted(), Err(Error::Tsp(_))));
    }

    #[test]
    fn timestamp_attribute_is_added_as_unsigned_attr() {
        let cms = include_bytes!("../../../tests/fixtures/test_gost512.attached.cms");
        let sd = SignedData::from_der(cms).unwrap();
        let sig = sd.signer_infos[0].signature.clone();
        let tok = TimeStampToken::from_der(&fake_token(&alg().digest(&sig), None)).unwrap();
        let out = add_timestamp_token(cms, 0, &tok).unwrap();
        let sd2 = SignedData::from_der(&out).unwrap();
        let si = &sd2.signer_infos[0];
        assert!(si.has_timestamp());
        assert_eq!(si.unsigned_attrs.len(), 1);
        assert_eq!(si.unsigned_attrs[0].values[0], tok.der);
        // Signed part untouched → still verifies, and the report carries the token.
        let r = crate::verify::verify(&out, crate::verify::Content::Attached, &[]).unwrap();
        assert_eq!(r[0].timestamp.as_ref().unwrap().serial, vec![42]);
        // Adding a second attribute keeps the first.
        let out2 = add_timestamp_token(&out, 0, &tok).unwrap();
        assert_eq!(
            SignedData::from_der(&out2).unwrap().signer_infos[0]
                .unsigned_attrs
                .len(),
            2
        );
        // A token over a different signature is refused.
        let bad = TimeStampToken::from_der(&fake_token(&alg().digest(b"x"), None)).unwrap();
        assert!(add_timestamp_token(cms, 0, &bad).is_err());
    }

    /// Live request to the NCA TSA; run with `cargo test -p kz-cms -- --ignored`.
    #[test]
    #[ignore = "needs network access to tsp.pki.gov.kz"]
    fn nca_tsa_grants_signature_timestamp() {
        let cms = include_bytes!("../../../tests/fixtures/test_gost512.attached.cms");
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
        let out = add_cades_t(
            cms,
            &TsaClient::nca().timeout(Duration::from_secs(20)),
            &mut rng,
        )
        .unwrap();
        let r = crate::verify::verify(&out, crate::verify::Content::Attached, &[]).unwrap();
        let ts = r[0].timestamp.as_ref().expect("timestamp present");
        assert_eq!(ts.imprint_algorithm, kz_pki::oid::GOST2015_512_HASH);
        eprintln!(
            "TSA genTime {} policy {} serial {}",
            ts.gen_time,
            ts.policy,
            hex_lower(&ts.serial)
        );
    }

    fn hex_lower(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
