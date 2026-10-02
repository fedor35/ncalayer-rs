//! CMS / CAdES methods of `commonUtils` and `basics.sign(format = "cms")`, built on `kz-cms`.
//!
//! Which variant adds a TSA time stamp follows the Java `CommonUtils` byte code:
//! * `createCMSSignatureFromBase64` / `createCMSSignatureFromFile` → CAdES-T (TSP always);
//! * `createCAdESFromBase64` / `createCAdESFromFile` / `createCAdESFromBase64Hash` → CAdES-BES;
//! * `applyCAdEST` → adds the time stamp to an existing CMS;
//! * `basics.sign` → TSP only when `signingParams.tsaProfile` is present.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use kz_cms::tsp::{TsaClient, NCA_TSA_URL};
use kz_pki::Entry;
use time::OffsetDateTime;

pub struct CmsRequest<'a> {
    pub data: &'a [u8],
    pub attached: bool,
    /// `data` is already a digest (`createCAdESFromBase64Hash`, `digested: true`).
    pub digested: bool,
    pub timestamp: bool,
}

/// Sign and base64-encode. TSP is blocking HTTP, so this must run on a blocking thread.
pub fn sign_blocking(entry: &Entry, req: &CmsRequest<'_>) -> Result<String> {
    let mut rng = rand::rng();
    let now = OffsetDateTime::now_utc();
    let mut cms = if req.digested {
        kz_cms::create_cades_bes_from_hash(entry, req.data, now, &mut rng)?
    } else {
        kz_cms::create_cades_bes(entry, req.data, req.attached, now, &mut rng)?
    };
    if req.timestamp {
        cms = kz_cms::add_cades_t(&cms, &TsaClient::new(NCA_TSA_URL), &mut rng).context("TSA")?;
    }
    Ok(B64.encode(cms))
}

/// `applyCAdEST(storage, keyType, base64 cms)`: add a time stamp to every signer lacking one.
pub fn apply_cades_t_blocking(cms_b64: &str) -> Result<String> {
    let cms = B64
        .decode(cms_b64.trim())
        .map_err(|e| anyhow!("bad base64: {e}"))?;
    let mut rng = rand::rng();
    let out = kz_cms::add_cades_t(&cms, &TsaClient::new(NCA_TSA_URL), &mut rng).context("TSA")?;
    Ok(B64.encode(out))
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>> {
    B64.decode(s.trim()).map_err(|e| anyhow!("bad base64: {e}"))
}
