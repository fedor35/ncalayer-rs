//! Deterministic nonce generation in the spirit of RFC 6979 §3.2, using
//! HMAC over Streebog (256 for 32-byte scalars, 512 for 64-byte scalars).
//!
//! This is *not* an interoperability format — no standard defines RFC 6979
//! for GOST — it only makes `k` a deterministic function of `(d, e)` so that
//! a broken system RNG cannot leak the private key.

use digest::{KeyInit, Mac};
use hmac::Hmac;
use streebog::{Streebog256, Streebog512};

use crate::curve::{from_be_bytes, to_be_bytes, Curve};
use crate::U512;

enum Prf {
    H256(Hmac<Streebog256>),
    H512(Hmac<Streebog512>),
}

fn prf(key: &[u8], chunks: &[&[u8]]) -> Vec<u8> {
    let mut mac = if key.len() == 32 {
        Prf::H256(Hmac::<Streebog256>::new_from_slice(key).expect("any key length is valid"))
    } else {
        Prf::H512(Hmac::<Streebog512>::new_from_slice(key).expect("any key length is valid"))
    };
    for c in chunks {
        match &mut mac {
            Prf::H256(m) => m.update(c),
            Prf::H512(m) => m.update(c),
        }
    }
    match mac {
        Prf::H256(m) => m.finalize().into_bytes().to_vec(),
        Prf::H512(m) => m.finalize().into_bytes().to_vec(),
    }
}

/// HMAC-DRBG state (RFC 6979 §3.2 steps b–h).
pub(crate) struct NonceGen<'a> {
    curve: &'a Curve,
    k: Vec<u8>,
    v: Vec<u8>,
}

impl<'a> NonceGen<'a> {
    /// Seed with `d` (secret scalar) and `e` (already reduced modulo `q`).
    pub(crate) fn new(curve: &'a Curve, d: &U512, e: &U512) -> Self {
        let len = curve.coordinate_len();
        let x = to_be_bytes(d, len);
        let h1 = to_be_bytes(e, len);
        let mut k = vec![0u8; len];
        let mut v = vec![1u8; len];
        k = prf(&k, &[&v, &[0u8], &x, &h1]);
        v = prf(&k, &[&v]);
        k = prf(&k, &[&v, &[1u8], &x, &h1]);
        v = prf(&k, &[&v]);
        NonceGen { curve, k, v }
    }

    /// Next candidate `k` in `[1, q-1]`.
    pub(crate) fn next_k(&mut self) -> U512 {
        let qlen_bytes = self.curve.coordinate_len();
        let qbits = self.curve.order_bits();
        loop {
            let mut t = Vec::with_capacity(qlen_bytes);
            while t.len() < qlen_bytes {
                self.v = prf(&self.k, &[&self.v]);
                t.extend_from_slice(&self.v);
            }
            t.truncate(qlen_bytes);
            // bits2int: keep the leftmost qbits bits.
            let mut cand = from_be_bytes(&t);
            let excess = (qlen_bytes as u32) * 8 - qbits;
            if excess > 0 {
                cand = cand.shr_vartime(excess);
            }
            // Prepare the state for the next candidate regardless of outcome.
            self.k = prf(&self.k, &[&self.v, &[0u8]]);
            self.v = prf(&self.k, &[&self.v]);
            if self.curve.is_valid_scalar(&cand) {
                return cand;
            }
        }
    }
}
