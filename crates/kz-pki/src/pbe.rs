//! Password-based decryption used inside PKCS#12: the legacy PKCS#12 PBE
//! schemes (RFC 7292 Appendix C) and PBES2 (RFC 8018).

use cipher::block_padding::Pkcs7;
use cipher::{BlockModeDecrypt, InnerIvInit, KeyIvInit};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use pkcs12::pbe_params::Pkcs12PbeParams;
use sha1::Sha1;
use spki::AlgorithmIdentifierOwned;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::oid;

/// Decrypt `ciphertext` under `alg` (an `AlgorithmIdentifier` of a PBE scheme)
/// with `password`.
pub fn decrypt(
    alg: &AlgorithmIdentifierOwned,
    password: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    match alg.oid {
        oid::PBE_SHA1_3DES => {
            let (key, iv) = pkcs12_kdf(alg, password, 24)?;
            cbc_decrypt(
                cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)?,
                ciphertext,
            )
        }
        oid::PBE_SHA1_2DES => {
            let (key, iv) = pkcs12_kdf(alg, password, 16)?;
            cbc_decrypt(
                cbc::Decryptor::<des::TdesEde2>::new_from_slices(&key, &iv)?,
                ciphertext,
            )
        }
        oid::PBE_SHA1_RC2_128 => rc2_decrypt(alg, password, 16, 128, ciphertext),
        oid::PBE_SHA1_RC2_40 => rc2_decrypt(alg, password, 5, 40, ciphertext),
        oid::PBES2 => {
            let scheme = pkcs5::EncryptionScheme::from_der(&alg.to_der()?)?;
            Ok(scheme.decrypt(password.as_bytes(), ciphertext)?)
        }
        other => Err(Error::UnsupportedAlgorithm(other)),
    }
}

/// Legacy PKCS#12 PBE schemes this module can encrypt with (what Kalkan writes:
/// 3DES for the key bag, 40-bit RC2 for the certificate `EncryptedData`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptScheme {
    /// `pbeWithSHAAnd3-KeyTripleDES-CBC`.
    Sha1TripleDes,
    /// `pbeWithSHAAnd40BitRC2-CBC`.
    Sha1Rc2_40,
}

/// Encrypt `plaintext` under a legacy PKCS#12 PBE scheme with the given salt and iteration
/// count. Returns the DER `AlgorithmIdentifier` and the ciphertext.
pub fn encrypt(
    scheme: EncryptScheme,
    password: &str,
    salt: &[u8],
    iterations: u32,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    use crate::derw;
    use cipher::BlockModeEncrypt;
    let it = i32::try_from(iterations)
        .map_err(|_| Error::Asn1("iteration count out of range".into()))?;
    let alg_oid = match scheme {
        EncryptScheme::Sha1TripleDes => oid::PBE_SHA1_3DES,
        EncryptScheme::Sha1Rc2_40 => oid::PBE_SHA1_RC2_40,
    };
    let key_len = match scheme {
        EncryptScheme::Sha1TripleDes => 24,
        EncryptScheme::Sha1Rc2_40 => 5,
    };
    let key = Zeroizing::new(derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::EncryptionKey,
        it,
        key_len,
    )?);
    let iv = derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::Iv, it, 8)?;
    let ct = match scheme {
        EncryptScheme::Sha1TripleDes => {
            cbc::Encryptor::<des::TdesEde3>::new_from_slices(&key, &iv)?
                .encrypt_padded_vec::<Pkcs7>(plaintext)
        }
        EncryptScheme::Sha1Rc2_40 => {
            let cipher = rc2::Rc2::new_with_eff_key_len(&key, 40);
            cbc::Encryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)?
                .encrypt_padded_vec::<Pkcs7>(plaintext)
        }
    };
    let params = derw::sequence(&[
        &derw::octet_string(salt),
        &derw::integer_u64(iterations.into()),
    ]);
    let alg = derw::sequence(&[&derw::oid(&alg_oid), &params]);
    Ok((alg, ct))
}

fn pkcs12_kdf(
    alg: &AlgorithmIdentifierOwned,
    password: &str,
    key_len: usize,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let params = alg
        .parameters
        .as_ref()
        .ok_or_else(|| Error::Asn1("missing PKCS#12 PBE parameters".into()))?;
    let params: Pkcs12PbeParams = params.decode_as()?;
    let salt = params.salt.as_bytes();
    let key = derive_key_utf8::<Sha1>(
        password,
        salt,
        Pkcs12KeyType::EncryptionKey,
        params.iterations,
        key_len,
    )?;
    let iv = derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::Iv, params.iterations, 8)?;
    Ok((Zeroizing::new(key), iv))
}

fn rc2_decrypt(
    alg: &AlgorithmIdentifierOwned,
    password: &str,
    key_len: usize,
    eff_bits: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (key, iv) = pkcs12_kdf(alg, password, key_len)?;
    let cipher = rc2::Rc2::new_with_eff_key_len(&key, eff_bits);
    let dec = cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(cipher, &iv)?;
    cbc_decrypt(dec, ciphertext)
}

fn cbc_decrypt<M: BlockModeDecrypt>(dec: M, ciphertext: &[u8]) -> Result<Vec<u8>> {
    dec.decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("bad padding (wrong password or corrupt data)".into()))
}

impl From<cipher::InvalidLength> for Error {
    fn from(_: cipher::InvalidLength) -> Self {
        Error::Decrypt("invalid key/IV length".into())
    }
}

/// Whether `oid` names a PBE scheme this module can handle.
pub fn is_supported(oid: &ObjectIdentifier) -> bool {
    matches!(
        *oid,
        oid::PBE_SHA1_3DES
            | oid::PBE_SHA1_2DES
            | oid::PBE_SHA1_RC2_128
            | oid::PBE_SHA1_RC2_40
            | oid::PBES2
    )
}
