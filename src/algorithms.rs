use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::aead::NewAead;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Tag;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use hkdf::Hkdf;

use sha2::Digest;
use sha2::Sha256;

use rand_core::RngCore;

use crate::Error;

use core::mem::size_of;

pub fn sha256_hash(id: &[u8], salt: &[u8], out: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(id);
    out[..32].copy_from_slice(&hasher.finalize());
}

pub const CHACHA_NONCE_LENGTH: usize = 12;
pub const CHACHA_TAG_LENGTH: usize = size_of::<Tag>();

const CHACHA_OVERHEAD: usize = CHACHA_TAG_LENGTH + CHACHA_NONCE_LENGTH;

pub fn chacha20poly1305_encrypt(
    shared_key: &[u8],
    buffer: &mut [u8],
    rng: &mut dyn RngCore,
) -> Result<(), Error> {
    let payload_len = match buffer.len().checked_sub(CHACHA_OVERHEAD) {
        Some(len) => Ok(len),
        None => Err(Error::TooShort),
    }?;
    let (payload, overhead) = buffer.split_at_mut(payload_len);

    let mut nonce = [0u8; CHACHA_NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);
    let nonce = GenericArray::from_slice(&nonce);

    let (nonce_spot, tag_spot) = overhead.split_at_mut(CHACHA_NONCE_LENGTH);
    nonce_spot.copy_from_slice(nonce);

    let shared_key = GenericArray::from_slice(&shared_key);
    let cipher = ChaCha20Poly1305::new(shared_key);

    let tag = cipher.encrypt_in_place_detached(nonce, b"", payload);
    if let Ok(tag) = tag {
        tag_spot.copy_from_slice(&tag);
        Ok(())
    } else {
        Err(Error::CannotEncrypt)
    }
}

pub fn chacha20poly1305_decrypt(shared_key: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    let payload_len = match buffer.len().checked_sub(CHACHA_OVERHEAD) {
        Some(len) => Ok(len),
        None => Err(Error::TooShort),
    }?;
    let (payload, overhead) = buffer.split_at_mut(payload_len);

    let shared_key = GenericArray::from_slice(&shared_key);
    let cipher = ChaCha20Poly1305::new(shared_key);

    let (nonce_spot, tag_spot) = overhead.split_at(CHACHA_NONCE_LENGTH);
    let nonce = GenericArray::from_slice(nonce_spot);
    let tag = GenericArray::from_slice(tag_spot);

    match cipher.decrypt_in_place_detached(nonce, b"", payload, tag) {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::CannotDecrypt),
    }
}

fn random_scalar(rng: &mut dyn RngCore) -> Scalar {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    Scalar::from_bits(key)
}

const ECIES_HKDF_INFO: &[u8; 13] = b"ecies-ed25519";
pub const ECIES_KEY_LENGTH: usize = 32;

pub fn ecies_derive(private_key: &[u8], out_public_key: &mut [u8]) -> Result<(), Error> {
    let mut key = [0u8; ECIES_KEY_LENGTH];
    key.copy_from_slice(private_key);
    let private_key = Scalar::from_bits(key);
    let public_key = &private_key * &ED25519_BASEPOINT_TABLE;
    let public_key = public_key.compress().to_bytes();
    out_public_key.copy_from_slice(&public_key);
    Ok(())
}

// public_key, nonce, payload, tag
pub fn ecies_encrypt(
    public_key: &[u8],
    buffer: &mut [u8],
    rng: &mut dyn RngCore,
) -> Result<(), Error> {
    let payload_len = match buffer.len().checked_sub(ECIES_KEY_LENGTH) {
        Some(len) => Ok(len),
        None => Err(Error::TooShort),
    }?;
    let (payload, pubkey_spot) = buffer.split_at_mut(payload_len);

    let peer_pk_point = {
        let p = CompressedEdwardsY::from_slice(public_key);
        p.decompress().ok_or(Error::InvalidPublicKey)?
    };
    // ephemeral keys
    let e_private_key = random_scalar(rng);
    let e_public_key = &e_private_key * &ED25519_BASEPOINT_TABLE;
    let e_public_key = e_public_key.compress();
    let e_public_key_bytes = e_public_key.as_bytes();

    pubkey_spot.copy_from_slice(e_public_key_bytes);

    let shared_point = (peer_pk_point * e_private_key).compress();
    let cipher_key = {
        let mut cipher_key = [0u8; 32];
        let mut shared_key = [0u8; 32 * 2];
        shared_key[..32].clone_from_slice(e_public_key_bytes);
        shared_key[32..].clone_from_slice(shared_point.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(None, &shared_key);
        let hkdf = hkdf.expand(ECIES_HKDF_INFO, &mut cipher_key);
        hkdf.ok().ok_or(Error::InvalidPublicKey)?;
        cipher_key
    };

    chacha20poly1305_encrypt(&cipher_key, payload, rng)
}

pub fn ecies_decrypt(private_key: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    let payload_len = match buffer.len().checked_sub(ECIES_KEY_LENGTH) {
        Some(len) => Ok(len),
        None => Err(Error::TooShort),
    }?;
    let (payload, e_public_key_bytes) = buffer.split_at_mut(payload_len);
    let peer_pk_point = {
        let p = CompressedEdwardsY::from_slice(e_public_key_bytes);
        p.decompress().ok_or(Error::InvalidPublicKey)?
    };

    let private_key = {
        let mut key = [0u8; 32];
        key.copy_from_slice(private_key);
        Scalar::from_bits(key)
    };

    let shared_point = (peer_pk_point * private_key).compress();
    let cipher_key = {
        let mut cipher_key = [0u8; 32];
        let mut shared_key = [0u8; 32 * 2];
        shared_key[..32].clone_from_slice(e_public_key_bytes);
        shared_key[32..].clone_from_slice(shared_point.as_bytes());
        let hkdf = Hkdf::<Sha256>::new(None, &shared_key);
        let hkdf = hkdf.expand(ECIES_HKDF_INFO, &mut cipher_key);
        hkdf.ok().ok_or(Error::InvalidPublicKey)?;
        cipher_key
    };

    chacha20poly1305_decrypt(&cipher_key, payload)
}
