use core::mem::size_of;
use rand_core::RngCore;

use crate::Version;
use crate::Error;
use crate::split_at;
use crate::split_at_mut;
use crate::try_read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderIdentity<'a> {
    /// Send a temporary public key
    AnonClient(&'a [u8]),
    /// Send identity key bytes
    Registered(&'a [u8]),
}

pub struct Handshake;

impl Handshake {
    pub fn write_request(
        v: &Version,
        to_send: &mut [u8],
        rng: &mut dyn RngCore,
        sender_id: &SenderIdentity,
        peer_id: &[u8],
        peer_public_key: &[u8],
        buf_size: Option<u64>,
        app_proto: u32,
        seed: &[u8],
    ) -> Result<(), Error> {
        assert_eq!(seed.len(), v.seed_len);

        let anon_sender = match sender_id {
            SenderIdentity::Registered(_) => false,
            SenderIdentity::AnonClient(_) => true,
        };
        let len = v.request_len(anon_sender);

        let to_send = to_send.get_mut(..len).expect("to_send is too small");
        let (hs_prefix, to_send) = to_send.split_at_mut(size_of::<u32>());
        let (hash_salt, to_send) = to_send.split_at_mut(v.hash_salt_len);
        let (hashed_id, secret) = to_send.split_at_mut(v.hashed_id_len);

        let hs_prefix_src = match anon_sender {
            true => v.handshake_inc_id_prefix,
            false => v.handshake_exc_id_prefix,
        };
        hs_prefix.copy_from_slice(&hs_prefix_src);

        rng.fill_bytes(hash_salt);
        (v.identity_hasher)(peer_id, hash_salt, hashed_id);

        {
            let buf_size_bytes = buf_size.unwrap_or(0).to_be_bytes();

            let (seed_spot, secret) = secret.split_at_mut(v.seed_len);
            let (sender, secret) = secret.split_at_mut(v.sender_len(anon_sender));
            let (buf_size, app_proto_id) = secret.split_at_mut(6);

            let sender_bytes = match sender_id {
                SenderIdentity::AnonClient(b) => b,
                SenderIdentity::Registered(b) => b,
            };

            sender.copy_from_slice(sender_bytes);
            app_proto_id.copy_from_slice(&app_proto.to_be_bytes());
            buf_size.copy_from_slice(&buf_size_bytes[2..]);
            seed_spot.copy_from_slice(seed);
        }

        (v.asym_encryptor)(peer_public_key, secret, rng)
    }

    pub fn parse_request<'a>(
        v: &Version,
        received: &'a mut [u8],
    ) -> Result<(&'a [u8], &'a [u8], &'a mut [u8]), Error> {
        let received = &mut received[v.handshake_inc_id_prefix.len()..];

        let len = v.hash_salt_len + v.hashed_id_len;
        let (hash_salt, received) = split_at_mut(received, v.hash_salt_len, len)?;
        let (hashed_id, secret) = received.split_at_mut(v.hashed_id_len);

        Ok((hash_salt, hashed_id, secret))
    }

    pub fn is_expected_recipient(
        v: &Version,
        hash_salt: &[u8],
        hashed_id: &[u8],
        tested_id: &[u8],
        scratch: &mut [u8],
    ) -> bool {
        let scratch = &mut scratch[..v.hashed_id_len];
        (v.identity_hasher)(tested_id, hash_salt, scratch);
        scratch == hashed_id
    }

    pub fn decrypt_request_secret<'a>(
        v: &Version,
        secret: &'a mut [u8],
        private_key: &[u8],
        anon_sender: bool,
    ) -> Result<(&'a [u8], SenderIdentity<'a>, Option<u64>, u32), Error> {
        let len = v.request_secret_len(anon_sender);
        assert_eq!(v.buffer_size_len, 6);
        assert_eq!(v.app_proto_len, 4);

        (v.asym_decryptor)(private_key, secret)?;

        let (s, secret) = split_at(secret, v.seed_len, len)?;
        let (id, secret) = secret.split_at(v.sender_len(anon_sender));
        let (c, secret) = secret.split_at(6);
        let (d, _) = secret.split_at(4);

        let mut buf_size_bytes = [0; 8];
        buf_size_bytes[2..].copy_from_slice(c);
        let b = u64::from_be_bytes(buf_size_bytes);
        let b = match b {
            0 => None,
            _ => Some(b),
        };

        let p = u32::from_be_bytes(try_read(d)?);

        Ok(match anon_sender {
            true => (s, SenderIdentity::AnonClient(id), b, p),
            false => (s, SenderIdentity::Registered(id), b, p),
        })
    }

    pub fn write_response(
        v: &Version,
        to_send: &mut [u8],
        peer_public_key: &[u8],
        rng: &mut dyn RngCore,
        buf_len: Option<u64>,
        seed: &[u8],
    ) -> Result<(), Error> {
        assert_eq!(seed.len(), v.seed_len);

        let to_send = &mut to_send[..v.response_len()];

        {
            let buf_len = buf_len.unwrap_or(0);
            let buf_len_bytes = &buf_len.to_be_bytes()[2..];

            let (seed_spot, to_send) = to_send.split_at_mut(v.seed_len);
            let (buf_len, _) = to_send.split_at_mut(v.buffer_size_len);

            seed_spot.copy_from_slice(seed);
            buf_len.copy_from_slice(buf_len_bytes);
        }

        (v.asym_encryptor)(peer_public_key, to_send, rng)
    }

    pub fn parse_response<'a>(
        v: &Version,
        received: &'a mut [u8],
        private_key: &[u8],
    ) -> Result<(&'a [u8], Option<u64>), Error> {
        let received = match received.get_mut(..v.response_len()) {
            Some(slice) => Ok(slice),
            None => Err(Error::TooShort),
        }?;

        (v.asym_decryptor)(private_key, received)?;

        let (seed, received) = received.split_at(v.seed_len);
        let (buf_len, _) = received.split_at(v.buffer_size_len);

        let mut buf_len_bytes = [0; 8];
        buf_len_bytes[2..].copy_from_slice(buf_len);

        let buf_len = u64::from_be_bytes(buf_len_bytes);
        let buf_len = match buf_len {
            0 => None,
            _ => Some(buf_len),
        };

        Ok((seed, buf_len))
    }

    pub fn write_ready(v: &Version, to_send: &mut [u8]) {
        let to_send = &mut to_send[..v.handshake_suffix.len()];
        to_send.copy_from_slice(v.handshake_suffix);
    }

    pub fn parse_ready(v: &Version, received: &[u8]) -> bool {
        received.starts_with(v.handshake_suffix)
    }
}

pub fn handshake_protocol(
    versions: &[Version],
    received: &[u8]
) -> Result<(usize, bool), Error> {
    let prefix: [u8; 4] = try_read(received)?;
    for i in 0..versions.len() {
        if versions[i].handshake_inc_id_prefix == &prefix {
            return Ok((i, true));
        } else if versions[i].handshake_exc_id_prefix == &prefix {
            return Ok((i, false));
        }
    }
    Err(Error::UnknownHandshakeProtocol)
}
