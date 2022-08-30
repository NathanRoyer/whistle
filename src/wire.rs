use rand_core::RngCore;

use crate::PREFIX_LEN;
use crate::Version;
use crate::Identity;
use crate::Error;
use crate::split_at;
use crate::split_at_mut;
use crate::try_read;

#[derive(Debug)]
pub struct Request<'a> {
    pub hash_salt: &'a [u8],
    pub hashed_server_id: &'a [u8],
    pub secret: &'a mut [u8],
}

#[derive(Debug)]
pub struct RequestSecret<'a> {
    pub client_seed: &'a [u8],
    pub client_id: Option<u64>,
    pub client_public_key: &'a [u8],
    pub client_buf_size: Option<u64>,
    pub session_protocol_id: u32,
}

#[derive(Debug)]
pub struct Response<'a> {
    pub server_seed: &'a [u8],
    pub server_buf_size: Option<u64>,
}

#[derive(Debug)]
pub enum Datagram<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
    Continue,
    Message(&'a mut [u8]),
}

#[derive(Debug)]
pub struct Writer;

impl<'a> Datagram<'a> {
    pub fn parse<I: Identity>(
        versions: &[Version],
        datagram: &'a mut [u8],
        identity: &Option<I>,
    ) -> Result<(Self, usize), Error> {
        if datagram.len() >= 4 {
            let (prefix, payload) = datagram.split_at_mut(PREFIX_LEN);
            for i in 0..versions.len() {
                let version = versions[i];
                if version.request_prefix == prefix {
                    // client request

                    let len = version.hash_salt_len + version.hashed_id_len;
                    let (hash_salt, payload) = split_at_mut(payload, version.hash_salt_len, len)?;
                    let (hashed_server_id, secret) = payload.split_at_mut(version.hashed_id_len);

                    let request = Request {
                        hash_salt,
                        hashed_server_id,
                        secret,
                    };

                    return Ok((Self::Request(request), i));

                } else if version.response_prefix == prefix {
                    // server response

                    let payload_len = version.response_len() - PREFIX_LEN;
                    let payload = match payload.get_mut(..payload_len) {
                        Some(slice) => Ok(slice),
                        None => Err(Error::TooShort),
                    }?;

                    let errmsg = "Need to decrypt a server response, but identity didn't have a private key";
                    let client_private_key = identity.as_ref().expect(errmsg).private_key();
                    (version.asym_decryptor)(client_private_key.expect(errmsg), payload)?;

                    let (seed, payload) = payload.split_at(version.seed_len);
                    let (buf_size, _) = payload.split_at(version.buffer_size_len);

                    let mut buf_size_bytes = [0; 8];
                    buf_size_bytes[2..].copy_from_slice(buf_size);
                    let buf_size = u64::from_be_bytes(buf_size_bytes);
                    let server_buf_size = match buf_size {
                        0 => None,
                        _ => Some(buf_size),
                    };

                    let response = Response {
                        server_seed: seed,
                        server_buf_size,
                    };

                    return Ok((Self::Response(response), i));

                } else if version.continue_prefix == prefix {
                    // client says go

                    return Ok((Self::Continue, i));

                } else if version.message_prefix == prefix {
                    // peer sent a message

                    return Ok((Self::Message(payload), i));

                }
            }
            Err(Error::UnknownHandshakeProtocol)
        } else {
            Err(Error::TooShort)
        }
    }
}

impl Writer {
    fn split(dg: &mut [u8], len: usize) -> Result<(&mut [u8], &mut [u8]), Error> {
        if let Some(dg) = dg.get_mut(..len) {
            Ok(dg.split_at_mut(PREFIX_LEN))
        } else {
            Err(Error::TooShort)
        }
    }

    pub fn write_request<R: RngCore, I: Identity>(
        version: &Version,
        server_id: &I,
        client_id: &I,
        client_buf_size: Option<u64>,
        client_seed: &[u8],
        session_protocol_id: u32,
        datagram: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        let len = version.request_len();
        let (prefix, payload) = Self::split(datagram, len)?;
        prefix.copy_from_slice(version.request_prefix);

        let (hash_salt, payload) = payload.split_at_mut(version.hash_salt_len);
        let (hashed_server_id, secret) = payload.split_at_mut(version.hashed_id_len);
        {
            let buf_size_bytes = client_buf_size.unwrap_or(0).to_be_bytes();
            let client_id_bytes = client_id.number().unwrap_or(0).to_be_bytes();
            let key = client_id.public_key().expect("need client public key");

            let (seed_spot, secret) = secret.split_at_mut(version.seed_len);
            let (client_id, secret) = secret.split_at_mut(version.identity_len);
            let (client_key, secret) = secret.split_at_mut(version.public_key_len);
            let (buf_size, secret) = secret.split_at_mut(6);
            let (app_proto_id, _) = secret.split_at_mut(4);

            seed_spot.copy_from_slice(client_seed);
            client_id.copy_from_slice(&client_id_bytes);
            client_key.copy_from_slice(key);
            buf_size.copy_from_slice(&buf_size_bytes[2..]);
            app_proto_id.copy_from_slice(&session_protocol_id.to_be_bytes());
        }

        let server_num = server_id.number().expect("need server id & pub key");
        let server_key = server_id.public_key().expect("need server id & pub key");
        (version.asym_encryptor)(server_key, secret, rng)?;

        let server_num = server_num.to_be_bytes();
        rng.fill_bytes(hash_salt);
        (version.identity_hasher)(&server_num, hash_salt, hashed_server_id);

        Ok(len)
    }

    pub fn write_response<R: RngCore, I: Identity>(
        version: &Version,
        client_id: &I,
        server_seed: &[u8],
        server_buf_size: Option<u64>,
        datagram: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        let len = version.response_len();
        let (prefix, payload) = Self::split(datagram, len)?;
        prefix.copy_from_slice(version.response_prefix);

        assert_eq!(server_seed.len(), version.seed_len);
        {
            let buf_size = server_buf_size.unwrap_or(0);
            let buf_size_bytes = &buf_size.to_be_bytes()[2..];

            let (seed_spot, payload) = payload.split_at_mut(version.seed_len);
            let (buf_size, _) = payload.split_at_mut(version.buffer_size_len);

            seed_spot.copy_from_slice(server_seed);
            buf_size.copy_from_slice(buf_size_bytes);
        }

        let client_public_key = client_id.public_key().expect("need client pub key");
        (version.asym_encryptor)(client_public_key, payload, rng)?;

        Ok(len)
    }

    pub fn write_continue<I: Identity>(
        version: &Version,
        datagram: &mut [u8],
    ) -> Result<usize, Error> {
        let (prefix, _) = Self::split(datagram, PREFIX_LEN)?;
        prefix.copy_from_slice(version.continue_prefix);
        Ok(PREFIX_LEN)
    }

    pub fn write_message<R: RngCore>(
        version: &Version,
        message: usize,
        cipher_key: &[u8],
        in_out_datagram: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        in_out_datagram.copy_within(..message, PREFIX_LEN);
        let len = PREFIX_LEN + message + version.cipher_overhead();
        let (prefix, payload) = Self::split(in_out_datagram, len)?;
        prefix.copy_from_slice(version.message_prefix);

        (version.cipher_encrypt)(cipher_key, payload, rng)?;

        Ok(len)
    }
}

impl<'a> RequestSecret<'a> {
    pub fn decrypt<I: Identity>(
        v: &Version,
        secret: &'a mut [u8],
        server_id: &I,
    ) -> Result<Self, Error> {
        let len = v.request_secret_len();
        assert_eq!(v.buffer_size_len, 6);
        assert_eq!(v.app_proto_len, 4);

        let server_private_key = server_id.private_key().expect("need server private key");
        (v.asym_decryptor)(server_private_key, secret)?;

        let (client_seed, secret) = split_at(secret, v.seed_len, len)?;
        let (client_id, secret) = secret.split_at(v.identity_len);
        let (client_public_key, secret) = secret.split_at(v.public_key_len);
        let (buf_size, secret) = secret.split_at(6);
        let (session_protocol_id, _) = secret.split_at(4);

        let mut client_id_bytes = [0; 8];
        client_id_bytes.copy_from_slice(client_id);
        let client_id = u64::from_be_bytes(client_id_bytes);
        let client_id = match client_id {
            0 => None,
            _ => Some(client_id),
        };

        let mut buf_size_bytes = [0; 8];
        buf_size_bytes[2..].copy_from_slice(buf_size);
        let buf_size = u64::from_be_bytes(buf_size_bytes);
        let client_buf_size = match buf_size {
            0 => None,
            _ => Some(buf_size),
        };

        Ok(Self {
            client_seed,
            client_id,
            client_public_key,
            client_buf_size,
            session_protocol_id: u32::from_be_bytes(try_read(session_protocol_id)?),
        })
    }
}

/// ![...](https://l0.pm/is-for-me.jpg)
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
