#![no_std]

use rand_core::RngCore;

pub mod wire;
pub mod algorithms;
pub mod reliability;
pub mod noalloc;

use wire::Request;
use wire::RequestSecret;
use wire::Response;
use wire::Writer;
use wire::Datagram;
use wire::is_expected_recipient;

use reliability::ReliableConnection;
use reliability::Length;
pub use reliability::MessageNum;

/// fn(id, salt, out_hash)
pub type Hash = fn(&[u8], &[u8], &mut [u8]);

/// fn(in_public_key, out_private_key)
pub type AsymKeyDerive = fn(&[u8], &mut [u8]) -> Result<(), Error>;

/// fn(private_key, in_out_data)
pub type AsymDecrypt = fn(&[u8], &mut [u8]) -> Result<(), Error>;

/// fn(public_key, in_out_data, rng)
pub type AsymEncrypt = fn(&[u8], &mut [u8], &mut dyn RngCore) -> Result<(), Error>;

/// fn(key, in_out_data)
pub type CipherDecrypt = fn(&[u8], &mut [u8]) -> Result<(), Error>;

/// fn(key, in_out_data, rng)
pub type CipherEncrypt = fn(&[u8], &mut [u8], &mut dyn RngCore) -> Result<(), Error>;

const PREFIX_LEN: usize = 4;

#[derive(Copy, Clone)]
pub struct Version {
    pub request_prefix: &'static [u8],
    pub response_prefix: &'static [u8],
    pub continue_prefix: &'static [u8],
    pub message_prefix: &'static [u8],

    pub hash_salt_len: usize,
    pub hashed_id_len: usize,
    pub identity_hasher: Hash,

    pub cipher_nonce_len: usize,
    pub cipher_tag_len: usize,
    pub cipher_encrypt: CipherEncrypt,
    pub cipher_decrypt: CipherDecrypt,

    pub seed_len: usize,
    pub identity_len: usize,
    pub buffer_size_len: usize,
    pub app_proto_len: usize,

    pub public_key_len: usize,
    pub private_key_len: usize,
    pub asym_encryptor: AsymEncrypt,
    pub asym_decryptor: AsymDecrypt,
    pub asym_derive: AsymKeyDerive,
}

pub const VERSIONS: [Version; 1] = [Version {
    request_prefix: &[b'H', b'E', b'Y', 0],
    response_prefix: &[b'T', b'H', b'X', 0],
    continue_prefix: &[b'B', b'Y', b'E', 0],
    message_prefix: &[b'T', b'I', b'L', 0],

    hash_salt_len: 16,
    hashed_id_len: 32,
    identity_hasher: algorithms::sha256_hash,

    cipher_nonce_len: algorithms::CHACHA_NONCE_LENGTH,
    cipher_tag_len: algorithms::CHACHA_TAG_LENGTH,
    cipher_encrypt: algorithms::chacha20poly1305_encrypt,
    cipher_decrypt: algorithms::chacha20poly1305_decrypt,

    seed_len: 8,
    identity_len: 8,
    buffer_size_len: 6,
    app_proto_len: 4,

    public_key_len: algorithms::ECIES_KEY_LENGTH,
    private_key_len: algorithms::ECIES_KEY_LENGTH,
    asym_encryptor: algorithms::ecies_encrypt,
    asym_decryptor: algorithms::ecies_decrypt,
    asym_derive: algorithms::ecies_derive,
}];

impl Version {
    pub const fn encryption_overhead(&self) -> usize {
        0 + self.public_key_len + self.cipher_nonce_len + self.cipher_tag_len
    }

    pub const fn request_len(&self) -> usize {
        PREFIX_LEN
            + self.hash_salt_len
            + self.hashed_id_len
            + self.encryption_overhead()
            + self.request_secret_len()
    }

    pub const fn response_len(&self) -> usize {
        PREFIX_LEN
            + self.encryption_overhead()
            + self.seed_len
            + self.buffer_size_len
    }

    pub const fn request_secret_len(&self) -> usize {
        0
            + self.seed_len
            + self.identity_len
            + self.public_key_len
            + self.buffer_size_len
            + self.app_proto_len
    }

    pub const fn payload_len(&self, secret: &[u8]) -> Result<usize, Error> {
        match secret.len().checked_sub(self.encryption_overhead()) {
            Some(len) => Ok(len),
            None => Err(Error::TooShort),
        }
    }

    pub const fn cipher_overhead(&self) -> usize {
        0 + self.cipher_nonce_len + self.cipher_tag_len
    }

    pub const fn cipher_key_len(&self) -> usize {
        self.seed_len * 2
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Error {
    UnknownHandshakeProtocol,
    UnknownSender(u64),
    InvalidSenderId,
    InvalidPublicKey,
    IllegalPeerOperation,
    UnresponsivePeer,
    NeedServerIdentity,
    LostBytes,
    CannotDecrypt,
    CannotEncrypt,
    TooShort,
}

pub fn split_at<'a>(slice: &'a [u8], i: usize, len: usize) -> Result<(&'a [u8], &'a [u8]), Error> {
    match slice.get(..len) {
        Some(_) => Ok(slice.split_at(i)),
        None => Err(Error::TooShort),
    }
}

pub fn split_at_mut<'a>(
    slice: &'a mut [u8],
    i: usize,
    len: usize,
) -> Result<(&'a mut [u8], &'a mut [u8]), Error> {
    match slice.get_mut(..len) {
        Some(_) => Ok(slice.split_at_mut(i)),
        None => Err(Error::TooShort),
    }
}

/// Utility function to use with usize::from_be_bytes
pub fn try_read<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    let mut result = [0; N];
    let mut i = 0;
    for b in bytes.get(..N).ok_or(Error::TooShort)? {
        result[i] = *b;
        i += 1;
    }
    Ok(result)
}

pub trait Identity: Clone {
    fn number(&self) -> Option<u64>;
    fn private_key(&self) -> Option<&[u8]>;
    fn public_key(&self) -> Option<&[u8]>;
    fn new(
        number: Option<u64>,
        private_key: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Self, ()>;
}

#[derive(Debug, Copy, Clone)]
pub enum MessageType<'a> {
    Outgoing(&'a [u8]),
    Incoming(usize),
}

pub trait Message {
    fn new(msg_type: MessageType) -> Result<Self, ()> where Self: Sized;
    fn get_mut(&mut self, offset: usize, length: usize) -> Option<&mut [u8]>;
    fn part_transmitted(&mut self, offset: usize, length: usize);
    fn tell(&mut self) -> (usize, usize, bool);
    fn seek_transfer(&mut self, offset: usize);
    fn advance(&mut self, length: usize) -> (usize, &[u8]);
    fn message_num(&self) -> MessageNum;
    fn set_message_num(&mut self, num: MessageNum);
    fn pause(&mut self);
    fn resume(&mut self);
    fn is_paused(&self) -> bool;
    fn is_transfer_complete(&self) -> bool;
}

pub trait MessageStorage {
    type Msg: Message;
    fn outgoing(&mut self) -> &mut [Self::Msg];
    fn incoming(&mut self) -> &mut [Self::Msg];
}

pub enum ClientIdentity<I: Identity> {
    Anonymous,
    Registered(I),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Reaction {
    Ignore,
    OutgoingMessageReceived(MessageNum),
    IncomingMessageReceived(MessageNum),
    AllocateMessage(MessageNum, Length),
    MessageRefused(MessageNum),
}

pub struct Connection<I: Identity, M: MessageStorage, const K: usize> {
    established: bool,
    messages: M,
    identity: Option<I>,
    versions: &'static [Version],
    version: Option<usize>,
    peer: Option<I>,
    max_datagram_size: Option<usize>,
    peer_max_dg_size: Option<usize>,
    app_protocol: Option<u32>,
    client: bool,
    cipher_key: [u8; K],
    reliability: ReliableConnection,
    outgoing_msg: usize,
}

impl<I: Identity, M: MessageStorage, const K: usize> Connection<I, M, K> {
    pub fn new_server<R: RngCore>(
        versions: &'static [Version],
        messages: M,
        max_datagram_size: Option<usize>,
        rng: &mut R,
    ) -> Self {
        let mut cipher_key = [0; K];
        rng.fill_bytes(&mut cipher_key);

        for version in versions {
            assert!(version.cipher_key_len() <= K, "K is too small");
        }

        Self {
            established: false,
            identity: None,
            messages,
            versions,
            version: None,
            peer: None,
            max_datagram_size,
            peer_max_dg_size: None,
            app_protocol: None,
            client: false,
            cipher_key,
            reliability: ReliableConnection::new(),
            outgoing_msg: 0,
        }
    }

    pub fn new_client<R: RngCore>(
        version: &'static [Version; 1],
        identity: ClientIdentity<I>,
        messages: M,
        peer: I,
        max_datagram_size: Option<usize>,
        app_protocol: u32,
        rng: &mut R,
    ) -> Result<Self, Error> {

        let identity_opt = match identity {
            ClientIdentity::Registered(identity) => Some(identity),
            ClientIdentity::Anonymous => {
                assert_eq!(K, version[0].private_key_len);
                let private = &mut [0; K][..version[0].private_key_len];
                let  public = &mut [0; K][..version[0].public_key_len];
                rng.fill_bytes(private);
                (version[0].asym_derive)(private, public)?;
                let identity = I::new(None, Some(&private), Some(&public));
                Some(identity.ok().ok_or(Error::TooShort)?)
            },
        };

        let mut cipher_key = [0; K];
        rng.fill_bytes(&mut cipher_key);

        Ok(Self {
            established: false,
            identity: identity_opt,
            messages,
            versions: version,
            version: Some(0),
            peer: Some(peer),
            max_datagram_size,
            peer_max_dg_size: None,
            app_protocol: Some(app_protocol),
            client: true,
            cipher_key,
            reliability: ReliableConnection::new(),
            outgoing_msg: 0,
        })
    }

    pub fn init_client<R: RngCore>(
        &self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        assert!(self.client);
        let version = &self.versions[self.version.unwrap()];
        Writer::write_request(
            version,
            self.peer.as_ref().unwrap(),
            self.identity.as_ref().unwrap(),
            self.max_datagram_size.map(|s| s as u64),
            &self.cipher_key[..version.seed_len],
            self.app_protocol.unwrap(),
            to_send,
            rng,
        )
    }

    fn send_handshake_response<R: RngCore>(
        &mut self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        let version = &self.versions[self.version.unwrap()];
        let cipher_contrib = version.seed_len..version.cipher_key_len();
        Writer::write_response(
            version,
            self.peer.as_ref().unwrap(),
            &self.cipher_key[cipher_contrib],
            self.max_datagram_size.map(|s| s as u64),
            to_send,
            rng,
        )
    }

    fn set_peer_seed(&mut self, seed: &[u8], peer_is_client: bool) {
        let seed_len = self.versions[self.version.unwrap()].seed_len;
        let offset = match peer_is_client {
            true => 0,
            false => seed_len,
        };
        for i in 0..seed_len {
            self.cipher_key[i + offset] = seed[i];
        }
    }

    pub fn on_timeout<R: RngCore>(
        &mut self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<Option<usize>, Error> {
        self.outgoing_msg = 0;

        if self.established {
            self.reliability.on_timeout(to_send)
        } else if self.client {
            Ok(Some(self.init_client(to_send, rng)?))
        } else if self.peer.is_some() {
            // we wait for the client to reply forever
            Ok(None)
        } else {
            // we wait for the client to introduce
            // itself forever
            Ok(None)
        }
    }

    pub fn on_datagram<R: RngCore>(
        &mut self,
        received: &mut [u8],
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<(Option<usize>, Reaction), Error> {
        self.outgoing_msg = 0;

        let (datagram, v) = Datagram::parse(&self.versions, received, &self.identity)?;
        match self.version {
            None => self.version = Some(v),
            Some(p) if p == v => (),
            _ => return Ok((None, Reaction::Ignore)),
        };

        match (datagram, self.client) {
            (Datagram::Request(request), false) => if let Some(identity) = &self.identity {

                let version = &self.versions[v];

                let request = RequestSecret::decrypt(
                    version,
                    request.secret,
                    identity,
                )?;

                if let Some(_client_id) = request.client_id {
                    // todo: lookup client, check matching id & public key
                } else {
                    let identity = I::new(None, None, Some(request.client_public_key)).ok();
                    self.peer = Some(identity.ok_or(Error::TooShort)?);
                }

                self.peer_max_dg_size = request.client_buf_size.map(|s| s as usize);
                self.app_protocol = Some(request.session_protocol_id);

                self.set_peer_seed(request.client_seed, true);

                let result = self.send_handshake_response(to_send, rng)?;
                Ok((Some(result), Reaction::Ignore))

            } else {

                Err(Error::NeedServerIdentity)

            },
            (Datagram::Response(response), true) => {

                self.peer_max_dg_size = response.server_buf_size.map(|s| s as usize);
                self.established = true;

                self.set_peer_seed(response.server_seed, false);

                let result = Writer::write_continue::<I>(
                    &self.versions[self.version.unwrap()],
                    to_send,
                )?;
                Ok((Some(result), Reaction::Ignore))

            },
            (Datagram::Message(message), _) => {

                let version = &self.versions[self.version.unwrap()];
                let payload_len = version.payload_len(message)?;

                let key = &self.cipher_key[..version.cipher_key_len()];
                (version.cipher_decrypt)(key, message)?;
                let message = &mut message[..payload_len];

                let (len, reaction) = self.reliability.on_datagram(
                    message,
                    to_send,
                    &mut self.messages,
                    usize::MAX,
                    usize::MAX,
                )?;

                if let Some(mut len) = len {
                    len += version.encryption_overhead();
                    (version.cipher_encrypt)(key, &mut to_send[..len], rng)?;
                    Ok((Some(len), reaction))
                } else {
                    Ok((None, reaction))
                }

            }
            _ => Ok((None, Reaction::Ignore)),

        }
    }

    pub fn find_server_identity(
        &mut self,
        received: &mut [u8],
        scratch: &mut [u8],
        identities: &[I],
    ) -> Result<bool, Error> {
        let version = &self.versions[self.version.unwrap()];

        let request = match Datagram::parse::<I>(&[*version], received, &None)? {
            (Datagram::Request(request), _) => request,
            _ => panic!("Please wait for Reaction::NeedServerIdentity before using find_server_identity"),
        };

        for identity in identities {
            let tested_id = identity.number().unwrap();
            let result = is_expected_recipient(
                version,
                request.hash_salt,
                request.hashed_server_id,
                &tested_id.to_be_bytes(),
                scratch,
            );
            if result {
                self.identity = Some(identity.clone());
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn other_datagram<'a, R: RngCore>(
        &'a mut self,
        to_send: &'a mut [u8],
        rng: &'a mut R,
    ) -> Result<Option<usize>, Error> {
        let version = &self.versions[self.version.unwrap()];
        let messages = self.messages.outgoing();
        let message = match messages.get_mut(self.outgoing_msg) {
            Some(message) => message,
            None => return Ok(None),
        };
        self.outgoing_msg += 1;

        let mut len = self.reliability.continue_message_transfer(
            to_send,
            message,
        )?;

        let key = &self.cipher_key[..version.cipher_key_len()];
        Ok(if let Some(len) = len {
            Some(Writer::write_message(
                version,
                len,
                key,
                to_send,
                rng,
            )?)
        } else { None })
    }
}
