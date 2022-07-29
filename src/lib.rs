#![no_std]

use core::mem::size_of;

use rand_core::RngCore;

pub mod handshake;
pub mod algorithms;
pub mod reliability;

use handshake::handshake_protocol;
use handshake::Handshake;
use handshake::SenderIdentity;

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

#[derive(Copy, Clone)]
pub struct Version {
    pub handshake_inc_id_prefix: &'static [u8],
    pub handshake_exc_id_prefix: &'static [u8],
    pub handshake_suffix: &'static [u8],

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
    handshake_inc_id_prefix: &[b'H', b'S', b'P', b'A'],
    handshake_exc_id_prefix: &[b'H', b'S', b'P', b'B'],
    handshake_suffix: &[b'T', b'H', b'X', 0],

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

    pub const fn sender_len(&self, anon_sender: bool) -> usize {
        match anon_sender {
            true => self.public_key_len,
            false => self.identity_len,
        }
    }

    pub const fn request_len(&self, anon_sender: bool) -> usize {
        0 + size_of::<u32>()
            + self.hash_salt_len
            + self.hashed_id_len
            + self.encryption_overhead()
            + self.request_secret_len(anon_sender)
    }

    pub const fn response_len(&self) -> usize {
        0 + self.encryption_overhead() + self.seed_len + self.buffer_size_len
    }

    pub const fn request_secret_len(&self, anon_sender: bool) -> usize {
        0 + self.seed_len + self.sender_len(anon_sender) + self.buffer_size_len + self.app_proto_len
    }

    pub const fn suffix_len(&self) -> usize {
        self.handshake_suffix.len()
    }

    pub const fn payload_len(&self, secret: &[u8]) -> Result<usize, Error> {
        match secret.len().checked_sub(self.encryption_overhead()) {
            Some(len) => Ok(len),
            None => Err(Error::TooShort),
        }
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
        Some(slice) => Ok(slice.split_at(i)),
        None => Err(Error::TooShort),
    }
}

pub fn split_at_mut<'a>(
    slice: &'a mut [u8],
    i: usize,
    len: usize,
) -> Result<(&'a mut [u8], &'a mut [u8]), Error> {
    match slice.get_mut(..len) {
        Some(slice) => Ok(slice.split_at_mut(i)),
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
    ) -> Self;
}

pub trait Message {
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
    version: Option<Version>,
    peer: Option<I>,
    max_datagram_size: Option<usize>,
    peer_max_dg_size: Option<usize>,
    app_protocol: Option<u32>,
    client: bool,
    cipher_key: Option<[u8; K]>,
    reliability: ReliableConnection,
    anon_client: bool,
    outgoing_msg: usize,
}

impl<I: Identity, M: MessageStorage, const K: usize> Connection<I, M, K> {
    pub fn new_server(
        versions: &'static [Version],
        messages: M,
        max_datagram_size: Option<usize>,
    ) -> Self {
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
            cipher_key: None,
            reliability: ReliableConnection::new(),
            anon_client: false,
            outgoing_msg: 0,
        }
    }

    pub fn new_client<R: RngCore>(
        version: Version,
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
                assert_eq!(K, version.private_key_len);
                let private = &mut [0; K][..version.private_key_len];
                let  public = &mut [0; K][..version.public_key_len];
                rng.fill_bytes(private);
                (version.asym_derive)(private, public)?;
                Some(I::new(None, Some(&private), Some(&public)))
            },
        };

        let mut cipher_key = [0; K];
        rng.fill_bytes(&mut cipher_key);
        let cipher_key = Some(cipher_key);

        Ok(Self {
            established: false,
            identity: identity_opt,
            messages,
            versions: &[],
            version: Some(version),
            peer: Some(peer),
            max_datagram_size,
            peer_max_dg_size: None,
            app_protocol: Some(app_protocol),
            client: true,
            cipher_key,
            reliability: ReliableConnection::new(),
            anon_client: false,
            outgoing_msg: 0,
        })
    }

    pub fn init_client<R: RngCore>(
        &self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<usize, Error> {
        assert!(self.client);

        let identity = self.identity.as_ref().unwrap();
        let id_number = identity.number();

        let anon;
        let id_bytes;
        let sender_id;
        if let Some(number) = id_number {
            id_bytes = number.to_be_bytes();
            sender_id = SenderIdentity::Registered(&id_bytes);
            anon = false;
        } else {
            let key = &identity.public_key().unwrap();
            sender_id = SenderIdentity::AnonClient(key);
            anon = true;
        };

        let peer = self.peer.as_ref().unwrap();
        let peer_id = peer.number().unwrap().to_be_bytes();
        let peer_public_key = peer.public_key().unwrap();

        let cipher_key = self.cipher_key.as_ref().unwrap();

        let version = self.version.as_ref().unwrap();
        Handshake::write_request(
            version,
            to_send,
            rng,
            &sender_id,
            &peer_id,
            peer_public_key,
            self.max_datagram_size.map(|s| s as u64),
            self.app_protocol.unwrap(),
            &cipher_key[..version.seed_len],
        )?;

        Ok(version.request_len(anon))
    }

    fn send_handshake_response<R: RngCore>(
        &mut self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<Option<usize>, Error> {
        let version = self.version.as_ref().unwrap();

        let peer = self.peer.as_ref().unwrap();
        let peer_public_key = peer.public_key().unwrap();

        let mut cipher_key = [0; K];
        rng.fill_bytes(&mut cipher_key);

        Handshake::write_response(
            version,
            to_send,
            peer_public_key,
            rng,
            self.max_datagram_size.map(|s| s as u64),
            &cipher_key[..version.seed_len],
        )?;

        self.cipher_key = Some(cipher_key);

        Ok(Some(version.response_len()))
    }

    fn apply_peer_seed(&mut self, seed: &[u8]) {
        let cipher_key = self.cipher_key.as_mut().unwrap();
        for i in 0..cipher_key.len() {
            cipher_key[i] ^= seed[i];
        }
    }

    pub fn on_timeout<R: RngCore>(
        &mut self,
        to_send: &mut [u8],
        rng: &mut R,
    ) -> Result<Option<usize>, Error> {
        self.outgoing_msg = 0;

        if self.established {
            // todo
            Err(Error::IllegalPeerOperation)
        } else if self.client {
            Ok(Some(self.init_client(to_send, rng)?))
        } else if self.peer.is_some() {
            Ok(None)
        } else {
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

        let identity = self.identity.as_ref().unwrap();
        let private_key = identity.private_key();

        if self.established {
            let version = self.version.as_ref().unwrap();

            let payload_len = version.payload_len(received)?;
            let key = &self.cipher_key.unwrap()[..version.seed_len];
            (version.cipher_decrypt)(key, received)?;
            let received = &mut received[..payload_len];

            let (len, reaction) = self.reliability.on_datagram(
                received,
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

        } else if self.client {
            let version = self.version.as_ref().unwrap();

            let (seed, peer_buf_len) = Handshake::parse_response(
                version,
                received,
                private_key.unwrap(),
            )?;

            self.peer_max_dg_size = peer_buf_len.map(|s| s as usize);
            self.established = true;

            self.apply_peer_seed(seed);

            let version = self.version.as_ref().unwrap();

            Handshake::write_ready(version, to_send);
            Ok((Some(version.suffix_len()), Reaction::Ignore))

        } else if self.peer.is_some() {

            self.established = true;
            self.on_datagram(received, to_send, rng)

        } else if let Some(identity) = &self.identity {
            let version = self.version.as_ref().unwrap();

            let (_, _, secret) = Handshake::parse_request(
                version,
                received,
            )?;

            let tuple = Handshake::decrypt_request_secret(
                version,
                secret,
                identity.private_key().unwrap(),
                self.anon_client,
            )?;
            let (seed, sender_id, peer_buf_len, app_protocol) = tuple;

            if self.peer.is_some() {
                self.peer_max_dg_size = peer_buf_len.map(|s| s as usize);
                self.established = true;
                self.app_protocol = Some(app_protocol);

                let result = self.send_handshake_response(to_send, rng)?;
                self.apply_peer_seed(seed);
                Ok((result, Reaction::Ignore))
            } else {
                let sender_id = match (self.anon_client, sender_id) {
                    ( true, SenderIdentity::AnonClient(b)) => Ok(b),
                    (false, SenderIdentity::Registered(b)) => Ok(b),
                    _ => Err(Error::IllegalPeerOperation),
                }?;

                if self.anon_client {
                    self.peer = Some(I::new(None, None, Some(sender_id)));
                    self.on_datagram(received, to_send, rng)
                } else {
                    let sender_id = try_read(sender_id)?;
                    let sender = u64::from_be_bytes(sender_id);
                    Err(Error::UnknownSender(sender))
                }
            }

        } else {

            let tuple = handshake_protocol(self.versions, received)?;
            let (v, anon_sender) = tuple;

            self.anon_client = anon_sender;
            self.version = Some(self.versions[v]);

            Err(Error::NeedServerIdentity)

        }
    }

    pub fn find_server_identity(
        &mut self,
        received: &mut [u8],
        scratch: &mut [u8],
        identities: &[I],
    ) -> Result<bool, Error> {
        let version = self.version.as_ref().unwrap();

        let (hash_salt, hashed_id, _) = Handshake::parse_request(
            version,
            received,
        )?;

        for identity in identities {
            let tested_id = identity.number().unwrap();
            let result = Handshake::is_expected_recipient(
                version,
                hash_salt,
                hashed_id,
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
        let version = self.version.as_ref().unwrap();
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

        if let Some(len) = len.as_mut() {
            let key = &self.cipher_key.unwrap()[..version.seed_len];
            *len += version.encryption_overhead();
            let to_send = &mut to_send[..*len];
            (version.cipher_encrypt)(key, to_send, rng)?;
            Ok(Some(*len))
        } else {
            self.other_datagram(to_send, rng)
        }
    }
}
