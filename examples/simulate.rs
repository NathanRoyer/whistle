use whistle::VERSIONS;
use whistle::Connection;
use whistle::Identity;
use whistle::Error;
use whistle::Reaction;
use whistle::ClientIdentity;

use whistle::algorithms::ecies_derive;
use whistle::noalloc::FixedSizeMessage;
use whistle::noalloc::FixedSizeMessageStorage;
use whistle::noalloc::FixedSizePeerIdentity;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;

const KEYSIZE: usize = VERSIONS[0].private_key_len;

type MessageStorage = FixedSizeMessageStorage::<FixedSizeMessage<256>, 16>;
type PeerIdentity = FixedSizePeerIdentity::<256>;
type ConnectionCfg = Connection::<PeerIdentity, MessageStorage, KEYSIZE>;

// all eights
const SERVER_PRIVATE_KEY: &[u8] = &[8; KEYSIZE];
const SERVER_IDENTITY: u64 = 0xdeadbeef;

const BUFSIZE: usize = 2048;

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(87638764);

    let mut srv_pubkey = [0; KEYSIZE];
    ecies_derive(&SERVER_PRIVATE_KEY, &mut srv_pubkey).unwrap();

    let srv_id_pub = PeerIdentity::new(Some(SERVER_IDENTITY), None, Some(&srv_pubkey)).unwrap();
    let srv_id_priv = PeerIdentity::new(Some(SERVER_IDENTITY), Some(&SERVER_PRIVATE_KEY), Some(&srv_pubkey)).unwrap();

    let mut buf1 = [0; BUFSIZE];
    let mut buf2 = [0; BUFSIZE];

    let mut server = ConnectionCfg::new_server(
        &VERSIONS,
        MessageStorage::new(),
        Some(BUFSIZE),
        &mut rng,
    );

    let mut client = ConnectionCfg::new_client(
        &VERSIONS,
        ClientIdentity::Anonymous,
        MessageStorage::new(),
        srv_id_pub,
        Some(BUFSIZE),
        1234,
        &mut rng,
    ).unwrap();

    let len = client.init_client(&mut buf1, &mut rng);
    assert_eq!(len, Ok(170));
    let len = len.unwrap();

    assert_eq!(server.on_datagram(&mut buf1[..len], &mut buf2, &mut rng), Err(Error::NeedServerIdentity));
    assert_eq!(server.find_server_identity(&mut buf1[..len], &mut buf2, &[srv_id_priv]), Ok(true));
    let len = server.on_datagram(&mut buf1[..len], &mut buf2, &mut rng);
    assert_eq!(len, Ok((Some(78), Reaction::Ignore)));
    let len = len.unwrap().0.unwrap();

    let len = client.on_datagram(&mut buf2[..len], &mut buf1, &mut rng);
    assert_eq!(len, Ok((Some(4), Reaction::Ignore)));
    let _len = len.unwrap();
}

