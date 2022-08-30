

#[derive(Clone)]
struct PeerIdentity {
    number: Option<u64>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl Identity for PeerIdentity {
    fn number(&self) -> Option<u64> {
        self.number
    }

    fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_ref().map(|v| v.as_slice())
    }

    fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_ref().map(|v| v.as_slice())
    }

    fn new(
        number: Option<u64>,
        private_key: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Self {
        Self {
            number,
            private_key: private_key.map(|s| s.to_vec()),
            public_key: public_key.map(|s| s.to_vec()),
        }
    }
}

struct VecMsgStore {
    incoming: Vec<Msg>,
    outgoing: Vec<Msg>,
}

impl MessageStorage for VecMsgStore {
    type Msg = Msg;

    fn outgoing(&mut self) -> &mut [Self::Msg] {
        &mut self.outgoing
    }

    fn incoming(&mut self) -> &mut [Self::Msg] {
        &mut self.incoming
    }
}