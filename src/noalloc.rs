use crate::Identity;
use crate::MessageStorage;
use crate::Message;
use crate::MessageNum;
use crate::MessageType;

#[derive(Debug, Copy, Clone)]
pub struct FixedSizePeerIdentity<const S: usize> {
    number: Option<u64>,
    private_key: Option<[u8; S]>,
    public_key: Option<[u8; S]>,
    public_key_len: usize,
    private_key_len: usize,
}

impl<const S: usize> Identity for FixedSizePeerIdentity<S> {
    fn number(&self) -> Option<u64> {
        self.number
    }

    fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_ref().map(|v| &v[..self.private_key_len])
    }

    fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_ref().map(|v| &v[..self.public_key_len])
    }

    fn new(
        number: Option<u64>,
        private_key: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Self, ()> {
        let public_key_len = public_key.unwrap_or(&[]).len();
        let private_key_len = private_key.unwrap_or(&[]).len();

        if public_key_len > S || private_key_len > S {
            return Err(());
        }

        let private_key = if let Some(key) = private_key {
            let mut array = [0; S];
            array[..private_key_len].copy_from_slice(&key);
            Some(array)
        } else { None };

        let public_key = if let Some(key) = public_key {
            let mut array = [0; S];
            array[..public_key_len].copy_from_slice(&key);
            Some(array)
        } else { None };

        Ok(Self {
            number,
            private_key,
            public_key,
            private_key_len,
            public_key_len,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct FixedSizeMessage<const L: usize> {
    data: [u8; L],
    data_len: usize,
    received: usize,
    message_num: Option<MessageNum>,
    paused: bool,
}

impl<const L: usize> Message for FixedSizeMessage<L> {
    fn new(msg_type: MessageType) -> Result<Self, ()> {
        let (length, slice) = match msg_type {
            MessageType::Outgoing(slice) => (slice.len(), slice),
            MessageType::Incoming(length) => (length, &[] as &[u8]),
        };
        if length > L {
            Err(())
        } else {
            let mut data = [0; L];
            data[..slice.len()].copy_from_slice(slice);
            Ok(Self {
                data,
                data_len: length,
                received: 0,
                message_num: None,
                paused: false,
            })
        }
    }

    fn get_mut(&mut self, offset: usize, length: usize) -> Option<&mut [u8]> {
        self.data.get_mut(offset..)?.get_mut(..length)
    }

    fn part_transmitted(&mut self, offset: usize, length: usize) {
        if offset == self.received {
            self.received += length;
        }
    }

    fn tell(&mut self) -> (usize, usize, bool) {
        let remaining = self.data_len - self.received;
        (self.received, remaining, true)
    }

    fn seek_transfer(&mut self, _offset: usize) {
        // do nothin
    }

    fn advance(&mut self, length: usize) -> (usize, &[u8]) {
        let offset = self.received;
        let length = length.max(self.data_len - self.received);
        self.received += length;
        (offset, &self.data[offset..][..length])
    }

    fn message_num(&self) -> MessageNum {
        self.message_num.unwrap()
    }

    fn set_message_num(&mut self, num: MessageNum) {
        self.message_num = Some(num);
    }

    fn pause(&mut self) {
        self.paused = true;
    }

    fn resume(&mut self) {
        self.paused = false;
    }

    fn is_paused(&self) -> bool {
        self.paused
    }

    fn is_transfer_complete(&self) -> bool {
        self.received == self.data_len
    }
}

#[derive(Debug, Clone)]
pub struct FixedSizeMessageStorage<M: Message, const L: usize> {
    outgoing: [M; L],
    incoming: [M; L],
    outgoing_len: usize,
    incoming_len: usize,
    next_outgoing_msg_num: u64,
}

impl<M: Message + Copy, const L: usize> FixedSizeMessageStorage<M, L> {
    pub fn new() -> Self {
        let msg_default = M::new(MessageType::Incoming(0)).unwrap();
        Self {
            outgoing: [msg_default; L],
            incoming: [msg_default; L],
            outgoing_len: 0,
            incoming_len: 0,
            next_outgoing_msg_num: 0,
        }
    }

    pub fn prepare_incoming(&mut self, num: MessageNum, length: usize) -> Result<(), ()> {
        let mut message = M::new(MessageType::Incoming(length))?;
        message.set_message_num(num);
        *self.incoming.get_mut(self.incoming_len).ok_or(())? = message;
        self.incoming_len += 1;
        Ok(())
    }

    pub fn push_outgoing(&mut self, content: &[u8]) -> Result<(), ()> {
        let mut message = M::new(MessageType::Outgoing(content))?;
        message.set_message_num(self.next_outgoing_msg_num);
        self.next_outgoing_msg_num += 1;
        *self.outgoing.get_mut(self.outgoing_len).ok_or(())? = message;
        self.outgoing_len += 1;
        Ok(())
    }

    pub fn remove_incoming(&mut self, num: MessageNum) -> M {
        let i = self.incoming()
            .iter()
            .position(|&m| m.message_num() == num)
            .unwrap();
        self.incoming.swap(i, self.incoming_len);
        let msg = self.incoming[self.incoming_len];
        self.incoming[self.incoming_len] = M::new(MessageType::Incoming(0)).unwrap();
        self.incoming_len -= 1;
        msg
    }

    pub fn remove_outgoing(&mut self, num: MessageNum) -> M {
        let i = self.outgoing()
            .iter()
            .position(|&m| m.message_num() == num)
            .unwrap();
        self.outgoing.swap(i, self.outgoing_len);
        let msg = self.outgoing[self.outgoing_len];
        self.outgoing[self.outgoing_len] = M::new(MessageType::Incoming(0)).unwrap();
        self.outgoing_len -= 1;
        msg
    }
}

impl<M: Message, const L: usize> MessageStorage for FixedSizeMessageStorage<M, L> {
    type Msg = M;

    fn outgoing(&mut self) -> &mut [Self::Msg] {
        &mut self.outgoing[..self.outgoing_len]
    }

    fn incoming(&mut self) -> &mut [Self::Msg] {
        &mut self.incoming[..self.incoming_len]
    }
}
