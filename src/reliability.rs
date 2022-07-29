use crate::split_at;
use crate::split_at_mut;
use crate::try_read;
use crate::Error;
use crate::Message;
use crate::MessageStorage;
use crate::Reaction;

pub type MessageNum = u64;
pub type Length = u64;
pub type Offset = u64;

pub struct ReliableConnection {
    pub initial_upgrade_condition: usize,
    pub maximum_upgrade_condition: usize,
    pub downgrade_condition: usize,
    pub must_tell_condition: usize,
    pub upgrade_condition: usize,
    pub reset_condition: usize,

    pub consecutive_successes: usize,
    pub consecutive_timeouts: usize,
    pub consecutive_errors: usize,
    pub peer_must_tell: bool,
    pub config: usize,
}

pub enum SocketEvent<'a> {
    Timeout,
    Datagram(&'a mut [u8]),
}

#[derive(Debug, Clone)]
pub enum Datagram<'a> {
    Offer(MessageNum, Length),
    Accept(MessageNum),
    Part(MessageNum, Offset, &'a [u8]),
    Tell(MessageNum),
    Hole(MessageNum, Offset, Length),
    Received(MessageNum, Offset, Length),
    Stop(MessageNum),
    Wait(MessageNum),
}

use Datagram::*;

fn message<'a, M: MessageStorage>(
    messages: &'a mut M,
    outgoing: bool,
    msg: MessageNum,
) -> Result<&'a mut M::Msg, Error> {
    let messages = match outgoing {
         true => messages.outgoing(),
        false => messages.incoming(),
    };
    for message in messages {
        if message.message_num() == msg {
            return Ok(message);
        }
    }
    Err(Error::LostBytes)
}

use Reaction::*;

impl ReliableConnection {
    pub fn new() -> Self {
        let upgrade_condition = 4;
        Self {
            downgrade_condition: 2,
            must_tell_condition: 4,
            reset_condition: 4,
            initial_upgrade_condition: upgrade_condition,
            maximum_upgrade_condition: 32,
            upgrade_condition,
            peer_must_tell: false,
            consecutive_timeouts: 0,
            consecutive_successes: 0,
            consecutive_errors: 0,
            config: 8,
        }
    }

    pub fn part_size(&self) -> usize {
        CONFIGURATIONS[self.config].0
    }

    pub fn timeout(&self) -> usize {
        CONFIGURATIONS[self.config].1
    }

    fn downgrade(&mut self) -> bool {
        match self.config.checked_sub(1) {
            Some(cfg) => {
                self.config = cfg;
                true
            }
            None => false,
        }
    }

    fn upgrade(&mut self) -> bool {
        let cfg = self.config + 1;
        match CONFIGURATIONS.get(cfg) {
            Some(_) => {
                self.config = cfg;
                true
            }
            None => false,
        }
    }

    pub fn on_timeout(
        &mut self,
        to_send: &mut [u8],
    ) -> Result<(Option<usize>, Reaction), Error> {
        self.consecutive_timeouts += 1;
        if self.peer_must_tell {
            if self.consecutive_timeouts >= self.downgrade_condition {
                if !self.downgrade() {
                    return Err(Error::IllegalPeerOperation);
                }
            }
        } else if self.consecutive_timeouts == self.must_tell_condition {
            self.peer_must_tell = true;
            self.consecutive_timeouts = 0;
            let reply = Datagram::Tell(MessageNum::MAX);
            let written = reply.dump(to_send)?;
            return Ok((Some(written), Ignore));
        }
        Ok((None, Ignore))
    }

    pub fn on_datagram<M: MessageStorage>(
        &mut self,
        datagram: &mut [u8],
        to_send: &mut [u8],
        messages: &mut M,
        abs_msg_max: usize,
        new_msg_max: usize,
    ) -> Result<(Option<usize>, Reaction), Error> {
        self.consecutive_timeouts = 0;

        let datagram = Datagram::parse(datagram)?;

        match datagram {
            Offer(msg, length_u64) => {
                let length = length_u64 as usize;
                let is_able = new_msg_max < length;
                let will_be_able = abs_msg_max <= length;
                let reply = match (is_able, will_be_able) {
                    (true, _) => Datagram::Accept(msg),
                    (false, true) => Datagram::Wait(msg),
                    (false, false) => Datagram::Stop(msg),
                };
                let written = reply.dump(to_send)?;
                return Ok((Some(written), AllocateMessage(msg, length_u64)));
            }
            Accept(msg) => {
                let message = message(messages, true, msg)?;
                message.resume();
                // return the default
            }
            Part(msg, offset_u64, src) => {
                let message = message(messages, false, msg)?;
                let length = src.len();
                let length_u64 = length as u64;
                let offset = offset_u64 as usize;
                if let Some(dst) = message.get_mut(offset, length) {
                    dst.copy_from_slice(src);
                } else {
                    return Err(Error::IllegalPeerOperation);
                }
                let reply = Datagram::Received(msg, offset_u64, length_u64);
                let written = reply.dump(to_send)?;
                let reaction = match message.is_transfer_complete() {
                    true => Reaction::IncomingMessageReceived(msg),
                    false => Reaction::Ignore,
                };
                return Ok((Some(written), reaction));
            }
            Tell(msg) => {
                let message = message(messages, false, msg);
                let (offset, length, is_hole) = match message {
                    Ok(message) => message.tell(),
                    Err(_) => (0, usize::MAX, false),
                };
                let offset = offset as u64;
                let length = length as u64;
                let reply = match is_hole {
                    true => Datagram::Hole(msg, offset, length),
                    false => Datagram::Received(msg, offset, length),
                };
                let written = reply.dump(to_send)?;
                return Ok((Some(written), Ignore));
            }
            Hole(msg, offset, _length) => {
                self.peer_must_tell = false;
                self.consecutive_successes = 0;
                self.consecutive_errors += 1;

                self.downgrade();
                if self.consecutive_errors == self.reset_condition {
                    self.upgrade_condition = self.initial_upgrade_condition;
                }

                let message = message(messages, true, msg)?;
                message.seek_transfer(offset as usize);
                // return the default
            }
            Received(msg, offset, length) => {
                self.peer_must_tell = false;
                self.consecutive_successes += 1;
                self.consecutive_errors = 0;

                if self.consecutive_successes == self.upgrade_condition {
                    self.upgrade();
                    let cond = self.upgrade_condition * 2;
                    let max = self.maximum_upgrade_condition;
                    self.upgrade_condition = cond.min(max);
                }

                let message = message(messages, true, msg)?;
                let offset = offset as usize;
                let length = length as usize;
                message.part_transmitted(offset, length);
                if message.is_transfer_complete() {
                    return Ok((None, OutgoingMessageReceived(msg)));
                };
            }
            Stop(msg) => {
                return Ok((None, MessageRefused(msg)));
            }
            Wait(msg) => {
                let message = message(messages, true, msg)?;
                message.pause();
                // return the default
            }
        }

        Ok((None, Ignore))
    }

    pub fn continue_message_transfer<M: Message>(
        &mut self,
        to_send: &mut [u8],
        outgoing: &mut M,
    ) -> Result<Option<usize>, Error> {
        if !outgoing.is_paused() {
            let max = self.part_size();
            let msg_num = outgoing.message_num();
            let (offset, bytes) = outgoing.advance(max);
            let reply = Datagram::Part(msg_num, offset as u64, bytes);
            Ok(Some(reply.dump(to_send)?))
        } else {
            Ok(None)
        }
    }
}

fn rd_u64(bytes: &[u8]) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(try_read(bytes)?))
}

impl<'a> Datagram<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let (dg_type, bytes) = split_at(bytes, 1, 9)?;
        let (msg, bytes) = bytes.split_at(8);
        let msg = rd_u64(msg)?;
        let payload = split_at(bytes, 8, 8);

        Ok(match (dg_type[0], payload) {
            (0, Ok((f1, _))) => Offer(msg, rd_u64(f1)?),
            (1, _) => Accept(msg),
            (2, Ok((f1, f2))) => Part(msg, rd_u64(f1)?, f2),
            (3, _) => Tell(msg),
            (4, Ok((f1, f2))) => Hole(msg, rd_u64(f1)?, rd_u64(f2)?),
            (5, Ok((f1, f2))) => Received(msg, rd_u64(f1)?, rd_u64(f2)?),
            (6, _) => Stop(msg),
            (7, _) => Wait(msg),
            _ => Err(Error::LostBytes)?,
        })
    }

    pub fn dump(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        let minimum = 1 + 8;
        let bonus = match self {
            Offer(_, _) => 8,
            Accept(_) => 0,
            Part(_, _, p) => 8 + p.len(),
            Tell(_) => 0,
            Hole(_, _, _) => 16,
            Received(_, _, _) => 16,
            Stop(_) => 0,
            Wait(_) => 0,
        };
        let len = minimum + bonus;

        let (dg_type_bytes, bytes) = split_at_mut(bytes, 1, len)?;
        let (msg_num_bytes, bytes) = bytes.split_at_mut(8);
        let (f1_bytes, f2_bytes) = bytes.split_at_mut(8);

        let zero: u64 = 0;

        let (dg_type, msg_num, f1, f2) = match self {
            Offer(m, length) => (0u8, m, *length, zero),
            Accept(m) => (1, m, zero, zero),
            Part(m, offset, _) => (2, m, *offset, zero),
            Tell(m) => (3, m, zero, zero),
            Hole(m, offset, length) => (4, m, *offset, *length),
            Received(m, offset, length) => (5, m, *offset, *length),
            Stop(m) => (6, m, zero, zero),
            Wait(m) => (7, m, zero, zero),
        };

        let f2_as_array = f2.to_be_bytes();
        let f2_src = if let Part(_, _, payload) = self {
            payload
        } else {
            f2_as_array.as_slice()
        };

        dg_type_bytes.copy_from_slice(&[dg_type]);
        msg_num_bytes.copy_from_slice(&msg_num.to_be_bytes());
        f1_bytes.copy_from_slice(&f1.to_be_bytes());
        f2_bytes[..f2_src.len()].copy_from_slice(f2_src);

        Ok(len)
    }
}

const CONFIGURATIONS: [(usize, usize); 40] = [
    (1_000_000, 64),
    (1_000_000, 128),
    (1_000_000, 256),
    (1_000_000, 512),
    (1_000_000, 1024),
    (1_000_000, 2048),
    (1_000_000, 4096),
    (1_000_000, 8192),
    (600_000, 64),
    (600_000, 256),
    (600_000, 1024),
    (600_000, 2048),
    (600_000, 4096),
    (600_000, 8192),
    (400_000, 128),
    (400_000, 1024),
    (400_000, 4096),
    (400_000, 8192),
    (200_000, 128),
    (200_000, 1024),
    (200_000, 8192),
    (100_000, 128),
    (100_000, 1024),
    (100_000, 8192),
    (100_000, 8192),
    (50_000, 128),
    (50_000, 1024),
    (50_000, 8192),
    (20_000, 128),
    (20_000, 1024),
    (20_000, 8192),
    (10_000, 128),
    (10_000, 1024),
    (10_000, 8192),
    (4_000, 256),
    (4_000, 8192),
    (1_000, 256),
    (1_000, 8192),
    (500, 512),
    (500, 8192),
];
