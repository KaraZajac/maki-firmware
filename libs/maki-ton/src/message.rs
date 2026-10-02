//! The messages a wallet is asked to send (TON's `MessageRelaxed`), read as wallets write them,
//! and what their bodies say: a comment (TEP-74's rules for text), a jetton transfer (TEP-74), or
//! something maki can't read.
//!
//! A wallet sends whatever message it's given; TON fills in who sends it, its fees and its time.
//! maki takes them as every wallet library writes them (`@ton/core`'s `internal`): no sender
//! named, those fields zero, an address on one of TON's two workchains, and refuses the rest, as
//! TON does what it can't send (anycast addresses, extra flags it doesn't know) and maki does what
//! it can't show (extra currencies).

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::cell::{Builder, Slice};
use crate::{Address, Error, Hash};

/// A comment's op (TEP-74): text, or binary if it starts with 0xff.
pub const COMMENT: u32 = 0;
/// An encrypted comment's op (as Tonkeeper and MyTonWallet write them).
pub const ENCRYPTED: u32 = 0x2167_da4b;
/// TEP-74's jetton transfer: what an account's jetton wallet is asked to send.
pub const JETTON_TRANSFER: u32 = 0x0f8a_7ea5;

/// A message a wallet sends.
#[derive(Debug, Clone)]
pub struct Message {
    /// Whether it comes back if nothing at the address takes it.
    pub bounce: bool,
    /// Where it goes.
    pub dest: Address,
    /// In nanotons.
    pub value: u128,
    /// A contract it sets up at `dest`: its first state.
    pub init: Option<Init>,
    /// What its body says.
    pub payload: Payload,
}

/// A contract's first state (`StateInit`), which its address is the hash of: its code and data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Init {
    /// Its code's cell: its hash and depth.
    pub code: (Hash, u16),
    /// Its data's cell: its hash and depth.
    pub data: (Hash, u16),
}

impl Init {
    /// The contract's address's hash: the hash of the state's cell (no fixed prefix, not
    /// tick-tock, its code and data, no libraries).
    pub fn hash(&self) -> Hash {
        Builder::new().uint(0b00110, 5).reference(self.code).reference(self.data).finish().0
    }

    /// A first state, read from `s` (a cell of its own, or the rest of a message's): its code and
    /// data, and nothing else a wallet would deploy.
    pub(crate) fn read(s: &mut Slice<'_>) -> Result<Init, Error> {
        // fixed_prefix_length:(Maybe (## 5)) special:(Maybe TickTock) code:(Maybe ^Cell)
        // data:(Maybe ^Cell) library:(Maybe ^Cell)
        let (prefix, special) = (s.bit()?, s.bit()?);
        let (code, data) = (s.bit()?, s.bit()?);
        let library = s.bit()?;
        if prefix || special || library {
            return Err(Error::Invalid(
                "a contract's first state with what wallets don't deploy: a fixed prefix, tick-tock, or libraries",
            ));
        }
        if !code || !data {
            return Err(Error::Invalid("a contract's first state without its code or its data"));
        }
        let code = s.reference_cell()?;
        let data = s.reference_cell()?;
        Ok(Init { code: s.cell_hash(code), data: s.cell_hash(data) })
    }
}

impl Message {
    /// A message, read whole from its cell.
    pub fn parse(mut s: Slice<'_>) -> Result<Message, Error> {
        // int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool src:MsgAddress
        // dest:MsgAddressInt value:CurrencyCollection extra_flags:(VarUInteger 16) fwd_fee:Grams
        // created_lt:uint64 created_at:uint32
        if s.bit()? {
            return Err(Error::Invalid("a message out of TON, to no account: wallets don't send those"));
        }
        let (ihr_disabled, bounce, bounced) = (s.bit()?, s.bit()?, s.bit()?);
        if s.address()?.is_some() {
            return Err(Error::Invalid("a message that names who sends it: wallets leave that to TON"));
        }
        let dest = s.address()?.ok_or(Error::Invalid("a message to no address: TON would refuse it"))?;
        if !matches!(dest.workchain, 0 | -1) {
            return Err(Error::Invalid("a message to a workchain TON doesn't have: it would refuse it"));
        }
        let value = s.coins()?;
        if s.bit()? {
            return Err(Error::Invalid("extra currencies, which maki doesn't read"));
        }
        let extra_flags = s.coins()?;
        if extra_flags > 3 {
            return Err(Error::Invalid("a message with flags TON doesn't know: it would refuse it"));
        }
        let (fwd_fee, lt, at) = (s.coins()?, s.uint(64)?, s.uint(32)?);
        if !ihr_disabled || bounced || extra_flags != 0 || fwd_fee != 0 || lt != 0 || at != 0 {
            return Err(Error::Invalid("a message not as wallets write it"));
        }
        // init:(Maybe (Either StateInit ^StateInit))
        let init = if s.bit()? {
            let init = if s.bit()? {
                let mut r = s.reference()?;
                let init = Init::read(&mut r)?;
                r.end()?;
                init
            } else {
                Init::read(&mut s)?
            };
            if init.hash() != dest.hash {
                return Err(Error::Invalid(
                    "a contract's first state that isn't for the address it's sent to",
                ));
            }
            Some(init)
        } else {
            None
        };
        // body:(Either X ^X)
        let payload = Payload::parse(s.either()?)?;
        Ok(Message { bounce, dest, value, init, payload })
    }
}

/// What a body (or a jetton transfer's forward payload) says.
#[derive(Debug, Clone)]
pub enum Payload {
    /// Nothing: TON sent, and that's all.
    Empty,
    /// A comment: its text (UTF-8, if the sender wrote it right).
    Text(Vec<u8>),
    /// A binary comment (0xff after the comment's op): for software, not people.
    Binary(Vec<u8>),
    /// An encrypted comment, which only the recipient's key opens.
    Encrypted,
    /// A jetton transfer.
    Jetton(Jetton),
    /// Anything else: its op, if it has one, and how big it is.
    Unknown { op: Option<u32>, bytes: usize, cells: usize },
}

/// TEP-74's transfer: an account asks its jetton wallet to send jettons.
#[derive(Debug, Clone)]
pub struct Jetton {
    /// The sender's number for it, which the jetton wallet's answer carries back.
    pub query_id: u64,
    /// In the jetton's smallest units.
    pub amount: u128,
    /// Whose jettons they become: the owner, whose jetton wallet gets them.
    pub destination: Address,
    /// Where what's left of the TON sent with it goes, if anywhere.
    pub response: Option<Address>,
    /// A payload for the jetton wallet itself, which maki can't read.
    pub custom: bool,
    /// TON the recipient's jetton wallet sends on to them with the news, in nanotons.
    pub forward_ton: u128,
    /// What goes to them with it.
    pub forward: Box<Payload>,
}

impl Payload {
    /// A message's body, read: a jetton transfer as TEP-74 has it and as the jetton wallets maki
    /// knows read it, a comment as TON writes text. One that says it's either but isn't, maki
    /// refuses: the contract it goes to would refuse it, or read it as something else.
    pub fn parse(body: Slice<'_>) -> Result<Payload, Error> { Payload::read(body, true) }

    fn read(mut body: Slice<'_>, jettons: bool) -> Result<Payload, Error> {
        if body.is_empty() {
            return Ok(Payload::Empty);
        }
        if body.bits_left() < 32 {
            let (bytes, cells) = body.size();
            return Ok(Payload::Unknown { op: None, bytes, cells });
        }
        let op = body.peek(32)? as u32;
        match op {
            COMMENT => {
                body.uint(32)?;
                let text = snake(body)?;
                Ok(match text.split_first() {
                    Some((0xff, rest)) => Payload::Binary(rest.to_vec()),
                    _ => Payload::Text(text),
                })
            }
            ENCRYPTED => Ok(Payload::Encrypted),
            JETTON_TRANSFER if jettons => {
                body.uint(32)?;
                Ok(Payload::Jetton(Jetton::read(body)?))
            }
            _ => {
                let (bytes, cells) = body.size();
                Ok(Payload::Unknown { op: Some(op), bytes, cells })
            }
        }
    }
}

impl Jetton {
    /// transfer#0f8a7ea5 query_id:uint64 amount:Coins destination:MsgAddress
    /// response_destination:MsgAddress custom_payload:(Maybe ^Cell) forward_ton_amount:Coins
    /// forward_payload:(Either Cell ^Cell), after its op.
    fn read(mut s: Slice<'_>) -> Result<Jetton, Error> {
        let query_id = s.uint(64)?;
        let amount = s.coins()?;
        let destination = s
            .address()?
            .ok_or(Error::Invalid("a jetton transfer to no one: the jetton's wallet would refuse it"))?;
        // jetton wallets live on the basechain, and only its accounts can have them
        if destination.workchain != 0 {
            return Err(Error::Invalid(
                "jettons to an account off the basechain: the jetton's wallet would refuse it",
            ));
        }
        let response = s.address()?;
        if response.is_some_and(|r| !matches!(r.workchain, 0 | -1)) {
            return Err(Error::Invalid("what's left of a jetton transfer to a workchain TON doesn't have"));
        }
        let custom = if s.bit()? {
            s.reference_cell()?;
            true
        } else {
            false
        };
        let forward_ton = s.coins()?;
        // a forward payload in a reference is that alone, as the jetton wallets maki knows check
        let forward = s.either()?;
        let forward = Box::new(Payload::read(forward, false)?);
        Ok(Jetton { query_id, amount, destination, response, custom, forward_ton, forward })
    }
}

/// Text as TON writes it ("snake" data): whole bytes in a cell, the rest of it in the cell's one
/// reference, and so on.
fn snake(mut s: Slice<'_>) -> Result<Vec<u8>, Error> {
    let mut text = Vec::new();
    loop {
        if !s.bits_left().is_multiple_of(8) || s.refs_left() > 1 {
            return Err(Error::Invalid("a comment not as TON writes text: not whole bytes, or branching"));
        }
        text.extend(s.rest_bytes()?);
        if s.refs_left() == 0 {
            return Ok(text);
        }
        s = s.reference()?;
    }
}
