//! TON's wallet contracts maki knows, the addresses a key has in them, and what each one signs.
//!
//! A wallet's address is the hash of its first state: its code and its data, which hold the key,
//! a wallet ID and a count of what it has sent (its seqno). v4R2's wallet ID is a subwallet number,
//! 698983191 for every wallet's first; W5's is the network's global ID mixed with which wallet it
//! is (version 0, workchain 0, subwallet 0), so the same key has another W5 address on TON's test
//! network. maki makes the ones every wallet makes.
//!
//! What a wallet's key signs is a request: the wallet ID, a time after which it's no good, the
//! seqno it must be, and what to do. The wallet takes the request in an external message with
//! the signature (v4R2: first; W5: last), checks it against the hash of the request's cell, counts
//! it, and does it: sends the messages it holds, each with a send mode; or, for v4R2, puts in or
//! takes out a plugin (which may then take TON from it), or for W5 adds or removes an extension
//! (which may then do anything with it). maki reads a request as the wallet's code does, and
//! refuses what it would refuse, or would read otherwise than its parts say.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::cell::{Boc, Builder, Slice};
use crate::message::{Init, Message};
use crate::{Address, Error, Hash, Key, Network};

/// A wallet contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wallet {
    /// wallet-contract's v4 (its second release): Ledger's, and every wallet's for years.
    V4R2,
    /// wallet-contract-v5's W5 (v5R1): today's wallets' first choice.
    V5R1,
}

/// v4R2's subwallet number, as every wallet's first v4R2 has it (698983191, plus its workchain:
/// 0).
pub const V4R2_SUBWALLET: u32 = 698_983_191;

/// What a W5 request starts with: `sign`, a request from outside, signed by its key.
pub const SIGNED_EXTERNAL: u32 = 0x7369_676e;
/// `sint`: the same request inside a message from another contract, which anyone can pass on.
pub const SIGNED_INTERNAL: u32 = 0x7369_6e74;
/// `extn`: an extension's request, which isn't signed.
pub const EXTENSION: u32 = 0x6578_746e;
/// `action_send_msg`: the one action a W5 request's list may hold.
pub const SEND_MSG: u32 = 0x0ec3_c86d;
/// The most messages W5 sends at once.
pub const MAX_W5_MESSAGES: usize = 255;
/// The most messages maki goes through in one request: each takes a page at least, and maki's
/// review screen goes through 128, two of them how long the request is good for and whose wallet
/// it is. A W5 request may hold more, which maki refuses before it reads them.
pub const MAX_MESSAGES: usize = 126;

/// The wallets' code: the hash and depth of its cell, as @ton/ton holds it (and Ledger's TON app
/// hashes v4R2's into its addresses).
const V4R2_CODE: (Hash, u16) = (
    [
        0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d, 0x84,
        0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0,
    ],
    7,
);
const V5R1_CODE: (Hash, u16) = (
    [
        0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74, 0xd1,
        0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
    ],
    6,
);

impl Wallet {
    /// Both, v4R2 first: the wallet Ledger's TON app knows, then W5.
    pub const ALL: [Wallet; 2] = [Wallet::V4R2, Wallet::V5R1];

    /// Its name, as wallets show it.
    pub fn name(self) -> &'static str {
        match self {
            Wallet::V4R2 => "v4R2",
            Wallet::V5R1 => "W5",
        }
    }

    /// Its name in maki's messages: `v4R2`, `v5R1`.
    pub fn id(self) -> &'static str {
        match self {
            Wallet::V4R2 => "v4R2",
            Wallet::V5R1 => "v5R1",
        }
    }

    /// A wallet by its name in maki's messages.
    pub fn from_id(id: &str) -> Option<Wallet> { Wallet::ALL.into_iter().find(|w| w.id() == id) }

    /// The wallet ID it's made with on `network`: v4R2's subwallet, or W5's (the network's global
    /// ID XOR its context: a 1, workchain 0, version 0, subwallet 0).
    pub fn wallet_id(self, network: Network) -> u32 {
        match self {
            Wallet::V4R2 => V4R2_SUBWALLET,
            Wallet::V5R1 => (network.global_id() ^ i32::MIN) as u32,
        }
    }

    /// Its code: its cell's hash and depth.
    pub fn code(self) -> (Hash, u16) {
        match self {
            Wallet::V4R2 => V4R2_CODE,
            Wallet::V5R1 => V5R1_CODE,
        }
    }

    /// Its first data, with `key`: v4R2's seqno, subwallet, key and no plugins; W5's signatures
    /// allowed, seqno, wallet ID, key and no extensions.
    fn data(self, key: &Key, network: Network) -> (Hash, u16) {
        let mut b = Builder::new();
        if self == Wallet::V5R1 {
            b.bit(true);
        }
        b.uint(0, 32).uint(self.wallet_id(network) as u64, 32).bytes(key).bit(false);
        b.finish()
    }

    /// Its first state with `key` on `network`.
    pub fn init(self, key: &Key, network: Network) -> Init {
        Init { code: self.code(), data: self.data(key, network) }
    }

    /// Its address with `key` on `network`: on the basechain, the hash of its first state.
    pub fn address(self, key: &Key, network: Network) -> Address {
        Address { workchain: 0, hash: self.init(key, network).hash() }
    }
}

/// What a request asks of the wallet.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send a message, with a send mode: `PAY_FEES_SEPARATELY` (1) pays its forwarding fee on top;
    /// `IGNORE_ERRORS` (2) skips it if it can't be sent; `DESTROY_IF_ZERO` (32) deletes the wallet
    /// if it's left with nothing; `ALL_BALANCE` (128) sends everything the wallet has.
    Send { mode: u8, message: Box<Message> },
    /// v4R2: set up a contract (its first state, with a first body maki can't read) with `amount`
    /// nanotons, and make it a plugin, which may take TON from the wallet whenever it asks.
    DeployPlugin { plugin: Address, amount: u128, init: Init },
    /// v4R2: make the contract at `plugin` a plugin, and send it `amount` nanotons to say so.
    InstallPlugin { plugin: Address, amount: u128 },
    /// v4R2: stop the contract at `plugin` being a plugin, and send it `amount` nanotons to say so.
    RemovePlugin { plugin: Address, amount: u128 },
    /// W5: make the contract at the address an extension, which can do anything the key can.
    AddExtension(Address),
    /// W5: stop the contract at the address being an extension.
    RemoveExtension(Address),
}

/// The send modes TON has: what each bit does is above. 4 and 8 it refuses; 16 (bounce if it
/// fails) and 64 (carry what's left of the message that ran it) are for contracts, not wallets.
pub mod mode {
    pub const PAY_FEES_SEPARATELY: u8 = 1;
    pub const IGNORE_ERRORS: u8 = 2;
    pub const BOUNCE_ON_FAIL: u8 = 16;
    pub const DESTROY_IF_ZERO: u8 = 32;
    pub const CARRY_INBOUND: u8 = 64;
    pub const ALL_BALANCE: u8 = 128;
}

/// A request a wallet's key signs.
#[derive(Debug, Clone)]
pub struct Request {
    /// The wallet contract it's for: its first bits say.
    pub wallet: Wallet,
    /// Which of the key's wallets it's for: its wallet ID.
    pub wallet_id: u32,
    /// The time (Unix, UTC) it's no good after; 0xffffffff, never.
    pub valid_until: u32,
    /// What the wallet's seqno must be.
    pub seqno: u32,
    /// What it asks, in the order the wallet does it.
    pub actions: Vec<Action>,
}

/// A send mode as maki takes it from `wallet`: what TON refuses and what wallets don't use,
/// refused, and for W5 a request from outside without `IGNORE_ERRORS`, which it refuses.
fn send_mode(m: u8, wallet: Wallet) -> Result<u8, Error> {
    use mode::*;
    if m & 0x0c != 0 || m & (CARRY_INBOUND | ALL_BALANCE) == CARRY_INBOUND | ALL_BALANCE {
        return Err(Error::Invalid("a send mode TON refuses"));
    }
    if m & (CARRY_INBOUND | BOUNCE_ON_FAIL) != 0 {
        return Err(Error::Invalid("a send mode for contracts (+16 or +64), which wallets don't use"));
    }
    if wallet == Wallet::V5R1 && m & IGNORE_ERRORS == 0 {
        return Err(Error::Invalid(
            "a message without +2 (ignore errors) in a request from outside: W5 would refuse it",
        ));
    }
    Ok(m)
}

/// A standard address on one of TON's workchains, for a plugin or an extension.
fn on_ton(a: Address) -> Result<Address, Error> {
    if !matches!(a.workchain, 0 | -1) {
        return Err(Error::Invalid("an address on a workchain TON doesn't have"));
    }
    Ok(a)
}

impl Request {
    /// A request, read from the cell its key signs (what @ton/ton hands a wallet's signer): W5's if
    /// it starts with `sign`, v4R2's otherwise (whose first 32 bits are its subwallet). Refused:
    /// what the wallet would refuse, or would read otherwise than its parts say.
    pub fn parse(boc: &Boc<'_>) -> Result<Request, Error> {
        let mut s = boc.root()?;
        match s.peek(32)? as u32 {
            SIGNED_EXTERNAL => {
                s.uint(32)?;
                let (wallet_id, valid_until, seqno) =
                    (s.uint(32)? as u32, s.uint(32)? as u32, s.uint(32)? as u32);
                let actions = w5_actions(s)?;
                Ok(Request { wallet: Wallet::V5R1, wallet_id, valid_until, seqno, actions })
            }
            SIGNED_INTERNAL => Err(Error::Invalid(
                "a request for another contract to pass on (W5's signed internal message): maki doesn't sign those",
            )),
            EXTENSION => Err(Error::Invalid("an extension's request, which no key signs")),
            _ => {
                let (wallet_id, valid_until, seqno) =
                    (s.uint(32)? as u32, s.uint(32)? as u32, s.uint(32)? as u32);
                let actions = v4_actions(s)?;
                Ok(Request { wallet: Wallet::V4R2, wallet_id, valid_until, seqno, actions })
            }
        }
    }
}

/// What a v4R2 request asks, after its seqno: an op, and its parts. The wallet reads a message
/// for each reference, a mode before each; plugins' ops their fields. Anything after, it would
/// ignore: maki refuses it.
fn v4_actions(mut s: Slice<'_>) -> Result<Vec<Action>, Error> {
    let mut actions = Vec::new();
    match s.uint(8)? {
        0 => {
            while s.refs_left() > 0 {
                let mode = send_mode(s.uint(8)? as u8, Wallet::V4R2)?;
                let message = Box::new(Message::parse(s.reference()?)?);
                actions.push(Action::Send { mode, message });
            }
        }
        1 => {
            let workchain = s.int8()?;
            let amount = s.coins()?;
            // its first state, a cell of its own whose hash the plugin's address is
            let mut init = s.reference()?;
            let state = Init::read(&mut init)?;
            init.end()?;
            // its first body, which only the plugin reads
            s.reference_cell()?;
            let plugin = on_ton(Address { workchain, hash: state.hash() })?;
            actions.push(Action::DeployPlugin { plugin, amount, init: state });
        }
        op @ (2 | 3) => {
            let workchain = s.int8()?;
            let plugin = on_ton(Address { workchain, hash: s.bytes()? })?;
            let amount = s.coins()?;
            s.uint(64)?;
            actions.push(if op == 2 {
                Action::InstallPlugin { plugin, amount }
            } else {
                Action::RemovePlugin { plugin, amount }
            });
        }
        _ => {
            return Err(Error::Invalid(
                "a wallet operation v4R2 doesn't have: it would do nothing but count it",
            ));
        }
    }
    s.end()?;
    Ok(actions)
}

/// What a W5 request asks, after its seqno: maybe a list of messages to send (`OutList`, each
/// `action_send_msg`, the last first), then whether other actions follow: each in the cell, the
/// next in its one reference.
fn w5_actions(mut s: Slice<'_>) -> Result<Vec<Action>, Error> {
    let mut actions = Vec::new();
    if let Some(list) = s.maybe_reference()? {
        // how long the list is, first: one longer than W5 sends, or than maki goes through, isn't read
        let (mut node, mut n) = (list, 0);
        while !node.is_empty() {
            n += 1;
            if n > MAX_W5_MESSAGES {
                return Err(Error::Invalid("more messages than W5 sends at once: it would refuse them"));
            }
            node = node.reference()?;
        }
        if n > MAX_MESSAGES {
            return Err(Error::Invalid("too much to go through on maki's screen"));
        }
        let mut node = list;
        let mut sends = Vec::with_capacity(n);
        while !node.is_empty() {
            // out_list$_ prev:^(OutList n) action:OutAction
            let prev = node.reference()?;
            if node.uint(32)? as u32 != SEND_MSG {
                return Err(Error::Invalid("an action W5 refuses: it sends messages, nothing else"));
            }
            let mode = send_mode(node.uint(8)? as u8, Wallet::V5R1)?;
            let message = Box::new(Message::parse(node.reference()?)?);
            node.end()?;
            sends.push(Action::Send { mode, message });
            node = prev;
        }
        // the list's last action is its first cell: TON does them first to last
        sends.reverse();
        actions.extend(sends);
    }
    if s.bit()? {
        loop {
            match s.uint(8)? {
                op @ (2 | 3) => {
                    let a = s
                        .address()?
                        .ok_or(Error::Invalid("an extension at no address: W5 would refuse it"))?;
                    if a.workchain != 0 {
                        return Err(Error::Invalid("an extension on another workchain: W5 would refuse it"));
                    }
                    actions.push(if op == 2 { Action::AddExtension(a) } else { Action::RemoveExtension(a) });
                }
                4 => {
                    return Err(Error::Invalid(
                        "turning its key's signatures off or on, which only an extension may: W5 would refuse it",
                    ));
                }
                _ => return Err(Error::Invalid("an action W5 doesn't have: it would refuse it")),
            }
            // the next action is in the one reference left, if there is one, and nothing else is
            if s.bits_left() != 0 || s.refs_left() > 1 {
                return Err(Error::Extra);
            }
            if s.refs_left() == 0 {
                break;
            }
            s = s.reference()?;
        }
    }
    s.end()?;
    Ok(actions)
}
