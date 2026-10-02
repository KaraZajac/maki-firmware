//! Cardano, for maki's Cardano app (ARCHITECTURE.md, "Wallets are apps"): an account's addresses,
//! and what it signs, read strictly and shown before it's signed. maki keeps the keys: BIP32-Ed25519
//! from the phrase's entropy (Icarus's master key, CIP-3), at CIP-1852's
//! `m/1852'/1815'/account'/role/index`, as Eternl, Lace, Yoroi, Daedalus, Ledger and Trezor make
//! them. An account's addresses pay one of its payment keys (role 0, or 1 for change) and stake
//! with its one stake key (`2/0`, CIP-11), so its rewards, its delegation and its votes are that
//! key's (`address`).
//!
//! This reads a transaction's body as the ledger does (`body`: Conway's CDDL, in the canonical CBOR
//! Cardano's hardware wallets take, CIP-21) and says what it does (`display`): ADA and tokens sent,
//! and to whom; change only where maki has made the address itself; staking, rewards and vote
//! delegation spelled out; the fee, which a body states, so nothing is hidden in the coins it
//! spends; and what maki doesn't sign (what's for scripts, pools and governance) refused, saying
//! why. What the computer asks beside the body, which keys sign and which outputs are change, is
//! `request`.
//!
//! What's signed is the BLAKE2b-256 of the body, its bytes as they go on chain: the transaction's
//! ID (`tx_id`). Each of the account's keys that must witness it signs that with Ed25519 (the
//! extended key's, which any Ed25519 verifier takes), and the computer puts each key with its
//! signature in the transaction's witness set.

#![no_std]
extern crate alloc;

use alloc::string::String;

use blake2::Blake2b;
use blake2::digest::Digest;
use blake2::digest::consts::{U28, U32};

pub mod address;
pub mod body;
mod cbor;
pub mod display;
pub mod request;
pub mod tokens;

pub use address::Address;
pub use body::Body;
pub use request::{Key, Request};

/// A key's or a script's hash, as addresses, certificates and policies name them: BLAKE2b-224.
pub type Hash28 = [u8; 28];

/// BIP32's hardened offset (`1852'`).
pub const HARDENED: u32 = 0x8000_0000;
/// CIP-1852's purpose: Cardano's keys since Shelley.
pub const PURPOSE: u32 = 1852 | HARDENED;
/// Cardano's coin type (SLIP-44).
pub const COIN: u32 = 1815 | HARDENED;
/// A key's role in its account (CIP-1852): the keys addresses are given out for.
pub const RECEIVE: u8 = 0;
/// The keys change goes back to.
pub const CHANGE: u8 = 1;
/// The account's stake key's role: the one at index 0 is its stake key (CIP-11).
pub const STAKING: u8 = 2;

/// One ADA, in lovelace: Cardano counts in millionths.
pub const LOVELACE_PER_ADA: u64 = 1_000_000;
/// All the ADA there will ever be (45 billion), in lovelace: no amount is more.
pub const MAX_LOVELACE: u64 = 45_000_000_000 * LOVELACE_PER_ADA;

/// Why maki won't read what it's asked to sign: each says why, for the computer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bigger than maki takes.
    TooBig,
    /// Not CBOR as Cardano's hardware wallets take a transaction (CIP-21): cut short, with more
    /// after it, or something written another way than its shortest, with its length stated,
    /// and each map's keys in order.
    Encoding,
    /// Something that isn't what Conway's CDDL has where it is: a number for bytes, a list too
    /// short, a hash too long.
    Shape,
    /// A field maki doesn't know: it won't sign what it can't show.
    Unknown,
    /// Something given twice: a map's key, a set's member.
    Duplicate,
    /// An address Cardano doesn't have, or not where it's found.
    Address,
    /// What maki doesn't sign: what it is.
    Unsupported(&'static str),
    /// Something Cardano would refuse, or maki won't take: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than a Cardano transaction can be"),
            Error::Encoding => f.write_str(
                "not written as Cardano's hardware wallets take a transaction (CIP-21's canonical CBOR): cut short, or written another way",
            ),
            Error::Shape => {
                f.write_str("not a Cardano transaction: something isn't what the ledger's CDDL has there")
            }
            Error::Unknown => f.write_str("a field maki doesn't know: it won't sign what it can't show"),
            Error::Duplicate => f.write_str("not a Cardano transaction: something given twice"),
            Error::Address => f.write_str("an address Cardano doesn't have"),
            Error::Unsupported(what) => write!(f, "{what}: maki doesn't sign those"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// Cardano's networks: its own, and Preprod, the test network wallets try things on (maki's network
/// 1, as Koios's `preprod` is). Every address says which kind it's for (its header's last bit: 1
/// for Cardano's own, 0 for any test network), and a body may say so too; maki takes a transaction
/// only for the network it's told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Cardano's own network, whose ADA is the real thing.
    Mainnet,
    /// Preprod, a test network, whose ADA is worth nothing.
    Preprod,
}

impl Network {
    /// The network a message's byte names: 0 for Cardano's own, 1 for Preprod.
    pub fn from_byte(b: u8) -> Option<Network> {
        match b {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Preprod),
            _ => None,
        }
    }

    /// Its network ID, as addresses and bodies carry it: 1 for Cardano's own, 0 for a test
    /// network (any of them).
    pub fn id(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Preprod => 0,
        }
    }

    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "Cardano",
            Network::Preprod => "Preprod (test)",
        }
    }

    /// Its ADA's unit: test ADA is marked as such.
    pub fn unit(self) -> &'static str {
        match self {
            Network::Mainnet => "ADA",
            Network::Preprod => "tADA",
        }
    }

    /// When slot `slot` began, in seconds since 1970, by the network's genesis: twenty seconds a
    /// slot in the Byron era, then one, from the first of Shelley's (mainnet's 4,492,800, at
    /// 2020-07-29 21:44:51 UTC; Preprod's 86,400, at 2022-06-21 00:00:00 UTC).
    pub fn slot_time(self, slot: u64) -> u64 {
        let (start, shelley, shelley_time) = match self {
            Network::Mainnet => (1_506_203_091, 4_492_800, 1_596_059_091),
            Network::Preprod => (1_654_041_600, 86_400, 1_655_769_600),
        };
        if slot < shelley { start + slot * 20 } else { (slot - shelley).saturating_add(shelley_time) }
    }

    /// The slot that begins at `time` (seconds since 1970), or the first if it's before then:
    /// `slot_time`'s inverse, in Shelley's slots.
    pub fn slot_at(self, time: u64) -> u64 {
        let (shelley, shelley_time) = match self {
            Network::Mainnet => (4_492_800, 1_596_059_091),
            Network::Preprod => (86_400, 1_655_769_600),
        };
        time.saturating_sub(shelley_time).saturating_add(shelley)
    }
}

/// Account `account`'s path: `m/1852'/1815'/account'`. Its public key and chain code give every
/// address under it.
pub fn account_path(account: u32) -> [u32; 3] { [PURPOSE, COIN, account | HARDENED] }

/// Key `index` of `role` in account `account`: `m/1852'/1815'/account'/role/index`.
pub fn key_path(account: u32, role: u8, index: u32) -> [u32; 5] {
    [PURPOSE, COIN, account | HARDENED, role as u32, index]
}

/// The account's stake key's path: `m/1852'/1815'/account'/2/0` (CIP-11).
pub fn stake_path(account: u32) -> [u32; 5] { key_path(account, STAKING, 0) }

/// A key's hash, as an address or a certificate names it: the BLAKE2b-224 of its 32 bytes.
pub fn key_hash(key: &[u8; 32]) -> Hash28 { Blake2b::<U28>::digest(key).into() }

/// A transaction's ID, and what each of its witnesses signs: the BLAKE2b-256 of its body's bytes,
/// exactly as they go on chain.
pub fn tx_id(body: &[u8]) -> [u8; 32] { Blake2b::<U32>::digest(body).into() }

/// `bytes` in hex, as Cardano's tools show hashes and IDs.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
