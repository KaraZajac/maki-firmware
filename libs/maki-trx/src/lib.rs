//! Tron, for maki's Tron app (ARCHITECTURE.md, "Wallets are apps"): an account's address, and what
//! it signs, read strictly and shown before it's signed. maki keeps the key: BIP32 on secp256k1 at
//! `m/44'/195'/0'/0/i`, the first as TronLink and Ledger's Tron app make it, the next ones as
//! TronLink, MetaMask and Keystone do (Ledger Live counts its accounts a level up, at
//! `m/44'/195'/i'/0/0`, so its others aren't these). This reads a transaction's `raw_data` as Tron's
//! own software writes it (`tx`), and says what it does (`display`): TRX and tokens sent and to
//! whom, staking, delegating and votes spelled out, the most the fee can be, a call maki can't read
//! flagged, and anything that would change who controls the account refused.
//!
//! What's signed is the SHA-256 of `raw_data`, which is also the transaction's ID, with ECDSA on
//! secp256k1. The signature goes in the transaction's `signature` as r, s and v, 65 bytes, v 27 or
//! 28 as TronWeb writes it (java-tron takes 0 and 1 too).

#![no_std]
extern crate alloc;

use alloc::string::String;

use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub mod base58;
pub mod display;
mod proto;
pub mod tokens;
pub mod tx;

pub use tx::Transaction;

/// An address as Tron's transactions carry it: `PREFIX`, then the last 20 bytes of the Keccak-256
/// of the account's public key (uncompressed, without its first byte), as Ethereum's are.
pub type Address = [u8; 21];

/// The first byte of every address on Tron's networks, the main one and its test networks: what
/// makes base58check write them with a `T`.
pub const PREFIX: u8 = 0x41;

/// BIP32's hardened offset (`44'`).
pub const HARDENED: u32 = 0x8000_0000;

/// Account `index`'s path: `m/44'/195'/0'/0/index`. The first, `m/44'/195'/0'/0/0`, is the one
/// every Tron wallet makes from a phrase; TronLink, MetaMask and Keystone count the ones after it
/// here, in the last place.
pub fn path(index: u32) -> [u32; 5] { [44 | HARDENED, 195 | HARDENED, HARDENED, 0, index] }

/// Tron's networks: its own, and Nile, the test network its developers use. A Tron transaction
/// doesn't say which network it's for (it names a recent block, which only that network has), so
/// this decides only what maki calls it, and which tokens it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Tron's own network, whose TRX is the real thing.
    Tron,
    /// Nile, a test network, whose TRX is worth nothing.
    Nile,
}

impl Network {
    /// The network a message's byte names: 0 for Tron's own, 1 for Nile.
    pub fn from_byte(b: u8) -> Option<Network> {
        match b {
            0 => Some(Network::Tron),
            1 => Some(Network::Nile),
            _ => None,
        }
    }

    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Tron => "Tron",
            Network::Nile => "Nile",
        }
    }
}

/// The address of the key `04 || x || y`; None if it isn't an uncompressed key.
pub fn address_of(key: &[u8; 65]) -> Option<Address> {
    if key[0] != 0x04 {
        return None;
    }
    let hash = Keccak256::digest(&key[1..]);
    let mut out = [PREFIX; 21];
    out[1..].copy_from_slice(&hash[12..]);
    Some(out)
}

/// An address as it's written: base58check, `T` and 33 more.
pub fn address(a: &Address) -> String { base58::check_encode(a) }

/// The address `text` writes, if it's a Tron address: base58check of 21 bytes, the first `PREFIX`.
pub fn parse_address(text: &str) -> Option<Address> {
    // every Tron address is 34 characters: nothing longer is worth decoding
    if text.len() != 34 {
        return None;
    }
    let a: Address = base58::check_decode(text)?.try_into().ok()?;
    (a[0] == PREFIX).then_some(a)
}

/// What's signed: the SHA-256 of a transaction's `raw_data`, which is its ID too.
pub fn txid(raw: &[u8]) -> [u8; 32] { Sha256::digest(raw).into() }

/// The signature as it goes in a transaction: r and s (s low), then v, 27 plus the recovery ID (0
/// to 3, as maki gives it), as TronWeb writes it.
pub fn signature(rs: &[u8; 64], recovery: u8) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(rs);
    out[64] = 27 + (recovery & 3);
    out
}
