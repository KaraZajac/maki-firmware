//! NEAR, for maki's NEAR app (ARCHITECTURE.md, "Wallets are apps"): an account's name and key, and
//! what it signs, read strictly and shown before it's signed. maki keeps the key: Ed25519 by
//! SLIP-10 at `m/44'/397'/i'`, the first as MyNearWallet, near-cli and Trust Wallet make it from a
//! phrase (Ledger's NEAR app uses `44'/397'/0'/0'/1'`, another key, so its accounts aren't these).
//! The account is the key's own, its implicit account: the key's 32 bytes in hex. This reads a
//! transaction as nearcore reads it (`tx`: borsh, the actions NEAR's own JavaScript library makes,
//! and what nearcore would refuse refused), and says what it does (`display`): NEAR and tokens sent
//! and to whom, contracts called and with what, keys added and deleted, staking, and the most the
//! fee can be; anything that hands the account, its code or what it holds to another, loudly.
//!
//! What's signed is the SHA-256 of the transaction's borsh bytes (`hash`, which is also its ID on
//! the chain), with Ed25519. The signed transaction NEAR's nodes take is the transaction's bytes,
//! then the signature's kind (0, Ed25519) and its 64 bytes.

#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};

use sha2::{Digest, Sha256};

pub mod account;
pub mod base58;
mod borsh;
pub mod display;
pub mod fees;
pub mod json;
pub mod tokens;
pub mod tx;

pub use tx::Transaction;

/// An Ed25519 public key: what an implicit account is named by.
pub type Key = [u8; 32];

/// BIP32's hardened offset (`44'`).
pub const HARDENED: u32 = 0x8000_0000;

/// One NEAR, in yoctoNEAR: NEAR counts in 10^-24.
pub const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;

/// Account `index`'s path: `m/44'/397'/index'`. The first, `m/44'/397'/0'`, is the one
/// MyNearWallet, near-cli and Trust Wallet make from a phrase; maki counts the ones after it in
/// the same place, as near-cli takes a path.
pub fn path(index: u32) -> [u32; 3] { [44 | HARDENED, 397 | HARDENED, index | HARDENED] }

/// NEAR's networks: its own, and its test network. A NEAR transaction doesn't say which network
/// it's for (it names a recent block, which only that network has), so this decides what maki
/// calls it, which tokens it knows, and which names give a transaction away as the other's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// NEAR's own network, whose NEAR is the real thing.
    Mainnet,
    /// Its test network, whose NEAR is worth nothing.
    Testnet,
}

impl Network {
    /// The network a message's byte names: 0 for NEAR's own, 1 for its test network.
    pub fn from_byte(b: u8) -> Option<Network> {
        match b {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "NEAR",
            Network::Testnet => "NEAR testnet",
        }
    }
}

/// The implicit account of `key`: its 32 bytes in lowercase hex, 64 characters. The account is
/// made when NEAR is first sent to it, with that key in control of it.
pub fn account_id(key: &Key) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    key.iter().flat_map(|b| [HEX[(b >> 4) as usize] as char, HEX[(b & 15) as usize] as char]).collect()
}

/// An Ed25519 key as NEAR writes it: `ed25519:` and the key in base58.
pub fn public_key(key: &Key) -> String { tx::PublicKey::Ed25519(*key).to_string() }

/// What's signed: the SHA-256 of a transaction's borsh bytes, which is also the transaction's ID
/// (in base58, as explorers show it).
pub fn hash(transaction: &[u8]) -> [u8; 32] { Sha256::digest(transaction).into() }
