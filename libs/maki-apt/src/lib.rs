//! Aptos, for maki's Aptos app (ARCHITECTURE.md, "Wallets are apps"): an account's address, and what
//! it signs, read strictly and shown before it's signed. maki keeps the key: Ed25519 by SLIP-10 at
//! `m/44'/637'/i'/0'/0'`, as Petra, Ledger's Aptos app and Aptos's own SDKs make it. This reads a
//! transaction (a `RawTransaction`, in BCS) as Aptos's own software reads it (`tx`), and says what it
//! does (`display`): APT, coins and fungible assets sent and to whom, in the units of the ones maki
//! knows; staking with a delegation pool; an object handed over; the network; when it expires; the
//! most the fee can be; any other call flagged, with its function and arguments; and anything that
//! would change who controls the account refused.
//!
//! What's signed is the transaction's signing message (`signing_message`): the SHA3-256 of
//! `APTOS::RawTransaction`, then the transaction's BCS, with Ed25519 over the whole of it. The
//! signature goes in a `SignedTransaction`, after the transaction, with this account's key
//! (`authenticator`).

#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sha3::{Digest, Sha3_256};

pub mod assets;
mod bcs;
pub mod call;
pub mod display;
pub mod tx;

pub use tx::Transaction;

/// An address: an account's (made from its key, `address_of`), an object's, or a module's home.
pub type Address = [u8; 32];

/// 0x1, where Aptos's own modules are (its framework): every function maki reads is one of them.
pub const FRAMEWORK: Address = {
    let mut a = [0u8; 32];
    a[31] = 1;
    a
};

/// BIP32's hardened offset (`44'`).
pub const HARDENED: u32 = 0x8000_0000;

/// Account `index`'s path: `m/44'/637'/index'/0'/0'`, every step hardened, as SLIP-10 has Ed25519.
/// Petra, Ledger's Aptos app and the SDKs count their accounts at the third step, as maki does.
pub fn path(index: u32) -> [u32; 5] { [44 | HARDENED, 637 | HARDENED, index | HARDENED, HARDENED, HARDENED] }

/// Aptos's networks: its own, and its test network. A transaction names the one it's for (its chain
/// ID), and no other takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Aptos's own network, whose APT is the real thing: chain 1.
    Mainnet,
    /// The test network, whose APT is worth nothing: chain 2.
    Testnet,
}

impl Network {
    /// The network a message's byte names: 0 for Aptos's own, 1 for its test network.
    pub fn from_byte(b: u8) -> Option<Network> {
        match b {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// The chain ID its transactions carry.
    pub fn chain_id(self) -> u8 {
        match self {
            Network::Mainnet => 1,
            Network::Testnet => 2,
        }
    }

    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "Aptos",
            Network::Testnet => "Aptos testnet",
        }
    }
}

/// The address an Ed25519 key makes: its authentication key, the SHA3-256 of the key and the byte
/// of its scheme, 0 (Ed25519's own, as Petra, Ledger's app and the SDKs make accounts; the same key
/// under `SingleKey`, scheme 2, makes another address, which they don't use). An account keeps the
/// address it was made with if its key is changed later; maki's account is the one its key makes,
/// and maki signs for no other.
pub fn address_of(key: &[u8; 32]) -> Address {
    let mut h = Sha3_256::new();
    h.update(key);
    h.update([0u8]);
    h.finalize().into()
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Whether an address is one of Aptos's own (0x0 to 0xf), which are written short.
pub fn is_special(a: &Address) -> bool { a[..31].iter().all(|&b| b == 0) && a[31] < 16 }

/// An address as Aptos writes it (AIP-40): `0x` and its 64 hex digits, or for one of Aptos's own
/// (0x0 to 0xf), `0x` and one.
pub fn address(a: &Address) -> String {
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    if is_special(a) {
        out.push(HEX[a[31] as usize] as char);
    } else {
        for b in a {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    out
}

/// The address `text` writes, as AIP-40 has addresses written: `0x` and 64 hex digits, or one for
/// Aptos's own (0x0 to 0xf). Nothing else, so no two texts are the same address.
pub fn parse_address(text: &str) -> Option<Address> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    let value = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut a = [0u8; 32];
    match digits.len() {
        1 => a[31] = value(digits[0])?,
        64 => {
            for (i, pair) in digits.chunks(2).enumerate() {
                a[i] = value(pair[0])? << 4 | value(pair[1])?;
            }
        }
        _ => return None,
    }
    Some(a)
}

/// What every transaction's signing message starts with: the SHA3-256 of `APTOS::RawTransaction`,
/// which keeps a transaction's signature from being anything else's.
pub fn prefix() -> [u8; 32] { Sha3_256::digest(b"APTOS::RawTransaction").into() }

/// What maki signs for a transaction (Ed25519 over the whole of it): `prefix`, then the
/// transaction's BCS.
pub fn signing_message(raw: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + raw.len());
    m.extend_from_slice(&prefix());
    m.extend_from_slice(raw);
    m
}

/// What follows the transaction in a `SignedTransaction` signed by a single Ed25519 key: its
/// `TransactionAuthenticator` (0, Ed25519), the key and the signature, each as BCS writes bytes (its
/// length, then it). The transaction's BCS and these are what Aptos's fullnodes take.
pub fn authenticator(key: &[u8; 32], signature: &[u8; 64]) -> [u8; 99] {
    let mut out = [0u8; 99];
    out[1] = 32;
    out[2..34].copy_from_slice(key);
    out[34] = 64;
    out[35..].copy_from_slice(signature);
    out
}
