//! Sui, for maki's Sui app (ARCHITECTURE.md, "Wallets are apps"): an account's address, and what
//! it signs, read strictly and shown before it's signed. maki keeps the key: Ed25519 by SLIP-10 at
//! `m/44'/784'/i'/0'/0'`, every step hardened, as Slush (Sui's own wallet), Ledger's Sui app and
//! Sui's TypeScript library make it from a phrase, with accounts counted at the third step as Sui's
//! wallet specification has them. This reads a transaction's data as Sui's validators read it
//! (`tx`), and says what it does (`display`): SUI and tokens sent and to whom, from coins or from
//! the address balance, staking, the most the fee can be, a Move call maki can't read flagged with
//! what it's given, and anything that would let another key or account act for this one refused.
//!
//! What's signed is the BLAKE2b-256 of the intent message: three bytes, [0, 0, 0] (a transaction's
//! data, intent version 0, Sui), then the transaction's data, as BCS. Ed25519 signs those 32
//! bytes. Sui takes the signature with its scheme's flag in front and the key after it: 0 (Ed25519),
//! the 64 bytes of signature, the 32 of key.

#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

mod bcs;
pub mod display;
pub mod tokens;
pub mod tx;

pub use tx::Transaction;

/// An address, or an object's ID: 32 bytes, as transactions carry them.
pub type Address = [u8; 32];

/// BIP32's hardened offset (`44'`).
pub const HARDENED: u32 = 0x8000_0000;

/// Account `index`'s path: `m/44'/784'/index'/0'/0'`. The first, `m/44'/784'/0'/0'/0'`, is every
/// Sui wallet's; Slush and Ledger count the ones after it at the third step, as Sui's wallet
/// specification asks.
pub fn path(index: u32) -> [u32; 5] { [44 | HARDENED, 784 | HARDENED, index | HARDENED, HARDENED, HARDENED] }

/// The flag that says a signature, or a key, is Ed25519's.
pub const ED25519: u8 = 0x00;

/// What's in front of a transaction's data when it's signed: an intent to sign a transaction's
/// data (0), version 0, for Sui (0). It keeps a signature for one thing from passing for another.
pub const INTENT: [u8; 3] = [0, 0, 0];

/// Sui's networks: its own, and its test network. A transaction names its network only when it
/// says when it's valid (with epochs, on a chain), or draws on an address balance in the way older
/// software does (a coin reservation); otherwise only the objects it names, which maki can't see,
/// tie it to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Sui's own network, whose SUI is the real thing.
    Mainnet,
    /// Sui's test network, whose SUI is worth nothing.
    Testnet,
}

impl Network {
    /// The network a message's byte names: 0 for Sui's own, 1 for its test network.
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
            Network::Mainnet => "Sui",
            Network::Testnet => "Sui testnet",
        }
    }

    /// Its chain identifier: the digest of its first checkpoint (sui-types' `MAINNET_` and
    /// `TESTNET_CHAIN_IDENTIFIER_BASE58`), which a transaction names to be good there alone.
    pub fn chain(self) -> [u8; 32] {
        match self {
            // 4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S
            Network::Mainnet => bytes32("35834a8ac17ca48fb14ac8f99c17c98747e95dd07294ae41a46b382246a4499b"),
            // 69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD
            Network::Testnet => bytes32("4c78adacf2a2f5ad80f27ed7d54aa69d3a78f1ca67fdef9ecf5754f5b8bb77b0"),
        }
    }

    /// The network a chain identifier is, if it's one of these.
    pub fn of_chain(chain: &[u8; 32]) -> Option<Network> {
        [Network::Mainnet, Network::Testnet].into_iter().find(|n| n.chain() == *chain)
    }
}

/// 32 bytes written as 64 hex digits, for the constants here; a mistake in one fails the build.
pub(crate) const fn bytes32(hex: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let h = hex.as_bytes();
    assert!(h.len() == 64, "not 32 bytes");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(h[2 * i]) << 4 | digit(h[2 * i + 1]);
        i += 1;
    }
    out
}

/// BLAKE2b with a 32-byte digest (Sui's `DefaultHash`), over `parts` one after the other.
pub(crate) fn blake2b(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// The address of the Ed25519 key `key`: the BLAKE2b-256 of its flag and the key, all 32 bytes.
pub fn address_of(key: &[u8; 32]) -> Address { blake2b(&[&[ED25519], key]) }

/// An address (or an object's ID) as Sui writes it: `0x` and 64 lowercase hex digits.
pub fn address(a: &Address) -> String {
    let mut out = String::from("0x");
    out.push_str(&hex(a));
    out
}

/// The address `text` writes, if it's written in full as Sui writes an account's: `0x` and 64 hex
/// digits, either case. The short forms Sui allows for its own objects (`0x2`) aren't anyone's
/// account.
pub fn parse_address(text: &str) -> Option<Address> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let value = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        out[i] = value(pair[0])? << 4 | value(pair[1])?;
    }
    Some(out)
}

/// What's signed for a transaction whose data (BCS, as `Transaction::parse` reads it) is `tx`: the
/// BLAKE2b-256 of `INTENT` and the data.
pub fn signing_digest(tx: &[u8]) -> [u8; 32] { blake2b(&[&INTENT, tx]) }

/// A signature as Sui takes it (a `GenericSignature`'s bytes, which its APIs take in base64): the
/// flag, the signature, the key.
pub fn signature(signature: &[u8; 64], key: &[u8; 32]) -> [u8; 97] {
    let mut out = [0u8; 97];
    out[0] = ED25519;
    out[1..65].copy_from_slice(signature);
    out[65..].copy_from_slice(key);
    out
}

/// Where Sui keeps address balances: the shared object `0xacc`, one dynamic field a balance.
pub const ACCUMULATOR_ROOT: Address =
    bytes32("0000000000000000000000000000000000000000000000000000000000000acc");

/// The dynamic field that holds `owner`'s address balance of `coin` (the type of coin, as
/// `0x2::sui::SUI`): a field of `ACCUMULATOR_ROOT` keyed by the owner's address, of type
/// `0x2::accumulator::Key<0x2::balance::Balance<coin>>`, whose ID is the BLAKE2b-256 of 0xf0, the
/// parent, the key's length (eight bytes) and the key, then the key's type, as Sui derives it.
pub fn balance_field(owner: &Address, coin: &tx::TypeTag) -> Address {
    let key = tx::TypeTag::framework("accumulator", "Key", alloc::vec![tx::TypeTag::balance(coin.clone())]);
    let mut tag = Vec::new();
    key.write(&mut tag);
    blake2b(&[&[0xf0], &ACCUMULATOR_ROOT, &32u64.to_le_bytes(), owner, &tag])
}

/// An object's ID masked with a chain identifier, or unmasked again: how a coin reservation names
/// the field it draws on, so that one made for one network names nothing on another.
pub fn mask(id: &Address, chain: &[u8; 32]) -> Address {
    let mut out = *id;
    for (o, c) in out.iter_mut().zip(chain) {
        *o ^= c;
    }
    out
}
