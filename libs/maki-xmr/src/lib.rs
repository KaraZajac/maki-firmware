//! Monero for maki's Monero app (ARCHITECTURE.md in the maki repo, "Wallets are apps"): the
//! addresses the app shows and hands the computer, from public keys maki gives it; and, with the
//! `keys` feature, what maki-keys makes those from: the account's keys from the recovery phrase,
//! as Ledger's Monero app makes them (so the phrase gives the same wallet there), its
//! subaddresses, and its 25-word backup, which restores it in any Monero wallet. The app never
//! holds a secret key: maki does the curve work, and shows the words itself.
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sha3::{Digest, Keccak256};

#[cfg(feature = "keys")]
mod english;
#[cfg(feature = "keys")]
mod keys;
#[cfg(feature = "keys")]
pub mod words;
#[cfg(feature = "keys")]
pub mod sign;
#[cfg(feature = "keys")]
pub mod bulletproof;
#[cfg(feature = "keys")]
pub mod spend;
pub mod request;
pub mod tx;

#[cfg(feature = "keys")]
pub use keys::Keys;

/// Which Monero: the real one, or a network for testing (addresses start `4` or `8`, `9` or `A`
/// and `B`, `5` or `7`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Stagenet,
}

/// An account's own address, or one of its subaddresses (any but account 0's address 0, which is
/// the account's own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Standard,
    Subaddress,
}

impl Network {
    /// The name people use.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "monero",
            Network::Testnet => "testnet",
            Network::Stagenet => "stagenet",
        }
    }

    /// The tag an address starts with (one byte: they're all under 128).
    fn tag(self, kind: Kind) -> u8 {
        match (self, kind) {
            (Network::Mainnet, Kind::Standard) => 18,
            (Network::Mainnet, Kind::Subaddress) => 42,
            (Network::Testnet, Kind::Standard) => 53,
            (Network::Testnet, Kind::Subaddress) => 63,
            (Network::Stagenet, Kind::Standard) => 24,
            (Network::Stagenet, Kind::Subaddress) => 36,
        }
    }

    /// The tag an integrated address (a standard one with a payment ID) starts with.
    fn integrated_tag(self) -> u8 {
        match self {
            Network::Mainnet => 19,
            Network::Testnet => 54,
            Network::Stagenet => 25,
        }
    }
}

/// Keccak-256, as Monero hashes (Keccak's own padding, not SHA-3's).
pub fn keccak(data: &[u8]) -> [u8; 32] { Keccak256::digest(data).into() }

/// An address, from its public spend and view keys: the tag, the keys and four bytes of their
/// hash to check them by, in Monero's base58 (95 characters).
pub fn address(network: Network, kind: Kind, spend: &[u8; 32], view: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(69);
    data.push(network.tag(kind));
    data.extend_from_slice(spend);
    data.extend_from_slice(view);
    let check = keccak(&data);
    data.extend_from_slice(&check[..4]);
    base58::encode(&data)
}

/// An integrated address: a standard address with a payment ID, which a payment to it carries,
/// encrypted (106 characters).
pub fn integrated_address(network: Network, spend: &[u8; 32], view: &[u8; 32], payment_id: &[u8; 8]) -> String {
    let mut data = Vec::with_capacity(77);
    data.push(network.integrated_tag());
    data.extend_from_slice(spend);
    data.extend_from_slice(view);
    data.extend_from_slice(payment_id);
    let check = keccak(&data);
    data.extend_from_slice(&check[..4]);
    base58::encode(&data)
}

/// What an address says: its network, kind and public spend and view keys. None if it isn't a
/// standard address or a subaddress (integrated addresses aren't taken), or its check fails.
pub fn read_address(text: &str) -> Option<(Network, Kind, [u8; 32], [u8; 32])> {
    let data = base58::decode(text)?;
    if data.len() != 69 || keccak(&data[..65])[..4] != data[65..] {
        return None;
    }
    let (network, kind) = [Network::Mainnet, Network::Testnet, Network::Stagenet]
        .into_iter()
        .flat_map(|n| [(n, Kind::Standard), (n, Kind::Subaddress)])
        .find(|(n, k)| n.tag(*k) == data[0])?;
    Some((network, kind, data[1..33].try_into().unwrap(), data[33..65].try_into().unwrap()))
}

/// Monero's base58: Bitcoin's alphabet, eight bytes at a time, each block eleven characters (a
/// last, shorter one fewer), so a string's length gives its bytes' away without a checksum.
pub mod base58 {
    use alloc::string::String;
    use alloc::vec::Vec;

    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    /// Characters for a block of n bytes.
    const ENCODED: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(8) * 11);
        for block in data.chunks(8) {
            let mut n = block.iter().fold(0u64, |n, b| (n << 8) | *b as u64);
            let mut chars = [b'1'; 11];
            let len = ENCODED[block.len()];
            for c in chars[..len].iter_mut().rev() {
                *c = ALPHABET[(n % 58) as usize];
                n /= 58;
            }
            out.extend(chars[..len].iter().map(|c| *c as char));
        }
        out
    }

    /// None for a character outside the alphabet, a length no data encodes to, or a block too
    /// big for its bytes.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let text = text.as_bytes();
        let mut out = Vec::with_capacity(text.len() / 11 * 8 + 8);
        for block in text.chunks(11) {
            let bytes = ENCODED.iter().position(|n| *n == block.len())?;
            let mut n: u128 = 0;
            for c in block {
                n = n * 58 + ALPHABET.iter().position(|a| a == c)? as u128;
            }
            if bytes < 8 && n >> (8 * bytes) != 0 || n > u64::MAX as u128 {
                return None;
            }
            out.extend_from_slice(&(n as u64).to_be_bytes()[8 - bytes..]);
        }
        Some(out)
    }
}
