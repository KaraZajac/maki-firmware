//! Kaspa's addresses: the network's prefix, a colon, then a version byte and a payload (an x-only
//! Schnorr key, an ECDSA key, or a script's hash) in base32, five bits a character, closed by a
//! 40-bit checksum over the prefix and the rest (CashAddr's, as rusty-kaspa's `kaspa-addresses`
//! computes it). Each address has one spelling here: lower case, its padding bits zero.
//!
//! An output's script public key is what it pays; the three kinds with addresses are Kaspa's
//! standard ones (rusty-kaspa's `ScriptClass`): pay to a Schnorr key (`OP_DATA_32 <key>
//! OP_CHECKSIG`), to an ECDSA key (`OP_DATA_33 <key> OP_CHECKSIGECDSA`), and to a script hash
//! (`OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL`). This wallet's addresses are the first kind.

use alloc::string::String;
use alloc::vec::Vec;

use crate::Network;
use crate::request::Script;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The checksum's generator (CashAddr's).
const GENERATORS: [u64; 5] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];

/// The longest address there is: `kaspatest:`, then a version byte and 33 bytes in 55 characters,
/// then 8 of checksum.
pub const MAX_ADDRESS: usize = 10 + 55 + 8;

/// What an address pays: its version byte, and how long its payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A Schnorr key, x only (version 0): this wallet's kind.
    Schnorr,
    /// An ECDSA key, compressed (version 1).
    Ecdsa,
    /// A script's BLAKE2b hash (version 8).
    ScriptHash,
}

impl Kind {
    pub fn version(self) -> u8 {
        match self {
            Kind::Schnorr => 0,
            Kind::Ecdsa => 1,
            Kind::ScriptHash => 8,
        }
    }

    pub fn payload_len(self) -> usize {
        match self {
            Kind::Schnorr | Kind::ScriptHash => 32,
            Kind::Ecdsa => 33,
        }
    }

    fn from_version(version: u8) -> Option<Kind> {
        match version {
            0 => Some(Kind::Schnorr),
            1 => Some(Kind::Ecdsa),
            8 => Some(Kind::ScriptHash),
            _ => None,
        }
    }
}

/// Why text isn't a Kaspa address maki takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No prefix, or not Kaspa's or its test networks'.
    Prefix,
    /// A character base32 hasn't (upper case among them).
    Character,
    /// The checksum doesn't match: a character mistyped.
    Checksum,
    /// Too short or too long, or a payload not as long as its version's.
    Length,
    /// A version Kaspa hasn't.
    Version,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Prefix => "not a Kaspa address: it doesn't start kaspa: or kaspatest:",
            Error::Character => "not a Kaspa address: a character it can't have",
            Error::Checksum => "not a Kaspa address: its checksum doesn't match",
            Error::Length => "not a Kaspa address: too short or too long",
            Error::Version => "a Kaspa address of a kind maki doesn't know",
        })
    }
}

/// An address read: whose network, what kind, and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub network: Network,
    pub kind: Kind,
    pub payload: Vec<u8>,
}

fn polymod(values: impl Iterator<Item = u8>) -> u64 {
    let mut c = 1u64;
    for d in values {
        let top = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64;
        for (bit, g) in GENERATORS.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                c ^= g;
            }
        }
    }
    c ^ 1
}

/// The checksum of a prefix and the five-bit groups after it.
fn checksum(prefix: &str, groups: &[u8]) -> u64 {
    polymod(prefix.bytes().map(|c| c & 0x1f).chain([0]).chain(groups.iter().copied()).chain([0; 8]))
}

/// Bytes as five-bit groups, the last padded with zeros.
fn to_groups(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut acc, mut bits) = (0u16, 0);
    for &b in bytes {
        acc = (acc << 8) | b as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

/// Five-bit groups as bytes, if they're some bytes' groups: fewer than five bits left over, and
/// those zero.
fn from_groups(groups: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(groups.len() * 5 / 8);
    let (mut acc, mut bits) = (0u16, 0);
    for &g in groups {
        acc = (acc << 5) | g as u16;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    (bits < 5 && acc == 0).then_some(out)
}

/// An address: `prefix`, then the version byte and payload, then the checksum. Any prefix and
/// payload, as Kaspa's own tests have them; `of_key` and `of_script` make a network's.
pub fn encode(prefix: &str, version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len());
    data.push(version);
    data.extend_from_slice(payload);
    let groups = to_groups(&data);
    let sum = to_groups(&checksum(prefix, &groups).to_be_bytes()[3..]);
    let mut out = String::with_capacity(prefix.len() + 1 + groups.len() + sum.len());
    out.push_str(prefix);
    out.push(':');
    out.extend(groups.iter().chain(&sum).map(|&g| CHARSET[g as usize] as char));
    out
}

/// An address, read strictly: Kaspa's prefix or its test networks', characters of base32's lower
/// case, the checksum right, and a payload as long as its version says.
pub fn decode(text: &str) -> Result<Address, Error> {
    if text.len() > MAX_ADDRESS {
        return Err(Error::Length);
    }
    let (prefix, rest) = text.split_once(':').ok_or(Error::Prefix)?;
    let network = match prefix {
        "kaspa" => Network::Mainnet,
        "kaspatest" => Network::Testnet,
        _ => return Err(Error::Prefix),
    };
    let groups = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|g| g as u8))
        .collect::<Option<Vec<u8>>>()
        .ok_or(Error::Character)?;
    let split = groups.len().checked_sub(8).filter(|&n| n > 0).ok_or(Error::Length)?;
    let (data, sum) = groups.split_at(split);
    let said = sum.iter().fold(0u64, |acc, &g| (acc << 5) | g as u64);
    if checksum(prefix, data) != said {
        return Err(Error::Checksum);
    }
    let data = from_groups(data).ok_or(Error::Length)?;
    let (&version, payload) = data.split_first().ok_or(Error::Length)?;
    let kind = Kind::from_version(version).ok_or(Error::Version)?;
    if payload.len() != kind.payload_len() {
        return Err(Error::Length);
    }
    Ok(Address { network, kind, payload: payload.to_vec() })
}

/// The script a coin of a Schnorr key's pays: `OP_DATA_32 <key> OP_CHECKSIG`.
pub fn schnorr_script(key: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x20);
    s.extend_from_slice(key);
    s.push(0xac);
    s
}

/// The x-only key (BIP340's) of a compressed one: what a Schnorr address and script carry.
pub fn x_only(key: &[u8; 33]) -> [u8; 32] {
    let mut x = [0u8; 32];
    x.copy_from_slice(&key[1..]);
    x
}

/// The address of a key of this wallet's (compressed), as Kaspa's wallets make it: the Schnorr
/// kind, of its x-only key.
pub fn of_key(network: Network, key: &[u8; 33]) -> String {
    encode(network.prefix(), Kind::Schnorr.version(), &x_only(key))
}

/// The address a script public key pays, if it's one of the three standard kinds; None for any
/// other, which Kaspa's nodes don't relay.
pub fn of_script(network: Network, script: &Script) -> Option<String> {
    if script.version != 0 {
        return None;
    }
    let (kind, payload) = match script.script.as_slice() {
        [0x20, key @ .., 0xac] if key.len() == 32 => (Kind::Schnorr, key),
        [0x21, key @ .., 0xab] if key.len() == 33 => (Kind::Ecdsa, key),
        [0xaa, 0x20, hash @ .., 0x87] if hash.len() == 32 => (Kind::ScriptHash, hash),
        _ => return None,
    };
    Some(encode(network.prefix(), kind.version(), payload))
}
