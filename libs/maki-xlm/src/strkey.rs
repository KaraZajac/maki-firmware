//! Stellar's addresses as people write them (StrKey, SEP-23): a version byte that says what it
//! is, the bytes, and a CRC16 checksum (XModem's, written least significant byte first), in
//! base32 (RFC 4648, no padding). `G…` an account, `M…` an account with an ID (a muxed account,
//! CAP-27), `C…` a contract, `T…`, `X…` and `P…` the signers an account can have besides keys,
//! `L…` a liquidity pool and `B…` a claimable balance. Secret keys (`S…`) maki never writes, and
//! doesn't read.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Hash, Key};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The longest StrKey there is: a signed payload of 64 bytes (165 characters).
pub const MAX_LENGTH: usize = 165;

/// What a StrKey is: its version byte's top five bits, which make its first letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `G…`: an account (its Ed25519 key).
    Account,
    /// `M…`: an account and an ID (a muxed account), which an exchange tells its customers apart
    /// by. The account's key signs for it, whatever the ID.
    Muxed,
    /// `T…`: a transaction's hash, which signs for an account once (a pre-authorized transaction).
    PreAuthTx,
    /// `X…`: the SHA-256 of a secret, which signs for an account by revealing it (hash-x).
    HashX,
    /// `P…`: a key and a payload it signs (a signed payload signer, CAP-40).
    SignedPayload,
    /// `C…`: a contract.
    Contract,
    /// `L…`: a liquidity pool.
    LiquidityPool,
    /// `B…`: a claimable balance.
    ClaimableBalance,
}

impl Kind {
    const fn version(self) -> u8 {
        match self {
            Kind::Account => 6 << 3,
            Kind::Muxed => 12 << 3,
            Kind::PreAuthTx => 19 << 3,
            Kind::HashX => 23 << 3,
            Kind::SignedPayload => 15 << 3,
            Kind::Contract => 2 << 3,
            Kind::LiquidityPool => 11 << 3,
            Kind::ClaimableBalance => 1 << 3,
        }
    }

    fn from_version(v: u8) -> Option<Kind> {
        [
            Kind::Account,
            Kind::Muxed,
            Kind::PreAuthTx,
            Kind::HashX,
            Kind::SignedPayload,
            Kind::Contract,
            Kind::LiquidityPool,
            Kind::ClaimableBalance,
        ]
        .into_iter()
        .find(|k| k.version() == v)
    }
}

/// CRC16-XModem: polynomial 0x1021, starting from 0, most significant bit first.
const fn crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let mut i = 0;
    while i < bytes.len() {
        crc ^= (bytes[i] as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
            bit += 1;
        }
        i += 1;
    }
    crc
}

fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Base32 read back, strictly: the alphabet's capitals alone, no padding, no length base32 can't
/// make (1, 3 or 6 more than a multiple of 8), and the last character's unused bits zero.
fn unbase32(text: &str) -> Option<Vec<u8>> {
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
    }
    (buffer == 0).then_some(out)
}

/// `payload` as a StrKey of `kind`: the version byte, the payload, the checksum, in base32. The
/// payload is as the kind has it (see the functions below).
pub fn encode(kind: Kind, payload: &[u8]) -> String {
    let mut raw = Vec::with_capacity(payload.len() + 3);
    raw.push(kind.version());
    raw.extend_from_slice(payload);
    let crc = crc16(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());
    base32(&raw)
}

/// An account: `G…`.
pub fn account(key: &Key) -> String { encode(Kind::Account, key) }

/// An account with an ID: `M…`, the key and then the ID (big-endian).
pub fn muxed(key: &Key, id: u64) -> String {
    let mut payload = [0u8; 40];
    payload[..32].copy_from_slice(key);
    payload[32..].copy_from_slice(&id.to_be_bytes());
    encode(Kind::Muxed, &payload)
}

/// A contract: `C…`.
pub fn contract(id: &Hash) -> String { encode(Kind::Contract, id) }

/// A liquidity pool: `L…`.
pub fn liquidity_pool(id: &Hash) -> String { encode(Kind::LiquidityPool, id) }

/// A claimable balance: `B…`, its ID's type (0, the only one) and then its hash.
pub fn claimable_balance(id: &Hash) -> String {
    let mut payload = [0u8; 33];
    payload[1..].copy_from_slice(id);
    encode(Kind::ClaimableBalance, &payload)
}

/// A pre-authorized transaction signer: `T…`.
pub fn pre_auth_tx(hash: &Hash) -> String { encode(Kind::PreAuthTx, hash) }

/// A hash-x signer: `X…`.
pub fn hash_x(hash: &Hash) -> String { encode(Kind::HashX, hash) }

/// A signed payload signer: `P…`, the key, the payload's length (a big-endian u32), the payload,
/// and zeros to a multiple of four bytes.
pub fn signed_payload(key: &Key, payload: &[u8]) -> String {
    let mut raw = Vec::with_capacity(36 + payload.len() + 3);
    raw.extend_from_slice(key);
    raw.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    raw.extend_from_slice(payload);
    raw.resize(raw.len().next_multiple_of(4), 0);
    encode(Kind::SignedPayload, &raw)
}

/// A StrKey read back, as SEP-23 has it: valid base32 that writes back the same, a version byte
/// maki knows, the right checksum, and the payload its kind has (a signed payload's length
/// matching it, its padding zero; a claimable balance's type 0). Its kind and payload, or None.
pub fn decode(text: &str) -> Option<(Kind, Vec<u8>)> {
    if text.is_empty() || text.len() > MAX_LENGTH {
        return None;
    }
    let raw = unbase32(text)?;
    if raw.len() < 3 {
        return None;
    }
    let (body, crc) = raw.split_at(raw.len() - 2);
    if crc16(body).to_le_bytes() != crc {
        return None;
    }
    let kind = Kind::from_version(body[0])?;
    let payload = &body[1..];
    let fits = match kind {
        Kind::Account | Kind::PreAuthTx | Kind::HashX | Kind::Contract | Kind::LiquidityPool => {
            payload.len() == 32
        }
        Kind::Muxed => payload.len() == 40,
        Kind::ClaimableBalance => payload.len() == 33 && payload[0] == 0,
        Kind::SignedPayload => {
            payload.len() >= 36 && {
                let n = u32::from_be_bytes([payload[32], payload[33], payload[34], payload[35]]) as usize;
                (1..=64).contains(&n)
                    && payload.len() == 36 + n.next_multiple_of(4)
                    && payload[36 + n..].iter().all(|&b| b == 0)
            }
        }
    };
    // and nothing written another way than its encoding writes it
    (fits && base32(&raw) == text).then(|| (kind, payload.to_vec()))
}

/// An account's key, if `text` is an account (`G…`).
pub fn decode_account(text: &str) -> Option<Key> {
    match decode(text)? {
        (Kind::Account, payload) => payload.try_into().ok(),
        _ => None,
    }
}

/// An account's key and ID, if `text` is a muxed account (`M…`).
pub fn decode_muxed(text: &str) -> Option<(Key, u64)> {
    match decode(text)? {
        (Kind::Muxed, payload) => {
            let key: Key = payload[..32].try_into().ok()?;
            Some((key, u64::from_be_bytes(payload[32..].try_into().ok()?)))
        }
        _ => None,
    }
}

/// An account's key written as its address (`G…`), read when the program is built: the issuers
/// maki knows. Panics (so doesn't build) for anything that isn't a valid account address.
pub const fn account_key(text: &str) -> Key {
    let t = text.as_bytes();
    assert!(t.len() == 56, "not an account address");
    let mut raw = [0u8; 35];
    let (mut buffer, mut bits, mut at) = (0u32, 0u32, 0usize);
    let mut i = 0;
    while i < t.len() {
        let mut v = 0;
        while v < 32 && ALPHABET[v] != t[i] {
            v += 1;
        }
        assert!(v < 32, "not base32");
        buffer = (buffer << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            raw[at] = (buffer >> (bits - 8)) as u8;
            at += 1;
            bits -= 8;
            buffer &= (1 << bits) - 1;
        }
        i += 1;
    }
    assert!(buffer == 0 && at == 35, "not an account address");
    assert!(raw[0] == Kind::Account.version(), "not an account address");
    let mut body = [0u8; 33];
    let mut j = 0;
    while j < 33 {
        body[j] = raw[j];
        j += 1;
    }
    let crc = crc16(&body);
    assert!(raw[33] == crc as u8 && raw[34] == (crc >> 8) as u8, "a wrong checksum");
    let mut key = [0u8; 32];
    let mut k = 0;
    while k < 32 {
        key[k] = raw[k + 1];
        k += 1;
    }
    key
}
