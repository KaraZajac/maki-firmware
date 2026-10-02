//! An XRP Ledger account's address: its account ID (RIPEMD-160 of the SHA-256 of its public key,
//! as Bitcoin hashes one) after a version byte of 0, with a checksum (the first four bytes of
//! SHA-256 twice), in base58 with the ledger's own alphabet: a classic address, `r...`.
//!
//! Tooling also writes an address with a destination tag in it (an X-address, `X...`); a
//! transaction never carries one: its codec splits it into the account and the tag, and those
//! are what maki reads and shows.

use alloc::string::String;
use alloc::vec::Vec;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// The ledger's base58 alphabet: Bitcoin's, reordered so a zero byte is `r`.
pub const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

/// An account, as transactions name it: 20 bytes.
pub type AccountId = [u8; 20];

/// The version byte of an account's address.
const VERSION: u8 = 0;

/// The account a public key (compressed, 33 bytes) is: the RIPEMD-160 of its SHA-256.
pub fn account_id(public_key: &[u8; 33]) -> AccountId { Ripemd160::digest(Sha256::digest(public_key)).into() }

/// The classic address of the account a public key is.
pub fn address(public_key: &[u8; 33]) -> String { encode(&account_id(public_key)) }

fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(payload));
    [h[0], h[1], h[2], h[3]]
}

/// An account's classic address.
pub fn encode(account: &AccountId) -> String {
    let mut payload = Vec::with_capacity(25);
    payload.push(VERSION);
    payload.extend_from_slice(account);
    let check = checksum(&payload);
    payload.extend_from_slice(&check);
    base58(&payload)
}

/// The account a classic address names, if `text` is one: base58 in the ledger's alphabet of a
/// version byte of 0, 20 bytes and their checksum, written the one way the ledger writes it.
pub fn decode(text: &str) -> Option<AccountId> {
    let bytes = unbase58(text)?;
    if bytes.len() != 25 {
        return None;
    }
    let (payload, check) = bytes.split_at(21);
    let account: AccountId = payload[1..].try_into().ok()?;
    if payload[0] != VERSION || check != checksum(payload) || encode(&account) != text {
        return None;
    }
    Some(account)
}

/// Base58 in the ledger's alphabet: each leading zero byte an `r`, then the rest as a number.
fn base58(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // base-58 digits, least significant first
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &b in &bytes[zeros..] {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(core::iter::repeat_n(ALPHABET[0] as char, zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// The bytes base58 text in the ledger's alphabet stands for, if it's that. An address is 25
/// bytes, so anything much longer isn't one, and isn't decoded.
fn unbase58(text: &str) -> Option<Vec<u8>> {
    if text.len() > 64 {
        return None;
    }
    let zeros = text.bytes().take_while(|&c| c == ALPHABET[0]).count();
    // base-256, least significant first
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes().skip(zeros) {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = alloc::vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}
