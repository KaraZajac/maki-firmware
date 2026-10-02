//! Base58, Bitcoin's alphabet, and base58check, as Tron writes its addresses: the bytes, then the
//! first four of their double SHA-256, so a mistyped address doesn't pass for another.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::Address;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// `bytes` in base58, a `1` for each zero byte they start with.
pub fn encode(bytes: &[u8]) -> String {
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
    out.extend(core::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

fn digit(c: u8) -> Option<u8> { ALPHABET.iter().position(|&a| a == c).map(|p| p as u8) }

/// The bytes base58 `text` writes; None if it has a character base58 doesn't. Its time grows with
/// the square of its length: callers keep it short (an address is 34 characters).
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    // base-256, least significant first
    let mut bytes: Vec<u8> = Vec::new();
    for c in text.bytes().skip(zeros) {
        let mut carry = digit(c)? as u32;
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

fn checksum(bytes: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(bytes));
    [h[0], h[1], h[2], h[3]]
}

/// Base58check: the bytes and their checksum, in base58.
pub fn check_encode(bytes: &[u8]) -> String {
    let mut all = Vec::with_capacity(bytes.len() + 4);
    all.extend_from_slice(bytes);
    all.extend_from_slice(&checksum(bytes));
    encode(&all)
}

/// The bytes base58check `text` holds, if its checksum is theirs.
pub fn check_decode(text: &str) -> Option<Vec<u8>> {
    let mut all = decode(text)?;
    if all.len() < 4 {
        return None;
    }
    let sum = all.split_off(all.len() - 4);
    (sum == checksum(&all)).then_some(all)
}

/// An address written in base58check, made when the program is built: the tokens' contracts. Panics
/// (so doesn't build) for anything that isn't base58 of 25 bytes starting with `PREFIX`; its
/// checksum, which this can't check without SHA-256, the tests do.
pub const fn address(text: &str) -> Address {
    let t = text.as_bytes();
    let mut all = [0u8; 25];
    let mut i = 0;
    while i < t.len() {
        let mut v = 0;
        while v < 58 && ALPHABET[v] != t[i] {
            v += 1;
        }
        assert!(v < 58, "not base58");
        let mut carry = v as u32;
        let mut j = 25;
        while j > 0 {
            j -= 1;
            carry += all[j] as u32 * 58;
            all[j] = carry as u8;
            carry >>= 8;
        }
        assert!(carry == 0, "more than 25 bytes");
        i += 1;
    }
    assert!(all[0] == crate::PREFIX, "not a Tron address");
    let mut out = [0u8; 21];
    let mut k = 0;
    while k < 21 {
        out[k] = all[k];
        k += 1;
    }
    out
}
