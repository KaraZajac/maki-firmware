//! Base58, Bitcoin's alphabet, as Solana writes its addresses and signatures.

use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

/// An address, if `text` is one: base58 of exactly 32 bytes.
pub fn decode_key(text: &str) -> Option<[u8; 32]> { decode(text)?.try_into().ok() }

/// A key written in base58, made when the program is built: the programs' and tokens' addresses.
/// Panics (so doesn't build) for anything that isn't 32 bytes of base58.
pub const fn key(text: &str) -> [u8; 32] {
    let t = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < t.len() {
        let mut v = 0;
        while v < 58 && ALPHABET[v] != t[i] {
            v += 1;
        }
        assert!(v < 58, "not base58");
        let mut carry = v as u32;
        let mut j = 32;
        while j > 0 {
            j -= 1;
            carry += out[j] as u32 * 58;
            out[j] = carry as u8;
            carry >>= 8;
        }
        assert!(carry == 0, "more than 32 bytes");
        i += 1;
    }
    out
}
