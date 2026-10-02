//! Bech32 (BIP-173), as Cosmos writes its addresses: a prefix that names the chain and what the
//! address is (an account, a validator), `1`, the bytes five bits to a character, and six characters
//! of checksum, which catch any one or two characters mistyped. In lower case only, as every Cosmos
//! wallet writes them, and with bech32's checksum, not bech32m's.

use alloc::string::String;
use alloc::vec::Vec;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

/// The longest a bech32 string can be (BIP-173): an address of 32 bytes is 59 characters and its
/// prefix.
pub const MAX_LENGTH: usize = 90;

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut check = 1u32;
    for v in values {
        let top = check >> 25;
        check = (check & 0x01ff_ffff) << 5 ^ v as u32;
        for (i, g) in GENERATORS.iter().enumerate() {
            if top >> i & 1 == 1 {
                check ^= g;
            }
        }
    }
    check
}

/// The prefix as the checksum covers it: each character's top bits, a zero, then their low bits.
fn expand(prefix: &str) -> impl Iterator<Item = u8> + '_ {
    prefix.bytes().map(|b| b >> 5).chain([0]).chain(prefix.bytes().map(|b| b & 31))
}

/// `prefix` and `bytes` in bech32. The prefix is one of maki's own (lower-case ASCII).
pub fn encode(prefix: &str, bytes: &[u8]) -> String {
    let mut five = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0);
    for &b in bytes {
        acc = (acc << 8 | b as u32) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five.push((acc >> bits & 31) as u8);
        }
    }
    if bits > 0 {
        five.push((acc << (5 - bits) & 31) as u8);
    }
    let check = polymod(expand(prefix).chain(five.iter().copied()).chain([0; 6])) ^ 1;
    let mut out = String::with_capacity(prefix.len() + 1 + five.len() + 6);
    out.push_str(prefix);
    out.push('1');
    out.extend(five.iter().map(|&v| CHARSET[v as usize] as char));
    out.extend((0..6).map(|i| CHARSET[(check >> (5 * (5 - i)) & 31) as usize] as char));
    out
}

/// The prefix and bytes `text` writes, if it's bech32 as Cosmos writes it: lower case, its checksum
/// its own, and its bytes whole (the bits left over at the end, fewer than five, all zero).
pub fn decode(text: &str) -> Option<(&str, Vec<u8>)> {
    if text.len() > MAX_LENGTH || !text.bytes().all(|b| (33..=126).contains(&b) && !b.is_ascii_uppercase()) {
        return None;
    }
    let at = text.rfind('1')?;
    let (prefix, data) = (&text[..at], &text[at + 1..]);
    if prefix.is_empty() || data.len() < 6 {
        return None;
    }
    let mut values = Vec::with_capacity(data.len());
    for c in data.bytes() {
        values.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }
    if polymod(expand(prefix).chain(values.iter().copied())) != 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(values.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0);
    for &v in &values[..values.len() - 6] {
        acc = (acc << 5 | v as u32) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
        }
    }
    if bits >= 5 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some((prefix, bytes))
}
