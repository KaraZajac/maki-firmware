//! Base58, Bitcoin's alphabet, as NEAR writes keys (`ed25519:` and the key) and hashes (a block's,
//! a transaction's, a contract's code): the bytes as a number in base 58, a `1` for each zero byte
//! they start with. maki only writes it: nothing it reads is in base58.

use alloc::string::String;
use alloc::vec::Vec;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// `bytes` in base58. Its time grows with the square of their length: a post-quantum key's 1952
/// bytes are the most maki writes.
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
