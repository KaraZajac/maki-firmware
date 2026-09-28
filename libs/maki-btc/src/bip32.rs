//! BIP32's extended public key, as wallet software takes an account (the keys themselves are
//! maki's: `maki_hd`).

use alloc::string::String;
use alloc::vec::Vec;

pub use maki_hd::HARDENED;
use maki_hd::Public;

use crate::hash::sha256d;

/// An extended public key, base58check with the given version bytes: `xpub` (0488b21e), `zpub`
/// (04b24746) for BIP84, `tpub`/`vpub` on test networks; `depth` and `child_number` are where
/// `public` is.
pub fn xpub(version: [u8; 4], depth: u8, child_number: u32, public: &Public) -> String {
    let mut data = Vec::with_capacity(82);
    data.extend_from_slice(&version);
    data.push(depth);
    data.extend_from_slice(&public.parent_fingerprint);
    data.extend_from_slice(&child_number.to_be_bytes());
    data.extend_from_slice(&public.chain_code);
    data.extend_from_slice(&public.key);
    base58check(&data)
}

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 with a 4-byte double-SHA-256 checksum, as xpubs and legacy addresses are written.
pub fn base58check(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&sha256d(payload)[..4]);
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base 256 to base 58
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data {
        let mut carry = byte as u32;
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
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}
