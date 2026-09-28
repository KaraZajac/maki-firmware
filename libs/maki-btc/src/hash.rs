use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] { Sha256::digest(data).into() }

pub fn sha256d(data: &[u8]) -> [u8; 32] { sha256(&sha256(data)) }

pub fn hash160(data: &[u8]) -> [u8; 20] { Ripemd160::digest(sha256(data)).into() }

/// BIP340's tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data), so a hash made for one
/// purpose can't stand in for another's.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
