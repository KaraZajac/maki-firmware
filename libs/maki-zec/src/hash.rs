//! Zcash's hashes. ZIP-244's digests are BLAKE2b with a 32-byte digest, unkeyed, personalized with a
//! 16-byte name of what each one hashes, so a hash made for one purpose is never another's. And
//! Bitcoin's, which transparent addresses keep: double SHA-256 (base58check's checksum) and HASH160
//! (a key's hash).

use blake2::Blake2bVarCore;
use blake2::digest::Output;
use blake2::digest::core_api::{Buffer, UpdateCore, VariableOutputCore};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// A personalized BLAKE2b-256 being made: bytes in, then `finish`. (The `blake2` crate's keyed
/// hasher takes a personalization, but feeds a block of zeros for an empty key, which isn't
/// unkeyed BLAKE2b; so its core, given the parameters, and its block buffer, as its own hashers
/// put them together.)
#[derive(Clone)]
pub struct Hasher {
    core: Blake2bVarCore,
    buffer: Buffer<Blake2bVarCore>,
}

impl Hasher {
    /// A hash personalized with `personal`: no key, no salt, a 32-byte digest.
    pub fn new(personal: &[u8; 16]) -> Hasher {
        Hasher {
            core: Blake2bVarCore::new_with_params(&[], personal, 0, 32),
            buffer: Buffer::<Blake2bVarCore>::default(),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let core = &mut self.core;
        self.buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
        self
    }

    pub fn finish(mut self) -> [u8; 32] {
        let mut out = Output::<Blake2bVarCore>::default();
        self.core.finalize_variable_core(&mut self.buffer, &mut out);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out[..32]);
        digest
    }
}

/// BLAKE2b-256 of `data`, personalized with `personal`.
pub fn blake2b(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new(personal);
    h.update(data);
    h.finish()
}

pub fn sha256d(data: &[u8]) -> [u8; 32] { Sha256::digest(Sha256::digest(data)).into() }

/// A key's HASH160: RIPEMD-160 of its SHA-256, what a pay-to-key-hash script names.
pub fn hash160(data: &[u8]) -> [u8; 20] { Ripemd160::digest(Sha256::digest(data)).into() }
