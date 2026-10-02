//! Kaspa's hashes of transactions: BLAKE2b with a 32-byte digest, keyed with the name of what it
//! hashes, so a hash made for one purpose is never another's (rusty-kaspa's `blake2b_hasher!`).
//! Numbers go in little-endian, and a run of bytes after its length as a u64, as rusty-kaspa's
//! `HasherExtensions` write them.

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};

/// The key of the hash an input's signature signs (`TransactionSigningHash`).
pub const SIGNING: &[u8] = b"TransactionSigningHash";

/// A hash being made: bytes in, then `finish`.
#[derive(Clone)]
pub struct Hasher(Blake2bMac<U32>);

impl Hasher {
    /// A hash keyed with `key`: one of Kaspa's names, all shorter than BLAKE2b's 64-byte key.
    fn new(key: &'static [u8]) -> Hasher {
        Hasher(Blake2bMac::new_from_slice(key).expect("Kaspa's hash keys fit BLAKE2b's 64 bytes"))
    }

    /// The signature hash's.
    pub fn signing() -> Hasher { Hasher::new(SIGNING) }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update(bytes);
        self
    }

    pub fn u8(&mut self, n: u8) -> &mut Self { self.bytes(&[n]) }

    pub fn u16(&mut self, n: u16) -> &mut Self { self.bytes(&n.to_le_bytes()) }

    pub fn u32(&mut self, n: u32) -> &mut Self { self.bytes(&n.to_le_bytes()) }

    pub fn u64(&mut self, n: u64) -> &mut Self { self.bytes(&n.to_le_bytes()) }

    /// Bytes after their length (a u64), as Kaspa writes a script or a payload.
    pub fn var_bytes(&mut self, bytes: &[u8]) -> &mut Self { self.u64(bytes.len() as u64).bytes(bytes) }

    pub fn finish(self) -> [u8; 32] { self.0.finalize_fixed().into() }
}
