//! What maki signs for a transaction, and the signature as the ledger takes it.
//!
//! An account signs a transaction's fields without its signatures (the bytes maki is given,
//! which carry the key that signs, SigningPubKey), after the prefix "STX\0", hashed with
//! SHA-512Half: the first 32 bytes of SHA-512. The signature is ECDSA on secp256k1 (RFC 6979,
//! as ripple-keypairs makes it, so the same every time), its s the lower of the two (rippled
//! takes no other), DER-encoded. It goes in the transaction as TxnSignature, which comes right
//! after SigningPubKey in the ledger's order; the transaction's ID (its hash) is SHA-512Half of
//! "TXN\0" and the signed transaction.

use alloc::vec::Vec;

use sha2::{Digest, Sha512};

use crate::codec;
use crate::codec::fields::{SIGNING_PUB_KEY, TXN_SIGNATURE};

/// What comes before a transaction to sign: "STX\0".
pub const SIGNING_PREFIX: [u8; 4] = *b"STX\0";
/// What comes before a signed transaction for its ID: "TXN\0".
pub const ID_PREFIX: [u8; 4] = *b"TXN\0";

/// SHA-512Half of `prefix` and `bytes`: the ledger's hash.
fn half(prefix: &[u8; 4], bytes: &[u8]) -> [u8; 32] {
    let h = Sha512::new().chain_update(prefix).chain_update(bytes).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    out
}

/// The digest maki signs for a transaction (its fields without signatures, as the app is
/// given them).
pub fn digest(transaction: &[u8]) -> [u8; 32] { half(&SIGNING_PREFIX, transaction) }

/// A signed transaction's ID: its hash, as explorers name it.
pub fn id(signed: &[u8]) -> [u8; 32] { half(&ID_PREFIX, signed) }

/// An ECDSA signature (r, then s, 32 bytes each, s low) in DER, as the ledger takes it: each a
/// positive integer in its fewest bytes. 70 to 72 bytes, almost always.
pub fn der(signature: &[u8; 64]) -> Vec<u8> {
    let integer = |x: &[u8]| {
        let start = x.iter().position(|&b| b != 0).unwrap_or(x.len() - 1);
        let mut v = Vec::with_capacity(33);
        if x[start] & 0x80 != 0 {
            v.push(0);
        }
        v.extend_from_slice(&x[start..]);
        v
    };
    let (r, s) = (integer(&signature[..32]), integer(&signature[32..]));
    let mut out = Vec::with_capacity(6 + r.len() + s.len());
    out.extend_from_slice(&[0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8]);
    out.extend_from_slice(&r);
    out.extend_from_slice(&[0x02, s.len() as u8]);
    out.extend_from_slice(&s);
    out
}

/// Why a signature can't go in a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The transaction isn't one: why.
    Codec(codec::Error),
    /// It has no key to sign it, or a signature already.
    Unsigned,
}

/// The transaction, signed: `der` put in as its TxnSignature, where the ledger's order puts it
/// (right after SigningPubKey, which a transaction to sign must have). What a wallet submits.
pub fn with_signature(transaction: &[u8], der: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, spans) = codec::read_spans(transaction).map_err(Error::Codec)?;
    if spans.iter().any(|s| s.0 == TXN_SIGNATURE) || !spans.iter().any(|s| s.0 == SIGNING_PUB_KEY) {
        return Err(Error::Unsigned);
    }
    // after every field that comes before it
    let at = spans.iter().filter(|s| s.0 < TXN_SIGNATURE).map(|s| s.2).max().unwrap_or(0);
    let mut out = Vec::with_capacity(transaction.len() + der.len() + 4);
    out.extend_from_slice(&transaction[..at]);
    // its header: type 7 (a blob), field 4, in a byte
    out.push((TXN_SIGNATURE.kind() << 4) | TXN_SIGNATURE.nth());
    out.extend_from_slice(&codec::length(der.len()));
    out.extend_from_slice(der);
    out.extend_from_slice(&transaction[at..]);
    Ok(out)
}
