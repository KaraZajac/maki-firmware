//! The programs maki reads the instructions of, and the addresses programs derive (PDAs): how a
//! token account is proven to be its owner's.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::base58::key;
use crate::Key;

pub const SYSTEM: Key = key("11111111111111111111111111111111");
pub const COMPUTE_BUDGET: Key = key("ComputeBudget111111111111111111111111111111");
pub const TOKEN: Key = key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022: Key = key("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ASSOCIATED_TOKEN: Key = key("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const MEMO: Key = key("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
pub const MEMO_1: Key = key("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo");
pub const STAKE: Key = key("Stake11111111111111111111111111111111111111");
pub const VOTE: Key = key("Vote111111111111111111111111111111111111111");
/// Programs that check signatures, each of which Solana charges for as it does a transaction's
/// own: the first byte of their data is how many.
pub const ED25519_VERIFY: Key = key("Ed25519SigVerify111111111111111111111111111");
pub const SECP256K1_VERIFY: Key = key("KeccakSecp256k11111111111111111111111111111");
pub const SECP256R1_VERIFY: Key = key("Secp256r1SigVerify1111111111111111111111111");

/// A program maki knows by name, for "owned by".
pub fn name(program: &Key) -> Option<&'static str> {
    Some(match *program {
        SYSTEM => "the System program",
        TOKEN => "the Token program",
        TOKEN_2022 => "the Token-2022 program",
        STAKE => "the Stake program",
        VOTE => "the Vote program",
        _ => return None,
    })
}

/// Whether `key` is a point on the Ed25519 curve, as Solana decides it: a key someone could hold
/// the secret of. A program's own addresses are off the curve.
pub fn on_curve(key: &Key) -> bool { CompressedEdwardsY(*key).decompress().is_some() }

/// A program's address from `seeds` (`find_program_address`): the first bump, down from 255,
/// whose hash is off the curve, and the bump.
pub fn find_address(seeds: &[&[u8]], program: &Key) -> Option<(Key, u8)> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let address: Key = h.finalize().into();
        if !on_curve(&address) {
            return Some((address, bump));
        }
    }
    None
}

/// The associated token account of `owner` for `mint`, under `token_program` (Token's or
/// Token-2022's): the account wallets send that token to.
pub fn associated_token_account(owner: &Key, token_program: &Key, mint: &Key) -> Option<Key> {
    find_address(&[owner, token_program, mint], &ASSOCIATED_TOKEN).map(|(a, _)| a)
}
