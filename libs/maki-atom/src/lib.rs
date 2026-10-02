//! Cosmos, for maki's Cosmos app (ARCHITECTURE.md, "Wallets are apps"): an account on the Cosmos
//! Hub and the chains that take its keys, and what it signs, read strictly and shown before it's
//! signed. maki keeps the key: BIP32 on secp256k1 at `m/44'/118'/0'/0/i`, the first as every Cosmos
//! wallet makes it from a phrase (Keplr, Cosmostation, Ledger's Cosmos app, CosmJS), the next ones in
//! the last place, as CosmJS (`makeCosmoshubPath`) and Cosmostation count them (Ledger Live counts
//! its accounts a level up, at `m/44'/118'/i'/0/0`, so its others aren't these). The account's
//! address is the RIPEMD-160 of the SHA-256 of its compressed key, in bech32 under each chain's
//! prefix: one key, an address on every chain (`chains`).
//!
//! What's signed is a sign doc in Amino JSON (SIGN_MODE_LEGACY_AMINO_JSON, what Ledger's Cosmos app
//! signs, and Keplr when a Ledger signs): JSON written one way only, as the chain itself writes it
//! to check the signature (`json`). This reads it strictly (`doc`): the chain it's for, which maki
//! must know, and on the network the computer says; the messages it reads (coins sent, over IBC
//! too, staking, rewards, votes), each this account's; the fee; the memo. And it says what it does
//! (`display`): a message maki can't read is shown as it's written and flagged, and a grant that
//! would let another account act for this one is refused.
//!
//! The signature is ECDSA on secp256k1 over the SHA-256 of the sign doc's bytes, deterministic (RFC
//! 6979) with s low, as the chain checks it: r and s, 64 bytes, as a transaction carries it.

#![no_std]
extern crate alloc;

use alloc::string::String;

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub mod bech32;
pub mod chains;
pub mod display;
pub mod doc;
pub mod json;

pub use chains::{Chain, Network};
pub use doc::SignDoc;

/// BIP32's hardened offset (`44'`).
pub const HARDENED: u32 = 0x8000_0000;

/// Account `index`'s path: `m/44'/118'/0'/0/index`. The first, `m/44'/118'/0'/0/0`, is the one every
/// Cosmos wallet makes from a phrase; CosmJS and Cosmostation count the ones after it here, in the
/// last place.
pub fn path(index: u32) -> [u32; 5] { [44 | HARDENED, 118 | HARDENED, HARDENED, 0, index] }

/// The account a key is: the RIPEMD-160 of the SHA-256 of the key, compressed (`02` or `03`, then
/// x), as every Cosmos chain makes it from a secp256k1 key.
pub fn account(key: &[u8; 33]) -> [u8; 20] { Ripemd160::digest(Sha256::digest(key)).into() }

/// The account's address on `chain`: bech32, under the chain's prefix (`cosmos1…`, `osmo1…`).
pub fn address(chain: &Chain, account: &[u8; 20]) -> String { bech32::encode(chain.prefix, account) }

/// The account bytes `text` writes, if it's an address of `chain`'s accounts (20 bytes, as a key's
/// address is).
pub fn parse_address(chain: &Chain, text: &str) -> Option<[u8; 20]> {
    let (prefix, bytes) = bech32::decode(text)?;
    if prefix != chain.prefix {
        return None;
    }
    bytes.try_into().ok()
}

/// What's signed: the SHA-256 of the sign doc's bytes.
pub fn digest(doc: &[u8]) -> [u8; 32] { Sha256::digest(doc).into() }
