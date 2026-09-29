//! maki's Bitcoin wallet: keys from the recovery phrase, addresses, and PSBTs reviewed on maki's
//! screen before they're signed (ARCHITECTURE.md, "Order of work").
//!
//! Two accounts, the standard ones, so the phrase also works in Sparrow, Electrum and the rest:
//! native SegWit (BIP84, `m/84'/0'/0'`) and taproot (BIP86, `m/86'/0'/0'`, spent with the key
//! alone). Transactions come in as PSBTs (BIP174, and BIP371 for taproot). The rules that keep a
//! lying computer from getting a signature the owner didn't mean to give:
//!
//! - every input must be this wallet's, proven by deriving its key; a native SegWit one must
//!   come with the whole transaction it spends, which must hash to the outpoint: an amount the
//!   computer claims is never trusted (the 2020 SegWit fee attack). A taproot signature covers
//!   every input's amount and script, so for taproot the amount claimed is enough: a false one
//!   makes a signature that fails;
//! - an output is called change only if it derives from this wallet's change chain; anything
//!   else is shown as a payment, with its full address;
//! - the fee is what the inputs hold minus what the outputs pay, and must not be negative;
//! - only SIGHASH_ALL is signed.
//!
//! And multisig wallets with maki's key among theirs (`multisig`: native SegWit, BIP48), once the
//! owner has registered one on maki: what spends from it is checked against the wallet as
//! registered, never against what the PSBT says the wallet is.

#![no_std]
extern crate alloc;

pub mod address;
pub mod bip32;
pub mod display;
mod hash;
pub mod multisig;
pub mod psbt;
pub mod taproot;
pub mod tx;
pub mod wallet;

pub use address::Network;
pub use multisig::{Multisig, Signer};
pub use wallet::{Account, Kind, Output, Review};
