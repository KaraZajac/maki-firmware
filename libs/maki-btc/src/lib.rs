//! maki's Bitcoin wallet: keys from the recovery phrase, addresses, and PSBTs reviewed on maki's
//! screen before they're signed (ARCHITECTURE.md, "Order of work").
//!
//! One account, the standard native SegWit one (BIP84, `m/84'/0'/0'`), so the phrase also works
//! in Sparrow, Electrum and the rest. Transactions come in as PSBTs (BIP174). The rules that
//! keep a lying computer from getting a signature the owner didn't mean to give:
//!
//! - every input must be this wallet's, proven by deriving its key, and must come with the whole
//!   transaction it spends, which must hash to the outpoint: an amount the computer claims is
//!   never trusted (the 2020 SegWit fee attack);
//! - an output is called change only if it derives from this wallet's change chain; anything
//!   else is shown as a payment, with its full address;
//! - the fee is what the inputs hold minus what the outputs pay, and must not be negative;
//! - only SIGHASH_ALL is signed.

#![no_std]
extern crate alloc;

pub mod address;
pub mod bip32;
pub mod display;
mod hash;
pub mod psbt;
pub mod tx;
pub mod wallet;

pub use address::Network;
pub use wallet::{Account, Output, Review};
