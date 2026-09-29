//! Solana, for maki's Solana app (ARCHITECTURE.md, "Wallets are apps"): an account's address (its
//! Ed25519 key in base58), and what it signs, read strictly and shown before it's signed. maki
//! keeps the key (SLIP-10 at `m/44'/501'/account'/0'`, as Phantom and Solflare make it); this
//! reads a transaction's message as Solana's runtime does (`message`), and says what it does
//! (`display`): SOL and tokens sent, and to whom, spelled out; what pays the fee, and the most it
//! can be; anything else flagged, with whether it can act as the account.

#![no_std]
extern crate alloc;

pub mod base58;
pub mod display;
pub mod message;
pub mod program;
pub mod tokens;

pub use message::{Key, Message};

/// An account's address: its key, in base58.
pub fn address(key: &Key) -> alloc::string::String { base58::encode(key) }
