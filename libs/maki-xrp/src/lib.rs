//! XRP, for maki's XRP app (ARCHITECTURE.md, "Wallets are apps"): an XRP Ledger account's
//! address (its secp256k1 key, hashed, in the ledger's own base58), and what it signs, read
//! strictly and shown before it's signed. maki keeps the key (BIP32 at
//! `m/44'/144'/account'/0/0`, as Ledger, Xaman, Trust Wallet and xrpl.js make it from a phrase).
//! This reads a transaction in the ledger's binary format as rippled reads it (`codec`, `tx`),
//! and says what it does (`display`): XRP and tokens sent, and to whom, with the tag an exchange
//! needs; the fee, and how long it stays good; anything that hands the account over or empties
//! it, loudly; anything else flagged. And it makes what maki signs, and the signature as the
//! ledger takes it (`sign`).

#![no_std]
extern crate alloc;

pub mod address;
pub mod codec;
pub mod definitions;
pub mod display;
pub mod sign;
pub mod tokens;
pub mod tx;

pub use address::address;
pub use tx::Transaction;

/// The networks maki signs for. A transaction names neither (only a network numbered above
/// 1024 carries a NetworkID, and maki signs for none of those), so which it's for is the
/// computer's word, which maki shows as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// The XRP Ledger.
    Main,
    /// Its test network (network 1).
    Test,
}

impl Network {
    /// Its name, as maki's screens say it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Main => "xrp",
            Network::Test => "xrp testnet",
        }
    }
}
