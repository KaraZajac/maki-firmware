//! Stellar, for maki's Stellar app (ARCHITECTURE.md, "Wallets are apps"): an account's address
//! (its Ed25519 key as a StrKey, `G…`), and what it signs, read strictly and shown before it's
//! signed. maki keeps the key (SLIP-10 at `m/44'/148'/account'`, as SEP-5 has it and Freighter and
//! Ledger's Stellar app make it); this reads a transaction envelope as stellar-core reads it
//! (`transaction`, and `soroban` for what contracts are given), holds it to the checks
//! stellar-core makes before it takes one, and says what it does (`display`): what it sends, and
//! to whom; its trades and trustlines; anything that changes who controls the account, loudly;
//! the most the fee can be, its time limit, its memo; and what maki can't read, flagged.
//!
//! What a signature signs is a hash (`Envelope::hash`): SHA-256 of the network's ID, the
//! envelope's type and the transaction, so the same transaction signed for the test network is no
//! use on the public one.

#![no_std]
extern crate alloc;

pub mod assets;
pub mod display;
pub mod soroban;
pub mod strkey;
pub mod transaction;
mod xdr;

use sha2::{Digest, Sha256};
pub use transaction::{Envelope, Error};

/// An account's key: 32 bytes of Ed25519 public key.
pub type Key = [u8; 32];

/// A hash: a contract's ID, a liquidity pool's, a claimable balance's, a transaction's.
pub type Hash = [u8; 32];

/// The two networks maki signs for. A signature is for one of them: what it signs starts with the
/// network's ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Stellar's public network, where XLM is worth something.
    Public,
    /// The Stellar Development Foundation's test network, where it isn't.
    Test,
}

impl Network {
    /// The network a message's network byte names: 0 the public network, 1 the test network.
    pub fn from_byte(n: u8) -> Option<Network> {
        match n {
            0 => Some(Network::Public),
            1 => Some(Network::Test),
            _ => None,
        }
    }

    /// The network's passphrase, which its ID is the hash of.
    pub fn passphrase(self) -> &'static str {
        match self {
            Network::Public => "Public Global Stellar Network ; September 2015",
            Network::Test => "Test SDF Network ; September 2015",
        }
    }

    /// The network's ID: SHA-256 of its passphrase.
    pub fn id(self) -> Hash { Sha256::digest(self.passphrase().as_bytes()).into() }

    /// The network as a page names it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Public => "Stellar's public network",
            Network::Test => "Stellar's test network",
        }
    }
}

/// An account's address: its key as a StrKey, `G…`.
pub fn address(key: &Key) -> alloc::string::String { strkey::account(key) }
