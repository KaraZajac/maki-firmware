//! TON, for maki's TON app (ARCHITECTURE.md, "Wallets are apps"): an account's wallets and their
//! addresses, and what they sign, read strictly and shown before it's signed. maki keeps the key
//! (SLIP-10 at `m/44'/607'/network'/0'/account'/0'`, as Ledger's TON app has it, and Ledger Live,
//! and Tonkeeper with a Ledger). On TON an account is a contract: a key's wallet is one of TON's
//! wallet contracts made with it, and its address is named by the contract's code and first data.
//! maki knows the two that hold people's money: v4R2 (Ledger's, and every wallet's for years) and
//! W5 (v5R1, today's wallets' first choice).
//!
//! This reads cells and the bags of cells (BOCs) they travel in as TON reads them (`cell`), what
//! each wallet signs (`wallet`) and the messages it's asked to send (`message`), and says what
//! they do (`display`): TON and jettons sent, and to whom, spelled out (jettons maki knows by
//! their master, `jettons`); comments; anything that sends all the account holds, closes it, or
//! lets another act for it, loudly; what maki can't read, flagged.
//!
//! What a signature signs is a cell's hash: the wallet's request, whose wallet ID names the
//! wallet (and for W5 the network), so a request for one wallet is no use to another.

#![no_std]
extern crate alloc;

pub mod address;
pub mod cell;
pub mod display;
pub mod jettons;
pub mod message;
pub mod wallet;

pub use address::Address;
pub use cell::Boc;
pub use wallet::{Request, Wallet};

/// An account's key: 32 bytes of Ed25519 public key.
pub type Key = [u8; 32];

/// A cell's hash: what names a contract (its first state's), and what a wallet's key signs.
pub type Hash = [u8; 32];

/// The two networks maki signs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// TON, where TON is worth something.
    Main,
    /// TON's test network, where it isn't.
    Test,
}

impl Network {
    /// The network a message's network byte names: 0 TON, 1 its test network.
    pub fn from_byte(n: u8) -> Option<Network> {
        match n {
            0 => Some(Network::Main),
            1 => Some(Network::Test),
            _ => None,
        }
    }

    /// The network's global ID (its configuration's parameter 19), which W5's wallet ID is made
    /// from.
    pub fn global_id(self) -> i32 {
        match self {
            Network::Main => -239,
            Network::Test => -3,
        }
    }

    /// The network as a page names it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Main => "TON",
            Network::Test => "TON's test network",
        }
    }
}

/// Account `account`'s key's path: `m/44'/607'/network'/0'/account'/0'`, every step hardened, as
/// ton-ledger-ts's `pathForAccount` makes it for Ledger's TON app (the 0 after the network is the
/// basechain, which TON's wallets live on; the last is kept for other wallets).
pub fn path(network: Network, account: u32) -> [u32; 6] {
    const H: u32 = 0x8000_0000;
    let net = match network {
        Network::Main => 0,
        Network::Test => 1,
    };
    [44 | H, 607 | H, net | H, H, account | H, H]
}

/// Why maki won't read something: TON wouldn't, or maki can't show it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// More than maki reads at once.
    TooBig,
    /// Not a bag of cells.
    NotBoc,
    /// A bag of cells whose header doesn't add up with what follows it.
    Header,
    /// A bag of cells with an index (or cache bits), which maki doesn't take.
    Index,
    /// A bag of cells whose CRC32C isn't its own.
    Checksum,
    /// A bag of cells with more than one root.
    Roots,
    /// A cell that refers back, to itself, or to a cell that isn't there.
    Order,
    /// A cell in the bag that nothing refers to.
    Unreached,
    /// A cell not written as TON writes cells: more than four references, its stored hashes, a
    /// level it can't have, data without its end mark.
    Encoding,
    /// A pruned branch or a Merkle proof or update: cells that stand for others maki can't see.
    Special,
    /// Cells nested deeper than TON allows.
    Deep,
    /// A cell that ends before what's read from it does.
    Short,
    /// A cell with more in it than what's read from it.
    Extra,
    /// TON would refuse it, or maki can't show it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::TooBig => "bigger than maki reads",
            Error::NotBoc => "not a TON bag of cells",
            Error::Header => "not a TON bag of cells: its sizes don't add up",
            Error::Index => "a bag of cells with an index, which maki doesn't take",
            Error::Checksum => "not a TON bag of cells: its checksum is wrong",
            Error::Roots => "a bag of cells without exactly one root",
            Error::Order => "not a TON bag of cells: a cell refers back, or to one that isn't there",
            Error::Unreached => "a bag of cells with a cell nothing refers to",
            Error::Encoding => "not a TON cell: not written as TON writes one",
            Error::Special => "a pruned branch or a Merkle proof, which maki can't see into",
            Error::Deep => "cells nested deeper than TON allows",
            Error::Short => "not as TON writes it: a cell ends too soon",
            Error::Extra => "not as TON writes it: more in a cell after what it holds",
            Error::Invalid(why) => why,
        })
    }
}
