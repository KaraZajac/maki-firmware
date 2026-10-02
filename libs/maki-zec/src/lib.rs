//! Zcash's transparent addresses, for maki's Zcash app (ARCHITECTURE.md, "Wallets are apps"): the
//! account's t-addresses, and the transactions it signs, read strictly and shown before they're
//! signed. maki keeps the keys (BIP32 on secp256k1 at `m/44'/133'/0'/chain/index`, as Ledger's Zcash
//! app, Zashi, zcashd and Zallet make transparent keys from the same phrase); this reads what the
//! computer asks to sign (`request`: a version 5 transaction, ZIP-225's, and what maki needs beside
//! it), checks it against the account (`wallet`), says what it does (`display`), and works out what
//! each input's signature signs (`sighash`, ZIP-244's digest).
//!
//! Transparent Zcash spends coins as Bitcoin does, and the rules that keep a lying computer from
//! getting a signature the owner didn't mean to give are the Bitcoin app's:
//!
//! - every input must be this wallet's, proven by deriving its key and the script that key's coins pay;
//! - an output is change only if it names one of this wallet's keys and pays that key's script (one that
//!   names a key and doesn't pay it is refused); anything else is a payment, shown with its full address, and
//!   must pay an address, or data;
//! - the fee is what the inputs hold minus what the outputs pay, and must not be negative;
//! - only SIGHASH_ALL is signed.
//!
//! What a coin holds is the computer's word, but ZIP-244's digest commits every input's signature to
//! every input's amount and script: a coin said to hold what it doesn't spoils every signature, so a
//! fee nobody saw (the SegWit fee attack of 2020) can't be signed, and nothing need be remembered
//! between requests (Kaspa's app must).
//!
//! maki can't see into shielded parts (Sapling's, Orchard's): a transaction with any is refused, by
//! name. A transaction commits to the consensus branch of the network upgrade it's for; maki signs
//! for the one in force (`tx::BRANCH_ID`, NU6.3's since July 2026), and must learn the next one's
//! before it activates (NU7: its branch is in ZIP 259, its height on the main network not yet).

#![no_std]
extern crate alloc;

pub mod address;
pub mod display;
pub mod hash;
pub mod request;
pub mod sighash;
pub mod tx;
pub mod wallet;

pub use request::Request;
pub use tx::Transaction;
pub use wallet::Account;

/// Zcash's coin type (SLIP-44): its transparent accounts are at `m/44'/133'/account'`.
pub const COIN_TYPE: u32 = 133;

/// Zatoshis in a ZEC: amounts are in zatoshis, eight decimals of a ZEC.
pub const ZATOSHIS_PER_ZEC: u64 = 100_000_000;

/// The most any amount, or sum of amounts, can be (the protocol's `MAX_MONEY`, 21 million ZEC):
/// more than there will ever be, and the most Zcash takes.
pub const MAX_MONEY: u64 = 21_000_000 * ZATOSHIS_PER_ZEC;

/// Which of Zcash's networks: its addresses, its coin type, and how its coins are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    /// The test network: other keys (coin type 1), other addresses (`tm…`), coins worth nothing
    /// (TAZ).
    Testnet,
}

impl Network {
    /// The network a message names: 0 for Zcash, 1 for its test network.
    pub fn from_byte(byte: u8) -> Option<Network> {
        match byte {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// Its accounts' coin type: Zcash's own, or 1, every test network's (as zcash_protocol has it).
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Mainnet => COIN_TYPE,
            Network::Testnet => 1,
        }
    }

    /// Its name, as the owner sees it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "zcash",
            Network::Testnet => "zcash testnet",
        }
    }

    /// Its coin's name: the test network's is TAZ, as Zcash's wallets call it.
    pub fn unit(self) -> &'static str {
        match self {
            Network::Mainnet => "ZEC",
            Network::Testnet => "TAZ",
        }
    }
}

/// Why maki won't show or sign what it was asked to: said to the computer, which shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Bigger than one message holds.
    TooBig,
    /// Cut short, or with bytes after it.
    Length,
    /// A transaction version maki doesn't read: its header (with the overwintered flag).
    Version(u32),
    /// A version group that isn't version 5's.
    Group,
    /// A consensus branch other than the one in force: the transaction is for another network
    /// upgrade's rules.
    Branch(u32),
    /// An expiry height past the most Zcash takes.
    Expiry,
    /// An input with its script already filled in: a signed transaction, or not one maki made.
    Signed,
    /// Shielded parts (Sapling spends or outputs, Orchard actions), named.
    Shielded(&'static str),
    /// No inputs, or no outputs.
    Empty,
    /// More inputs or outputs than maki goes through.
    TooMany,
    /// A field that isn't one of the values it can take.
    Flag,
    /// A key off this wallet's chains: a chain other than receive (0) and change (1), or an index past
    /// BIP32's unhardened ones.
    Path,
    /// This input spends nothing: a coinbase's null coin.
    Coinbase(usize),
    /// This input spends a coin an earlier one spends.
    Duplicate(usize),
    /// An amount no coin can hold: alone or added up, more than `MAX_MONEY`.
    Amount,
    /// The outputs pay more than the inputs hold.
    NegativeFee,
    /// This output pays a script that isn't an address or data: maki can't show who it pays.
    NonStandard(usize),
    /// This input isn't this wallet's: its coin doesn't pay the key it names.
    NotOurs(usize),
    /// This output names one of this wallet's keys, and doesn't pay it.
    NotChange(usize),
    /// This output is to be shown as a TEX address, and doesn't pay a key's hash.
    NotTex(usize),
    /// maki couldn't make a key or a signature: it's locked, or said no.
    Keys(maki_hd::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes in one message"),
            Error::Length => f.write_str("not a transaction maki can read: cut short, or with more after it"),
            Error::Version(tx::VERSION_6) => f.write_str(
                "a version 6 transaction (ZIP 229, NU6.3's): maki reads version 5, which Zcash still takes",
            ),
            Error::Version(tx::VERSION_4) => {
                f.write_str("a version 4 transaction (Sapling's): maki reads version 5 (ZIP 225)")
            }
            Error::Version(_) => {
                f.write_str("not a Zcash transaction version maki reads (it reads version 5)")
            }
            Error::Group => {
                f.write_str("not a transaction maki can read: version 5's version group isn't this")
            }
            Error::Branch(id) => match tx::upgrade(*id) {
                Some(name) => write!(
                    f,
                    "a transaction for {name}'s rules (consensus branch {id:08x}), which Zcash has left behind: it follows {}'s",
                    tx::UPGRADE
                ),
                None => write!(
                    f,
                    "a transaction for a network upgrade maki doesn't know (consensus branch {id:08x}): it signs for {}'s, the one in force",
                    tx::UPGRADE
                ),
            },
            Error::Expiry => f.write_str("an expiry height past the most Zcash takes (499,999,999)"),
            Error::Signed => {
                f.write_str("a transaction already signed: maki signs one whose inputs' scripts are empty")
            }
            Error::Shielded(what) => write!(
                f,
                "a transaction with {what}, which are shielded: maki can't see into them, and signs transparent transactions only"
            ),
            Error::Empty => f.write_str("a transaction needs coins to spend and outputs to pay"),
            Error::TooMany => f.write_str("more inputs or outputs than maki goes through"),
            Error::Flag => f.write_str("not a request maki can read: a field that isn't one of its values"),
            Error::Path => f.write_str("a key that isn't on this wallet's receive or change chain"),
            Error::Coinbase(i) => {
                write!(f, "input {i} spends nothing (a coinbase's null coin): Zcash would refuse it")
            }
            Error::Duplicate(i) => {
                write!(f, "input {i} spends a coin an earlier input spends: Zcash would refuse it")
            }
            Error::Amount => f.write_str("an amount no coin can hold: more ZEC than there can be"),
            Error::NegativeFee => f.write_str("the outputs pay more than the inputs hold"),
            Error::NonStandard(j) => {
                write!(
                    f,
                    "output {j} pays a script that isn't an address or data: maki can't show who it pays"
                )
            }
            Error::NotOurs(i) => write!(
                f,
                "input {i} isn't this wallet's (maki signs for Zcash's transparent account, m/44'/133'/0')"
            ),
            Error::NotChange(j) => write!(f, "output {j} says it pays this wallet, and doesn't"),
            Error::NotTex(j) => {
                write!(f, "output {j} is to be shown as a TEX address, and doesn't pay a key's hash")
            }
            Error::Keys(e) => write!(f, "{e}"),
        }
    }
}
