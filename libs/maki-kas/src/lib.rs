//! Kaspa, for maki's Kaspa app (ARCHITECTURE.md, "Wallets are apps"): the account's addresses, and
//! the transactions it signs, read strictly and shown before they're signed. maki keeps the keys
//! (BIP32 on secp256k1 at `m/44'/111111'/0'/chain/index`, as Kaspium, Kaspa NG, Kastle and Ledger's
//! Kaspa app make them from the same phrase); this reads what the computer asks to sign
//! (`request`), checks it against the account (`wallet`), says what it does (`display`), and works
//! out what each input's signature signs (`sighash`, Kaspa's own, ported from rusty-kaspa).
//!
//! Kaspa spends coins (UTXOs), as Bitcoin does, and the rules that keep a lying computer from
//! getting a signature the owner didn't mean to give are the Bitcoin app's:
//!
//! - every input must be this wallet's, proven by deriving its key and the script that key's coins pay;
//! - an output is change only if it names one of this wallet's keys and pays that key's script (one that
//!   names a key and doesn't pay it is refused); anything else is a payment, shown with its full address, and
//!   must pay an address, a script Kaspa's nodes relay;
//! - the fee is what the inputs hold minus what the outputs pay, and must not be negative;
//! - only SIGHASH_ALL is signed.
//!
//! What a coin holds is the computer's word. An input's signature covers its own coin's amount and
//! no other's, so a false amount spoils that input's signature but not the rest: asked for the same
//! transaction twice, lying about a different coin each time, maki would sign every input once, each
//! time over a fee that isn't the fee (the SegWit fee attack of 2020). So the app keeps what it was
//! told each coin it signed for held (`claims`), and won't sign for a coin said to hold another.
//!
//! Nor does a signature say which network it's for, and Kaspa's wallets use the same keys on its test
//! network: what's signed as test coins spends real KAS if the coins are real. A review on the test
//! network says so before anything else.

#![no_std]
extern crate alloc;

pub mod address;
pub mod claims;
pub mod display;
pub mod hash;
pub mod request;
pub mod sighash;
pub mod wallet;

pub use request::Request;
pub use wallet::Account;

/// Kaspa's coin type (SLIP-44): its accounts are at `m/44'/111111'/account'`.
pub const COIN_TYPE: u32 = 111111;

/// Sompi in a KAS: amounts are in sompi, eight decimals of a KAS.
pub const SOMPI_PER_KAS: u64 = 100_000_000;

/// The most any amount, or sum of amounts, can be (rusty-kaspa's `MAX_SOMPI`, 29 billion KAS): more
/// than there will ever be, and the most Kaspa takes.
pub const MAX_SOMPI: u64 = 29_000_000_000 * SOMPI_PER_KAS;

/// Which of Kaspa's networks: its addresses' prefix, and how its coins are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    /// The test networks (testnet-10 and those after it): the same keys, other addresses, coins
    /// worth nothing.
    Testnet,
}

impl Network {
    /// The network a message names: 0 for Kaspa, 1 for its test network.
    pub fn from_byte(byte: u8) -> Option<Network> {
        match byte {
            0 => Some(Network::Mainnet),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// What its addresses start with, before the colon.
    pub fn prefix(self) -> &'static str {
        match self {
            Network::Mainnet => "kaspa",
            Network::Testnet => "kaspatest",
        }
    }

    /// Its name, as the owner sees it.
    pub fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "kaspa",
            Network::Testnet => "kaspa testnet",
        }
    }

    /// Its coin's name: test coins are marked as such, as Kaspa's own wallets mark them.
    pub fn unit(self) -> &'static str {
        match self {
            Network::Mainnet => "KAS",
            Network::Testnet => "TKAS",
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
    /// A transaction version Kaspa doesn't have (it has 0, and Toccata's 1).
    Version,
    /// No inputs, or no outputs.
    Empty,
    /// More inputs or outputs than maki goes through.
    TooMany,
    /// A flag that isn't 0 or 1.
    Flag,
    /// A key off this wallet's chains: a chain other than receive (0) and change (1), or an index past
    /// BIP32's unhardened ones.
    Path,
    /// This input spends a coin an earlier one spends.
    Duplicate(usize),
    /// This output pays nothing.
    Zero(usize),
    /// An amount no coin can hold: nothing, or (alone or added up) more than `MAX_SOMPI`.
    Amount,
    /// The outputs pay more than the inputs hold.
    NegativeFee,
    /// A subnetwork other than the native one: a lane's transaction (Toccata's), or a coinbase's.
    Subnetwork,
    /// Gas, which only a lane's transactions have.
    Gas,
    /// More data (payload) than maki shows.
    Payload,
    /// This output is bound to a covenant (Toccata's), which maki can't show.
    Covenant(usize),
    /// This output pays a script that isn't an address: Kaspa's nodes don't relay it.
    NonStandard(usize),
    /// This input isn't this wallet's: its coin doesn't pay the key it names.
    NotOurs(usize),
    /// This output names one of this wallet's keys, and doesn't pay it.
    NotChange(usize),
    /// This input of this wallet's commits to other than the one signature check its coin takes.
    SigOps(usize),
    /// This input's coin was said to hold another amount when maki signed for it before.
    Claim(usize),
    /// maki couldn't make a key or a signature: it's locked, or said no.
    Keys(maki_hd::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes in one message"),
            Error::Length => f.write_str("not a transaction maki can read: cut short, or with more after it"),
            Error::Version => f.write_str("a transaction version Kaspa doesn't have"),
            Error::Empty => f.write_str("a transaction needs coins to spend and outputs to pay"),
            Error::TooMany => f.write_str("more inputs or outputs than maki goes through"),
            Error::Flag => f.write_str("not a transaction maki can read: a flag that isn't 0 or 1"),
            Error::Path => f.write_str("a key that isn't on this wallet's receive or change chain"),
            Error::Duplicate(i) => {
                write!(f, "input {i} spends a coin an earlier input spends: Kaspa would refuse it")
            }
            Error::Zero(j) => write!(f, "output {j} pays nothing: Kaspa would refuse it"),
            Error::Amount => {
                f.write_str("an amount no coin can hold: nothing, or more KAS than there can be")
            }
            Error::NegativeFee => f.write_str("the outputs pay more than the inputs hold"),
            Error::Subnetwork => f.write_str(
                "a transaction for a subnetwork (a lane), not a payment: maki can't show what it does",
            ),
            Error::Gas => {
                f.write_str("a transaction with gas, which only a lane's has: Kaspa would refuse it")
            }
            Error::Payload => write!(f, "more data than maki can show ({} bytes)", request::MAX_PAYLOAD),
            Error::Covenant(j) => {
                write!(f, "output {j} is bound to a covenant: maki can't show what that allows")
            }
            Error::NonStandard(j) => {
                write!(f, "output {j} pays a script that isn't an address: Kaspa's nodes won't relay it")
            }
            Error::NotOurs(i) => write!(
                f,
                "input {i} isn't this wallet's (maki signs for Kaspa's standard account, m/44'/111111'/0')"
            ),
            Error::NotChange(j) => write!(f, "output {j} says it pays this wallet, and doesn't"),
            Error::SigOps(i) => {
                write!(f, "input {i} doesn't commit to the one signature check its coin takes")
            }
            Error::Claim(i) => write!(
                f,
                "input {i}'s coin was said to hold another amount when maki signed for it before: one of the two isn't true, so maki won't sign"
            ),
            Error::Keys(e) => write!(f, "{e}"),
        }
    }
}
