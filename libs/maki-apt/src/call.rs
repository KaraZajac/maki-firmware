//! What the calls maki knows do: Aptos's own functions (at 0x1) for sending APT, coins and fungible
//! assets, one payment or several; for staking with a delegation pool; and for handing an object
//! over. Each one's arguments are read as the function takes them, exactly, and its type arguments
//! held to what it allows: what Aptos would refuse, maki refuses. The functions that would change who
//! controls the account are known by name, to be refused. Any other call is one maki can't read.

use alloc::vec::Vec;

use crate::bcs::Reader;
use crate::tx::{EntryFunction, Error, StructTag, TypeTag};
use crate::{Address, FRAMEWORK};

/// What's sent: APT, a coin by its type (Aptos's first kind of token), or a fungible asset by its
/// metadata's address (the newer kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asset {
    Apt,
    Coin(StructTag),
    Fungible(Address),
}

/// A payment: to whom, and how much, in the asset's smallest units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payment {
    pub to: Address,
    pub amount: u64,
}

/// What's done with a delegation pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Staking {
    /// APT staked with the pool (`add_stake`).
    Add,
    /// Staked APT unlocked, to withdraw once the pool's lockup ends (`unlock`).
    Unlock,
    /// Unlocked APT staked again (`reactivate_stake`).
    Reactivate,
    /// Unlocked APT whose lockup has ended, withdrawn (`withdraw`).
    Withdraw,
}

/// What a call does, as far as maki knows its function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// Payments of one asset from this account: one (`aptos_account::transfer`,
    /// `aptos_account::transfer_coins<T>`, `coin::transfer<T>`, `primary_fungible_store::transfer<T>`,
    /// `aptos_account::transfer_fungible_assets`), or several at once (`batch` for aptos_account's
    /// `batch_transfer`, `batch_transfer_coins<T>` and `batch_transfer_fungible_assets`).
    Send { asset: Asset, payments: Vec<Payment>, batch: bool },
    /// APT, in octas, staked, unlocked, staked again or withdrawn with a delegation pool
    /// (`delegation_pool`'s `add_stake`, `unlock`, `reactivate_stake`, `withdraw`).
    Stake { action: Staking, pool: Address, amount: u64 },
    /// An object handed over to another (`object::transfer<T>`, or `object::transfer_call` by its
    /// address alone): its type, if the call names it.
    Object { object: Address, to: Address, kind: Option<StructTag> },
    /// A change of who controls the account: why maki won't sign it.
    Control(&'static str),
    /// A function maki doesn't know: it can't say what it does.
    Other,
}

const ARGUMENTS: Error =
    Error::Invalid("arguments that aren't what the function takes: Aptos would refuse it");
const TYPES: Error =
    Error::Invalid("type arguments that aren't what the function takes: Aptos would refuse it");

/// The call's arguments, if it has `N` of them.
fn args<const N: usize>(f: &EntryFunction) -> Result<[&[u8]; N], Error> {
    let args: Vec<&[u8]> = f.args.iter().map(Vec::as_slice).collect();
    args.try_into().map_err(|_| ARGUMENTS)
}

/// The call's type arguments, if it has `N` of them, each a struct (a coin's type, or one an object
/// has: a type that has the `key` ability is one).
fn structs<const N: usize>(f: &EntryFunction) -> Result<[&StructTag; N], Error> {
    let mut out = Vec::with_capacity(f.type_args.len());
    for t in &f.type_args {
        match t {
            TypeTag::Struct(s) => out.push(&**s),
            _ => return Err(TYPES),
        }
    }
    out.try_into().map_err(|_| TYPES)
}

/// An `address` (or an `Object<T>`, which is its address): 32 bytes.
fn address(arg: &[u8]) -> Result<Address, Error> { arg.try_into().map_err(|_| ARGUMENTS) }

/// A `u64`: 8 bytes, little-endian.
fn amount(arg: &[u8]) -> Result<u64, Error> { Ok(u64::from_le_bytes(arg.try_into().map_err(|_| ARGUMENTS)?)) }

/// A `vector<T>` of fixed-size `T`s, each read by `item`.
fn vector<T>(arg: &[u8], size: usize, item: impl Fn(&[u8]) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    let mut r = Reader::new(arg);
    let n = r.len().map_err(|_| ARGUMENTS)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(item(r.take(size).map_err(|_| ARGUMENTS)?)?);
    }
    r.end().map_err(|_| ARGUMENTS)?;
    Ok(out)
}

fn one(asset: Asset, to: &[u8], n: &[u8]) -> Result<Call, Error> {
    Ok(Call::Send {
        asset,
        payments: alloc::vec![Payment { to: address(to)?, amount: amount(n)? }],
        batch: false,
    })
}

/// Several payments: a `vector<address>` and a `vector<u64>`, one for each.
fn several(asset: Asset, to: &[u8], n: &[u8]) -> Result<Call, Error> {
    let to = vector(to, 32, address)?;
    let amounts = vector(n, 8, amount)?;
    if to.len() != amounts.len() {
        return Err(Error::Invalid("recipients and amounts that don't pair up: Aptos would refuse it"));
    }
    let payments = to.into_iter().zip(amounts).map(|(to, amount)| Payment { to, amount }).collect();
    Ok(Call::Send { asset, payments, batch: true })
}

fn none(f: &EntryFunction) -> Result<(), Error> { if f.type_args.is_empty() { Ok(()) } else { Err(TYPES) } }

/// What `f` does, if it's one of the functions maki knows.
pub fn read(f: &EntryFunction) -> Result<Call, Error> {
    if f.address != FRAMEWORK {
        return other(f);
    }
    match (f.module.as_str(), f.function.as_str()) {
        ("aptos_account", "transfer") => {
            none(f)?;
            let [to, n] = args(f)?;
            one(Asset::Apt, to, n)
        }
        ("aptos_account", "transfer_coins") | ("coin", "transfer") => {
            let [coin] = structs(f)?;
            let [to, n] = args(f)?;
            one(Asset::Coin(coin.clone()), to, n)
        }
        ("aptos_account", "batch_transfer") => {
            none(f)?;
            let [to, n] = args(f)?;
            several(Asset::Apt, to, n)
        }
        ("aptos_account", "batch_transfer_coins") => {
            let [coin] = structs(f)?;
            let [to, n] = args(f)?;
            several(Asset::Coin(coin.clone()), to, n)
        }
        // the asset is the metadata object at that address, whichever of its types the call names
        ("primary_fungible_store", "transfer") => {
            structs::<1>(f)?;
            let [metadata, to, n] = args(f)?;
            one(Asset::Fungible(address(metadata)?), to, n)
        }
        ("aptos_account", "transfer_fungible_assets") => {
            none(f)?;
            let [metadata, to, n] = args(f)?;
            one(Asset::Fungible(address(metadata)?), to, n)
        }
        ("aptos_account", "batch_transfer_fungible_assets") => {
            none(f)?;
            let [metadata, to, n] = args(f)?;
            several(Asset::Fungible(address(metadata)?), to, n)
        }
        ("delegation_pool", name @ ("add_stake" | "unlock" | "reactivate_stake" | "withdraw")) => {
            none(f)?;
            let [pool, n] = args(f)?;
            let (pool, amount) = (address(pool)?, amount(n)?);
            let action = match name {
                "add_stake" => Staking::Add,
                "unlock" => Staking::Unlock,
                "reactivate_stake" => Staking::Reactivate,
                _ => Staking::Withdraw,
            };
            // the others do nothing with nothing; a withdrawal of it, the pool refuses
            if action == Staking::Withdraw && amount == 0 {
                return Err(Error::Invalid("nothing withdrawn: Aptos would refuse it"));
            }
            Ok(Call::Stake { action, pool, amount })
        }
        ("object", "transfer") => {
            let [kind] = structs(f)?;
            let [object, to] = args(f)?;
            Ok(Call::Object { object: address(object)?, to: address(to)?, kind: Some(kind.clone()) })
        }
        ("object", "transfer_call") => {
            none(f)?;
            let [object, to] = args(f)?;
            Ok(Call::Object { object: address(object)?, to: address(to)?, kind: None })
        }
        ("account", name)
            if name.starts_with("rotate_authentication_key")
                || name.starts_with("upsert_ed25519_backup_key") =>
        {
            Ok(Call::Control("it changes this account's key: maki won't sign that"))
        }
        ("account", "offer_rotation_capability") => {
            Ok(Call::Control("it lets another change this account's key: maki won't sign that"))
        }
        ("account", "offer_signer_capability") => {
            Ok(Call::Control("it lets another act as this account: maki won't sign that"))
        }
        (
            "account_abstraction",
            "add_authentication_function" | "add_dispatchable_authentication_function",
        ) => Ok(Call::Control("it lets another's code sign for this account: maki won't sign that")),
        ("multisig_account", name) if name.starts_with("create_with_existing_account") => Ok(Call::Control(
            "it makes this account a multisig account, others' to control: maki won't sign that",
        )),
        _ => other(f),
    }
}

/// A call maki can't read. Every argument is the BCS of some type, a byte at least: an empty one,
/// Aptos would refuse.
fn other(f: &EntryFunction) -> Result<Call, Error> {
    if f.args.iter().any(|a| a.is_empty()) {
        return Err(Error::Invalid("an empty argument: Aptos would refuse it"));
    }
    Ok(Call::Other)
}
