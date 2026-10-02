//! Soroban, Stellar's contracts: what a transaction gives a contract, read far enough to say which
//! contract and which function, whether it's given this account's authority, and what a
//! contract's transaction says it uses (its footprint: the ledger entries it reads and writes; and
//! its resource fee). A contract's arguments (`SCVal`s) are read strictly, as everything else is,
//! but not interpreted: what a contract does with them, maki can't tell, and the review says so.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::transaction::{Asset, Body, Error, account_id, asset, balance_id};
use crate::xdr::{Reader, UNBOUNDED};
use crate::{Hash, Key, Network, strkey};

/// How deep a contract's values, authorizations and their delegates may nest for maki to read
/// them. Stellar allows deeper; maki refuses what it can't read whole.
pub const MAX_DEPTH: usize = 32;
/// The most a resource fee can be (`MAX_RESOURCE_FEE`), in stroops.
pub const MAX_RESOURCE_FEE: i64 = 1 << 50;

/// An address a contract sees (`SCAddress`): an account, a contract, an account with an ID, a
/// claimable balance or a liquidity pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    Account(Key),
    Contract(Hash),
    Muxed { key: Key, id: u64 },
    ClaimableBalance(Hash),
    LiquidityPool(Hash),
}

impl Address {
    /// As a page shows it: its StrKey.
    pub fn strkey(&self) -> String {
        match self {
            Address::Account(k) => strkey::account(k),
            Address::Contract(h) => strkey::contract(h),
            Address::Muxed { key, id } => strkey::muxed(key, *id),
            Address::ClaimableBalance(h) => strkey::claimable_balance(h),
            Address::LiquidityPool(h) => strkey::liquidity_pool(h),
        }
    }

    /// Whether it's the account `key`, with an ID or without.
    pub fn is(&self, key: &Key) -> bool {
        matches!(self, Address::Account(k) | Address::Muxed { key: k, .. } if k == key)
    }
}

/// What a contract runs: code uploaded before (by its hash), a Stellar asset's contract, or
/// another's code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Executable {
    Wasm(Hash),
    StellarAsset,
    External { owner: Address, tag: Vec<u8> },
}

/// What a new contract's ID is made from: an address and a salt, or a Stellar asset (its asset
/// contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preimage {
    Address { address: Address, salt: Hash },
    Asset(Asset),
}

/// What an `InvokeHostFunction` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFunction {
    /// A contract's function called, with `args` arguments.
    Call { contract: Address, function: Vec<u8>, args: usize },
    /// A contract made; `args`, its constructor's, for the second version.
    Create { preimage: Preimage, executable: Executable, args: Option<usize> },
    /// Code uploaded for contracts to run: `size` bytes of WebAssembly.
    Upload { size: usize },
}

/// Who authorizes what an authorization entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credentials {
    /// The operation's source account, by signing the transaction: whoever signs it as that
    /// account authorizes it.
    SourceAccount,
    /// An address, by a signature of its own in the entry (made apart from the transaction's),
    /// with `delegates` more by others it lets sign for it.
    Address { address: Address, nonce: i64, expiration: u32, delegates: usize },
}

/// What an authorization entry's tree starts with: a contract's function, or a contract made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorized {
    Call { contract: Address, function: Vec<u8> },
    Create { executable: Executable },
}

/// An authorization entry: who authorizes, the call its tree starts with, and how many calls the
/// tree has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub credentials: Credentials,
    pub root: Authorized,
    pub calls: usize,
}

/// An `InvokeHostFunction` operation: what it runs, and what it's authorized to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoke {
    pub function: HostFunction,
    pub auth: Vec<Auth>,
}

/// A ledger entry a contract's transaction reads or writes, as far as a page tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    Account(Key),
    TrustLine(Key),
    Offer,
    Data,
    ClaimableBalance,
    LiquidityPool(Hash),
    /// A contract's data: kept for good (persistent), or for a while (temporary).
    ContractData {
        contract: Address,
        persistent: bool,
    },
    ContractCode(Hash),
    ConfigSetting,
    Ttl,
}

/// What a contract's transaction says it uses (`SorobanTransactionData`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Data {
    pub read_only: Vec<Entry>,
    pub read_write: Vec<Entry>,
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    /// Which of the entries it writes are archived, to bring back.
    pub archived: Vec<u32>,
    /// What of the fee pays for its resources, in stroops.
    pub resource_fee: i64,
}

impl Data {
    /// What stellar-core refuses of a footprint for the operation it's with: extending entries'
    /// time to live reads contracts' entries and writes none; restoring writes contracts' entries
    /// kept for good, and reads none.
    pub(crate) fn check(&self, body: &Body) -> Result<(), Error> {
        let contracts = |e: &Entry| matches!(e, Entry::ContractData { .. } | Entry::ContractCode(_));
        let kept =
            |e: &Entry| matches!(e, Entry::ContractData { persistent: true, .. } | Entry::ContractCode(_));
        match body {
            Body::ExtendFootprintTtl { .. }
                if !self.read_write.is_empty() || !self.read_only.iter().all(contracts) =>
            {
                Err(Error::Invalid("extending what contracts don't keep: Stellar would refuse it"))
            }
            Body::RestoreFootprint if !self.read_only.is_empty() || !self.read_write.iter().all(kept) => {
                Err(Error::Invalid("restoring what contracts don't keep: Stellar would refuse it"))
            }
            _ => Ok(()),
        }
    }
}

/// A Stellar asset's contract on `network` (its Stellar asset contract, through which contracts
/// move it): its ID, SHA-256 of the network's ID and the asset, tagged as a contract's ID made
/// from an asset (`HashIDPreimage`'s `ENVELOPE_TYPE_CONTRACT_ID`, `CONTRACT_ID_PREIMAGE_FROM_ASSET`).
pub fn asset_contract(asset: &Asset, network: Network) -> Hash {
    Sha256::new()
        .chain_update(8u32.to_be_bytes())
        .chain_update(network.id())
        .chain_update(1u32.to_be_bytes())
        .chain_update(asset.to_xdr())
        .finalize()
        .into()
}

fn deeper(depth: usize) -> Result<usize, Error> {
    if depth >= MAX_DEPTH {
        return Err(Error::Deep);
    }
    Ok(depth + 1)
}

/// A value a contract is given (`SCVal`), read whole and left as it is.
fn value(r: &mut Reader, depth: usize) -> Result<(), Error> {
    let depth = deeper(depth)?;
    match r.kind(22)? {
        // a bool
        0 => {
            r.bool()?;
        }
        // nothing; a contract instance's key
        1 | 20 => {}
        // an error: its kind, and a contract's code or one of the host's
        2 => match r.kind(9)? {
            0 => {
                r.u32()?;
            }
            _ => {
                r.kind(9)?;
            }
        },
        // 32-bit numbers
        3 | 4 => {
            r.u32()?;
        }
        // 64-bit numbers, times and durations
        5..=8 => {
            r.u64()?;
        }
        // 128-bit numbers
        9 | 10 => {
            r.take(16)?;
        }
        // 256-bit numbers
        11 | 12 => {
            r.take(32)?;
        }
        // bytes, a string, an executable's tag
        13 | 14 | 22 => {
            r.opaque(UNBOUNDED)?;
        }
        // a symbol
        15 => {
            r.opaque(32)?;
        }
        // a list, if it's there
        16 => {
            if r.bool()? {
                values(r, depth)?;
            }
        }
        // a map, if it's there
        17 => {
            if r.bool()? {
                map(r, depth)?;
            }
        }
        18 => {
            address(r)?;
        }
        // a contract instance: what it runs, and its storage
        19 => {
            executable(r)?;
            if r.bool()? {
                map(r, depth)?;
            }
        }
        // a nonce's key
        _ => {
            r.i64()?;
        }
    }
    Ok(())
}

/// A list of values: how many.
fn values(r: &mut Reader, depth: usize) -> Result<usize, Error> {
    let n = r.count(UNBOUNDED)?;
    for _ in 0..n {
        value(r, depth)?;
    }
    Ok(n)
}

fn map(r: &mut Reader, depth: usize) -> Result<(), Error> {
    for _ in 0..r.count(UNBOUNDED)? {
        value(r, depth)?;
        value(r, depth)?;
    }
    Ok(())
}

fn address(r: &mut Reader) -> Result<Address, Error> {
    Ok(match r.kind(4)? {
        0 => Address::Account(account_id(r)?),
        1 => Address::Contract(r.hash()?),
        // an account with an ID: the ID first
        2 => {
            let id = r.u64()?;
            Address::Muxed { key: r.key()?, id }
        }
        3 => Address::ClaimableBalance(balance_id(r)?),
        _ => Address::LiquidityPool(r.hash()?),
    })
}

fn executable(r: &mut Reader) -> Result<Executable, Error> {
    Ok(match r.kind(2)? {
        0 => Executable::Wasm(r.hash()?),
        1 => Executable::StellarAsset,
        _ => {
            let owner = address(r)?;
            Executable::External { owner, tag: r.opaque(UNBOUNDED)?.to_vec() }
        }
    })
}

fn preimage(r: &mut Reader) -> Result<Preimage, Error> {
    Ok(match r.kind(1)? {
        0 => {
            let address = address(r)?;
            Preimage::Address { address, salt: r.hash()? }
        }
        _ => Preimage::Asset(asset(r)?),
    })
}

/// A call's contract, function and arguments (`InvokeContractArgs`), `depth` deep.
fn call(r: &mut Reader, depth: usize) -> Result<(Address, Vec<u8>, usize), Error> {
    let contract = address(r)?;
    let function = r.opaque(32)?.to_vec();
    Ok((contract, function, values(r, depth)?))
}

fn host_function(r: &mut Reader) -> Result<HostFunction, Error> {
    Ok(match r.kind(3)? {
        0 => {
            let (contract, function, args) = call(r, 0)?;
            HostFunction::Call { contract, function, args }
        }
        1 => {
            let preimage = preimage(r)?;
            HostFunction::Create { preimage, executable: executable(r)?, args: None }
        }
        2 => HostFunction::Upload { size: r.opaque(UNBOUNDED)?.len() },
        _ => {
            let preimage = preimage(r)?;
            let executable = executable(r)?;
            HostFunction::Create { preimage, executable, args: Some(values(r, 0)?) }
        }
    })
}

/// Signatures by those an address lets sign for it, and theirs: how many.
fn delegates(r: &mut Reader, depth: usize) -> Result<usize, Error> {
    let depth = deeper(depth)?;
    let n = r.count(UNBOUNDED)?;
    let mut all = n;
    for _ in 0..n {
        address(r)?;
        value(r, depth)?;
        all += delegates(r, depth)?;
    }
    Ok(all)
}

fn credentials(r: &mut Reader) -> Result<Credentials, Error> {
    let kind = r.kind(3)?;
    if kind == 0 {
        return Ok(Credentials::SourceAccount);
    }
    // an address's own, its second version the same, and one with others signing for it
    let address = address(r)?;
    let nonce = r.i64()?;
    let expiration = r.u32()?;
    value(r, 0)?;
    let delegates = if kind == 3 { delegates(r, 0)? } else { 0 };
    Ok(Credentials::Address { address, nonce, expiration, delegates })
}

/// An authorized call and the calls under it, `depth` deep, counted into `calls`.
fn invocation(r: &mut Reader, depth: usize, calls: &mut usize) -> Result<Authorized, Error> {
    let depth = deeper(depth)?;
    *calls += 1;
    let authorized = match r.kind(2)? {
        0 => {
            let (contract, function, _) = call(r, depth)?;
            Authorized::Call { contract, function }
        }
        1 => {
            preimage(r)?;
            Authorized::Create { executable: executable(r)? }
        }
        _ => {
            preimage(r)?;
            let executable = executable(r)?;
            values(r, depth)?;
            Authorized::Create { executable }
        }
    };
    for _ in 0..r.count(UNBOUNDED)? {
        invocation(r, depth, calls)?;
    }
    Ok(authorized)
}

/// An `InvokeHostFunction` operation's body.
pub(crate) fn invoke(r: &mut Reader) -> Result<Invoke, Error> {
    let function = host_function(r)?;
    let mut auth = Vec::new();
    for _ in 0..r.count(UNBOUNDED)? {
        let credentials = credentials(r)?;
        let mut calls = 0;
        let root = invocation(r, 0, &mut calls)?;
        auth.push(Auth { credentials, root, calls });
    }
    Ok(Invoke { function, auth })
}

/// A ledger entry's key in a footprint, read whole. Trustlines' assets aren't held to what
/// operations' are: stellar-core doesn't check a footprint's.
fn entry(r: &mut Reader) -> Result<Entry, Error> {
    Ok(match r.kind(9)? {
        0 => Entry::Account(account_id(r)?),
        1 => {
            let account = account_id(r)?;
            match r.kind(3)? {
                0 => {}
                1 => {
                    r.array::<4>()?;
                    account_id(r)?;
                }
                2 => {
                    r.array::<12>()?;
                    account_id(r)?;
                }
                _ => {
                    r.hash()?;
                }
            }
            Entry::TrustLine(account)
        }
        2 => {
            account_id(r)?;
            r.i64()?;
            Entry::Offer
        }
        3 => {
            account_id(r)?;
            r.opaque(64)?;
            Entry::Data
        }
        4 => {
            balance_id(r)?;
            Entry::ClaimableBalance
        }
        5 => Entry::LiquidityPool(r.hash()?),
        6 => {
            let contract = address(r)?;
            value(r, 0)?;
            Entry::ContractData { contract, persistent: r.kind(1)? == 1 }
        }
        7 => Entry::ContractCode(r.hash()?),
        // which of the network's settings: `ConfigSettingID`'s 0 to 20
        8 => {
            r.kind(20)?;
            Entry::ConfigSetting
        }
        _ => {
            r.hash()?;
            Entry::Ttl
        }
    })
}

/// A footprint's entries, and each one's bytes as written, to find any named twice.
fn footprint<'a>(r: &mut Reader<'a>, written: &mut Vec<&'a [u8]>) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    for _ in 0..r.count(UNBOUNDED)? {
        let start = r.at();
        entries.push(entry(r)?);
        written.push(r.since(start));
    }
    Ok(entries)
}

/// A transaction's `SorobanTransactionData`. An entry named twice in its footprint (in either
/// list, or both) stellar-core refuses.
pub(crate) fn data(r: &mut Reader) -> Result<Data, Error> {
    let archived = match r.kind(1)? {
        0 => Vec::new(),
        _ => {
            let mut archived = Vec::new();
            for _ in 0..r.count(UNBOUNDED)? {
                archived.push(r.u32()?);
            }
            archived
        }
    };
    let mut written = Vec::new();
    let read_only = footprint(r, &mut written)?;
    let read_write = footprint(r, &mut written)?;
    for (i, w) in written.iter().enumerate() {
        if written[..i].contains(w) {
            return Err(Error::Invalid("a contract's entry named twice: Stellar would refuse it"));
        }
    }
    let instructions = r.u32()?;
    let disk_read_bytes = r.u32()?;
    let write_bytes = r.u32()?;
    Ok(Data {
        read_only,
        read_write,
        instructions,
        disk_read_bytes,
        write_bytes,
        archived,
        resource_fee: r.i64()?,
    })
}
