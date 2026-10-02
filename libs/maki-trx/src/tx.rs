//! A transaction's `raw_data` (`Transaction.raw` in Tron's Tron.proto), what a Tron signature signs:
//! read as Tron's own software writes it (`proto`), with the one contract java-tron takes, and held
//! to what java-tron accepts, so anything Tron would refuse maki refuses before it's shown. The
//! contracts maki reads are TRX and TRC-10 tokens sent, contracts called (TRC-20 tokens among
//! them), staking (Tron's second kind: staking, unstaking, withdrawing, cancelling, delegating and
//! reclaiming), votes and voting rewards, and a change of the account's permissions, read only as
//! far as whose account it is, to refuse it. Any other kind it refuses, by name.

use alloc::vec::Vec;

use crate::proto::{self, Fields};
use crate::{Address, PREFIX};

/// The longest `raw_data` maki reads: a message from the computer is 4096 bytes at most.
pub const MAX_RAW: usize = 4096;
/// One TRX, in sun: Tron counts in millionths.
pub const SUN_PER_TRX: u64 = 1_000_000;
/// The most witnesses one vote can name (java-tron's `MAX_VOTE_NUMBER`).
pub const MAX_VOTES: usize = 30;
/// TRC-10 tokens are numbered from one past this (java-tron's `MIN_TOKEN_ID`).
pub const MIN_TOKEN_ID: u64 = 1_000_000;
/// How long a delegation is locked when it doesn't say: three days of three-second blocks
/// (java-tron's `DELEGATE_PERIOD`).
pub const DEFAULT_LOCK_BLOCKS: u64 = 86_400;
/// The prefix every contract's type URL has, before its name.
const TYPE_URL: &[u8] = b"type.googleapis.com/protocol.";

/// Why maki won't read a transaction: each says why, for the computer that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than maki reads.
    TooBig,
    /// Cut short, or not written as Tron writes it.
    Encoding,
    /// A field maki doesn't know: it won't sign what it can't show.
    Unknown,
    /// A field given twice.
    Duplicate,
    /// Not exactly one contract, as Tron takes them.
    Contracts,
    /// A contract whose type and contents don't agree.
    Mismatch,
    /// An address that isn't one of Tron's: 21 bytes, the first `PREFIX`.
    Address,
    /// A kind of contract maki doesn't sign: its name.
    Unsupported(&'static str),
    /// Something Tron would refuse: why.
    Invalid(&'static str),
}

impl From<proto::Error> for Error {
    fn from(e: proto::Error) -> Error {
        match e {
            proto::Error::Encoding => Error::Encoding,
            proto::Error::Unknown => Error::Unknown,
            proto::Error::Duplicate => Error::Duplicate,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes a Tron transaction"),
            Error::Encoding => {
                f.write_str("not a Tron transaction as Tron writes one: cut short, or written another way")
            }
            Error::Unknown => f.write_str("a field maki doesn't know: it won't sign what it can't show"),
            Error::Duplicate => f.write_str("not a Tron transaction: a field given twice"),
            Error::Contracts => f.write_str("not one contract: Tron takes exactly one"),
            Error::Mismatch => f.write_str("a contract whose type and contents don't agree"),
            Error::Address => f.write_str("an address that isn't Tron's"),
            Error::Unsupported(name) => {
                let a = if name.starts_with(['A', 'E', 'I', 'O', 'U']) { "an" } else { "a" };
                write!(f, "{a} {name}: maki doesn't sign those")
            }
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// What staked TRX is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Bandwidth: a transaction's bytes.
    Bandwidth,
    /// Energy: a contract's work.
    Energy,
}

impl Resource {
    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Resource::Bandwidth => "bandwidth",
            Resource::Energy => "energy",
        }
    }
}

/// The contract a transaction carries: what it does. In each, `owner` is the account it's for,
/// which signs it; every amount is in sun, or in a token's smallest units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contract {
    /// TRX sent (`TransferContract`).
    Transfer { owner: Address, to: Address, amount: u64 },
    /// A TRC-10 token sent (`TransferAssetContract`): the token by its number.
    TransferToken { owner: Address, to: Address, token: u64, amount: u64 },
    /// A contract called (`TriggerSmartContract`), with TRX (`call_value`) and a TRC-10 token
    /// (`token_value` of `token`, 0 for none) sent along; a TRC-20 token's transfer is one.
    Call { owner: Address, contract: Address, data: Vec<u8>, call_value: u64, token: u64, token_value: u64 },
    /// TRX staked for a resource (`FreezeBalanceV2Contract`).
    Stake { owner: Address, amount: u64, resource: Resource },
    /// Staked TRX unstaked (`UnfreezeBalanceV2Contract`): it can be withdrawn after a wait.
    Unstake { owner: Address, amount: u64, resource: Resource },
    /// Unstaked TRX whose wait is over, withdrawn (`WithdrawExpireUnfreezeContract`).
    WithdrawUnstaked { owner: Address },
    /// Every unstaking still waiting, staked again (`CancelAllUnfreezeV2Contract`).
    CancelUnstaking { owner: Address },
    /// What staked TRX makes, given to another account to use (`DelegateResourceContract`), locked
    /// for some blocks or not.
    Delegate { owner: Address, receiver: Address, amount: u64, resource: Resource, lock: Option<u64> },
    /// A delegation taken back (`UnDelegateResourceContract`).
    Reclaim { owner: Address, receiver: Address, amount: u64, resource: Resource },
    /// Votes for witnesses, each with as many votes (`VoteWitnessContract`).
    Vote { owner: Address, votes: Vec<(Address, u64)> },
    /// The rewards voting has earned, claimed (`WithdrawBalanceContract`).
    ClaimRewards { owner: Address },
    /// The keys that may sign for the account changed (`AccountPermissionUpdateContract`): read
    /// only as far as whose account it is, since maki doesn't sign it.
    UpdatePermissions { owner: Address },
}

impl Contract {
    /// The account it's for, which signs it.
    pub fn owner(&self) -> &Address {
        match self {
            Contract::Transfer { owner, .. }
            | Contract::TransferToken { owner, .. }
            | Contract::Call { owner, .. }
            | Contract::Stake { owner, .. }
            | Contract::Unstake { owner, .. }
            | Contract::WithdrawUnstaked { owner }
            | Contract::CancelUnstaking { owner }
            | Contract::Delegate { owner, .. }
            | Contract::Reclaim { owner, .. }
            | Contract::Vote { owner, .. }
            | Contract::ClaimRewards { owner }
            | Contract::UpdatePermissions { owner } => owner,
        }
    }
}

/// A transaction's `raw_data`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The block it names (its number's last two bytes, and bytes 8 to 16 of its ID): a network
    /// takes the transaction only while that block is one of its last 65,536.
    pub ref_block_bytes: [u8; 2],
    /// The block's ID's bytes 8 to 16, which only that network's block has.
    pub ref_block_hash: [u8; 8],
    /// When it expires, in milliseconds since 1970: Tron takes it only before then, and only in
    /// the day before.
    pub expiration: u64,
    /// When it was made, in milliseconds since 1970, as whoever made it says; 0 if it doesn't.
    pub timestamp: u64,
    /// A memo (`data`): anything, for anyone to read on chain; empty for none.
    pub memo: Vec<u8>,
    /// The most TRX, in sun, a contract call may burn for energy; 0 if it doesn't say.
    pub fee_limit: u64,
    /// Which of the account's permissions signs it: 0 its owner, 2 and up one of its active ones.
    pub permission: u32,
    /// What it does.
    pub contract: Contract,
    /// How many bytes `raw_data` is: what its bandwidth is counted from.
    pub size: usize,
}

/// Every kind of contract Tron has, by its number (Tron.proto's `ContractType`).
const KINDS: &[(i32, &str)] = &[
    (0, "AccountCreateContract"),
    (1, "TransferContract"),
    (2, "TransferAssetContract"),
    (3, "VoteAssetContract"),
    (4, "VoteWitnessContract"),
    (5, "WitnessCreateContract"),
    (6, "AssetIssueContract"),
    (8, "WitnessUpdateContract"),
    (9, "ParticipateAssetIssueContract"),
    (10, "AccountUpdateContract"),
    (11, "FreezeBalanceContract"),
    (12, "UnfreezeBalanceContract"),
    (13, "WithdrawBalanceContract"),
    (14, "UnfreezeAssetContract"),
    (15, "UpdateAssetContract"),
    (16, "ProposalCreateContract"),
    (17, "ProposalApproveContract"),
    (18, "ProposalDeleteContract"),
    (19, "SetAccountIdContract"),
    (20, "CustomContract"),
    (30, "CreateSmartContract"),
    (31, "TriggerSmartContract"),
    (32, "GetContract"),
    (33, "UpdateSettingContract"),
    (41, "ExchangeCreateContract"),
    (42, "ExchangeInjectContract"),
    (43, "ExchangeWithdrawContract"),
    (44, "ExchangeTransactionContract"),
    (45, "UpdateEnergyLimitContract"),
    (46, "AccountPermissionUpdateContract"),
    (48, "ClearABIContract"),
    (49, "UpdateBrokerageContract"),
    (51, "ShieldedTransferContract"),
    (52, "MarketSellAssetContract"),
    (53, "MarketCancelOrderContract"),
    (54, "FreezeBalanceV2Contract"),
    (55, "UnfreezeBalanceV2Contract"),
    (56, "WithdrawExpireUnfreezeContract"),
    (57, "DelegateResourceContract"),
    (58, "UnDelegateResourceContract"),
    (59, "CancelAllUnfreezeV2Contract"),
];

/// An address, as a contract carries it.
fn address(b: &[u8]) -> Result<Address, Error> {
    let a: Address = b.try_into().map_err(|_| Error::Address)?;
    if a[0] != PREFIX {
        return Err(Error::Address);
    }
    Ok(a)
}

/// An amount Tron takes only above zero.
fn positive(n: i64, why: &'static str) -> Result<u64, Error> {
    if n > 0 { Ok(n as u64) } else { Err(Error::Invalid(why)) }
}

/// A number Tron takes only at zero or above.
fn not_negative(n: i64, why: &'static str) -> Result<u64, Error> {
    if n >= 0 { Ok(n as u64) } else { Err(Error::Invalid(why)) }
}

/// What staked TRX is for, as a contract says it: bandwidth (0, so not written), or energy.
/// Tron Power (2) is staked for only under a resource model Tron hasn't turned on.
fn resource(n: i32) -> Result<Resource, Error> {
    match n {
        0 => Ok(Resource::Bandwidth),
        1 => Ok(Resource::Energy),
        _ => Err(Error::Invalid("a resource other than bandwidth or energy: Tron would refuse it")),
    }
}

/// A TRC-10 token's number, written as Tron writes it: its digits, as a string.
fn token_number(b: &[u8]) -> Result<u64, Error> {
    let bad = Error::Invalid("a TRC-10 token that isn't named by its number: Tron would refuse it");
    if b.is_empty() || b.len() > 19 || b[0] == b'0' || !b.iter().all(u8::is_ascii_digit) {
        return Err(bad);
    }
    let n = b.iter().fold(0u64, |n, d| n * 10 + (d - b'0') as u64);
    if n <= MIN_TOKEN_ID || n > i64::MAX as u64 {
        return Err(bad);
    }
    Ok(n)
}

impl Transaction {
    /// A transaction's `raw_data`, read whole: everything in it, nothing after it.
    pub fn parse(raw: &[u8]) -> Result<Transaction, Error> {
        if raw.len() > MAX_RAW {
            return Err(Error::TooBig);
        }
        let mut f = Fields::read(raw)?;
        let ref_block_bytes = f.bytes(1)?.try_into().map_err(|_| {
            Error::Invalid("a reference block that isn't Tron's two bytes of number: Tron would refuse it")
        })?;
        let ref_block_hash = f.bytes(4)?.try_into().map_err(|_| {
            Error::Invalid("a reference block that isn't Tron's eight bytes of hash: Tron would refuse it")
        })?;
        let expiration = positive(f.int64(8)?, "no expiration: Tron would refuse it")?;
        let memo = f.bytes(10)?.to_vec();
        let contracts = f.messages(11)?;
        let timestamp = not_negative(f.int64(14)?, "made before 1970")?;
        let fee_limit = not_negative(f.int64(18)?, "a fee limit below nothing: Tron would refuse it")?;
        f.end()?;
        let [contract] = contracts.as_slice() else { return Err(Error::Contracts) };
        let (contract, permission) = read_contract(contract)?;
        // only a contract's call can burn TRX for energy: a limit on anything else means nothing
        if fee_limit != 0 && !matches!(contract, Contract::Call { .. }) {
            return Err(Error::Invalid("a fee limit on a transaction that calls no contract"));
        }
        Ok(Transaction {
            ref_block_bytes,
            ref_block_hash,
            expiration,
            timestamp,
            memo,
            fee_limit,
            permission,
            contract,
            size: raw.len(),
        })
    }
}

/// A `Transaction.Contract`: its type, its parameter (a `google.protobuf.Any` holding the contract
/// itself, whose type URL must name that type), and the permission that signs it.
fn read_contract(b: &[u8]) -> Result<(Contract, u32), Error> {
    let mut f = Fields::read(b)?;
    let kind = f.int32(1)?;
    let parameter = f.message(2)?.ok_or(Error::Mismatch)?;
    let permission = f.int32(5)?;
    f.end()?;
    let permission = match permission {
        0 => 0,
        1 => {
            return Err(Error::Invalid(
                "signed with the witness permission, which signs blocks: Tron would refuse it",
            ));
        }
        p if p < 0 => return Err(Error::Invalid("a permission that can't be: Tron would refuse it")),
        p => p as u32,
    };
    let mut any = Fields::read(parameter)?;
    let url = any.bytes(1)?;
    let value = any.bytes(2)?;
    any.end()?;
    let Some(&(_, name)) = KINDS.iter().find(|(k, _)| *k == kind) else {
        return Err(Error::Unsupported("contract of a kind Tron doesn't have"));
    };
    if url.strip_prefix(TYPE_URL) != Some(name.as_bytes()) {
        return Err(Error::Mismatch);
    }
    let mut f = Fields::read(value)?;
    let contract = match kind {
        1 => transfer(&mut f)?,
        2 => transfer_token(&mut f)?,
        4 => vote(&mut f)?,
        13 => Contract::ClaimRewards { owner: address(f.bytes(1)?)? },
        31 => call(&mut f)?,
        46 => update_permissions(&mut f)?,
        54 | 55 => stake(&mut f, kind == 54)?,
        56 => Contract::WithdrawUnstaked { owner: address(f.bytes(1)?)? },
        57 => delegate(&mut f)?,
        58 => reclaim(&mut f)?,
        59 => Contract::CancelUnstaking { owner: address(f.bytes(1)?)? },
        _ => return Err(Error::Unsupported(name)),
    };
    f.end()?;
    Ok((contract, permission))
}

fn transfer(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let to = address(f.bytes(2)?)?;
    let amount = positive(f.int64(3)?, "nothing sent: Tron would refuse it")?;
    if to == owner {
        return Err(Error::Invalid("TRX sent to the account it's from: Tron would refuse it"));
    }
    Ok(Contract::Transfer { owner, to, amount })
}

fn transfer_token(f: &mut Fields) -> Result<Contract, Error> {
    let token = token_number(f.bytes(1)?)?;
    let owner = address(f.bytes(2)?)?;
    let to = address(f.bytes(3)?)?;
    let amount = positive(f.int64(4)?, "nothing sent: Tron would refuse it")?;
    if to == owner {
        return Err(Error::Invalid("a token sent to the account it's from: Tron would refuse it"));
    }
    Ok(Contract::TransferToken { owner, to, token, amount })
}

fn call(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let contract = address(f.bytes(2)?)?;
    let call_value = not_negative(f.int64(3)?, "TRX below nothing sent with a call: Tron would refuse it")?;
    let data = f.bytes(4)?.to_vec();
    let token_value =
        not_negative(f.int64(5)?, "tokens below nothing sent with a call: Tron would refuse it")?;
    let token = not_negative(f.int64(6)?, "a TRC-10 token that can't be: Tron would refuse it")?;
    if contract == owner {
        return Err(Error::Invalid(
            "a call to the account itself, which isn't a contract: Tron would refuse it",
        ));
    }
    if token != 0 && token <= MIN_TOKEN_ID {
        return Err(Error::Invalid("a TRC-10 token that can't be: Tron would refuse it"));
    }
    if token_value != 0 && token == 0 {
        return Err(Error::Invalid(
            "a TRC-10 token sent with a call without saying which: Tron would refuse it",
        ));
    }
    // Tron lets it be, but it means nothing: a token named, and none of it sent
    if token != 0 && token_value == 0 {
        return Err(Error::Invalid("a TRC-10 token named, and none of it sent"));
    }
    Ok(Contract::Call { owner, contract, data, call_value, token, token_value })
}

/// Staking (`FreezeBalanceV2Contract`, 1 TRX at least) or unstaking (`UnfreezeBalanceV2Contract`):
/// the same fields.
fn stake(f: &mut Fields, staking: bool) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let amount = f.int64(2)?;
    let resource = resource(f.int32(3)?)?;
    if staking {
        if amount < SUN_PER_TRX as i64 {
            return Err(Error::Invalid("less than 1 TRX staked: Tron would refuse it"));
        }
        Ok(Contract::Stake { owner, amount: amount as u64, resource })
    } else {
        let amount = positive(amount, "nothing unstaked: Tron would refuse it")?;
        Ok(Contract::Unstake { owner, amount, resource })
    }
}

fn delegate(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let resource = resource(f.int32(2)?)?;
    let amount = f.int64(3)?;
    let receiver = address(f.bytes(4)?)?;
    let lock = f.bool(5)?;
    let period = not_negative(f.int64(6)?, "a lock shorter than nothing: Tron would refuse it")?;
    if amount < SUN_PER_TRX as i64 {
        return Err(Error::Invalid("less than 1 TRX's worth delegated: Tron would refuse it"));
    }
    if receiver == owner {
        return Err(Error::Invalid("delegated to the account itself: Tron would refuse it"));
    }
    // Tron lets it be, but without a lock its period means nothing
    if !lock && period != 0 {
        return Err(Error::Invalid("a lock's period, without the lock"));
    }
    let lock = lock.then_some(if period == 0 { DEFAULT_LOCK_BLOCKS } else { period });
    Ok(Contract::Delegate { owner, receiver, amount: amount as u64, resource, lock })
}

fn reclaim(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let resource = resource(f.int32(2)?)?;
    let amount = positive(f.int64(3)?, "nothing reclaimed: Tron would refuse it")?;
    let receiver = address(f.bytes(4)?)?;
    if receiver == owner {
        return Err(Error::Invalid("reclaimed from the account itself: Tron would refuse it"));
    }
    Ok(Contract::Reclaim { owner, receiver, amount, resource })
}

fn vote(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let entries = f.messages(2)?;
    if entries.is_empty() || entries.len() > MAX_VOTES {
        return Err(Error::Invalid("no votes, or more than 30 witnesses: Tron would refuse it"));
    }
    let mut votes: Vec<(Address, u64)> = Vec::with_capacity(entries.len());
    for e in entries {
        let mut v = Fields::read(e)?;
        let witness = address(v.bytes(1)?)?;
        let count = positive(v.int64(2)?, "a vote of nothing: Tron would refuse it")?;
        v.end()?;
        // Tron adds them up, but who'd read two for one witness as that?
        if votes.iter().any(|(w, _)| *w == witness) {
            return Err(Error::Invalid("the same witness voted for twice"));
        }
        votes.push((witness, count));
    }
    Ok(Contract::Vote { owner, votes })
}

/// A change of the account's permissions, read only as far as whose account it is: its new
/// owner's, witness's and active permissions maki doesn't show, because it doesn't sign them.
fn update_permissions(f: &mut Fields) -> Result<Contract, Error> {
    let owner = address(f.bytes(1)?)?;
    let _ = f.message(2)?;
    let _ = f.message(3)?;
    let _ = f.messages(4)?;
    Ok(Contract::UpdatePermissions { owner })
}
