//! A sign doc: what SIGN_MODE_LEGACY_AMINO_JSON signs, as a chain's own software writes it from a
//! transaction to check its signature (the SDK's x/tx, `aminojson`), and as CosmJS's `makeSignDoc`
//! and `serializeSignDoc` write it for a wallet to sign. The chain it's for, the account's number and
//! sequence, the fee, the memo and the messages, and a block height it's good until if it says one:
//!
//! ```text
//! {"account_number":"..","chain_id":"..","fee":{"amount":[..],"gas":".."},"memo":"..","msgs":[..],"sequence":".."}
//! ```
//!
//! Read strictly (`json`, then each field in its place, nothing the chain wouldn't write, nothing
//! maki doesn't know but a message's contents), and held to what the chain would accept, so
//! anything it would refuse maki refuses before it's shown. Each message maki reads is read whole,
//! its addresses this chain's; a message of a kind maki doesn't read is kept as it's written, to
//! show as that; a grant that would let another account act for this one is refused here, by name.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::bech32;
use crate::chains::{self, Chain};
use crate::json::{self, Value};

/// The longest sign doc maki reads: a message from the computer is 4096 bytes at most, its head
/// included.
pub const MAX_DOC: usize = 4096;
/// The most gas a transaction may ask for (the SDK's `MaxGasWanted`).
pub const MAX_GAS: u64 = (1 << 63) - 1;
/// The longest receiver an IBC transfer may name (ibc-go's `MaximumReceiverLength`).
pub const MAX_RECEIVER: usize = 2048;
/// How many of a weight's smallest units are one whole: a vote's weights are decimals of 18 places.
pub const WHOLE: u64 = 1_000_000_000_000_000_000;

/// Why maki won't read a sign doc: each says why, for the computer that sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Longer than maki reads.
    TooBig,
    /// Not JSON as Cosmos writes it: where, and why.
    Json(json::Error),
    /// A field maki doesn't know (its name): it won't sign what it can't show.
    Unknown(String),
    /// A field that should be there and isn't (its name).
    Missing(&'static str),
    /// A field of another kind than it should be, or not written as the chain writes it (its name).
    Field(&'static str),
    /// A chain maki doesn't know (its ID): it can't say what its coin is.
    Chain(String),
    /// An address that isn't one of this chain's (which field).
    Address(&'static str),
    /// A kind of message maki won't sign: why.
    Refused(&'static str),
    /// Something the chain would refuse, or maki can't show: why.
    Invalid(&'static str),
}

impl From<json::Error> for Error {
    fn from(e: json::Error) -> Error { Error::Json(e) }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TooBig => f.write_str("bigger than maki takes a sign doc"),
            Error::Json(e) => write!(f, "not a sign doc as Cosmos writes one: {e}"),
            Error::Unknown(name) => {
                write!(f, "a field maki doesn't know ({name}): it won't sign what it can't show")
            }
            Error::Missing(name) => write!(f, "not a sign doc as Cosmos writes one: no {name}"),
            Error::Field(name) => write!(f, "not a sign doc as Cosmos writes one: its {name}"),
            Error::Chain(id) => write!(f, "a chain maki doesn't know ({id}): it won't sign for it"),
            Error::Address(name) => write!(f, "an address that isn't this chain's: its {name}"),
            Error::Refused(why) | Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// A coin, as a message carries it: its denom, and an amount of its smallest units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub denom: String,
    pub amount: u128,
}

/// A vote's option, as governance counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    Yes,
    Abstain,
    No,
    NoWithVeto,
}

impl Vote {
    /// As the owner reads it.
    pub fn name(self) -> &'static str {
        match self {
            Vote::Yes => "Yes",
            Vote::Abstain => "Abstain",
            Vote::No => "No",
            Vote::NoWithVeto => "No with veto",
        }
    }
}

/// A message maki reads: what it does. Every address in one is this chain's (an account's, or a
/// validator's) but an IBC transfer's receiver, which is another chain's; every amount is in a
/// coin's smallest units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// Coins sent (`cosmos-sdk/MsgSend`).
    Send { from: String, to: String, amount: Vec<Coin> },
    /// Coins sent to several accounts at once (`cosmos-sdk/MsgMultiSend`), from one, as the chain
    /// has it: what each gets.
    MultiSend { from: String, outputs: Vec<(String, Vec<Coin>)> },
    /// Coins staked with a validator (`cosmos-sdk/MsgDelegate`).
    Delegate { delegator: String, validator: String, amount: Coin },
    /// Staked coins unstaked (`cosmos-sdk/MsgUndelegate`).
    Undelegate { delegator: String, validator: String, amount: Coin },
    /// Staked coins moved from one validator to another (`cosmos-sdk/MsgBeginRedelegate`).
    Redelegate { delegator: String, from: String, to: String, amount: Coin },
    /// Coins being unstaked, staked again (`cosmos-sdk/MsgCancelUnbondingDelegation`): of what
    /// began unstaking at block `height`.
    CancelUnstake { delegator: String, validator: String, amount: Coin, height: u64 },
    /// The rewards of staking with a validator, claimed (`cosmos-sdk/MsgWithdrawDelegationReward`).
    ClaimRewards { delegator: String, validator: String },
    /// Where the account's staking rewards go from now on (`cosmos-sdk/MsgModifyWithdrawAddress`).
    RewardsTo { delegator: String, to: String },
    /// Coins given to the community pool (`cosmos-sdk/MsgFundCommunityPool`).
    Donate { depositor: String, amount: Vec<Coin> },
    /// A vote on a proposal (`cosmos-sdk/MsgVote`; and governance v1's, `cosmos-sdk/v1/MsgVote`,
    /// which can carry a note).
    Vote { voter: String, proposal: u64, vote: Vote, note: String },
    /// A vote split between options (`cosmos-sdk/MsgVoteWeighted`): each with its weight, in
    /// `WHOLE`ths.
    SplitVote { voter: String, proposal: u64, options: Vec<(Vote, u64)> },
    /// Coins deposited on a proposal (`cosmos-sdk/MsgDeposit`, `cosmos-sdk/v1/MsgDeposit`).
    Deposit { depositor: String, proposal: u64, amount: Vec<Coin> },
    /// Coins sent to another chain over IBC (`cosmos-sdk/MsgTransfer`), by a channel of this
    /// chain's: they come back if they haven't arrived by the other chain's block `timeout_height`
    /// (its revision and height; zeros for none) or by `timeout` (nanoseconds since 1970; zero for
    /// none). A memo for the chain at the other end, which may act on it.
    Transfer {
        sender: String,
        receiver: String,
        channel: String,
        token: Coin,
        timeout_height: (u64, u64),
        timeout: u64,
        memo: String,
    },
    /// A permission this account gave another, to send a kind of message for it, taken back
    /// (`cosmos-sdk/MsgRevoke`).
    Revoke { granter: String, grantee: String, kind: String },
    /// An allowance this account gave another, to pay its fees from this one, taken back
    /// (`cosmos-sdk/MsgRevokeAllowance`).
    RevokeAllowance { granter: String, grantee: String },
    /// A message of a kind maki doesn't read: its type, and its value as it's written.
    Other { kind: String, value: String },
}

impl Msg {
    /// The account whose message it is, which signs it: None for one maki doesn't read.
    pub fn signer(&self) -> Option<&str> {
        match self {
            Msg::Send { from, .. } | Msg::MultiSend { from, .. } => Some(from),
            Msg::Delegate { delegator, .. }
            | Msg::Undelegate { delegator, .. }
            | Msg::Redelegate { delegator, .. }
            | Msg::CancelUnstake { delegator, .. }
            | Msg::ClaimRewards { delegator, .. }
            | Msg::RewardsTo { delegator, .. } => Some(delegator),
            Msg::Donate { depositor, .. } | Msg::Deposit { depositor, .. } => Some(depositor),
            Msg::Vote { voter, .. } | Msg::SplitVote { voter, .. } => Some(voter),
            Msg::Transfer { sender, .. } => Some(sender),
            Msg::Revoke { granter, .. } | Msg::RevokeAllowance { granter, .. } => Some(granter),
            Msg::Other { .. } => None,
        }
    }
}

/// The fee: what it pays, the most gas it may use, and who pays if not the signer (`payer`, who
/// signs it too) or from whose allowance (`granter`, who gave this account one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: u64,
    pub payer: Option<String>,
    pub granter: Option<String>,
}

/// A sign doc, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignDoc {
    /// The chain it's for: its ID is in what's signed.
    pub chain: &'static Chain,
    /// The signing account's number and sequence on that chain: a signature for another number,
    /// or a sequence it's past, the chain won't take.
    pub account_number: u64,
    pub sequence: u64,
    pub fee: Fee,
    /// For anyone to read, on chain; empty for none.
    pub memo: String,
    pub msgs: Vec<Msg>,
    /// The last block it can be in; 0 for no limit.
    pub timeout_height: u64,
}

/// A field name as an error says it: the first 32 bytes, at a character.
fn named(name: &str) -> String {
    let mut end = name.len().min(32);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

/// An object's fields, read in the order of their names (the order the chain writes them in): each
/// in its place, and none left over that the reader doesn't know.
struct Fields<'a> {
    fields: &'a [(String, Value)],
    next: usize,
}

impl<'a> Fields<'a> {
    fn of(value: &'a Value, what: &'static str) -> Result<Fields<'a>, Error> {
        match value {
            Value::Object(fields) => Ok(Fields { fields, next: 0 }),
            _ => Err(Error::Field(what)),
        }
    }

    /// The field `name`, if it's there. One before it that wasn't asked for is a field the reader
    /// doesn't know.
    fn maybe(&mut self, name: &str) -> Result<Option<&'a Value>, Error> {
        match self.fields.get(self.next) {
            Some((n, _)) if n.as_str() < name => Err(Error::Unknown(named(n))),
            Some((n, v)) if n == name => {
                self.next += 1;
                Ok(Some(v))
            }
            _ => Ok(None),
        }
    }

    fn take(&mut self, name: &'static str) -> Result<&'a Value, Error> {
        self.maybe(name)?.ok_or(Error::Missing(name))
    }

    /// A string the chain leaves out when it's empty: there, it isn't.
    fn text(&mut self, name: &'static str) -> Result<Option<&'a str>, Error> {
        match self.maybe(name)? {
            None => Ok(None),
            Some(v) => match text(v, name)? {
                "" => Err(Error::Field(name)),
                t => Ok(Some(t)),
            },
        }
    }

    /// The end: every field read.
    fn end(self) -> Result<(), Error> {
        match self.fields.get(self.next) {
            Some((n, _)) => Err(Error::Unknown(named(n))),
            None => Ok(()),
        }
    }
}

fn text<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, Error> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(Error::Field(name)),
    }
}

fn array<'a>(value: &'a Value, name: &'static str) -> Result<&'a [Value], Error> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(Error::Field(name)),
    }
}

/// Digits, as Go writes a whole number: no sign, no leading zero.
fn digits<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, Error> {
    let t = text(value, name)?;
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) || (t.len() > 1 && t.starts_with('0')) {
        return Err(Error::Field(name));
    }
    Ok(t)
}

/// A uint64, which amino writes as a string of its digits.
fn uint(value: &Value, name: &'static str) -> Result<u64, Error> {
    digits(value, name)?.parse().map_err(|_| Error::Field(name))
}

/// A uint64 the chain leaves out when it's zero: there, it isn't.
fn positive(fields: &mut Fields, name: &'static str) -> Result<u64, Error> {
    match fields.maybe(name)? {
        None => Ok(0),
        Some(v) => match uint(v, name)? {
            0 => Err(Error::Field(name)),
            n => Ok(n),
        },
    }
}

/// What a denom may be (the SDK's `ValidateDenom`): a letter, then 2 to 127 letters, digits and
/// `/ : . _ -`.
fn denom_ok(denom: &str) -> bool {
    let b = denom.as_bytes();
    (3..=128).contains(&b.len())
        && b[0].is_ascii_alphabetic()
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b':' | b'.' | b'_' | b'-'))
}

/// A coin, of a denom the chain takes, and an amount of it, nothing or more. maki reads amounts up
/// to 2^128 - 1 (the chain's go to 2^256 - 1): more than any coin there is.
fn coin_of(value: &Value, name: &'static str) -> Result<Coin, Error> {
    let mut f = Fields::of(value, name)?;
    let amount = digits(f.take("amount")?, name)?;
    let denom = text(f.take("denom")?, name)?;
    f.end()?;
    if !denom_ok(denom) {
        return Err(Error::Invalid("a coin's denom the chain wouldn't take"));
    }
    let amount = amount.parse().map_err(|_| Error::Invalid("an amount bigger than maki reads"))?;
    Ok(Coin { denom: denom.into(), amount })
}

/// A coin, of something: what a message moves.
fn coin(value: &Value, name: &'static str) -> Result<Coin, Error> {
    let c = coin_of(value, name)?;
    if c.amount == 0 {
        return Err(Error::Invalid("an amount of nothing: the chain would refuse it"));
    }
    Ok(c)
}

/// Coins, as the chain takes them in a list: sorted by denom, no denom twice, each read by `read`.
fn listed(
    value: &Value,
    name: &'static str,
    read: fn(&Value, &'static str) -> Result<Coin, Error>,
) -> Result<Vec<Coin>, Error> {
    let mut out: Vec<Coin> = Vec::new();
    for item in array(value, name)? {
        let c = read(item, name)?;
        if out.last().is_some_and(|last| last.denom.as_bytes() >= c.denom.as_bytes()) {
            return Err(Error::Invalid("coins out of order, or one twice: the chain would refuse them"));
        }
        out.push(c);
    }
    Ok(out)
}

/// Coins, each of something.
fn coins(value: &Value, name: &'static str) -> Result<Vec<Coin>, Error> { listed(value, name, coin) }

/// Coins, at least one.
fn some_coins(value: &Value, name: &'static str) -> Result<Vec<Coin>, Error> {
    let c = coins(value, name)?;
    if c.is_empty() {
        return Err(Error::Invalid("no coins: the chain would refuse it"));
    }
    Ok(c)
}

/// An address of `prefix`'s, as bech32 writes it: 20 bytes, as a key's address is, or 32, as a
/// contract's or a module's can be.
fn bech32_of<'a>(value: &'a Value, prefix: &str, name: &'static str) -> Result<&'a str, Error> {
    let t = text(value, name)?;
    match bech32::decode(t) {
        Some((p, bytes)) if p == prefix && (bytes.len() == 20 || bytes.len() == 32) => Ok(t),
        _ => Err(Error::Address(name)),
    }
}

/// An account's address on this chain.
fn account(chain: &Chain, value: &Value, name: &'static str) -> Result<String, Error> {
    bech32_of(value, chain.prefix, name).map(String::from)
}

/// A validator's address on this chain (its operator's: `cosmosvaloper1…`).
fn validator(chain: &Chain, value: &Value, name: &'static str) -> Result<String, Error> {
    bech32_of(value, &chain.valoper(), name).map(String::from)
}

/// A stake: coins of the denom this chain stakes, as it takes them.
fn stake(chain: &Chain, value: &Value) -> Result<Coin, Error> {
    let c = coin(value, "amount")?;
    if c.denom != chain.bond {
        return Err(Error::Invalid("a coin other than the one this chain stakes: the chain would refuse it"));
    }
    Ok(c)
}

fn vote(value: &Value) -> Result<Vote, Error> {
    match value {
        Value::Number(1) => Ok(Vote::Yes),
        Value::Number(2) => Ok(Vote::Abstain),
        Value::Number(3) => Ok(Vote::No),
        Value::Number(4) => Ok(Vote::NoWithVeto),
        Value::Number(_) => {
            Err(Error::Invalid("a vote that isn't yes, no, abstain or veto: the chain would refuse it"))
        }
        _ => Err(Error::Field("option")),
    }
}

/// A proposal's number: one that can be (they start at 1).
fn proposal(value: &Value) -> Result<u64, Error> {
    match uint(value, "proposal_id")? {
        0 => Err(Error::Invalid("proposal 0, which there isn't: the chain would refuse it")),
        n => Ok(n),
    }
}

/// A vote's weight, as a decimal of 18 places is written (`0.500000000000000000`), in `WHOLE`ths:
/// above nothing, and a whole at most.
fn weight(value: &Value) -> Result<u64, Error> {
    let t = text(value, "weight")?;
    let ok = t.len() == 20
        && (t.starts_with("0.") || t.starts_with("1."))
        && t.bytes().enumerate().all(|(i, b)| i == 1 || b.is_ascii_digit());
    if !ok {
        return Err(Error::Field("weight"));
    }
    let whole = (t.as_bytes()[0] - b'0') as u64;
    let fraction: u64 = t[2..].parse().map_err(|_| Error::Field("weight"))?;
    let w = whole * WHOLE + fraction;
    if w == 0 || w > WHOLE {
        return Err(Error::Invalid("a vote's weight that isn't above nothing and a whole at most"));
    }
    Ok(w)
}

/// A channel's identifier as IBC takes it (ibc-go's `ChannelIdentifierValidator`: `channel-141`): 8
/// to 64 letters, digits and `. _ + - # [ ] < >`.
fn identifier_ok(id: &str) -> bool {
    (8..=64).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._+-#[]<>".contains(&c))
}

impl SignDoc {
    /// A sign doc, read whole: as Cosmos writes it, for a chain maki knows, every message read or
    /// kept to show, nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<SignDoc, Error> {
        if bytes.len() > MAX_DOC {
            return Err(Error::TooBig);
        }
        let root = json::parse(bytes)?;
        let mut f = Fields::of(&root, "sign doc")?;
        let account_number = uint(f.take("account_number")?, "account_number")?;
        let id = text(f.take("chain_id")?, "chain_id")?;
        let chain = chains::by_id(id).ok_or_else(|| Error::Chain(named(id)))?;
        let fee = read_fee(chain, f.take("fee")?)?;
        let memo = text(f.take("memo")?, "memo")?.into();
        let msgs = array(f.take("msgs")?, "msgs")?;
        let sequence = uint(f.take("sequence")?, "sequence")?;
        let timeout_height = positive(&mut f, "timeout_height")?;
        // anything else (a tip, an unordered transaction's timestamp) maki doesn't read
        f.end()?;
        if msgs.is_empty() {
            return Err(Error::Invalid("a transaction of no messages: the chain would refuse it"));
        }
        let msgs = msgs.iter().map(|m| read_msg(chain, m)).collect::<Result<Vec<_>, _>>()?;
        Ok(SignDoc { chain, account_number, sequence, fee, memo, msgs, timeout_height })
    }
}

fn read_fee(chain: &Chain, value: &Value) -> Result<Fee, Error> {
    let mut f = Fields::of(value, "fee")?;
    // a fee of nothing the chain takes, and doesn't charge (as CosmJS writes one at a gas price of
    // nothing); one of nothing beside one of something, it refuses
    let amount = listed(f.take("amount")?, "fee", coin_of)?;
    if amount.iter().any(|c| c.amount == 0) && amount.iter().any(|c| c.amount > 0) {
        return Err(Error::Invalid("a fee of nothing beside a fee of something: the chain would refuse it"));
    }
    let gas = uint(f.take("gas")?, "gas")?;
    let granter = f.maybe("granter")?.map(|v| account(chain, v, "fee's granter")).transpose()?;
    let payer = f.maybe("payer")?.map(|v| account(chain, v, "fee's payer")).transpose()?;
    f.end()?;
    if gas > MAX_GAS {
        return Err(Error::Invalid("more gas than a transaction can have: the chain would refuse it"));
    }
    Ok(Fee { amount, gas, payer, granter })
}

fn read_msg(chain: &Chain, value: &Value) -> Result<Msg, Error> {
    let mut f = Fields::of(value, "message")?;
    let kind = text(f.take("type")?, "message's type")?;
    let value = f.take("value")?;
    f.end()?;
    // each kind reads its value's fields itself
    let v = || Fields::of(value, "message's value");
    let msg = match kind {
        "cosmos-sdk/MsgSend" => {
            let mut v = v()?;
            let amount = some_coins(v.take("amount")?, "amount")?;
            let from = account(chain, v.take("from_address")?, "from_address")?;
            let to = account(chain, v.take("to_address")?, "to_address")?;
            v.end()?;
            Msg::Send { from, to, amount }
        }
        "cosmos-sdk/MsgMultiSend" => multi_send(chain, v()?)?,
        "cosmos-sdk/MsgDelegate" | "cosmos-sdk/MsgUndelegate" => {
            let mut v = v()?;
            let amount = stake(chain, v.take("amount")?)?;
            let delegator = account(chain, v.take("delegator_address")?, "delegator_address")?;
            let validator = validator(chain, v.take("validator_address")?, "validator_address")?;
            v.end()?;
            if kind == "cosmos-sdk/MsgDelegate" {
                Msg::Delegate { delegator, validator, amount }
            } else {
                Msg::Undelegate { delegator, validator, amount }
            }
        }
        "cosmos-sdk/MsgBeginRedelegate" => {
            let mut v = v()?;
            let amount = stake(chain, v.take("amount")?)?;
            let delegator = account(chain, v.take("delegator_address")?, "delegator_address")?;
            let to = validator(chain, v.take("validator_dst_address")?, "validator_dst_address")?;
            let from = validator(chain, v.take("validator_src_address")?, "validator_src_address")?;
            v.end()?;
            if from == to {
                return Err(Error::Invalid(
                    "restaked with the validator it's staked with: the chain would refuse it",
                ));
            }
            Msg::Redelegate { delegator, from, to, amount }
        }
        "cosmos-sdk/MsgCancelUnbondingDelegation" => {
            let mut v = v()?;
            let amount = stake(chain, v.take("amount")?)?;
            let height = positive(&mut v, "creation_height")?;
            let delegator = account(chain, v.take("delegator_address")?, "delegator_address")?;
            let validator = validator(chain, v.take("validator_address")?, "validator_address")?;
            v.end()?;
            // an int64, and one the unstaking began at
            if height == 0 || height > i64::MAX as u64 {
                return Err(Error::Invalid("unstaking that began at no block: the chain would refuse it"));
            }
            Msg::CancelUnstake { delegator, validator, amount, height }
        }
        "cosmos-sdk/MsgWithdrawDelegationReward" => {
            let mut v = v()?;
            let delegator = account(chain, v.take("delegator_address")?, "delegator_address")?;
            let validator = validator(chain, v.take("validator_address")?, "validator_address")?;
            v.end()?;
            Msg::ClaimRewards { delegator, validator }
        }
        "cosmos-sdk/MsgModifyWithdrawAddress" => {
            let mut v = v()?;
            let delegator = account(chain, v.take("delegator_address")?, "delegator_address")?;
            let to = account(chain, v.take("withdraw_address")?, "withdraw_address")?;
            v.end()?;
            Msg::RewardsTo { delegator, to }
        }
        "cosmos-sdk/MsgFundCommunityPool" => {
            let mut v = v()?;
            let amount = some_coins(v.take("amount")?, "amount")?;
            let depositor = account(chain, v.take("depositor")?, "depositor")?;
            v.end()?;
            Msg::Donate { depositor, amount }
        }
        "cosmos-sdk/MsgVote" | "cosmos-sdk/v1/MsgVote" => {
            let mut v = v()?;
            let note = if kind == "cosmos-sdk/v1/MsgVote" { v.text("metadata")?.unwrap_or("") } else { "" };
            let vote = vote(v.take("option")?)?;
            let proposal = proposal(v.take("proposal_id")?)?;
            let voter = account(chain, v.take("voter")?, "voter")?;
            v.end()?;
            Msg::Vote { voter, proposal, vote, note: note.into() }
        }
        "cosmos-sdk/MsgVoteWeighted" => split_vote(chain, v()?)?,
        "cosmos-sdk/MsgDeposit" | "cosmos-sdk/v1/MsgDeposit" => {
            let mut v = v()?;
            let amount = some_coins(v.take("amount")?, "amount")?;
            let depositor = account(chain, v.take("depositor")?, "depositor")?;
            let proposal = proposal(v.take("proposal_id")?)?;
            v.end()?;
            Msg::Deposit { depositor, proposal, amount }
        }
        "cosmos-sdk/MsgTransfer" => transfer(chain, v()?)?,
        "cosmos-sdk/MsgRevoke" => {
            let mut v = v()?;
            let grantee = account(chain, v.take("grantee")?, "grantee")?;
            let granter = account(chain, v.take("granter")?, "granter")?;
            let kind = v.text("msg_type_url")?.ok_or(Error::Missing("msg_type_url"))?;
            v.end()?;
            let ok = kind.len() <= 128
                && kind.starts_with('/')
                && kind[1..].bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_');
            if !ok {
                return Err(Error::Invalid("a permission that isn't a kind of message"));
            }
            Msg::Revoke { granter, grantee, kind: kind.into() }
        }
        "cosmos-sdk/MsgRevokeAllowance" => {
            let mut v = v()?;
            let grantee = account(chain, v.take("grantee")?, "grantee")?;
            let granter = account(chain, v.take("granter")?, "granter")?;
            v.end()?;
            Msg::RevokeAllowance { granter, grantee }
        }
        "cosmos-sdk/MsgGrant" => {
            return Err(Error::Refused(
                "an authz grant, which lets another account act for this one until it's revoked: maki won't sign that",
            ));
        }
        "cosmos-sdk/MsgGrantAllowance" => {
            return Err(Error::Refused(
                "a fee grant, which lets another account spend this one's coins on its fees: maki won't sign that",
            ));
        }
        _ => {
            let shown = kind.len() <= 128 && kind.bytes().all(|c| c.is_ascii_graphic());
            if !shown {
                return Err(Error::Invalid("a message whose type maki can't show"));
            }
            Msg::Other { kind: kind.into(), value: json::write(value) }
        }
    };
    Ok(msg)
}

/// A multi-send: from one account, as the chain takes it, to as many as it says, every coin it
/// sends one of its outputs'.
fn multi_send(chain: &Chain, mut v: Fields) -> Result<Msg, Error> {
    let inputs = array(v.take("inputs")?, "inputs")?;
    let outputs = array(v.take("outputs")?, "outputs")?;
    v.end()?;
    let [input] = inputs else {
        return Err(Error::Invalid("a multi-send from other than one account: the chain would refuse it"));
    };
    let mut i = Fields::of(input, "input")?;
    let from = account(chain, i.take("address")?, "input's address")?;
    let sent = some_coins(i.take("coins")?, "input's coins")?;
    i.end()?;
    if outputs.is_empty() {
        return Err(Error::Invalid("a multi-send to no one: the chain would refuse it"));
    }
    let mut paid: Vec<Coin> = Vec::new();
    let mut out = Vec::with_capacity(outputs.len());
    for o in outputs {
        let mut o = Fields::of(o, "output")?;
        let to = account(chain, o.take("address")?, "output's address")?;
        let coins = some_coins(o.take("coins")?, "output's coins")?;
        o.end()?;
        for c in &coins {
            match paid.iter_mut().find(|p| p.denom == c.denom) {
                Some(p) => {
                    p.amount = p
                        .amount
                        .checked_add(c.amount)
                        .ok_or(Error::Invalid("an amount bigger than maki reads"))?
                }
                None => paid.push(c.clone()),
            }
        }
        out.push((to, coins));
    }
    paid.sort_by(|a, b| a.denom.as_bytes().cmp(b.denom.as_bytes()));
    if paid != sent {
        return Err(Error::Invalid(
            "a multi-send whose outputs aren't what it sends: the chain would refuse it",
        ));
    }
    Ok(Msg::MultiSend { from, outputs: out })
}

/// A vote split between options: each once, each weighed above nothing, the weights a whole.
fn split_vote(chain: &Chain, mut v: Fields) -> Result<Msg, Error> {
    let items = array(v.take("options")?, "options")?;
    let proposal = proposal(v.take("proposal_id")?)?;
    let voter = account(chain, v.take("voter")?, "voter")?;
    v.end()?;
    let mut options: Vec<(Vote, u64)> = Vec::with_capacity(items.len());
    for item in items {
        let mut o = Fields::of(item, "options")?;
        let vote = vote(o.take("option")?)?;
        let weight = weight(o.take("weight")?)?;
        o.end()?;
        if options.iter().any(|(v, _)| *v == vote) {
            return Err(Error::Invalid("a vote's option given twice: the chain would refuse it"));
        }
        options.push((vote, weight));
    }
    // at most four options of a whole at most each: no overflow
    if options.iter().map(|(_, w)| w).sum::<u64>() != WHOLE {
        return Err(Error::Invalid("a split vote whose weights aren't a whole: the chain would refuse it"));
    }
    Ok(Msg::SplitVote { voter, proposal, options })
}

/// An IBC transfer: by the transfer port, through a channel, to a receiver on the chain at the
/// other end, timing out by a block there or a time, or both.
fn transfer(chain: &Chain, mut v: Fields) -> Result<Msg, Error> {
    let memo = v.text("memo")?.unwrap_or("");
    let receiver = v.text("receiver")?.ok_or(Error::Missing("receiver"))?;
    let sender = account(chain, v.take("sender")?, "sender")?;
    let channel = v.text("source_channel")?.ok_or(Error::Missing("source_channel"))?;
    let port = v.text("source_port")?.ok_or(Error::Missing("source_port"))?;
    let mut height = Fields::of(v.take("timeout_height")?, "timeout_height")?;
    let revision_height = positive(&mut height, "revision_height")?;
    let revision_number = positive(&mut height, "revision_number")?;
    height.end()?;
    let timeout = positive(&mut v, "timeout_timestamp")?;
    let token = coin(v.take("token")?, "token")?;
    v.end()?;
    if port != "transfer" {
        return Err(Error::Invalid("an IBC transfer from a port other than transfer's"));
    }
    if !identifier_ok(channel) {
        return Err(Error::Invalid("an IBC channel that can't be: the chain would refuse it"));
    }
    if receiver.len() > MAX_RECEIVER || receiver.chars().any(|c| c.is_whitespace()) {
        return Err(Error::Invalid("an IBC receiver maki can't show: too long, or with spaces in it"));
    }
    if revision_height == 0 && revision_number != 0 {
        return Err(Error::Invalid("an IBC transfer that times out at block 0"));
    }
    if revision_height == 0 && timeout == 0 {
        return Err(Error::Invalid("an IBC transfer that never times out: the chain would refuse it"));
    }
    Ok(Msg::Transfer {
        sender,
        receiver: receiver.into(),
        channel: channel.into(),
        token,
        timeout_height: (revision_number, revision_height),
        timeout,
        memo: memo.into(),
    })
}
