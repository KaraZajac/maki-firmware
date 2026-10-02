//! A transaction's body: what its witnesses sign (the BLAKE2b-256 of its bytes is the
//! transaction's ID), read as Conway's CDDL has it (`conway.cddl`), written as Cardano's hardware
//! wallets take it (CIP-21: canonical CBOR, every set tagged 258 or none), and held to what the
//! ledger accepts, so anything Cardano would refuse maki refuses before it's shown.
//!
//! maki reads all of it: the coins it spends (by their transaction and place: what they hold isn't
//! in it), its outputs (in Alonzo's list form or Babbage's map, ADA and tokens, and what's for
//! scripts: a datum, a script to refer to), its fee, when it's valid, certificates for staking and
//! vote delegation, withdrawals of rewards, its metadata's hash, tokens minted and burnt, its
//! network, the treasury's amount it's valid for, and a donation to it. What's for running Plutus
//! scripts (collateral, required signers, reference inputs, a script data hash), for pools and
//! DReps, and governance's votes and proposals, it refuses, by name.

use alloc::vec::Vec;

use crate::address::{Address, Credential, Kind, RewardAccount};
use crate::cbor::{ARRAY, EMBEDDED, Keys, MAP, Reader, UINT};
use crate::{Error, Hash28, MAX_LOVELACE};

/// The biggest body maki reads: a whole transaction is 16 KiB at most (the protocol's
/// `maxTxSize`, 16,384 bytes since Alonzo), its witnesses too.
pub const MAX_BODY: usize = 16_384;
/// The longest asset name: 32 bytes.
pub const MAX_ASSET_NAME: usize = 32;

/// A coin the transaction spends: the transaction that made it, and which of its outputs it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input {
    pub tx: [u8; 32],
    pub index: u16,
}

/// A token and how many of it: in its smallest units (an output's, above zero), or minted (above
/// zero) or burnt (below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<N> {
    /// Its name under its policy: up to 32 bytes, any of them.
    pub name: Vec<u8>,
    pub amount: N,
}

/// A policy's tokens: what its script (whose hash is its ID) lets be minted, and how many of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy<N> {
    pub id: Hash28,
    pub tokens: Vec<Token<N>>,
}

/// Data a script reads, attached to an output: by its hash, or whole (inline), here by its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datum {
    Hash([u8; 32]),
    Inline(usize),
}

/// An output: what it pays, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub address: Address,
    /// ADA, in lovelace.
    pub coin: u64,
    /// Tokens, by policy, each in its smallest units.
    pub tokens: Vec<Policy<u64>>,
    /// Data for a script, if there's any.
    pub datum: Option<Datum>,
    /// A script anyone may refer to (Babbage's reference scripts), here by its size.
    pub script: Option<usize>,
}

/// A DRep, whom an account's stake votes as: one by a key or a script, or always abstaining, or
/// always no confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DRep {
    Credential(Credential),
    Abstain,
    NoConfidence,
}

/// A certificate this account may sign: one of staking's, or vote delegation, or a few at once.
/// Each names a stake credential, whose witness it needs (but registration's of Shelley's kind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certificate {
    /// The stake key registered, paying a deposit: Conway's says how much, Shelley's (`None`)
    /// pays Cardano's key deposit without saying.
    Register { stake: Credential, deposit: Option<u64> },
    /// The stake key deregistered, its deposit back: Conway's says how much, Shelley's doesn't.
    Deregister { stake: Credential, refund: Option<u64> },
    /// The stake delegated to a pool.
    Delegate { stake: Credential, pool: Hash28 },
    /// The stake's votes delegated to a DRep.
    Vote { stake: Credential, drep: DRep },
    /// Both at once (Conway's `stake_vote_deleg_cert`).
    DelegateAndVote { stake: Credential, pool: Hash28, drep: DRep },
    /// Registered and delegated (`stake_reg_deleg_cert`).
    RegisterAndDelegate { stake: Credential, pool: Hash28, deposit: u64 },
    /// Registered and its votes delegated (`vote_reg_deleg_cert`).
    RegisterAndVote { stake: Credential, drep: DRep, deposit: u64 },
    /// All three (`stake_vote_reg_deleg_cert`).
    RegisterDelegateAndVote { stake: Credential, pool: Hash28, drep: DRep, deposit: u64 },
}

impl Certificate {
    /// The stake credential it's for.
    pub fn stake(&self) -> &Credential {
        match self {
            Certificate::Register { stake, .. }
            | Certificate::Deregister { stake, .. }
            | Certificate::Delegate { stake, .. }
            | Certificate::Vote { stake, .. }
            | Certificate::DelegateAndVote { stake, .. }
            | Certificate::RegisterAndDelegate { stake, .. }
            | Certificate::RegisterAndVote { stake, .. }
            | Certificate::RegisterDelegateAndVote { stake, .. } => stake,
        }
    }
}

/// A transaction's body, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    /// The coins it spends (`0`): what they hold isn't in the body, and doesn't need to be, since
    /// Cardano takes it only if they add up exactly to what it pays out.
    pub inputs: Vec<Input>,
    /// What it pays (`1`).
    pub outputs: Vec<Output>,
    /// Its fee (`2`), in lovelace: stated, not what's left over.
    pub fee: u64,
    /// The slot it's valid until (`3`, not in it): none for no limit.
    pub ttl: Option<u64>,
    /// Its certificates (`4`), in order.
    pub certificates: Vec<Certificate>,
    /// Rewards withdrawn (`5`), from each account.
    pub withdrawals: Vec<(RewardAccount, u64)>,
    /// Its auxiliary data's hash (`7`): metadata, which isn't in the body.
    pub metadata: Option<[u8; 32]>,
    /// The slot it's valid from (`8`).
    pub valid_from: Option<u64>,
    /// Tokens minted, or burnt (`9`).
    pub mint: Vec<Policy<i64>>,
    /// The network it says it's for (`15`): 1 for Cardano's own, 0 for a test network.
    pub network: Option<u8>,
    /// The treasury's amount it's valid only with (`21`).
    pub treasury: Option<u64>,
    /// ADA given to the treasury (`22`).
    pub donation: Option<u64>,
    /// Whether its sets are tagged 258.
    pub tagged: bool,
    /// How many bytes it is.
    pub size: usize,
}

/// An amount of ADA: no more than there will ever be.
fn coin(r: &mut Reader) -> Result<u64, Error> {
    let n = r.uint()?;
    if n > MAX_LOVELACE {
        return Err(Error::Invalid("more ADA than there will ever be: Cardano would refuse it"));
    }
    Ok(n)
}

/// A credential: `[0, key hash]` or `[1, script hash]`.
fn credential(r: &mut Reader) -> Result<Credential, Error> {
    if r.array()? != 2 {
        return Err(Error::Shape);
    }
    match r.uint()? {
        0 => Ok(Credential::Key(r.hash()?)),
        1 => Ok(Credential::Script(r.hash()?)),
        _ => Err(Error::Shape),
    }
}

/// A DRep: `[0, key hash]`, `[1, script hash]`, `[2]` (always abstain), `[3]` (always no
/// confidence).
fn drep(r: &mut Reader) -> Result<DRep, Error> {
    let n = r.array()?;
    match (r.uint()?, n) {
        (0, 2) => Ok(DRep::Credential(Credential::Key(r.hash()?))),
        (1, 2) => Ok(DRep::Credential(Credential::Script(r.hash()?))),
        (2, 1) => Ok(DRep::Abstain),
        (3, 1) => Ok(DRep::NoConfidence),
        _ => Err(Error::Shape),
    }
}

/// Coins spent, by their transaction and place: `[id, index]`, the index below 65,536.
fn input(r: &mut Reader) -> Result<Input, Error> {
    if r.array()? != 2 {
        return Err(Error::Shape);
    }
    let tx = r.hash()?;
    let index = u16::try_from(r.uint()?).map_err(|_| Error::Shape)?;
    Ok(Input { tx, index })
}

/// A set of inputs, none twice.
fn inputs(r: &mut Reader, tagged: &mut Option<bool>) -> Result<Vec<Input>, Error> {
    let n = r.set(tagged)?;
    let mut out: Vec<Input> = Vec::with_capacity(n);
    for _ in 0..n {
        let i = input(r)?;
        if out.contains(&i) {
            return Err(Error::Duplicate);
        }
        out.push(i);
    }
    Ok(out)
}

/// Tokens by policy (`multiasset`), each amount read by `amount`: policies and names in canonical
/// order, none twice, a policy with no tokens refused, as Conway refuses it.
fn multiasset<N>(
    r: &mut Reader,
    amount: impl Fn(&mut Reader) -> Result<N, Error>,
) -> Result<Vec<Policy<N>>, Error> {
    let n = r.map()?;
    let mut policies = Vec::with_capacity(n);
    let mut ids = Keys::new();
    for _ in 0..n {
        let start = r.at();
        let id: Hash28 = r.hash()?;
        ids.next(r.since(start))?;
        let count = r.map()?;
        if count == 0 {
            return Err(Error::Invalid("a policy with no tokens: Cardano would refuse it"));
        }
        let mut tokens = Vec::with_capacity(count);
        let mut names = Keys::new();
        for _ in 0..count {
            let start = r.at();
            let name = r.bytes()?;
            names.next(r.since(start))?;
            if name.len() > MAX_ASSET_NAME {
                return Err(Error::Invalid("an asset name longer than 32 bytes: Cardano would refuse it"));
            }
            tokens.push(Token { name: name.to_vec(), amount: amount(r)? });
        }
        policies.push(Policy { id, tokens });
    }
    Ok(policies)
}

/// An output's value: ADA alone, or `[ADA, tokens]`, each token's amount above zero. Tokens that
/// are none at all aren't written as an empty map (CIP-21; and Cardano's next era refuses it).
fn value(r: &mut Reader) -> Result<(u64, Vec<Policy<u64>>), Error> {
    match r.peek() {
        Some(UINT) => Ok((coin(r)?, Vec::new())),
        Some(ARRAY) => {
            if r.array()? != 2 {
                return Err(Error::Shape);
            }
            let ada = coin(r)?;
            let tokens = multiasset(r, |r| {
                let n = r.uint()?;
                if n == 0 {
                    return Err(Error::Invalid("none of a token sent: Cardano would refuse it"));
                }
                Ok(n)
            })?;
            if tokens.is_empty() {
                return Err(Error::Invalid(
                    "ADA alone written with an empty map of tokens: CIP-21 writes it as ADA alone",
                ));
            }
            Ok((ada, tokens))
        }
        _ => Err(Error::Shape),
    }
}

/// An output's address: one an output can pay (not a reward account's).
fn address(r: &mut Reader) -> Result<Address, Error> { Address::parse(r.bytes()?) }

/// A transaction output, in either form the ledger takes: Alonzo's list, `[address, value, ?
/// datum hash]`, or Babbage's map, `{0: address, 1: value, ? 2: datum, ? 3: script}`, its keys in
/// order.
fn output(r: &mut Reader) -> Result<Output, Error> {
    match r.peek() {
        Some(ARRAY) => {
            let n = r.array()?;
            if !(2..=3).contains(&n) {
                return Err(Error::Shape);
            }
            let address = address(r)?;
            let (coin, tokens) = value(r)?;
            let datum = if n == 3 { Some(Datum::Hash(r.hash()?)) } else { None };
            Ok(Output { address, coin, tokens, datum, script: None })
        }
        Some(MAP) => {
            let n = r.map()?;
            let (mut address_, mut value_, mut datum, mut script) = (None, None, None, None);
            let mut last = None;
            for _ in 0..n {
                let key = r.uint()?;
                match last {
                    Some(l) if key == l => return Err(Error::Duplicate),
                    Some(l) if key < l => return Err(Error::Encoding),
                    _ => last = Some(key),
                }
                match key {
                    0 => address_ = Some(address(r)?),
                    1 => value_ = Some(value(r)?),
                    2 => datum = Some(datum_option(r)?),
                    3 => script = Some(embedded(r)?),
                    _ => return Err(Error::Unknown),
                }
            }
            let (Some(address), Some((coin, tokens))) = (address_, value_) else {
                return Err(Error::Shape);
            };
            Ok(Output { address, coin, tokens, datum, script })
        }
        _ => Err(Error::Shape),
    }
}

/// CBOR inside bytes (`#6.24(bytes)`): an inline datum or a reference script, by its size. Not
/// empty (CIP-21).
fn embedded(r: &mut Reader) -> Result<usize, Error> {
    if r.tag()? != EMBEDDED {
        return Err(Error::Shape);
    }
    let b = r.bytes()?;
    if b.is_empty() {
        return Err(Error::Invalid("an empty datum or script: CIP-21 has none"));
    }
    Ok(b.len())
}

/// A datum: `[0, hash]` or `[1, #6.24(bytes)]`.
fn datum_option(r: &mut Reader) -> Result<Datum, Error> {
    if r.array()? != 2 {
        return Err(Error::Shape);
    }
    match r.uint()? {
        0 => Ok(Datum::Hash(r.hash()?)),
        1 => Ok(Datum::Inline(embedded(r)?)),
        _ => Err(Error::Shape),
    }
}

/// A certificate, by its number in the CDDL: the ones this account may sign read, the others
/// refused by name.
fn certificate(r: &mut Reader) -> Result<Certificate, Error> {
    let n = r.array()?;
    let kind = r.uint()?;
    let fields = match kind {
        0 | 1 => 2,
        2 | 7 | 8 | 9 => 3,
        10..=12 => 4,
        13 => 5,
        3 => return Err(Error::Unsupported("a stake pool's registration")),
        4 => return Err(Error::Unsupported("a stake pool's retirement")),
        14 => return Err(Error::Unsupported("a constitutional committee member's hot key")),
        15 => return Err(Error::Unsupported("a constitutional committee member's resignation")),
        16 => return Err(Error::Unsupported("a DRep's registration")),
        17 => return Err(Error::Unsupported("a DRep's retirement")),
        18 => return Err(Error::Unsupported("a DRep's update")),
        _ => return Err(Error::Invalid("a certificate Conway doesn't have: Cardano would refuse it")),
    };
    if n != fields {
        return Err(Error::Shape);
    }
    let stake = credential(r)?;
    Ok(match kind {
        0 => Certificate::Register { stake, deposit: None },
        1 => Certificate::Deregister { stake, refund: None },
        2 => Certificate::Delegate { stake, pool: r.hash()? },
        7 => Certificate::Register { stake, deposit: Some(coin(r)?) },
        8 => Certificate::Deregister { stake, refund: Some(coin(r)?) },
        9 => Certificate::Vote { stake, drep: drep(r)? },
        10 => Certificate::DelegateAndVote { stake, pool: r.hash()?, drep: drep(r)? },
        11 => Certificate::RegisterAndDelegate { stake, pool: r.hash()?, deposit: coin(r)? },
        12 => Certificate::RegisterAndVote { stake, drep: drep(r)?, deposit: coin(r)? },
        _ => {
            Certificate::RegisterDelegateAndVote { stake, pool: r.hash()?, drep: drep(r)?, deposit: coin(r)? }
        }
    })
}

/// Certificates: a set (Conway's `nonempty_oset`), in order, none twice.
fn certificates(r: &mut Reader, tagged: &mut Option<bool>) -> Result<Vec<Certificate>, Error> {
    let n = r.set(tagged)?;
    if n == 0 {
        return Err(Error::Invalid("an empty list of certificates: Cardano would refuse it"));
    }
    let mut out: Vec<Certificate> = Vec::with_capacity(n);
    for _ in 0..n {
        let c = certificate(r)?;
        if out.contains(&c) {
            return Err(Error::Duplicate);
        }
        out.push(c);
    }
    Ok(out)
}

/// Withdrawals: reward accounts, in order, each with what's taken from it.
fn withdrawals(r: &mut Reader) -> Result<Vec<(RewardAccount, u64)>, Error> {
    let n = r.map()?;
    if n == 0 {
        return Err(Error::Invalid("an empty map of withdrawals: Cardano would refuse it"));
    }
    let mut out = Vec::with_capacity(n);
    let mut keys = Keys::new();
    for _ in 0..n {
        let start = r.at();
        let account = RewardAccount::parse(r.bytes()?)?;
        keys.next(r.since(start))?;
        out.push((account, coin(r)?));
    }
    Ok(out)
}

/// Tokens minted and burnt: Conway's `mint`, each amount a 64-bit number other than zero.
fn mint(r: &mut Reader) -> Result<Vec<Policy<i64>>, Error> {
    let policies = multiasset(r, |r| match r.int64()? {
        0 => Err(Error::Invalid("none of a token minted: Cardano would refuse it")),
        n => Ok(n),
    })?;
    if policies.is_empty() {
        return Err(Error::Invalid("an empty map of tokens to mint: Cardano would refuse it"));
    }
    Ok(policies)
}

impl Body {
    /// A transaction's body, read whole: everything in it, nothing after it.
    pub fn parse(b: &[u8]) -> Result<Body, Error> {
        if b.len() > MAX_BODY {
            return Err(Error::TooBig);
        }
        let mut r = Reader::new(b);
        let mut tagged = None;
        let mut body = Body {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            ttl: None,
            certificates: Vec::new(),
            withdrawals: Vec::new(),
            metadata: None,
            valid_from: None,
            mint: Vec::new(),
            network: None,
            treasury: None,
            donation: None,
            tagged: false,
            size: b.len(),
        };
        let (mut has_inputs, mut has_outputs, mut has_fee) = (false, false, false);
        let mut last = None;
        for _ in 0..r.map()? {
            let key = r.uint()?;
            match last {
                Some(l) if key == l => return Err(Error::Duplicate),
                Some(l) if key < l => return Err(Error::Encoding),
                _ => last = Some(key),
            }
            match key {
                0 => {
                    body.inputs = inputs(&mut r, &mut tagged)?;
                    has_inputs = true;
                }
                1 => {
                    let n = r.array()?;
                    body.outputs.reserve(n);
                    for _ in 0..n {
                        body.outputs.push(output(&mut r)?);
                    }
                    has_outputs = true;
                }
                2 => {
                    body.fee = coin(&mut r)?;
                    has_fee = true;
                }
                3 => body.ttl = Some(r.uint()?),
                4 => body.certificates = certificates(&mut r, &mut tagged)?,
                5 => body.withdrawals = withdrawals(&mut r)?,
                7 => body.metadata = Some(r.hash()?),
                8 => body.valid_from = Some(r.uint()?),
                9 => body.mint = mint(&mut r)?,
                11 | 13 | 16 | 17 => {
                    return Err(Error::Unsupported("a transaction that runs Plutus scripts"));
                }
                14 => return Err(Error::Unsupported("a transaction with required signers, for scripts")),
                18 => {
                    return Err(Error::Unsupported("a transaction that refers to scripts or data on chain"));
                }
                15 => {
                    body.network = Some(match r.uint()? {
                        n @ (0 | 1) => n as u8,
                        _ => return Err(Error::Shape),
                    })
                }
                19 => return Err(Error::Unsupported("votes on Cardano's governance")),
                20 => return Err(Error::Unsupported("governance proposals")),
                21 => body.treasury = Some(coin(&mut r)?),
                22 => {
                    body.donation = Some(match coin(&mut r)? {
                        0 => return Err(Error::Invalid("a donation of nothing: Cardano would refuse it")),
                        n => n,
                    })
                }
                _ => return Err(Error::Unknown),
            }
        }
        r.end()?;
        if !(has_inputs && has_outputs && has_fee) {
            return Err(Error::Invalid(
                "a body without its inputs, its outputs or its fee: Cardano would refuse it",
            ));
        }
        if body.inputs.is_empty() {
            return Err(Error::Invalid("no coins spent: Cardano would refuse it"));
        }
        // and what the ledger counts up: no more ADA out than there is
        let out = body
            .outputs
            .iter()
            .try_fold(body.fee, |sum, o| sum.checked_add(o.coin))
            .filter(|&s| s <= MAX_LOVELACE);
        if out.is_none() {
            return Err(Error::Invalid("more ADA paid out than there will ever be: Cardano would refuse it"));
        }
        body.tagged = tagged == Some(true);
        Ok(body)
    }

    /// Whether anything in it says which network it's for: an output's address, a withdrawal's
    /// account, or the body itself.
    pub fn names_network(&self) -> bool {
        self.network.is_some() || !self.outputs.is_empty() || !self.withdrawals.is_empty()
    }
}

impl Output {
    /// Whether it pays a script: what can be done with it is up to the script.
    pub fn pays_script(&self) -> bool {
        matches!(self.address.kind, Kind::Shelley { payment: Credential::Script(_), .. })
    }
}
