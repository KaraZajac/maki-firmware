//! A transaction envelope: what Stellar's tools hand over to be signed (`TransactionEnvelope`,
//! XDR), and what a signature signs. Read as stellar-core reads it (`xdr`: strictly, and nothing
//! after it), then held to the checks stellar-core makes of a transaction before it takes one,
//! those that don't depend on the ledger (`checkValid`'s malformed transactions and operations):
//! anything it would refuse, maki refuses to show.
//!
//! Three kinds of envelope: version 1, a transaction; version 0, the same as Stellar's tools wrote
//! it before protocol 13 (stellar-core still takes it, as version 1); and a fee bump, which pays
//! the fee of a version 1 transaction someone has signed already, and is signed by whoever pays.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::soroban;
use crate::xdr::Reader;
use crate::{Hash, Key, Network};

/// The biggest envelope maki reads: more than maki's link brings at once (4 KiB), and than any
/// transaction of Stellar's own operations takes.
pub const MAX_ENVELOPE: usize = 64 * 1024;
/// The most operations a transaction has (`MAX_OPS_PER_TX`).
pub const MAX_OPERATIONS: usize = 100;
/// The most signatures an envelope carries.
pub const MAX_SIGNATURES: usize = 20;
/// Stroops in an XLM, and in a unit of any asset: amounts are in 10,000,000ths.
pub const STROOPS: u64 = 10_000_000;
/// How deep a claimable balance's conditions may nest, as stellar-core counts it.
pub const MAX_PREDICATE_DEPTH: usize = 4;
/// A liquidity pool's fee, in hundredths of a percent: the only one there is
/// (`LIQUIDITY_POOL_FEE_V18`).
pub const LIQUIDITY_POOL_FEE: i32 = 30;

/// The types a transaction envelope is, and what its signature hashes tag it with.
const ENVELOPE_TYPE_TX_V0: u32 = 0;
const ENVELOPE_TYPE_TX: u32 = 2;
const ENVELOPE_TYPE_TX_FEE_BUMP: u32 = 5;
/// `EnvelopeType`'s values: 0 to 10.
const LAST_ENVELOPE_TYPE: u32 = 10;

/// Why an envelope isn't one maki reads: not Stellar's XDR, or something stellar-core refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than any transaction maki reads.
    TooBig,
    /// Cut short, or with bytes after it.
    Length,
    /// Padding that isn't zeros.
    Padding,
    /// A type or value Stellar doesn't have.
    Unknown,
    /// A list or text longer than Stellar allows.
    TooLong,
    /// Nested deeper than maki reads.
    Deep,
    /// stellar-core would refuse it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::TooBig => "bigger than a Stellar transaction maki reads",
            Error::Length => "not a Stellar transaction: cut short, or with more after it",
            Error::Padding => "not a Stellar transaction: padding that isn't zero",
            Error::Unknown => "not a Stellar transaction: a type or value Stellar doesn't have",
            Error::TooLong => "not a Stellar transaction: a list or text longer than Stellar allows",
            Error::Deep => "a contract's data nested deeper than maki reads",
            Error::Invalid(why) => why,
        })
    }
}

/// An account, maybe with an ID (a muxed account, CAP-27: `M…`). The ID tells an account's
/// owner's customers apart; the account's key signs for it, whatever the ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Muxed {
    pub key: Key,
    pub id: Option<u64>,
}

/// An asset's code: one to four letters and digits (`AlphaNum4`), or five to twelve
/// (`AlphaNum12`), as stellar-core allows them, zeros after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code {
    bytes: [u8; 12],
    long: bool,
}

impl Code {
    /// A code as written, `long` for `AlphaNum12`'s twelve bytes: refused unless it's letters and
    /// digits, then only zeros, and of the length its kind has.
    fn new(written: &[u8], long: bool) -> Result<Code, Error> {
        let n = written.iter().position(|&b| b == 0).unwrap_or(written.len());
        let ok = written[..n].iter().all(|b| b.is_ascii_alphanumeric())
            && written[n..].iter().all(|&b| b == 0)
            && if long { n >= 5 } else { n >= 1 };
        if !ok {
            return Err(Error::Invalid("an asset code Stellar doesn't allow: it would refuse it"));
        }
        let mut bytes = [0u8; 12];
        bytes[..written.len()].copy_from_slice(written);
        Ok(Code { bytes, long })
    }

    /// A code as people write it, `USDC`: four letters and digits at most make an `AlphaNum4`,
    /// five to twelve an `AlphaNum12`.
    pub fn from_text(text: &str) -> Option<Code> {
        let t = text.as_bytes();
        let mut written = [0u8; 12];
        written.get_mut(..t.len())?.copy_from_slice(t);
        let long = t.len() > 4;
        Code::new(if long { &written } else { &written[..4] }, long).ok()
    }

    /// The code: `USDC`.
    pub fn as_str(&self) -> &str {
        let n = self.bytes.iter().position(|&b| b == 0).unwrap_or(12);
        // letters and digits alone (`new`)
        core::str::from_utf8(&self.bytes[..n]).unwrap_or("")
    }

    /// Written as XDR has it: four bytes, or twelve.
    fn written(&self) -> &[u8] { if self.long { &self.bytes } else { &self.bytes[..4] } }
}

/// An asset: XLM, or a code and the account that issues it. Anyone can issue an asset of any
/// code: the issuer is what says whose it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Native,
    Credit { code: Code, issuer: Key },
}

impl Asset {
    /// The issuer, for any asset but XLM.
    pub fn issuer(&self) -> Option<&Key> {
        match self {
            Asset::Native => None,
            Asset::Credit { issuer, .. } => Some(issuer),
        }
    }

    /// As XDR writes it.
    pub fn to_xdr(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52);
        match self {
            Asset::Native => out.extend_from_slice(&0u32.to_be_bytes()),
            Asset::Credit { code, issuer } => {
                out.extend_from_slice(&if code.long { 2u32 } else { 1u32 }.to_be_bytes());
                out.extend_from_slice(code.written());
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(issuer);
            }
        }
        out
    }

    /// stellar-core's order of assets (its XDR's): by type, then code, then issuer. A pool's
    /// first asset comes before its second.
    fn before(&self, other: &Asset) -> bool {
        let rank = |a: &Asset| match a {
            Asset::Native => (0u8, [0u8; 12], [0u8; 32]),
            Asset::Credit { code, issuer } => (if code.long { 2 } else { 1 }, code.bytes, *issuer),
        };
        rank(self) < rank(other)
    }
}

/// A price: `n` of one asset for `d` of another, a fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub n: i32,
    pub d: i32,
}

/// Who can sign for an account besides its own key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerKey {
    /// Another key.
    Ed25519(Key),
    /// One transaction, by its hash: it's signed for once it's sent.
    PreAuthTx(Hash),
    /// Whoever reveals the secret this is the SHA-256 of.
    HashX(Hash),
    /// A key's signature of this payload.
    SignedPayload { key: Key, payload: Vec<u8> },
}

impl SignerKey {
    /// As a page shows it: its StrKey.
    pub fn strkey(&self) -> String {
        match self {
            SignerKey::Ed25519(k) => crate::strkey::account(k),
            SignerKey::PreAuthTx(h) => crate::strkey::pre_auth_tx(h),
            SignerKey::HashX(h) => crate::strkey::hash_x(h),
            SignerKey::SignedPayload { key, payload } => crate::strkey::signed_payload(key, payload),
        }
    }
}

/// A signer and its weight, for `SetOptions`: weight 0 removes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub key: SignerKey,
    pub weight: u32,
}

/// When a claimable balance can be claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Unconditional,
    And(Box<Predicate>, Box<Predicate>),
    Or(Box<Predicate>, Box<Predicate>),
    Not(Box<Predicate>),
    /// Before this time (Unix seconds).
    Before(i64),
    /// Within this many seconds of the balance being made.
    Within(i64),
}

/// Who may claim a claimable balance, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimant {
    pub destination: Key,
    pub predicate: Predicate,
}

/// What a trustline is for: an asset, or a liquidity pool's shares, by the pool's assets and fee
/// (in hundredths of a percent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAsset {
    Asset(Asset),
    Pool { a: Asset, b: Asset, fee: i32 },
}

/// A liquidity pool's ID: SHA-256 of its kind (constant product) and its parameters.
pub fn pool_id(a: &Asset, b: &Asset, fee: i32) -> Hash {
    let mut h = Sha256::new();
    h.update(0u32.to_be_bytes());
    h.update(a.to_xdr());
    h.update(b.to_xdr());
    h.update(fee.to_be_bytes());
    h.finalize().into()
}

/// A trustline's asset, as a ledger entry's key names it: an asset, or a pool by its ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLineAsset {
    Asset(Asset),
    Pool(Hash),
}

/// What a sponsorship is revoked of: an entry of an account's, or one of its signers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sponsored {
    Account(Key),
    TrustLine { account: Key, asset: TrustLineAsset },
    Offer { seller: Key, id: i64 },
    Data { account: Key, name: String },
    ClaimableBalance(Hash),
    Signer { account: Key, key: SignerKey },
}

/// What `SetOptions` changes: each only if it's there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetOptions {
    pub inflation_destination: Option<Key>,
    pub clear_flags: Option<u32>,
    pub set_flags: Option<u32>,
    pub master_weight: Option<u32>,
    pub low: Option<u32>,
    pub medium: Option<u32>,
    pub high: Option<u32>,
    pub home_domain: Option<String>,
    pub signer: Option<Signer>,
}

/// An account's flags, for its issuer's assets.
pub mod flags {
    /// Its trustlines need it to authorize them.
    pub const AUTH_REQUIRED: u32 = 1;
    /// It can take back a trustline's authorization.
    pub const AUTH_REVOCABLE: u32 = 2;
    /// Its flags can never change again, and it can't be merged.
    pub const AUTH_IMMUTABLE: u32 = 4;
    /// It can claw back its assets.
    pub const AUTH_CLAWBACK_ENABLED: u32 = 8;
    /// Every account flag there is (`MASK_ACCOUNT_FLAGS_V17`).
    pub const ACCOUNT: u32 = 0xf;
    /// A trustline is authorized: its account can hold and use the asset.
    pub const AUTHORIZED: u32 = 1;
    /// A trustline may keep what it has (its offers, its balance), and take nothing more.
    pub const AUTHORIZED_TO_MAINTAIN_LIABILITIES: u32 = 2;
    /// The issuer can claw back what a trustline holds.
    pub const TRUSTLINE_CLAWBACK_ENABLED: u32 = 4;
    /// Every trustline flag there is (`MASK_TRUSTLINE_FLAGS_V17`).
    pub const TRUSTLINE: u32 = 7;
}

/// What an operation does: Stellar's operations, each as its XDR has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    CreateAccount {
        destination: Key,
        balance: i64,
    },
    Payment {
        destination: Muxed,
        asset: Asset,
        amount: i64,
    },
    /// Sends at most `send_max` of one asset so the destination gets exactly `amount` of
    /// another, traded through `path`.
    PathPaymentStrictReceive {
        send_asset: Asset,
        send_max: i64,
        destination: Muxed,
        asset: Asset,
        amount: i64,
        path: Vec<Asset>,
    },
    /// Sends exactly `send_amount` of one asset so the destination gets at least `min` of
    /// another, traded through `path`.
    PathPaymentStrictSend {
        send_asset: Asset,
        send_amount: i64,
        destination: Muxed,
        asset: Asset,
        min: i64,
        path: Vec<Asset>,
    },
    /// An offer to sell `amount` of `selling` at `price` of `buying` each: new (`offer` 0),
    /// changed, or cancelled (`amount` 0).
    ManageSellOffer {
        selling: Asset,
        buying: Asset,
        amount: i64,
        price: Price,
        offer: i64,
    },
    /// An offer that doesn't take offers at its own price.
    CreatePassiveSellOffer {
        selling: Asset,
        buying: Asset,
        amount: i64,
        price: Price,
    },
    SetOptions(SetOptions),
    /// A trustline, up to `limit`: added or changed, or removed (`limit` 0).
    ChangeTrust {
        line: TrustAsset,
        limit: i64,
    },
    /// The issuer (the operation's source) authorizes, or doesn't, `trustor`'s trustline.
    AllowTrust {
        trustor: Key,
        code: Code,
        authorize: u32,
    },
    /// The account closes, everything it holds in XLM to the destination.
    AccountMerge {
        destination: Muxed,
    },
    /// Data on the account, by name: set, or deleted (no value).
    ManageData {
        name: String,
        value: Option<Vec<u8>>,
    },
    BumpSequence {
        to: i64,
    },
    /// An offer to buy `amount` of `buying` at `price` of `selling` each.
    ManageBuyOffer {
        selling: Asset,
        buying: Asset,
        amount: i64,
        price: Price,
        offer: i64,
    },
    CreateClaimableBalance {
        asset: Asset,
        amount: i64,
        claimants: Vec<Claimant>,
    },
    ClaimClaimableBalance {
        balance: Hash,
    },
    /// The source pays the reserves of what `sponsored` adds, until it ends the sponsorship.
    BeginSponsoringFutureReserves {
        sponsored: Key,
    },
    EndSponsoringFutureReserves,
    RevokeSponsorship(Sponsored),
    /// The issuer takes its asset back.
    Clawback {
        asset: Asset,
        from: Muxed,
        amount: i64,
    },
    ClawbackClaimableBalance {
        balance: Hash,
    },
    /// The issuer sets and clears a trustline's flags.
    SetTrustLineFlags {
        trustor: Key,
        asset: Asset,
        clear: u32,
        set: u32,
    },
    LiquidityPoolDeposit {
        pool: Hash,
        max_a: i64,
        max_b: i64,
        min_price: Price,
        max_price: Price,
    },
    LiquidityPoolWithdraw {
        pool: Hash,
        amount: i64,
        min_a: i64,
        min_b: i64,
    },
    /// A contract called, made, or its code uploaded (Soroban).
    InvokeHostFunction(soroban::Invoke),
    /// The contract data and code the transaction's footprint names kept for `extend_to` more
    /// ledgers.
    ExtendFootprintTtl {
        extend_to: u32,
    },
    /// The archived contract data and code the transaction's footprint names brought back.
    RestoreFootprint,
}

impl Body {
    /// Whether it's Soroban's: run by contracts' host, alone in its transaction.
    pub fn is_soroban(&self) -> bool {
        matches!(self, Body::InvokeHostFunction(_) | Body::ExtendFootprintTtl { .. } | Body::RestoreFootprint)
    }
}

/// An operation, and the account it acts as if it isn't the transaction's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub source: Option<Muxed>,
    pub body: Body,
}

/// A memo: what the transaction says, for its recipient (an exchange may need it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Memo {
    None,
    /// Up to 28 bytes, meant to be text.
    Text(Vec<u8>),
    Id(u64),
    Hash(Hash),
    /// The hash of a transaction this one sends back.
    Return(Hash),
}

/// When a transaction can go through, by the ledger's close time (Unix seconds): from `min`, to
/// `max` (0 for no end).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeBounds {
    pub min: u64,
    pub max: u64,
}

/// When a transaction can go through, by ledger number: from `min`, to before `max` (0 for no
/// end).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerBounds {
    pub min: u32,
    pub max: u32,
}

/// What must be so for a transaction to go through (`Preconditions`): none, time bounds alone,
/// or any of these (CAP-21).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conditions {
    pub time: Option<TimeBounds>,
    pub ledgers: Option<LedgerBounds>,
    /// The source's sequence may be anything from this to the transaction's less one, not just
    /// one less.
    pub min_sequence: Option<i64>,
    /// Seconds since the source's sequence last changed.
    pub min_age: u64,
    /// Ledgers since the source's sequence last changed.
    pub min_ledger_gap: u32,
    /// Signatures it needs besides those its accounts do.
    pub extra_signers: Vec<SignerKey>,
}

/// A transaction: its source account (which pays its fee and whose sequence it uses), the most
/// its fee can be (in stroops), its sequence number, its conditions, its memo, its operations,
/// and for Soroban, its resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub source: Muxed,
    pub fee: u32,
    pub sequence: i64,
    pub conditions: Conditions,
    pub memo: Memo,
    pub operations: Vec<Operation>,
    pub soroban: Option<soroban::Data>,
}

impl Transaction {
    /// The account an operation acts as: its own source, or the transaction's.
    pub fn source_of(&self, op: &Operation) -> Key { op.source.unwrap_or(self.source).key }
}

/// Which kind of envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Version 0, as Stellar's tools wrote it before protocol 13: its source a bare key, time
    /// bounds its only condition. It signs as version 1.
    V0,
    /// Version 1: a transaction.
    V1,
    /// A fee bump: `source` pays the fee of the transaction inside it, up to `fee` stroops; the
    /// transaction inside carries its own signatures (`inner_signatures` of them) already.
    FeeBump { source: Muxed, fee: i64, inner_signatures: usize },
}

/// A transaction envelope, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Which kind: version 0, version 1, or a fee bump.
    pub kind: Kind,
    /// The transaction (inside a fee bump, the one it pays for).
    pub tx: Transaction,
    /// Signatures the envelope carries already (another signer's): not part of what's signed.
    pub signatures: usize,
    /// What's hashed after the network's ID: the type it's signed as, and the transaction.
    tagged: Vec<u8>,
}

impl Envelope {
    /// An envelope, read whole and checked: nothing after it, and nothing stellar-core would
    /// refuse before looking at the ledger.
    pub fn parse(bytes: &[u8]) -> Result<Envelope, Error> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(Error::TooBig);
        }
        let mut r = Reader::new(bytes);
        let envelope = match r.kind(LAST_ENVELOPE_TYPE)? {
            ENVELOPE_TYPE_TX_V0 => {
                let start = r.at();
                let tx = transaction_v0(&mut r)?;
                // signed as version 1: the same bytes, after the source's key type (ed25519, 0)
                let mut tagged = Vec::with_capacity(r.at() - start + 8);
                tagged.extend_from_slice(&ENVELOPE_TYPE_TX.to_be_bytes());
                tagged.extend_from_slice(&0u32.to_be_bytes());
                tagged.extend_from_slice(r.since(start));
                let signatures = signatures(&mut r)?;
                Envelope { kind: Kind::V0, tx, signatures, tagged }
            }
            ENVELOPE_TYPE_TX => {
                let start = r.at();
                let tx = transaction(&mut r)?;
                let tagged = [&ENVELOPE_TYPE_TX.to_be_bytes()[..], r.since(start)].concat();
                let signatures = signatures(&mut r)?;
                Envelope { kind: Kind::V1, tx, signatures, tagged }
            }
            ENVELOPE_TYPE_TX_FEE_BUMP => {
                let start = r.at();
                let source = muxed(&mut r)?;
                let fee = r.i64()?;
                // the transaction inside: version 1, the only kind a fee bump has
                if r.u32()? != ENVELOPE_TYPE_TX {
                    return Err(Error::Unknown);
                }
                let tx = transaction(&mut r)?;
                let inner_signatures = signatures(&mut r)?;
                extension_point(&mut r)?;
                let tagged = [&ENVELOPE_TYPE_TX_FEE_BUMP.to_be_bytes()[..], r.since(start)].concat();
                let signatures = signatures(&mut r)?;
                Envelope { kind: Kind::FeeBump { source, fee, inner_signatures }, tx, signatures, tagged }
            }
            _ => return Err(Error::Unknown),
        };
        r.done()?;
        envelope.check()?;
        Ok(envelope)
    }

    /// What a signature signs the hash of (`TransactionSignaturePayload`): the network's ID, the
    /// type the envelope signs as, and the transaction (or the fee bump).
    pub fn signature_base(&self, network: Network) -> Vec<u8> { [&network.id()[..], &self.tagged].concat() }

    /// The hash a signature signs: SHA-256 of `signature_base`. It's the transaction's hash too,
    /// as explorers name it.
    pub fn hash(&self, network: Network) -> Hash {
        Sha256::new().chain_update(network.id()).chain_update(&self.tagged).finalize().into()
    }

    /// The account that signs for it first: the fee bump's payer, or the transaction's source.
    pub fn payer(&self) -> &Muxed {
        match &self.kind {
            Kind::FeeBump { source, .. } => source,
            _ => &self.tx.source,
        }
    }

    /// What stellar-core refuses of a transaction before it looks at the ledger.
    fn check(&self) -> Result<(), Error> {
        let tx = &self.tx;
        if let Kind::FeeBump { fee, .. } = self.kind {
            if fee < 0 {
                return Err(Error::Invalid("a fee bump's fee below nothing: Stellar would refuse it"));
            }
        }
        let c = &tx.conditions;
        if let [a, b] = c.extra_signers.as_slice() {
            if a == b {
                return Err(Error::Invalid("the same extra signer twice: Stellar would refuse it"));
            }
        }
        if c.extra_signers
            .iter()
            .any(|s| matches!(s, SignerKey::SignedPayload { payload, .. } if payload.is_empty()))
        {
            return Err(Error::Invalid("an extra signer's empty payload: Stellar would refuse it"));
        }
        if tx.operations.is_empty() {
            return Err(Error::Invalid("no operations: Stellar would refuse it"));
        }
        let soroban = tx.operations[0].body.is_soroban();
        if tx.operations.iter().any(|op| op.body.is_soroban() != soroban)
            || (soroban && tx.operations.len() != 1)
        {
            return Err(Error::Invalid(
                "a contract's operation with others: Stellar would refuse it, it takes them alone",
            ));
        }
        match (&tx.soroban, soroban) {
            (None, true) => {
                return Err(Error::Invalid(
                    "a contract's operation without its resources: Stellar would refuse it",
                ));
            }
            (Some(_), false) => {
                return Err(Error::Invalid(
                    "resources for a contract with no contract: Stellar would refuse it",
                ));
            }
            (Some(data), true) => {
                if !(0..=soroban::MAX_RESOURCE_FEE).contains(&data.resource_fee) {
                    return Err(Error::Invalid("a resource fee Stellar would refuse"));
                }
                // inside a fee bump, the fee bump pays: the transaction's own fee may be less
                if !matches!(self.kind, Kind::FeeBump { .. }) && data.resource_fee > tx.fee as i64 {
                    return Err(Error::Invalid(
                        "a resource fee more than the whole fee: Stellar would refuse it",
                    ));
                }
                let op = &tx.operations[0];
                if let Body::InvokeHostFunction(_) = op.body {
                    let muxed = tx.source.id.is_some() || op.source.is_some_and(|s| s.id.is_some());
                    if tx.memo != Memo::None || muxed {
                        return Err(Error::Invalid(
                            "a contract call with a memo, or an account's ID: Stellar would refuse it",
                        ));
                    }
                }
                data.check(&op.body)?;
            }
            (None, false) => {}
        }
        for op in &tx.operations {
            check_operation(&op.body, &tx.source_of(op))?;
        }
        // a fee bump bumps: what it pays for each operation (its own one more) is at least what
        // the transaction inside offered, leaving out what goes to a contract's resources
        if let Kind::FeeBump { fee, .. } = self.kind {
            let resources = tx.soroban.as_ref().map_or(0, |d| d.resource_fee) as i128;
            let (outer, inner) = (fee as i128 - resources, tx.fee as i128 - resources);
            let ops = tx.operations.len() as i128;
            if inner >= 0 && outer * ops < inner * (ops + 1) {
                return Err(Error::Invalid(
                    "a fee bump that offers less than the fee it bumps: Stellar would refuse it",
                ));
            }
        }
        Ok(())
    }
}

fn invalid<T>(why: &'static str) -> Result<T, Error> { Err(Error::Invalid(why)) }

/// What stellar-core refuses of an operation, `source` the account it acts as.
fn check_operation(body: &Body, source: &Key) -> Result<(), Error> {
    match body {
        Body::CreateAccount { destination, balance } => {
            if *balance < 0 {
                return invalid("an account made with less than nothing: Stellar would refuse it");
            }
            if destination == source {
                return invalid("an account making itself: Stellar would refuse it");
            }
        }
        Body::Payment { amount, .. } => {
            if *amount <= 0 {
                return invalid("a payment of nothing: Stellar would refuse it");
            }
        }
        Body::PathPaymentStrictReceive { send_max, amount, .. } => {
            if *send_max <= 0 || *amount <= 0 {
                return invalid("a path payment of nothing: Stellar would refuse it");
            }
        }
        Body::PathPaymentStrictSend { send_amount, min, .. } => {
            if *send_amount <= 0 || *min <= 0 {
                return invalid("a path payment of nothing: Stellar would refuse it");
            }
        }
        Body::ManageSellOffer { selling, buying, amount, price, offer }
        | Body::ManageBuyOffer { selling, buying, amount, price, offer } => {
            check_offer(selling, buying, *amount, price, *offer)?
        }
        Body::CreatePassiveSellOffer { selling, buying, amount, price } => {
            check_offer(selling, buying, *amount, price, 0)?
        }
        Body::SetOptions(o) => {
            for f in [o.set_flags, o.clear_flags].into_iter().flatten() {
                if f & !flags::ACCOUNT != 0 {
                    return invalid("a flag Stellar doesn't have: it would refuse it");
                }
            }
            if let (Some(set), Some(clear)) = (o.set_flags, o.clear_flags) {
                if set & clear != 0 {
                    return invalid("a flag both set and cleared: Stellar would refuse it");
                }
            }
            if [o.master_weight, o.low, o.medium, o.high].into_iter().flatten().any(|w| w > 255) {
                return invalid("a weight or threshold over 255: Stellar would refuse it");
            }
            if let Some(s) = &o.signer {
                if s.key == SignerKey::Ed25519(*source) || s.weight > 255 {
                    return invalid(
                        "a signer Stellar would refuse: the account itself, or a weight over 255",
                    );
                }
                if matches!(&s.key, SignerKey::SignedPayload { payload, .. } if payload.is_empty()) {
                    return invalid("a signer's empty payload: Stellar would refuse it");
                }
            }
        }
        Body::ChangeTrust { line, limit } => {
            if *limit < 0 {
                return invalid("a trustline's limit below nothing: Stellar would refuse it");
            }
            match line {
                TrustAsset::Asset(Asset::Native) => {
                    return invalid("a trustline to XLM: Stellar would refuse it");
                }
                TrustAsset::Asset(a) if a.issuer() == Some(source) => {
                    return invalid("a trustline to an account's own asset: Stellar would refuse it");
                }
                TrustAsset::Pool { a, b, fee } => {
                    if !a.before(b) || *fee != LIQUIDITY_POOL_FEE {
                        return invalid("a liquidity pool Stellar doesn't have: it would refuse it");
                    }
                }
                TrustAsset::Asset(_) => {}
            }
        }
        Body::AllowTrust { trustor, authorize, .. } => {
            if *authorize > flags::AUTHORIZED_TO_MAINTAIN_LIABILITIES {
                return invalid("an authorization Stellar doesn't have: it would refuse it");
            }
            if trustor == source {
                return invalid("an issuer authorizing itself: Stellar would refuse it");
            }
        }
        Body::AccountMerge { destination } => {
            if destination.key == *source {
                return invalid("an account merged into itself: Stellar would refuse it");
            }
        }
        Body::ManageData { name, .. } => {
            if name.is_empty() {
                return invalid("data without a name: Stellar would refuse it");
            }
        }
        Body::BumpSequence { to } => {
            if *to < 0 {
                return invalid("a sequence below nothing: Stellar would refuse it");
            }
        }
        Body::CreateClaimableBalance { amount, claimants, .. } => {
            if *amount <= 0 || claimants.is_empty() {
                return invalid("a claimable balance of nothing, or for no one: Stellar would refuse it");
            }
            for (i, c) in claimants.iter().enumerate() {
                if claimants[..i].iter().any(|o| o.destination == c.destination) {
                    return invalid("a claimant named twice: Stellar would refuse it");
                }
            }
        }
        Body::BeginSponsoringFutureReserves { sponsored } => {
            if sponsored == source {
                return invalid("an account sponsoring itself: Stellar would refuse it");
            }
        }
        Body::RevokeSponsorship(s) => match s {
            Sponsored::TrustLine { account, asset } => match asset {
                TrustLineAsset::Asset(Asset::Native) => {
                    return invalid("a trustline to XLM: Stellar would refuse it");
                }
                TrustLineAsset::Asset(a) if a.issuer() == Some(account) => {
                    return invalid("a trustline to an account's own asset: Stellar would refuse it");
                }
                _ => {}
            },
            Sponsored::Offer { id, .. } if *id <= 0 => {
                return invalid("an offer that can't be: Stellar would refuse it");
            }
            Sponsored::Data { name, .. } if name.is_empty() => {
                return invalid("data without a name: Stellar would refuse it");
            }
            _ => {}
        },
        Body::Clawback { asset, from, amount } => {
            if from.id.is_none() && from.key == *source {
                return invalid("an issuer clawing back from itself: Stellar would refuse it");
            }
            if *amount < 1 {
                return invalid("a clawback of nothing: Stellar would refuse it");
            }
            if asset.issuer() != Some(source) {
                return invalid("a clawback by another than the asset's issuer: Stellar would refuse it");
            }
        }
        Body::SetTrustLineFlags { trustor, asset, clear, set } => {
            if asset.issuer() != Some(source) {
                return invalid(
                    "a trustline's flags set by another than its issuer: Stellar would refuse it",
                );
            }
            if trustor == source {
                return invalid("an issuer setting its own trustline's flags: Stellar would refuse it");
            }
            let both = flags::AUTHORIZED | flags::AUTHORIZED_TO_MAINTAIN_LIABILITIES;
            if set & clear != 0
                || set & !flags::TRUSTLINE != 0
                || clear & !flags::TRUSTLINE != 0
                || set & both == both
                || set & flags::TRUSTLINE_CLAWBACK_ENABLED != 0
            {
                return invalid("trustline flags Stellar would refuse");
            }
        }
        Body::LiquidityPoolDeposit { max_a, max_b, min_price, max_price, .. } => {
            let positive = |p: &Price| p.n > 0 && p.d > 0;
            if *max_a <= 0 || *max_b <= 0 || !positive(min_price) || !positive(max_price) {
                return invalid("a deposit of nothing, or at no price: Stellar would refuse it");
            }
            if min_price.n as i64 * max_price.d as i64 > min_price.d as i64 * max_price.n as i64 {
                return invalid("a deposit's least price above its most: Stellar would refuse it");
            }
        }
        Body::LiquidityPoolWithdraw { amount, min_a, min_b, .. } => {
            if *amount <= 0 || *min_a < 0 || *min_b < 0 {
                return invalid("a withdrawal of nothing: Stellar would refuse it");
            }
        }
        Body::ClaimClaimableBalance { .. }
        | Body::EndSponsoringFutureReserves
        | Body::ClawbackClaimableBalance { .. }
        | Body::InvokeHostFunction(_)
        | Body::ExtendFootprintTtl { .. }
        | Body::RestoreFootprint => {}
    }
    Ok(())
}

fn check_offer(selling: &Asset, buying: &Asset, amount: i64, price: &Price, offer: i64) -> Result<(), Error> {
    if selling == buying {
        return invalid("an offer of an asset for itself: Stellar would refuse it");
    }
    if amount < 0 || price.n <= 0 || price.d <= 0 {
        return invalid("an offer of less than nothing, or at no price: Stellar would refuse it");
    }
    if offer < 0 || (offer == 0 && amount == 0) {
        return invalid("an offer that can't be: Stellar would refuse it");
    }
    Ok(())
}

/// An `ExtensionPoint`, or a version that has nothing yet: 0.
pub(crate) fn extension_point(r: &mut Reader) -> Result<(), Error> {
    match r.u32()? {
        0 => Ok(()),
        _ => Err(Error::Unknown),
    }
}

pub(crate) fn account_id(r: &mut Reader) -> Result<Key, Error> {
    // PUBLIC_KEY_TYPE_ED25519: the only kind of account key
    r.kind(0)?;
    r.key()
}

pub(crate) fn muxed(r: &mut Reader) -> Result<Muxed, Error> {
    match r.u32()? {
        // KEY_TYPE_ED25519
        0 => Ok(Muxed { key: r.key()?, id: None }),
        // KEY_TYPE_MUXED_ED25519: the ID, then the key
        0x100 => {
            let id = r.u64()?;
            Ok(Muxed { key: r.key()?, id: Some(id) })
        }
        _ => Err(Error::Unknown),
    }
}

pub(crate) fn asset(r: &mut Reader) -> Result<Asset, Error> {
    match r.kind(2)? {
        0 => Ok(Asset::Native),
        1 => {
            let code = Code::new(&r.array::<4>()?, false)?;
            Ok(Asset::Credit { code, issuer: account_id(r)? })
        }
        _ => {
            let code = Code::new(&r.array::<12>()?, true)?;
            Ok(Asset::Credit { code, issuer: account_id(r)? })
        }
    }
}

fn price(r: &mut Reader) -> Result<Price, Error> { Ok(Price { n: r.i32()?, d: r.i32()? }) }

pub(crate) fn signer_key(r: &mut Reader) -> Result<SignerKey, Error> {
    Ok(match r.kind(3)? {
        0 => SignerKey::Ed25519(r.key()?),
        1 => SignerKey::PreAuthTx(r.hash()?),
        2 => SignerKey::HashX(r.hash()?),
        _ => {
            let key = r.key()?;
            SignerKey::SignedPayload { key, payload: r.opaque(64)?.to_vec() }
        }
    })
}

/// A claimable balance's or an asset's ID: its type (0, the only one) and its hash.
pub(crate) fn balance_id(r: &mut Reader) -> Result<Hash, Error> {
    r.kind(0)?;
    r.hash()
}

/// Text Stellar takes as a name: printable ASCII (`isStringValid`).
fn ascii(bytes: &[u8], why: &'static str) -> Result<String, Error> {
    if !bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(Error::Invalid(why));
    }
    Ok(bytes.iter().map(|&b| b as char).collect())
}

fn time_bounds(r: &mut Reader) -> Result<TimeBounds, Error> {
    Ok(TimeBounds { min: r.u64()?, max: r.u64()? })
}

fn preconditions(r: &mut Reader) -> Result<Conditions, Error> {
    Ok(match r.kind(2)? {
        0 => Conditions::default(),
        1 => Conditions { time: Some(time_bounds(r)?), ..Conditions::default() },
        _ => {
            let time = if r.bool()? { Some(time_bounds(r)?) } else { None };
            let ledgers = if r.bool()? { Some(LedgerBounds { min: r.u32()?, max: r.u32()? }) } else { None };
            let min_sequence = if r.bool()? { Some(r.i64()?) } else { None };
            let (min_age, min_ledger_gap) = (r.u64()?, r.u32()?);
            let mut extra_signers = Vec::new();
            for _ in 0..r.count(2)? {
                extra_signers.push(signer_key(r)?);
            }
            Conditions { time, ledgers, min_sequence, min_age, min_ledger_gap, extra_signers }
        }
    })
}

fn memo(r: &mut Reader) -> Result<Memo, Error> {
    Ok(match r.kind(4)? {
        0 => Memo::None,
        1 => Memo::Text(r.opaque(28)?.to_vec()),
        2 => Memo::Id(r.u64()?),
        3 => Memo::Hash(r.hash()?),
        _ => Memo::Return(r.hash()?),
    })
}

fn signatures(r: &mut Reader) -> Result<usize, Error> {
    let n = r.count(MAX_SIGNATURES)?;
    for _ in 0..n {
        // its hint (the key's last four bytes) and the signature
        r.array::<4>()?;
        r.opaque(64)?;
    }
    Ok(n)
}

fn operations(r: &mut Reader) -> Result<Vec<Operation>, Error> {
    let mut ops = Vec::new();
    for _ in 0..r.count(MAX_OPERATIONS)? {
        let source = if r.bool()? { Some(muxed(r)?) } else { None };
        ops.push(Operation { source, body: body(r)? });
    }
    Ok(ops)
}

fn transaction(r: &mut Reader) -> Result<Transaction, Error> {
    let source = muxed(r)?;
    let fee = r.u32()?;
    let sequence = r.i64()?;
    let conditions = preconditions(r)?;
    let memo = memo(r)?;
    let operations = operations(r)?;
    let soroban = match r.kind(1)? {
        0 => None,
        _ => Some(soroban::data(r)?),
    };
    Ok(Transaction { source, fee, sequence, conditions, memo, operations, soroban })
}

fn transaction_v0(r: &mut Reader) -> Result<Transaction, Error> {
    let key = r.key()?;
    let fee = r.u32()?;
    let sequence = r.i64()?;
    let time = if r.bool()? { Some(time_bounds(r)?) } else { None };
    let memo = memo(r)?;
    let operations = operations(r)?;
    extension_point(r)?;
    Ok(Transaction {
        source: Muxed { key, id: None },
        fee,
        sequence,
        conditions: Conditions { time, ..Conditions::default() },
        memo,
        operations,
        soroban: None,
    })
}

/// A claimable balance's condition, `depth` deep (the claimant's own is 1): stellar-core refuses
/// one deeper than `MAX_PREDICATE_DEPTH`, an "and" or an "or" of other than two, a "not" of
/// nothing, and a time before 0.
fn predicate(r: &mut Reader, depth: usize) -> Result<Predicate, Error> {
    const WHY: &str = "a claim condition Stellar would refuse";
    if depth > MAX_PREDICATE_DEPTH {
        return invalid(WHY);
    }
    Ok(match r.kind(5)? {
        0 => Predicate::Unconditional,
        k @ (1 | 2) => {
            let n = r.count(2)?;
            let mut both = Vec::with_capacity(2);
            for _ in 0..n {
                both.push(Box::new(predicate(r, depth + 1)?));
            }
            let (Some(b), Some(a)) = (both.pop(), both.pop()) else { return invalid(WHY) };
            if k == 1 { Predicate::And(a, b) } else { Predicate::Or(a, b) }
        }
        3 => {
            if !r.bool()? {
                return invalid(WHY);
            }
            Predicate::Not(Box::new(predicate(r, depth + 1)?))
        }
        k => {
            let t = r.i64()?;
            if t < 0 {
                return invalid(WHY);
            }
            if k == 4 { Predicate::Before(t) } else { Predicate::Within(t) }
        }
    })
}

/// A trustline's asset in a ledger entry's key: an asset, or a pool's ID.
fn trust_line_asset(r: &mut Reader) -> Result<TrustLineAsset, Error> {
    match r.kind(3)? {
        0 => Ok(TrustLineAsset::Asset(Asset::Native)),
        k @ (1 | 2) => {
            let long = k == 2;
            let code =
                if long { Code::new(&r.array::<12>()?, true)? } else { Code::new(&r.array::<4>()?, false)? };
            Ok(TrustLineAsset::Asset(Asset::Credit { code, issuer: account_id(r)? }))
        }
        _ => Ok(TrustLineAsset::Pool(r.hash()?)),
    }
}

fn revoke(r: &mut Reader) -> Result<Sponsored, Error> {
    if r.kind(1)? == 1 {
        let account = account_id(r)?;
        return Ok(Sponsored::Signer { account, key: signer_key(r)? });
    }
    // a ledger entry: of the kinds that are sponsored
    Ok(match r.kind(9)? {
        0 => Sponsored::Account(account_id(r)?),
        1 => {
            let account = account_id(r)?;
            Sponsored::TrustLine { account, asset: trust_line_asset(r)? }
        }
        2 => {
            let seller = account_id(r)?;
            Sponsored::Offer { seller, id: r.i64()? }
        }
        3 => {
            let account = account_id(r)?;
            let name = ascii(r.opaque(64)?, "a data name Stellar would refuse")?;
            Sponsored::Data { account, name }
        }
        4 => Sponsored::ClaimableBalance(balance_id(r)?),
        // liquidity pools, and contracts' entries: nothing sponsors those
        _ => return invalid("a sponsorship of what isn't sponsored: Stellar would refuse it"),
    })
}

fn body(r: &mut Reader) -> Result<Body, Error> {
    Ok(match r.kind(26)? {
        0 => {
            let destination = account_id(r)?;
            Body::CreateAccount { destination, balance: r.i64()? }
        }
        1 => {
            let destination = muxed(r)?;
            let asset = asset(r)?;
            Body::Payment { destination, asset, amount: r.i64()? }
        }
        2 => {
            let (send_asset, send_max) = (asset(r)?, r.i64()?);
            let destination = muxed(r)?;
            let (asset, amount) = (asset(r)?, r.i64()?);
            Body::PathPaymentStrictReceive {
                send_asset,
                send_max,
                destination,
                asset,
                amount,
                path: path(r)?,
            }
        }
        3 => {
            let (selling, buying) = (asset(r)?, asset(r)?);
            let (amount, price) = (r.i64()?, price(r)?);
            Body::ManageSellOffer { selling, buying, amount, price, offer: r.i64()? }
        }
        4 => {
            let (selling, buying) = (asset(r)?, asset(r)?);
            let amount = r.i64()?;
            Body::CreatePassiveSellOffer { selling, buying, amount, price: price(r)? }
        }
        5 => Body::SetOptions(set_options(r)?),
        6 => {
            let line = match r.kind(3)? {
                0 => TrustAsset::Asset(Asset::Native),
                k @ (1 | 2) => {
                    let code = if k == 2 {
                        Code::new(&r.array::<12>()?, true)?
                    } else {
                        Code::new(&r.array::<4>()?, false)?
                    };
                    TrustAsset::Asset(Asset::Credit { code, issuer: account_id(r)? })
                }
                _ => {
                    // LIQUIDITY_POOL_CONSTANT_PRODUCT: the only kind of pool
                    r.kind(0)?;
                    let (a, b) = (asset(r)?, asset(r)?);
                    TrustAsset::Pool { a, b, fee: r.i32()? }
                }
            };
            Body::ChangeTrust { line, limit: r.i64()? }
        }
        7 => {
            let trustor = account_id(r)?;
            let code = match r.kind(2)? {
                1 => Code::new(&r.array::<4>()?, false)?,
                2 => Code::new(&r.array::<12>()?, true)?,
                // an asset code is of an asset that has one
                _ => return Err(Error::Unknown),
            };
            Body::AllowTrust { trustor, code, authorize: r.u32()? }
        }
        8 => Body::AccountMerge { destination: muxed(r)? },
        9 => return invalid("inflation, which Stellar no longer runs: it would refuse it"),
        10 => {
            let name = ascii(r.opaque(64)?, "a data name Stellar would refuse")?;
            let value = if r.bool()? { Some(r.opaque(64)?.to_vec()) } else { None };
            Body::ManageData { name, value }
        }
        11 => Body::BumpSequence { to: r.i64()? },
        12 => {
            let (selling, buying) = (asset(r)?, asset(r)?);
            let (amount, price) = (r.i64()?, price(r)?);
            Body::ManageBuyOffer { selling, buying, amount, price, offer: r.i64()? }
        }
        13 => {
            let (send_asset, send_amount) = (asset(r)?, r.i64()?);
            let destination = muxed(r)?;
            let (asset, min) = (asset(r)?, r.i64()?);
            Body::PathPaymentStrictSend { send_asset, send_amount, destination, asset, min, path: path(r)? }
        }
        14 => {
            let (asset, amount) = (asset(r)?, r.i64()?);
            let mut claimants = Vec::new();
            for _ in 0..r.count(10)? {
                // CLAIMANT_TYPE_V0: the only kind
                r.kind(0)?;
                let destination = account_id(r)?;
                claimants.push(Claimant { destination, predicate: predicate(r, 1)? });
            }
            Body::CreateClaimableBalance { asset, amount, claimants }
        }
        15 => Body::ClaimClaimableBalance { balance: balance_id(r)? },
        16 => Body::BeginSponsoringFutureReserves { sponsored: account_id(r)? },
        17 => Body::EndSponsoringFutureReserves,
        18 => Body::RevokeSponsorship(revoke(r)?),
        19 => {
            let asset = asset(r)?;
            let from = muxed(r)?;
            Body::Clawback { asset, from, amount: r.i64()? }
        }
        20 => Body::ClawbackClaimableBalance { balance: balance_id(r)? },
        21 => {
            let trustor = account_id(r)?;
            let asset = asset(r)?;
            let clear = r.u32()?;
            Body::SetTrustLineFlags { trustor, asset, clear, set: r.u32()? }
        }
        22 => {
            let pool = r.hash()?;
            let (max_a, max_b) = (r.i64()?, r.i64()?);
            let min_price = price(r)?;
            Body::LiquidityPoolDeposit { pool, max_a, max_b, min_price, max_price: price(r)? }
        }
        23 => {
            let pool = r.hash()?;
            let amount = r.i64()?;
            let min_a = r.i64()?;
            Body::LiquidityPoolWithdraw { pool, amount, min_a, min_b: r.i64()? }
        }
        24 => Body::InvokeHostFunction(soroban::invoke(r)?),
        25 => {
            extension_point(r)?;
            Body::ExtendFootprintTtl { extend_to: r.u32()? }
        }
        _ => {
            extension_point(r)?;
            Body::RestoreFootprint
        }
    })
}

/// A path payment's path: up to five assets it's traded through.
fn path(r: &mut Reader) -> Result<Vec<Asset>, Error> {
    let mut path = Vec::new();
    for _ in 0..r.count(5)? {
        path.push(asset(r)?);
    }
    Ok(path)
}

fn set_options(r: &mut Reader) -> Result<SetOptions, Error> {
    let mut o = SetOptions::default();
    if r.bool()? {
        o.inflation_destination = Some(account_id(r)?);
    }
    fn maybe(r: &mut Reader) -> Result<Option<u32>, Error> {
        Ok(if r.bool()? { Some(r.u32()?) } else { None })
    }
    o.clear_flags = maybe(r)?;
    o.set_flags = maybe(r)?;
    o.master_weight = maybe(r)?;
    o.low = maybe(r)?;
    o.medium = maybe(r)?;
    o.high = maybe(r)?;
    if r.bool()? {
        o.home_domain = Some(ascii(r.opaque(32)?, "a home domain Stellar would refuse")?);
    }
    if r.bool()? {
        let key = signer_key(r)?;
        o.signer = Some(Signer { key, weight: r.u32()? });
    }
    Ok(o)
}
