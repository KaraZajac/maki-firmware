//! What the owner reads on maki's review screen before a Tron transaction is signed, as pages: the
//! network; what it does (TRX and tokens sent and to whom, staking, delegating, votes), each amount
//! exact, in TRX or the token's own units if maki knows it; a memo; the permission it's signed
//! under, if it isn't the owner's; when it expires, if that's out of the ordinary; and the most the
//! fee can be, saying what maki can't know of it. An approval to spend tokens is called out, a
//! contract call maki can't read is flagged with what it could do, and a change of who controls the
//! account is refused.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::tokens::{self, Token};
use crate::tx::{Contract, Transaction};
use crate::{Address, Network, PREFIX, address};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// A few words at the top: what this page is about.
    pub heading: String,
    /// The thing to check, in bold: an amount.
    pub value: String,
    /// Fixed-width text, across as many lines as it takes: an address.
    pub mono: String,
    /// Small words, wrapped: what it means.
    pub prose: String,
}

fn page(heading: &str, value: impl Into<String>, mono: impl Into<String>, prose: impl Into<String>) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

/// What maki's review screen shows of a transaction: its pages, then the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// What the owner goes through, a page at a time.
    pub pages: Vec<Page>,
    /// The line under the question: what it does, and the most the fee can be.
    pub summary: String,
}

/// Why maki won't show a transaction for this account to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The transaction is another account's: it isn't this one's to sign.
    NotMine,
    /// maki won't sign it, or can't show it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotMine => f.write_str("another account's transaction, not this one's to sign"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The most text a page shows (maki's review screen's limit): a memo longer than that, maki
/// can't show.
pub const MAX_SHOWN: usize = 4096;

// What Tron charges, as its governance has set it for both networks (each read with TronGrid's
// /wallet/getchainparameters on 2026-10-01). Proposals can change these; the fee page says what
// each part is for.

/// TRX burnt for each byte of bandwidth a transaction takes beyond what the account has
/// (`getTransactionFee`), in sun.
pub const SUN_PER_BYTE: u64 = 1_000;
/// The bandwidth every account gets free each day, in bytes (`getFreeNetLimit`).
pub const FREE_BANDWIDTH: u64 = 600;
/// What sending TRX or a TRC-10 token to an address new to Tron costs, in sun: its account made
/// (`getCreateNewAccountFeeInSystemContract`, 1 TRX), and the bandwidth that takes, unless staked
/// bandwidth covers it (`getCreateAccountFee`, 0.1 TRX).
pub const NEW_ACCOUNT_FEE: u64 = 1_100_000;
/// What a memo costs (`getMemoFee`), in sun.
pub const MEMO_FEE: u64 = 1_000_000;
/// What a transaction signed more than once costs more (`getMultiSignFee`), in sun.
pub const MULTI_SIGN_FEE: u64 = 1_000_000;

/// How long unstaked TRX waits before it can be withdrawn (`getUnfreezeDelayDays`).
pub fn unstake_days(network: Network) -> u64 {
    match network {
        Network::Tron => 14,
        Network::Nile => 1,
    }
}

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;
/// Tron makes a block every three seconds: what a delegation's lock is counted in.
const BLOCK: u64 = 3_000;

/// How many bytes a number takes as a varint.
fn varint_len(mut n: u64) -> u64 {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// The bandwidth a transaction of `size` bytes of `raw_data` takes, as java-tron counts it: the
/// signed transaction (`raw_data`, and a signature of 65 bytes, each with its field's key and
/// length), and 64 bytes for its result.
pub fn bandwidth(size: usize) -> u64 {
    let raw = size as u64;
    (1 + varint_len(raw) + raw) + (1 + 1 + 65) + 64
}

/// The whole number `digits` with `places` decimals, exactly, without trailing zeros.
fn point(digits: &str, places: u8) -> String {
    let places = places as usize;
    if places == 0 {
        return digits.into();
    }
    let padded =
        if digits.len() <= places { "0".repeat(places + 1 - digits.len()) + digits } else { digits.into() };
    let (whole, frac) = padded.split_at(padded.len() - places);
    match frac.trim_end_matches('0') {
        "" => whole.into(),
        frac => format!("{whole}.{frac}"),
    }
}

/// `n` with `places` decimals, exactly, without trailing zeros: `decimals(1500, 3)` is `1.5`.
pub fn decimals(n: u128, places: u8) -> String { point(&n.to_string(), places) }

/// A 256-bit number (big-endian, as a contract's arguments carry it), in decimal.
pub fn uint256(n: &[u8; 32]) -> String {
    // decimal digits, least significant first
    let mut digits: Vec<u8> = Vec::new();
    for &byte in n {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 10) as u8;
            carry /= 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return String::from("0");
    }
    digits.iter().rev().map(|&d| (b'0' + d) as char).collect()
}

/// Sun, exactly, in TRX: `1.5 TRX`.
pub fn trx(sun: u128) -> String { format!("{} TRX", decimals(sun, 6)) }

/// An amount of a token maki knows, exactly, and its symbol: `5.25 USDT`.
pub fn token_amount(token: &Token, smallest: &[u8; 32]) -> String {
    format!("{} {}", point(&uint256(smallest), token.decimals), token.symbol)
}

fn leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// The date `days` after 1970-01-01: its year, month and day.
fn date(mut days: u64) -> (u64, u64, u64) {
    // the calendar repeats every 400 years, 146,097 days
    let mut year = 1970 + 400 * (days / 146_097);
    days %= 146_097;
    loop {
        let len = if leap(year) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    let february = if leap(year) { 29 } else { 28 };
    let mut month = 1;
    for len in [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] {
        if days < len {
            break;
        }
        days -= len;
        month += 1;
    }
    (year, month, days + 1)
}

/// A time (milliseconds since 1970) as the owner reads it: `2026-10-02 01:59:51 UTC`.
pub fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = date(secs / 86_400);
    let s = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

fn plural(n: u64, unit: &str) -> String { format!("{n} {unit}{}", if n == 1 { "" } else { "s" }) }

/// A span of time (milliseconds) in its two largest units, rounded down: `3 days`, `6 hours`,
/// `1 hour 30 minutes`.
pub fn span(ms: u64) -> String {
    let (days, hours, minutes) = (ms / DAY, ms % DAY / HOUR, ms % HOUR / 60_000);
    let parts = if days > 0 {
        [(days, "day"), (hours, "hour")]
    } else if hours > 0 {
        [(hours, "hour"), (minutes, "minute")]
    } else {
        [(minutes, "minute"), (ms % 60_000 / 1000, "second")]
    };
    match parts {
        [(a, u), (0, _)] => plural(a, u),
        [(0, _), (b, v)] => plural(b, v),
        [(a, u), (b, v)] => format!("{} {}", plural(a, u), plural(b, v)),
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// A TRC-20 call maki spells out: `transfer(address,uint256)` or `approve(address,uint256)`, as
/// Solidity's ABI writes them, and nothing after.
enum Abi {
    Transfer { to: Address, amount: [u8; 32] },
    Approve { spender: Address, amount: [u8; 32] },
}

/// The first four bytes of the Keccak-256 of `transfer(address,uint256)`.
const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// The first four bytes of the Keccak-256 of `approve(address,uint256)`.
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

fn abi(data: &[u8]) -> Option<Abi> {
    if data.len() != 4 + 32 + 32 {
        return None;
    }
    let (selector, who, amount) = (&data[..4], &data[4..36], &data[36..]);
    // an address argument: twelve zero bytes, then the address without its first byte
    if who[..12].iter().any(|&b| b != 0) {
        return None;
    }
    let mut address = [PREFIX; 21];
    address[1..].copy_from_slice(&who[12..]);
    let mut n = [0u8; 32];
    n.copy_from_slice(amount);
    match selector {
        s if s == TRANSFER => Some(Abi::Transfer { to: address, amount: n }),
        s if s == APPROVE => Some(Abi::Approve { spender: address, amount: n }),
        _ => None,
    }
}

struct Reading<'a> {
    tx: &'a Transaction,
    network: Network,
    pages: Vec<Page>,
    /// What it does, as the line under the question says it.
    said: Vec<String>,
    /// What it does that the owner must not miss.
    warnings: Vec<String>,
    /// Something maki can't read.
    unreadable: bool,
}

impl Reading<'_> {
    fn send(&mut self, amount: String, to: &Address, prose: &str) {
        self.said.push(format!("sends {amount}"));
        self.pages.push(page("Send", amount, address(to), prose));
    }

    fn contract(&mut self) -> Result<(), Error> {
        let days = plural(unstake_days(self.network), "day");
        match &self.tx.contract {
            Contract::Transfer { to, amount, .. } => self.send(trx(*amount as u128), to, ""),
            Contract::TransferToken { to, token, amount, .. } => {
                self.said.push(format!("sends {amount} units of token {token}"));
                self.pages.push(page(
                    "Send",
                    format!("{amount} units"),
                    address(to),
                    format!("Of TRC-10 token {token}, in its smallest units: maki doesn't know it."),
                ));
            }
            Contract::Call { contract, data, call_value, token, token_value, .. } => {
                self.call(contract, data);
                if *call_value > 0 {
                    self.send(trx(*call_value as u128), contract, "To the contract, with the call.");
                }
                if *token_value > 0 {
                    self.said.push(format!("sends {token_value} units of token {token}"));
                    self.pages.push(page(
                        "Send",
                        format!("{token_value} units"),
                        address(contract),
                        format!("Of TRC-10 token {token}, to the contract, with the call."),
                    ));
                }
            }
            Contract::Stake { amount, resource, .. } => {
                let amount = trx(*amount as u128);
                self.said.push(format!("stakes {amount} for {}", resource.name()));
                self.pages.push(page(
                    "Stake",
                    amount,
                    "",
                    format!(
                        "For {}. Staked, it stays this account's but can't be spent: unstaking it takes {days}.",
                        resource.name()
                    ),
                ));
            }
            Contract::Unstake { amount, resource, .. } => {
                let amount = trx(*amount as u128);
                self.said.push(format!("unstakes {amount}"));
                self.pages.push(page(
                    "Unstake",
                    amount,
                    "",
                    format!(
                        "Staked for {}. It can be withdrawn in {days}. If this account's votes need more than stays staked, they're cut to fit.",
                        resource.name()
                    ),
                ));
            }
            Contract::WithdrawUnstaked { .. } => {
                self.said.push(String::from("withdraws unstaked TRX"));
                self.pages.push(page(
                    "Withdraw",
                    "unstaked TRX",
                    "",
                    "Whatever is done unstaking comes back to this account, to spend.",
                ));
            }
            Contract::CancelUnstaking { .. } => {
                self.said.push(String::from("cancels unstaking"));
                self.pages.push(page(
                    "Cancel unstaking",
                    "all of it",
                    "",
                    "TRX this account is unstaking is staked again, as it was; any that's done unstaking comes back to it.",
                ));
            }
            Contract::Delegate { receiver, amount, resource, lock, .. } => {
                let (amount, r) = (trx(*amount as u128), resource.name());
                let lock = match lock {
                    Some(blocks) => format!(
                        " Locked for {}: it can't be reclaimed sooner.",
                        span(blocks.saturating_mul(BLOCK))
                    ),
                    None => String::new(),
                };
                self.said.push(format!("delegates {amount} of {r}"));
                self.pages.push(page(
                    &format!("Delegate {r}"),
                    amount.clone(),
                    address(receiver),
                    format!("That address uses the {r} this account's staked {amount} makes; the TRX stays this account's.{lock}"),
                ));
            }
            Contract::Reclaim { receiver, amount, resource, .. } => {
                let (amount, r) = (trx(*amount as u128), resource.name());
                self.said.push(format!("reclaims {amount} of {r}"));
                self.pages.push(page(
                    &format!("Reclaim {r}"),
                    amount.clone(),
                    address(receiver),
                    format!("That address stops using the {r} this account's staked {amount} makes."),
                ));
            }
            Contract::Vote { votes, .. } => {
                for (i, (witness, n)) in votes.iter().enumerate() {
                    let prose = if i == 0 {
                        "These votes replace every vote this account has made; each takes 1 TRX it has staked."
                    } else {
                        ""
                    };
                    self.pages.push(page("Vote", plural(*n, "vote"), address(witness), prose));
                }
                self.said.push(match votes.len() {
                    1 => String::from("votes for 1 witness"),
                    n => format!("votes for {n} witnesses"),
                });
            }
            Contract::ClaimRewards { .. } => {
                self.said.push(String::from("claims voting rewards"));
                self.pages.push(page(
                    "Claim rewards",
                    "for voting",
                    "",
                    "The rewards this account has earned by voting come to it.",
                ));
            }
            Contract::UpdatePermissions { .. } => {
                return Err(Error::Invalid("it changes who controls this account: maki won't sign that"));
            }
        }
        Ok(())
    }

    /// A contract called: a TRC-20 transfer or approval spelled out, in the token's units if maki
    /// knows it; anything else flagged, with what it could do.
    fn call(&mut self, contract: &Address, data: &[u8]) {
        let known = tokens::known(self.network, contract);
        match (abi(data), known) {
            (Some(Abi::Transfer { to, amount }), Some(t)) => self.send(token_amount(t, &amount), &to, ""),
            (Some(Abi::Transfer { to, amount }), None) => {
                self.send(
                    format!("{} units", uint256(&amount)),
                    &to,
                    "Of a token maki doesn't know, if that's what the contract is: maki can't tell what it does.",
                );
                self.stranger(contract);
            }
            (Some(Abi::Approve { spender, amount }), t) => {
                let what = t.map(|t| t.symbol).unwrap_or("tokens");
                if amount == [0; 32] {
                    self.said.push(format!("revokes an approval of {what}"));
                    self.pages.push(page(
                        "Revoke",
                        what,
                        address(&spender),
                        format!("That address may no longer spend this account's {what}."),
                    ));
                } else {
                    let how_much = match t {
                        _ if amount == [0xff; 32] => format!("all its {what}"),
                        Some(t) => format!("up to {}", token_amount(t, &amount)),
                        None => format!("up to {} units", uint256(&amount)),
                    };
                    self.warnings.push(format!("lets another spend its {what}"));
                    self.said.push(format!("approves {how_much}"));
                    self.pages.push(page(
                        "Approve!",
                        how_much,
                        address(&spender),
                        format!(
                            "That address may spend this account's {what} without asking, until it's revoked."
                        ),
                    ));
                }
                if t.is_none() {
                    self.stranger(contract);
                }
            }
            (None, t) => {
                self.unreadable = true;
                let what = match data {
                    [] => String::from("no data"),
                    [a, b, c, d, ..] => {
                        format!("function {}, {}", hex(&[*a, *b, *c, *d]), plural(data.len() as u64, "byte"))
                    }
                    _ => plural(data.len() as u64, "byte"),
                };
                let prose = match t {
                    Some(t) => format!(
                        "A call to {}'s contract that maki can't spell out. It acts as this account: it may move its {}.",
                        t.symbol, t.symbol
                    ),
                    None => String::from(
                        "maki can't tell what it does. It acts as this account: it may move its tokens of that contract, and any it's let it spend.",
                    ),
                };
                self.pages.push(page(
                    "Contract call",
                    "maki can't read it",
                    format!("{}\n{what}", address(contract)),
                    prose,
                ));
            }
        }
    }

    /// The page for a contract maki doesn't know a token by.
    fn stranger(&mut self, contract: &Address) {
        self.unreadable = true;
        self.pages.push(page(
            "Token",
            "one maki doesn't know",
            address(contract),
            "Check its contract's address: maki can't tell what the contract does.",
        ));
    }

    /// When it expires, if that's out of the ordinary: already past, or further off than an hour
    /// (than a day, and Tron won't take it until the day before). Judged by maki's clock, if it has
    /// one, or by when the transaction says it was made.
    fn expiry(&mut self, now: Option<u64>) {
        let expiration = self.tx.expiration;
        let (then, past) = match (now, self.tx.timestamp) {
            (Some(now), _) => (now, "That's past, by maki's clock: Tron won't take it."),
            (None, made) if made > 0 => (made, "That's before it says it was made: Tron won't take it."),
            _ => {
                self.pages.push(page(
                    "Expires",
                    utc(expiration),
                    "",
                    "maki can't tell how far off that is: the transaction doesn't say when it was made.",
                ));
                return;
            }
        };
        if expiration <= then {
            self.warnings.push(String::from("already expired"));
            self.pages.push(page("Expired!", utc(expiration), "", past));
        } else if expiration - then > DAY {
            self.warnings.push(String::from("can only be sent later"));
            self.pages.push(page(
                "Expires late!",
                utc(expiration),
                "",
                "Tron takes a transaction only in the day before it expires: whoever has this one can send it then, and not before.",
            ));
        } else if expiration - then > HOUR {
            self.pages.push(page(
                "Valid for",
                span(expiration - then),
                "",
                format!("Whoever has it can send it until {}.", utc(expiration)),
            ));
        }
    }

    /// The most the fee can be, and the page that says what it's for: bandwidth (free while the
    /// account has some), energy (for a call, up to its fee limit), a new account made, a memo.
    fn fee(&self) -> (Page, u128) {
        let bytes = bandwidth(self.tx.size);
        let burnt = bytes as u128 * SUN_PER_BYTE as u128;
        let (mut max, mut prose) = match &self.tx.contract {
            Contract::Transfer { .. } | Contract::TransferToken { .. } => (
                burnt.max(NEW_ACCOUNT_FEE as u128),
                format!(
                    "{} if the recipient is new to Tron. If not, {} for {bytes} bytes of bandwidth, or nothing while this account has bandwidth left: {FREE_BANDWIDTH} bytes free a day.",
                    trx(NEW_ACCOUNT_FEE as u128),
                    trx(burnt)
                ),
            ),
            Contract::Call { .. } => {
                let limit = self.tx.fee_limit as u128;
                let energy = if limit == 0 {
                    String::from("No TRX burnt for energy: the call has only what this account has staked.")
                } else {
                    format!(
                        "Up to {} burnt for energy, if this account's staked energy runs short.",
                        trx(limit)
                    )
                };
                (
                    limit + burnt,
                    format!(
                        "{energy} {} for {bytes} bytes of bandwidth, if its bandwidth does: {FREE_BANDWIDTH} bytes free a day.",
                        trx(burnt)
                    ),
                )
            }
            _ => (
                burnt,
                format!(
                    "For {bytes} bytes of bandwidth, only if this account has none left: {FREE_BANDWIDTH} bytes free a day."
                ),
            ),
        };
        if !self.tx.memo.is_empty() {
            max += MEMO_FEE as u128;
            prose.push_str(&format!(" And {} for the memo.", trx(MEMO_FEE as u128)));
        }
        (page("Max fee", trx(max), "", prose), max)
    }
}

/// The network a transaction calling `contract` is for, if maki can tell: a token's contract is on
/// one network alone. Tron's transactions don't name theirs, and a computer that said Nile of one
/// for Tron's own network would have its owner spend real money as play money.
fn network_of(contract: &Address) -> Option<Network> {
    tokens::TOKENS.iter().find(|t| t.contract == *contract).map(|t| t.network)
}

/// The pages the owner goes through before `me` signs `tx`, on `network`, and the line that goes
/// with them. `now` is maki's clock (milliseconds since 1970), if it has one.
pub fn review(tx: &Transaction, me: &Address, network: Network, now: Option<u64>) -> Result<Review, Error> {
    if tx.contract.owner() != me {
        return Err(Error::NotMine);
    }
    if let Contract::Call { contract, .. } = &tx.contract {
        match (network, network_of(contract)) {
            (Network::Nile, Some(Network::Tron)) => {
                return Err(Error::Invalid(
                    "a call to a token of Tron's own network: it's for that network, not Nile",
                ));
            }
            (Network::Tron, Some(Network::Nile)) => {
                return Err(Error::Invalid(
                    "a call to a token of Nile's: it's for Nile, not Tron's own network",
                ));
            }
            _ => {}
        }
    }
    let mut r =
        Reading { tx, network, pages: Vec::new(), said: Vec::new(), warnings: Vec::new(), unreadable: false };
    r.pages.push(match network {
        Network::Tron => page("Network", "Tron", "", ""),
        Network::Nile => page(
            "Network",
            "Nile (test)",
            "",
            "Tron's test network, whose TRX is worth nothing. A transaction doesn't name its network: made for Tron's own, it would work there.",
        ),
    });
    r.contract()?;
    if !tx.memo.is_empty() {
        let p = match text(&tx.memo) {
            Some(t) => page("Memo", "", t, "Everyone can read it, on chain."),
            None => page("Memo", "in hex", hex(&tx.memo), "Everyone can read it, on chain."),
        };
        if p.mono.len() > MAX_SHOWN {
            return Err(Error::Invalid("a memo too long to show on maki's screen"));
        }
        r.pages.push(p);
    }
    if tx.permission != 0 {
        r.pages.push(page(
            "Permission",
            format!("active #{}", tx.permission),
            "",
            format!(
                "It's signed under one of this account's active permissions, which may need others' signatures too: with more than one, Tron charges {} more.",
                trx(MULTI_SIGN_FEE as u128)
            ),
        ));
    }
    r.expiry(now);
    let (fee, max) = r.fee();
    r.pages.push(fee);
    let what = if !r.warnings.is_empty() {
        let mut w: Vec<&str> = Vec::new();
        for x in &r.warnings {
            if !w.contains(&x.as_str()) {
                w.push(x);
            }
        }
        format!("{}!{}", w.join(", "), if r.unreadable { " And maki can't read all of it" } else { "" })
    } else if r.unreadable {
        String::from("maki can't read all of it")
    } else {
        r.said.join(", ")
    };
    let mut summary = format!("{what}; fee up to {}", trx(max));
    // the line under the question is short (the pages say it all): cut, if it must be, at a character
    if summary.len() > MAX_SUMMARY {
        let mut end = MAX_SUMMARY - '…'.len_utf8();
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary.push('…');
    }
    Ok(Review { pages: r.pages, summary })
}
