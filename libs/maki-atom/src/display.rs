//! What the owner reads on maki's review screen before a sign doc is signed, as pages: the chain;
//! what each message does (coins sent, here or over IBC, and to whom; staking, rewards, votes),
//! each amount exact, in the coin's own units if maki knows it; a memo; and the fee, in full. A
//! change of where the account's staking rewards go is said loudly, an IBC memo the other chain may
//! act on is flagged, and so is a message maki can't read, shown as it's written. Every message
//! maki reads must be this account's, and the chain must be on the network the computer said.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::chains::{self, Chain, Network};
use crate::doc::{Coin, Msg, SignDoc};
use crate::{address, bech32};

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

/// What maki's review screen shows of a sign doc: its pages, then the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    /// What the owner goes through, a page at a time.
    pub pages: Vec<Page>,
    /// The line under the question: what it does, and the fee.
    pub summary: String,
}

/// Why maki won't show a sign doc for this account to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// For a chain of the other kind of network than the computer said: that chain.
    Network(&'static Chain),
    /// Another account's: not this one's to sign.
    NotMine,
    /// maki can't show it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Network(c) if c.network == Network::Test => {
                write!(f, "a test network's transaction ({}), sent as a main network's", c.id)
            }
            Error::Network(c) => {
                write!(
                    f,
                    "a main network's transaction ({}), sent as a test network's: its coins are real",
                    c.id
                )
            }
            Error::NotMine => f.write_str("another account's transaction, not this one's to sign"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The longest value a page can have (maki's review screen's limit).
pub const MAX_VALUE: usize = 128;
/// The most text a page shows in its fixed-width text or its prose (maki's review screen's limit).
pub const MAX_SHOWN: usize = 4096;

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

/// A coin, as the pages say it.
struct Said {
    /// Its amount: in the coin's own units if maki knows it on this chain (`5.25 ATOM`), else in its
    /// smallest units (`42 units`).
    amount: String,
    /// What a page says of it beside its amount: where a coin from another chain came from, or the
    /// denom of one maki doesn't know.
    about: Option<String>,
    /// As the line under the question says it: a coin maki doesn't know isn't named there.
    brief: String,
    /// The coin, if maki knows it.
    known: Option<chains::Known>,
}

/// A coin as the pages say it, looked up once: a coin from another chain is known by hashing the
/// paths it could have come by.
fn said(chain: &'static Chain, coin: &Coin) -> Said {
    let known = chains::token(chain, &coin.denom);
    match known {
        Some(k) => {
            let amount = format!("{} {}", decimals(coin.amount, k.token.decimals), k.token.symbol);
            let about = k
                .from
                .map(|(from, channel)| format!("{} from {}, by IBC ({channel}).", k.token.symbol, the(from)));
            Said { brief: amount.clone(), amount, about, known }
        }
        None => Said {
            amount: format!("{} units", coin.amount),
            about: Some(format!("Of {}, in its smallest units: maki doesn't know it.", coin.denom)),
            brief: format!("{} units of a coin maki doesn't know", coin.amount),
            known,
        },
    }
}

/// An amount of a coin, as a page says it: in the coin's own units if maki knows it on this chain
/// (`5.25 ATOM`), else in its smallest units (`42 units`).
pub fn amount(chain: &'static Chain, coin: &Coin) -> String { said(chain, coin).amount }

/// A chain's name as a sentence says it: `the Cosmos Hub`, `Osmosis`, `the Osmosis testnet`.
fn the(chain: &Chain) -> String {
    if chain.network == Network::Test || chain.name == "Cosmos Hub" {
        format!("the {}", chain.name)
    } else {
        chain.name.into()
    }
}

fn plural(n: u64, unit: &str) -> String { format!("{n} {unit}{}", if n == 1 { "" } else { "s" }) }

/// A span of time (seconds) in its two largest units, rounded down: `21 days`, `14 days 1 hour`.
pub fn span(seconds: u64) -> String {
    let (days, hours, minutes) = (seconds / 86_400, seconds % 86_400 / 3_600, seconds % 3_600 / 60);
    let parts = if days > 0 {
        [(days, "day"), (hours, "hour")]
    } else if hours > 0 {
        [(hours, "hour"), (minutes, "minute")]
    } else {
        [(minutes, "minute"), (seconds % 60, "second")]
    };
    match parts {
        [(a, u), (0, _)] => plural(a, u),
        [(0, _), (b, v)] => plural(b, v),
        [(a, u), (b, v)] => format!("{} {}", plural(a, u), plural(b, v)),
    }
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

/// A time (nanoseconds since 1970, as IBC counts) as the owner reads it: `2026-10-02 05:00:00 UTC`.
pub fn utc(nanos: u64) -> String {
    let secs = nanos / 1_000_000_000;
    let (y, m, d) = date(secs / 86_400);
    let s = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

/// A vote's weight, in `WHOLE`ths, as a percentage: `70%`, `33.3333333333333333%`.
fn percent(weight: u64) -> String { format!("{}%", decimals(weight as u128, 16)) }

struct Reading<'a> {
    doc: &'a SignDoc,
    chain: &'static Chain,
    /// This account's address on the chain.
    me: String,
    pages: Vec<Page>,
    /// What it does, as the line under the question says it.
    said: Vec<String>,
    /// What it does that the owner must not miss.
    warnings: Vec<&'static str>,
    /// Something maki can't read.
    unreadable: bool,
    /// How many validators' rewards it claims, and where the line says so.
    claims: Option<(usize, usize)>,
}

impl Reading<'_> {
    /// A prose that says so, if an address is this account's.
    fn whose(&self, address: &str) -> &'static str {
        if address == self.me { "That's this account." } else { "" }
    }

    fn send(&mut self, coin: &Coin, to: &str) -> String {
        let s = said(self.chain, coin);
        let prose = [s.about.unwrap_or_default(), self.whose(to).into()];
        let prose = prose.iter().filter(|p| !p.is_empty()).cloned().collect::<Vec<_>>().join(" ");
        self.pages.push(page("Send", s.amount, to, prose));
        s.brief
    }

    fn msg(&mut self, m: &Msg) {
        let chain = self.chain;
        let days = span(chain.unbonding as u64);
        match m {
            Msg::Send { to, amount, .. } => {
                let sent: Vec<String> = amount.iter().map(|c| self.send(c, to)).collect();
                self.said.push(format!("sends {}", sent.join(" and ")));
            }
            Msg::MultiSend { outputs, .. } => {
                let mut sent: Vec<Coin> = Vec::new();
                let mut payments = 0;
                for (to, coins) in outputs {
                    for c in coins {
                        self.send(c, to);
                        payments += 1;
                        match sent.iter_mut().find(|s| s.denom == c.denom) {
                            // the outputs add up to the input, which is at most 2^128 - 1
                            Some(s) => s.amount = s.amount.saturating_add(c.amount),
                            None => sent.push(c.clone()),
                        }
                    }
                }
                self.said.push(match sent.as_slice() {
                    [one] if payments > 1 => {
                        format!("sends {} in {payments} payments", said(chain, one).brief)
                    }
                    [one] => format!("sends {}", said(chain, one).brief),
                    _ => format!("sends {payments} payments"),
                });
            }
            Msg::Delegate { validator, amount: a, .. } => {
                let a = amount(chain, a);
                self.said.push(format!("stakes {a}"));
                self.pages.push(page(
                    "Stake",
                    a,
                    validator,
                    format!(
                        "With that validator. Staked, it stays this account's and earns rewards, but can't be spent: unstaking takes {days}. If the validator breaks the chain's rules, part of it can be lost."
                    ),
                ));
            }
            Msg::Undelegate { validator, amount: a, .. } => {
                let a = amount(chain, a);
                self.said.push(format!("unstakes {a}"));
                self.pages.push(page(
                    "Unstake",
                    a,
                    validator,
                    format!(
                        "From that validator. It comes back to this account in {days}; until then it earns nothing and can't be spent."
                    ),
                ));
            }
            Msg::Redelegate { from, to, amount: a, .. } => {
                let a = amount(chain, a);
                self.said.push(format!("restakes {a}"));
                self.pages.push(page(
                    "Restake",
                    a,
                    format!("from {from}\nto {to}"),
                    format!("Moved from the first validator to the second at once, staked all the while. It can't be moved on again for {days}."),
                ));
            }
            Msg::CancelUnstake { validator, amount: a, height, .. } => {
                let a = amount(chain, a);
                self.said.push(format!("stakes {a} again"));
                self.pages.push(page(
                    "Cancel unstaking",
                    a,
                    validator,
                    format!("Staked with that validator again: of what began unstaking at block {height}."),
                ));
            }
            Msg::ClaimRewards { validator, .. } => {
                self.claims = match self.claims {
                    None => {
                        self.said.push(String::from("claims rewards"));
                        Some((self.said.len() - 1, 1))
                    }
                    Some((at, n)) => Some((at, n + 1)),
                };
                self.pages.push(page(
                    "Claim rewards",
                    "of staking",
                    validator,
                    "What this account has earned staking with that validator is paid out: to this account, or to the address its rewards are set to go to.",
                ));
            }
            Msg::RewardsTo { to, .. } if *to == self.me => {
                self.said.push(String::from("has its rewards paid to it"));
                self.pages.push(page(
                    "Rewards to",
                    "this account",
                    to,
                    "Its staking rewards are paid to this account itself, from now on.",
                ));
            }
            Msg::RewardsTo { to, .. } => {
                self.warnings.push("sends its staking rewards elsewhere");
                self.pages.push(page(
                    "Rewards to!",
                    "another address",
                    to,
                    "Every staking reward this account earns would be paid to that address, until it's set back.",
                ));
            }
            Msg::Donate { amount: coins, .. } => {
                for c in coins {
                    let s = said(chain, c);
                    self.said.push(format!("donates {}", s.brief));
                    let prose = format!(
                        "To {}'s community pool, which its governance spends: it doesn't come back.{}",
                        the(chain),
                        s.about.map(|a| format!(" {a}")).unwrap_or_default()
                    );
                    self.pages.push(page("Donate", s.amount, "", prose));
                }
            }
            Msg::Vote { proposal, vote, note, .. } => {
                self.said.push(format!("votes {} on proposal {proposal}", vote.name().to_lowercase()));
                let prose = format!("On proposal {proposal}. Until voting ends, another vote replaces it.");
                self.pages.push(page("Vote", vote.name(), note.as_str(), prose));
            }
            Msg::SplitVote { proposal, options, .. } => {
                self.said.push(format!("splits its vote on proposal {proposal}"));
                let lines: Vec<String> =
                    options.iter().map(|(v, w)| format!("{} {}", v.name(), percent(*w))).collect();
                self.pages.push(page(
                    "Vote",
                    "split",
                    lines.join("\n"),
                    format!(
                        "On proposal {proposal}: this account's vote, split as it says. Until voting ends, another vote replaces it."
                    ),
                ));
            }
            Msg::Deposit { proposal, amount: coins, .. } => {
                for c in coins {
                    let s = said(chain, c);
                    self.said.push(format!("deposits {} on proposal {proposal}", s.brief));
                    let prose = format!(
                        "On proposal {proposal}. Whether it comes back depends on how the proposal fares: it can be burnt.{}",
                        s.about.map(|a| format!(" {a}")).unwrap_or_default()
                    );
                    self.pages.push(page("Deposit", s.amount, "", prose));
                }
            }
            Msg::Transfer { receiver, channel, token, timeout_height, timeout, memo, .. } => {
                self.transfer(receiver, channel, token, timeout_height.1, *timeout, memo)
            }
            Msg::Revoke { grantee, kind, .. } => {
                self.said.push(String::from("revokes a permission"));
                self.pages.push(page(
                    "Revoke",
                    "a permission",
                    format!("{grantee}\n{kind}"),
                    "That address may no longer send this kind of message for this account.",
                ));
            }
            Msg::RevokeAllowance { grantee, .. } => {
                self.said.push(String::from("revokes a fee allowance"));
                self.pages.push(page(
                    "Revoke",
                    "a fee allowance",
                    grantee,
                    "That address may no longer pay its fees from this account.",
                ));
            }
            Msg::Other { kind, value } => {
                self.unreadable = true;
                self.pages.push(page(
                    "Message",
                    "maki can't read it",
                    format!("{kind}\n{value}"),
                    "As it's written. If it's this account's to sign, it can do anything this account can.",
                ));
            }
        }
    }

    fn transfer(
        &mut self,
        receiver: &str,
        channel: &str,
        token: &Coin,
        height: u64,
        timeout: u64,
        memo: &str,
    ) {
        let chain = self.chain;
        let to = chains::route(chain, channel);
        let s = said(chain, token);
        let mut prose = Vec::new();
        match (to, s.known) {
            // a coin going home, the way it came
            (Some(c), Some(chains::Known { token, from: Some((from, _)) })) if from == c => {
                prose.push(format!("{} back to {}, by IBC ({channel}).", token.symbol, the(c)))
            }
            (Some(c), _) => {
                prose.extend(s.about);
                prose.push(format!("To {}, by IBC ({channel}).", the(c)));
            }
            (None, _) => {
                prose.extend(s.about);
                prose.push(format!("By IBC ({channel}), to a chain maki doesn't know: check the channel."));
            }
        }
        if let Some(c) = to {
            if bech32::decode(receiver).is_none_or(|(prefix, _)| prefix != c.prefix) {
                prose.push(format!("The receiver isn't an address of {}'s: it would send it back.", the(c)));
            }
        }
        prose.push(match (height, timeout) {
            (0, t) => format!("If it hasn't arrived by {}, it comes back.", utc(t)),
            (h, 0) => format!("If it hasn't arrived by block {h} there, it comes back."),
            (h, t) => format!("If it hasn't arrived by {} or by block {h} there, it comes back.", utc(t)),
        });
        self.said.push(match to {
            Some(c) => format!("sends {} to {}", s.brief, the(c)),
            None => format!("sends {} over IBC", s.brief),
        });
        self.pages.push(page("Send over IBC", s.amount, receiver, prose.join(" ")));
        if memo.is_empty() {
            return;
        }
        // middleware on the other chain reads a memo of JSON as instructions: to forward the coins
        // on (to someone other than the receiver), or call a contract with them
        if memo.trim_start().starts_with('{') {
            self.unreadable = true;
            self.pages.push(page(
                "IBC memo",
                "maki can't read it",
                memo,
                "Instructions the chain at the other end may follow: to send the coins on, to someone else, or swap them.",
            ));
        } else {
            self.pages.push(page(
                "IBC memo",
                "",
                memo,
                "For the chain at the other end. Everyone can read it.",
            ));
        }
    }

    /// The fee's page, and the fee as the line under the question says it.
    fn fee(&self) -> (Page, String) {
        let (chain, fee) = (self.chain, &self.doc.fee);
        let coins: Vec<Said> = fee.amount.iter().map(|c| said(chain, c)).collect();
        let all: Vec<&str> = coins.iter().map(|s| s.amount.as_str()).collect();
        let what = if all.is_empty() { String::from("nothing") } else { all.join(" + ") };
        let mut prose = vec![format!("For up to {} gas.", fee.gas)];
        prose.extend(coins.iter().filter_map(|s| s.about.clone()));
        if let Some(g) = &fee.granter {
            prose.push(format!("Paid from the fee allowance {g} gave this account."));
        }
        if let Some(p) = fee.payer.as_ref().filter(|p| **p != self.me) {
            prose.push(format!("Paid by {p}, which signs it too."));
        }
        let page = if what.len() <= MAX_VALUE {
            page("Max fee", what.clone(), "", prose.join(" "))
        } else {
            page("Max fee", plural(all.len() as u64, "coin"), all.join("\n"), prose.join(" "))
        };
        let others = fee.granter.is_some() || fee.payer.as_ref().is_some_and(|p| *p != self.me);
        let free = fee.amount.iter().all(|c| c.amount == 0);
        let line = match (others, free) {
            (true, _) => String::from("another pays the fee"),
            (false, true) => String::from("no fee"),
            (false, false) => format!("fee up to {what}"),
        };
        (page, line)
    }
}

/// The pages the owner goes through before the account with address bytes `me` signs `doc`, which
/// the computer said is for `network`, and the line that goes with them.
pub fn review(doc: &SignDoc, me: &[u8; 20], network: Network) -> Result<Review, Error> {
    let chain = doc.chain;
    if chain.network != network {
        return Err(Error::Network(chain));
    }
    let me = address(chain, me);
    if doc.msgs.iter().any(|m| m.signer().is_some_and(|s| s != me)) {
        return Err(Error::NotMine);
    }
    let mut r = Reading {
        doc,
        chain,
        me,
        pages: Vec::new(),
        said: Vec::new(),
        warnings: Vec::new(),
        unreadable: false,
        claims: None,
    };
    r.pages.push(match chain.network {
        Network::Main => page("Network", chain.name, chain.id, ""),
        Network::Test => page(
            "Network",
            chain.name,
            chain.id,
            format!("A test network: its {} is worth nothing.", chain.coin.symbol),
        ),
    });
    for m in &doc.msgs {
        r.msg(m);
    }
    if let Some((at, n)) = r.claims.filter(|&(_, n)| n > 1) {
        r.said[at] = format!("claims rewards from {n} validators");
    }
    if !doc.memo.is_empty() {
        r.pages.push(page("Memo", "", doc.memo.as_str(), "Everyone can read it, on chain."));
    }
    if doc.timeout_height > 0 {
        r.pages.push(page(
            "Valid until",
            format!("block {}", doc.timeout_height),
            "",
            "The chain won't take it in a block after that.",
        ));
    }
    let (fee, line) = r.fee();
    r.pages.push(fee);
    if r.pages.iter().any(|p| p.mono.len() > MAX_SHOWN || p.prose.len() > MAX_SHOWN) {
        return Err(Error::Invalid("too long to show on maki's screen"));
    }
    let what = if !r.warnings.is_empty() {
        let mut w: Vec<&str> = Vec::new();
        for x in &r.warnings {
            if !w.contains(x) {
                w.push(x);
            }
        }
        format!("{}!{}", w.join(", "), if r.unreadable { " And maki can't read all of it" } else { "" })
    } else if r.unreadable {
        String::from("maki can't read all of it")
    } else {
        r.said.join(", ")
    };
    let mut summary = format!("{what}; {line}");
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
