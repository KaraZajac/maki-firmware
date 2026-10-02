//! What the owner reads on maki's review screen before a Stellar transaction is signed: each
//! operation in turn, as pages. What it sends, how much and to whom (an account with an ID as
//! such, and the account it is); trades, trustlines and what an issuer does with its asset;
//! anything that changes who controls the account (signers, weights, thresholds, merging it
//! away), loudly; then the memo, how long it's valid, the most the fee can be, and whose
//! transaction it is, on which network. Assets maki doesn't know show their issuer, and anything
//! maki can't read (what a contract is asked to do) is flagged as such.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::assets::{KNOWN, known, lookalike};
use crate::soroban::{
    Address, Authorized, Credentials, Entry, Executable, HostFunction, Invoke, Preimage, asset_contract,
};
use crate::transaction::{
    Asset, Body, Claimant, Code, Kind, Memo, Muxed, Operation, Predicate, Price, SetOptions, SignerKey,
    Sponsored, Transaction, TrustAsset, TrustLineAsset, flags, pool_id,
};
use crate::{Envelope, Hash, Key, Network, address, strkey};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
}

fn page(heading: &str, value: impl Into<String>, mono: impl Into<String>, prose: impl Into<String>) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

/// What the owner goes through before a transaction is signed: the pages, and a line about them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub pages: Vec<Page>,
    /// The line under the question: what it does, and the most the fee can be.
    pub summary: String,
}

/// Why maki won't show a transaction it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Nothing in it is this account's to sign: not its source, none of its operations', not the
    /// fee bump's payer.
    NotMine,
    /// More pages than maki's review screen goes through.
    TooMuch,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::NotMine => "not this account's to sign: it doesn't act as this account",
            Error::TooMuch => "too much to go through on maki's screen",
        })
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The most pages maki's review screen goes through.
pub const MAX_PAGES: usize = 128;
/// The most lines a list on a page (claimants, a footprint's contracts) runs to.
const MAX_LINES: usize = 12;

/// `n` with `places` decimals, exactly, without trailing zeros: `decimals(1500, 3)` is `1.5`.
pub fn decimals(n: u128, places: u8) -> String {
    let digits = n.to_string();
    let places = places as usize;
    if places == 0 {
        return digits;
    }
    let padded =
        if digits.len() <= places { "0".repeat(places + 1 - digits.len()) + &digits } else { digits };
    let (whole, frac) = padded.split_at(padded.len() - places);
    match frac.trim_end_matches('0') {
        "" => whole.into(),
        frac => format!("{whole}.{frac}"),
    }
}

/// An amount in stroops (any asset's are in 10,000,000ths), exactly: `12.5`.
pub fn amount(stroops: i64) -> String {
    let n = decimals(stroops.unsigned_abs() as u128, 7);
    if stroops < 0 { format!("-{n}") } else { n }
}

/// Stroops, exactly, in XLM: `0.00001 XLM`.
pub fn xlm(stroops: u128) -> String { format!("{} XLM", decimals(stroops, 7)) }

/// A Unix time as a date, in UTC: `2027-01-01 00:00:00 UTC`.
pub fn date(unix: u64) -> String {
    // days to a civil date (Howard Hinnant's algorithm), on the proleptic Gregorian calendar
    let (days, secs) = ((unix / 86_400) as i64, unix % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", secs / 3_600, secs % 3_600 / 60, secs % 60)
}

/// Seconds as people say them: `1 day, 2 hours`.
pub fn duration(seconds: u64) -> String {
    let parts = [
        (seconds / 86_400, "day"),
        (seconds % 86_400 / 3_600, "hour"),
        (seconds % 3_600 / 60, "minute"),
        (seconds % 60, "second"),
    ];
    let said: Vec<String> = parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, unit)| format!("{n} {unit}{}", if *n == 1 { "" } else { "s" }))
        .collect();
    if said.is_empty() { String::from("0 seconds") } else { said.join(", ") }
}

fn gcd(a: u128, b: u128) -> u128 { if b == 0 { a } else { gcd(b, a % b) } }

/// The most decimal places a price is written with: past that, a fraction reads better.
const MAX_PRICE_PLACES: u32 = 12;

/// A price, `n` over `d` (both above zero): exactly, as a decimal if it has a short one (`0.11`),
/// or as the fraction (`1/3`).
pub fn price(p: &Price) -> String {
    let (n, d) = (p.n.max(0) as u128, p.d.max(1) as u128);
    let g = gcd(n, d).max(1);
    let (n, d) = (n / g, d / g);
    let (mut rest, mut twos, mut fives) = (d, 0u32, 0u32);
    while rest % 2 == 0 {
        rest /= 2;
        twos += 1;
    }
    while rest % 5 == 0 {
        rest /= 5;
        fives += 1;
    }
    let places = twos.max(fives);
    match (rest, places <= MAX_PRICE_PLACES) {
        // n times 10^12 fits: n is below 2^31
        (1, true) => decimals(n * 10u128.pow(places) / d, places as u8),
        _ => format!("{n}/{d}"),
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// An account flag's name.
fn account_flags(f: u32) -> String {
    let names = [
        (flags::AUTH_REQUIRED, "auth required"),
        (flags::AUTH_REVOCABLE, "revocable"),
        (flags::AUTH_IMMUTABLE, "immutable"),
        (flags::AUTH_CLAWBACK_ENABLED, "clawback"),
    ];
    names.iter().filter(|(bit, _)| f & bit != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

fn trustline_flags(f: u32) -> String {
    let names = [
        (flags::AUTHORIZED, "authorized"),
        (flags::AUTHORIZED_TO_MAINTAIN_LIABILITIES, "authorized to keep what it has"),
        (flags::TRUSTLINE_CLAWBACK_ENABLED, "clawback"),
    ];
    names.iter().filter(|(bit, _)| f & bit != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

/// A list on a page: each line, or as many as fit and how many more.
fn lines(all: Vec<String>) -> String {
    let n = all.len();
    let mut shown: Vec<String> = all.into_iter().take(MAX_LINES).collect();
    if n > MAX_LINES {
        shown.push(format!("and {} more", n - MAX_LINES));
    }
    shown.join("\n")
}

struct Reading<'a> {
    tx: &'a Transaction,
    me: &'a Key,
    network: Network,
    pages: Vec<Page>,
    /// Something maki can't read.
    unreadable: bool,
    /// What it does that the owner must not miss.
    warnings: Vec<&'static str>,
    /// What it does as this account, a few words each, for the summary.
    said: Vec<String>,
    /// XLM it sends from this account, exactly, in stroops, and in how many payments: if they're
    /// all it does, the summary adds them up.
    sent_xlm: u128,
    xlm_payments: usize,
    /// Assets that maki doesn't know whose page has been shown.
    explained: Vec<Asset>,
    /// Pools the transaction names the assets of (by a trustline to them).
    pools: Vec<(Hash, Asset, Asset)>,
}

impl Reading<'_> {
    fn is_me(&self, key: &Key) -> bool { key == self.me }

    /// An account, as a page shows it: this account, or its address.
    fn who(&self, key: &Key) -> String { if self.is_me(key) { "this account".into() } else { address(key) } }

    /// A destination, as a page shows it: an account with an ID shows as such, and the account
    /// it is.
    fn whom(&self, m: &Muxed) -> String { muxed(m, self.me) }

    /// An asset's name: XLM, a code maki knows by its issuer, or a code (one that borrows a known
    /// asset's says it's another issuer's).
    fn name(&self, asset: &Asset) -> String {
        match asset {
            Asset::Native => "XLM".into(),
            Asset::Credit { code, .. } if lookalike(asset, self.network).is_some() => {
                format!("{} (another issuer's)", code.as_str())
            }
            Asset::Credit { code, .. } => code.as_str().into(),
        }
    }

    /// An amount of an asset: `5.25 USDC`.
    fn amount(&self, n: i64, asset: &Asset) -> String { format!("{} {}", amount(n), self.name(asset)) }

    /// A page for an asset maki doesn't know, once: its code and issuer.
    fn explain(&mut self, asset: &Asset) {
        let Asset::Credit { code, issuer } = asset else { return };
        if known(asset, self.network).is_some() || self.explained.contains(asset) {
            return;
        }
        self.explained.push(*asset);
        let code = code.as_str();
        let mono = format!("{code}\nissued by\n{}", self.who(issuer));
        self.pages.push(match lookalike(asset, self.network) {
            Some(k) => page(
                &format!("Another {code}!"),
                "not the one maki knows",
                mono,
                format!(
                    "Anyone can issue an asset called {code}: this one's issuer isn't the one {} issues {code} from.",
                    k.by
                ),
            ),
            None => page(
                "Asset",
                "one maki doesn't know",
                mono,
                "Anyone can issue an asset of any name: what it's worth depends on who issued it.",
            ),
        });
    }

    /// What a page adds when an operation isn't simply this account's: whose it is.
    fn acting(&self, op: &Operation) -> String {
        let actor = op.source.unwrap_or(self.tx.source);
        if self.is_me(&actor.key) {
            match (actor.id, self.is_me(&self.tx.source.key)) {
                (Some(id), _) => format!("As this account, ID {id}."),
                (None, false) => String::from("As this account."),
                (None, true) => String::new(),
            }
        } else {
            format!("As {}, not this account.", address(&actor.key))
        }
    }

    fn push(&mut self, op: &Operation, heading: &str, value: String, mono: String, prose: &str) {
        let acting = self.acting(op);
        let prose = match (prose.is_empty(), acting.is_empty()) {
            (_, true) => prose.into(),
            (true, false) => acting,
            (false, false) => format!("{prose} {acting}"),
        };
        self.pages.push(page(heading, value, mono, prose));
    }

    /// Something it does as this account, for the summary.
    fn say(&mut self, op: &Operation, what: String) {
        if self.is_me(&self.tx.source_of(op)) {
            self.said.push(what);
        }
    }

    fn warn(&mut self, op: &Operation, warning: &'static str) {
        if self.is_me(&self.tx.source_of(op)) && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    /// XLM sent from this account, exactly that much, for the summary's total.
    fn sends(&mut self, op: &Operation, asset: &Asset, n: i64) {
        if self.is_me(&self.tx.source_of(op)) && *asset == Asset::Native {
            self.sent_xlm += n.max(0) as u128;
            self.xlm_payments += 1;
        }
    }

    fn path(&self, path: &[Asset]) -> String {
        if path.is_empty() {
            return String::new();
        }
        let names: Vec<String> = path.iter().map(|a| self.name(a)).collect();
        format!(" Through {}.", names.join(", "))
    }

    fn operation(&mut self, op: &Operation) {
        let actor = self.tx.source_of(op);
        let mine = self.is_me(&actor);
        match &op.body {
            Body::CreateAccount { destination, balance } => {
                self.push(op, "New account", xlm(*balance as u128), self.who(destination), "Its first XLM.");
                self.say(op, format!("opens an account with {}", xlm(*balance as u128)));
            }
            Body::Payment { destination, asset, amount } => {
                let value = self.amount(*amount, asset);
                self.push(op, "Send", value.clone(), self.whom(destination), "");
                self.explain(asset);
                if mine {
                    self.sends(op, asset, *amount);
                    self.said.push(format!("sends {value}"));
                } else if self.is_me(&destination.key) {
                    self.said.push(format!("gets {value}"));
                }
            }
            Body::PathPaymentStrictSend { send_asset, send_amount, destination, asset, min, path } => {
                let (sent, got) = (self.amount(*send_amount, send_asset), self.amount(*min, asset));
                let through = self.path(path);
                if self.is_me(&destination.key) && destination.id.is_none() {
                    let prose = format!("For at least {got}, traded on Stellar's exchange.{through}");
                    self.push(op, "Swap", sent.clone(), String::new(), &prose);
                    self.say(op, format!("swaps {sent} for at least {got}"));
                } else {
                    let prose = format!("They get at least {got}, traded on Stellar's exchange.{through}");
                    self.push(op, "Send", sent.clone(), self.whom(destination), &prose);
                    self.sends(op, send_asset, *send_amount);
                    self.say(op, format!("sends {sent}"));
                }
                for a in [send_asset, asset].into_iter().chain(path) {
                    self.explain(a);
                }
            }
            Body::PathPaymentStrictReceive { send_asset, send_max, destination, asset, amount, path } => {
                let (most, got) = (self.amount(*send_max, send_asset), self.amount(*amount, asset));
                let through = self.path(path);
                if self.is_me(&destination.key) && destination.id.is_none() {
                    let prose = format!("For {got}, traded on Stellar's exchange.{through}");
                    self.push(op, "Swap", format!("up to {most}"), String::new(), &prose);
                    self.say(op, format!("swaps up to {most} for {got}"));
                } else {
                    let prose = format!("They get {got}, traded on Stellar's exchange.{through}");
                    self.push(op, "Send", format!("up to {most}"), self.whom(destination), &prose);
                    self.say(op, format!("sends up to {most}"));
                }
                for a in [send_asset, asset].into_iter().chain(path) {
                    self.explain(a);
                }
            }
            Body::ManageSellOffer { selling, buying, amount, price: p, offer } => {
                let (s, b) = (self.name(selling), self.name(buying));
                if *amount == 0 {
                    let prose =
                        format!("Its offer to sell {s} for {b} goes, and what it held back is free again.");
                    self.push(op, "Cancel offer", format!("#{offer}"), String::new(), &prose);
                    self.say(op, format!("cancels offer #{offer}"));
                } else {
                    let value = self.amount(*amount, selling);
                    let lasts = if *offer == 0 {
                        String::from("It stays on Stellar's exchange until it's taken or cancelled.")
                    } else {
                        format!("It replaces offer #{offer}.")
                    };
                    let prose = format!("For {b}, at least {} {b} each. {lasts}", price(p));
                    self.push(op, "Sell offer", value.clone(), String::new(), &prose);
                    self.say(op, format!("offers {value} for {b}"));
                }
                self.explain(selling);
                self.explain(buying);
            }
            Body::ManageBuyOffer { selling, buying, amount, price: p, offer } => {
                let (s, b) = (self.name(selling), self.name(buying));
                if *amount == 0 {
                    let prose =
                        format!("Its offer to buy {b} with {s} goes, and what it held back is free again.");
                    self.push(op, "Cancel offer", format!("#{offer}"), String::new(), &prose);
                    self.say(op, format!("cancels offer #{offer}"));
                } else {
                    let value = self.amount(*amount, buying);
                    let lasts = if *offer == 0 {
                        String::from("It stays on Stellar's exchange until it's taken or cancelled.")
                    } else {
                        format!("It replaces offer #{offer}.")
                    };
                    let prose = format!("Paying {s}, at most {} {s} each. {lasts}", price(p));
                    self.push(op, "Buy offer", value.clone(), String::new(), &prose);
                    self.say(op, format!("offers to buy {value}"));
                }
                self.explain(selling);
                self.explain(buying);
            }
            Body::CreatePassiveSellOffer { selling, buying, amount, price: p } => {
                let b = self.name(buying);
                let value = self.amount(*amount, selling);
                let prose = format!(
                    "For {b}, at least {} {b} each. It doesn't take offers at its own price; it stays until it's taken or cancelled.",
                    price(p)
                );
                self.push(op, "Passive offer", value.clone(), String::new(), &prose);
                self.say(op, format!("offers {value} for {b}"));
                self.explain(selling);
                self.explain(buying);
            }
            Body::SetOptions(o) => self.set_options(op, o),
            Body::ChangeTrust { line, limit } => self.trust(op, line, *limit),
            Body::AllowTrust { trustor, code, authorize } => {
                let code = code.as_str();
                let what = match *authorize {
                    0 => "may no longer hold or use it",
                    flags::AUTHORIZED => "may hold and use it",
                    _ => "may keep what it has, and take no more",
                };
                let prose = format!("As {code}'s issuer: that account {what}.");
                self.push(op, "Authorize", code.into(), self.who(trustor), &prose);
                self.say(op, format!("authorizes a {code} trustline"));
            }
            Body::AccountMerge { destination } => {
                if mine {
                    let prose =
                        "This account closes, and all its XLM goes to that address: it can't be taken back.";
                    self.push(op, "Close account!", "all of its XLM".into(), self.whom(destination), prose);
                    self.warn(op, "closes this account");
                } else {
                    let prose = format!("{} closes, and all its XLM goes to that address.", address(&actor));
                    self.push(op, "Close account", "all of its XLM".into(), self.whom(destination), &prose);
                    if self.is_me(&destination.key) {
                        self.said.push(String::from("gets another account's XLM"));
                    }
                }
            }
            Body::ManageData { name, value } => match value {
                Some(v) => {
                    let shown = match text(v) {
                        Some(t) => t.to_string(),
                        None => hex(v),
                    };
                    self.push(
                        op,
                        "Set data",
                        name.clone(),
                        shown,
                        "Kept on the account, for anyone to read.",
                    );
                    self.say(op, String::from("sets data"));
                }
                None => {
                    self.push(op, "Delete data", name.clone(), String::new(), "");
                    self.say(op, String::from("deletes data"));
                }
            },
            Body::BumpSequence { to } => {
                let prose = "Transactions signed for it with lower numbers can't go through any more.";
                self.push(op, "Sequence", format!("jumps to {to}"), String::new(), prose);
                self.say(op, String::from("bumps its sequence"));
            }
            Body::CreateClaimableBalance { asset, amount, claimants } => {
                let value = self.amount(*amount, asset);
                let mono = lines(claimants.iter().map(|c| self.claimant(c)).collect());
                let prose = "Set aside: those named may claim it, each when their condition holds, its times from when it's set aside.";
                self.push(op, "Claimable", value.clone(), mono, prose);
                self.explain(asset);
                self.say(op, format!("sets aside {value}"));
            }
            Body::ClaimClaimableBalance { balance } => {
                let to = if mine { String::from("this account") } else { address(&actor) };
                let prose = format!("What it holds goes to {to}, if it may claim it now.");
                self.push(
                    op,
                    "Claim",
                    "a claimable balance".into(),
                    strkey::claimable_balance(balance),
                    &prose,
                );
                self.say(op, String::from("claims a balance"));
            }
            Body::BeginSponsoringFutureReserves { sponsored } => {
                let payer = if mine { String::from("This account") } else { address(&actor) };
                let prose = format!(
                    "{payer} pays the reserves of what that account adds next in this transaction, for as long as it's there."
                );
                self.push(op, "Sponsor", "reserves".into(), self.who(sponsored), &prose);
                self.say(op, String::from("sponsors another's reserves"));
            }
            Body::EndSponsoringFutureReserves => {
                self.push(
                    op,
                    "End sponsoring",
                    String::new(),
                    String::new(),
                    "The sponsorship begun for it ends.",
                );
            }
            Body::RevokeSponsorship(s) => {
                let (what, mono) = self.sponsored(s);
                let prose =
                    "Its sponsor stops paying its reserve: its owner does, or this account's own sponsor.";
                self.push(op, "Revoke sponsorship", what.into(), mono, prose);
                self.say(op, String::from("revokes a sponsorship"));
            }
            Body::Clawback { asset, from, amount } => {
                let value = self.amount(*amount, asset);
                let prose =
                    format!("As {}'s issuer: it takes them back from that account.", self.name(asset));
                self.push(op, "Claw back", value.clone(), self.whom(from), &prose);
                self.say(op, format!("claws back {value}"));
            }
            Body::ClawbackClaimableBalance { balance } => {
                let prose = "As its asset's issuer: it takes back what it holds.";
                self.push(
                    op,
                    "Claw back",
                    "a claimable balance".into(),
                    strkey::claimable_balance(balance),
                    prose,
                );
                self.say(op, String::from("claws back a balance"));
            }
            Body::SetTrustLineFlags { trustor, asset, clear, set } => {
                let mut changes = Vec::new();
                if *set != 0 {
                    changes.push(format!("sets {}", trustline_flags(*set)));
                }
                if *clear != 0 {
                    changes.push(format!("clears {}", trustline_flags(*clear)));
                }
                if changes.is_empty() {
                    changes.push(String::from("changes nothing"));
                }
                let name = self.name(asset);
                let prose =
                    format!("As {name}'s issuer, on that account's trustline: {}.", changes.join("; "));
                self.push(op, "Trustline flags", name.clone(), self.who(trustor), &prose);
                self.say(op, format!("sets a {name} trustline's flags"));
            }
            Body::LiquidityPoolDeposit { pool, max_a, max_b, min_price, max_price } => {
                let mono = strkey::liquidity_pool(pool);
                match self.pool(pool) {
                    Some((a, b)) => {
                        // its prices are of the first asset in the second's
                        let (na, nb) = (self.name(&a), self.name(&b));
                        let prose = format!(
                            "And up to {}, at {} to {} {na} for each {nb}.",
                            self.amount(*max_b, &b),
                            price(min_price),
                            price(max_price)
                        );
                        self.push(
                            op,
                            "Pool deposit",
                            format!("up to {}", self.amount(*max_a, &a)),
                            mono,
                            &prose,
                        );
                    }
                    None => {
                        self.unreadable = true;
                        let prose = format!(
                            "Up to {} of its first asset and {} of its second: which they are, maki can't see.",
                            amount(*max_a),
                            amount(*max_b)
                        );
                        self.push(op, "Pool deposit", "maki can't see what".into(), mono, &prose);
                    }
                }
                self.say(op, String::from("deposits into a pool"));
            }
            Body::LiquidityPoolWithdraw { pool, amount: shares, min_a, min_b } => {
                let mono = strkey::liquidity_pool(pool);
                let prose = match self.pool(pool) {
                    Some((a, b)) => {
                        format!("For at least {} and {}.", self.amount(*min_a, &a), self.amount(*min_b, &b))
                    }
                    None => {
                        self.unreadable = true;
                        format!(
                            "For at least {} of its first asset and {} of its second: which they are, maki can't see.",
                            amount(*min_a),
                            amount(*min_b)
                        )
                    }
                };
                self.push(op, "Pool withdrawal", format!("{} shares", amount(*shares)), mono, &prose);
                self.say(op, String::from("withdraws from a pool"));
            }
            Body::InvokeHostFunction(invoke) => self.invoke(op, invoke),
            Body::ExtendFootprintTtl { extend_to } => {
                let mono = self.footprint(true);
                let prose = "It pays to keep these contracts' data and code for that many more ledgers.";
                self.push(op, "Keep alive", format!("{extend_to} ledgers"), mono, prose);
                self.say(op, String::from("keeps contract data"));
            }
            Body::RestoreFootprint => {
                let mono = self.footprint(false);
                let prose = "It pays to bring these contracts' data and code back from the archive.";
                self.push(op, "Restore", "archived contract data".into(), mono, prose);
                self.say(op, String::from("restores contract data"));
            }
        }
    }

    fn claimant(&self, c: &Claimant) -> String {
        format!("{}\n {}", self.who(&c.destination), condition(&c.predicate))
    }

    fn sponsored(&self, s: &Sponsored) -> (&'static str, String) {
        match s {
            Sponsored::Account(k) => ("an account", self.who(k)),
            Sponsored::TrustLine { account, asset } => {
                let of = match asset {
                    TrustLineAsset::Asset(a) => self.name(a),
                    TrustLineAsset::Pool(p) => strkey::liquidity_pool(p),
                };
                ("a trustline", format!("{of} trustline of\n{}", self.who(account)))
            }
            Sponsored::Offer { seller, id } => ("an offer", format!("offer #{id} of\n{}", self.who(seller))),
            Sponsored::Data { account, name } => ("data", format!("\"{name}\" of\n{}", self.who(account))),
            Sponsored::ClaimableBalance(b) => ("a claimable balance", strkey::claimable_balance(b)),
            Sponsored::Signer { account, key } => {
                ("a signer", format!("{}\nof {}", key.strkey(), self.who(account)))
            }
        }
    }

    /// A pool's assets, if a trustline in this transaction names them.
    fn pool(&self, id: &Hash) -> Option<(Asset, Asset)> {
        self.pools.iter().find(|(p, ..)| p == id).map(|(_, a, b)| (*a, *b))
    }

    fn trust(&mut self, op: &Operation, line: &TrustAsset, limit: i64) {
        let up_to =
            if limit == i64::MAX { String::from("any amount") } else { format!("up to {}", amount(limit)) };
        // whose trustline: this account's, or another's
        let (holder, holds) = if self.is_me(&self.tx.source_of(op)) {
            (String::from("this account"), String::from("This account"))
        } else {
            let a = address(&self.tx.source_of(op));
            (a.clone(), a)
        };
        let hold = |what: &str| format!("Lets {holder} hold {up_to} of {what}.");
        match line {
            TrustAsset::Asset(asset) => {
                let Asset::Credit { code, issuer } = asset else { return };
                let name = self.name(asset);
                let whose = match (known(asset, self.network), lookalike(asset, self.network)) {
                    (Some(k), _) => format!("{}'s {}.", k.by, k.code),
                    (None, Some(k)) => format!(
                        "Its issuer isn't the one {} issues {} from: anyone can issue an asset called {}.",
                        k.by, k.code, k.code
                    ),
                    (None, None) => {
                        String::from("An asset maki doesn't know: anyone can issue one of any name.")
                    }
                };
                let mono = format!("{}\nissued by\n{}", code.as_str(), self.who(issuer));
                if limit == 0 {
                    let prose = format!("{whose} {holds} stops holding it: its balance of it must be 0.");
                    self.push(op, "Drop trustline", name.clone(), mono, &prose);
                    self.say(op, format!("drops its {name} trustline"));
                } else {
                    let prose = format!("{whose} {} Its reserve holds back some XLM.", hold("it"));
                    self.push(op, "Trust", name.clone(), mono, &prose);
                    self.say(op, format!("trusts {name}"));
                }
                // its page is this one
                self.explained.push(*asset);
            }
            TrustAsset::Pool { a, b, fee } => {
                let id = pool_id(a, b, *fee);
                self.pools.push((id, *a, *b));
                let mono = format!("{} / {}\n{}", self.name(a), self.name(b), strkey::liquidity_pool(&id));
                if limit == 0 {
                    let prose = format!("{holds} stops holding its shares: it must have none left.");
                    self.push(op, "Drop trustline", "pool shares".into(), mono, &prose);
                    self.say(op, String::from("drops a pool's trustline"));
                } else {
                    let prose = format!(
                        "{} Its fee: {}%.",
                        hold("that liquidity pool's shares"),
                        decimals(*fee as u128, 2)
                    );
                    self.push(op, "Trust", "pool shares".into(), mono, &prose);
                    self.say(op, String::from("trusts a pool"));
                }
                self.explain(a);
                self.explain(b);
            }
        }
    }

    fn set_options(&mut self, op: &Operation, o: &SetOptions) {
        let before = self.pages.len();
        let mine = self.is_me(&self.tx.source_of(op));
        let loud = |h: &'static str, quiet: &'static str| if mine { h } else { quiet };
        let account = self.who(&self.tx.source_of(op));
        if let Some(k) = o.inflation_destination {
            let prose = "Stellar no longer runs inflation: this does nothing that matters.";
            self.push(op, "Inflation vote", String::new(), self.who(&k), prose);
            self.say(op, String::from("sets its inflation vote"));
        }
        if o.set_flags.is_some_and(|f| f != 0) || o.clear_flags.is_some_and(|f| f != 0) {
            let mut changes = Vec::new();
            if let Some(f) = o.set_flags.filter(|f| *f != 0) {
                changes.push(format!("sets {}", account_flags(f)));
            }
            if let Some(f) = o.clear_flags.filter(|f| *f != 0) {
                changes.push(format!("clears {}", account_flags(f)));
            }
            let immutable = o.set_flags.is_some_and(|f| f & flags::AUTH_IMMUTABLE != 0);
            let mut prose = String::from("For the assets it issues.");
            if o.set_flags.is_some_and(|f| f & flags::AUTH_CLAWBACK_ENABLED != 0) {
                prose.push_str(" Clawback lets it take back what it issues from whoever holds it.");
            }
            if immutable {
                prose.push_str(
                    " Immutable can't be undone: its flags never change again, and it can't be closed.",
                );
                self.warn(op, "makes its issuer flags permanent");
            }
            let heading = if immutable { loud("Issuer flags!", "Issuer flags") } else { "Issuer flags" };
            self.push(op, heading, changes.join("; "), String::new(), &prose);
            self.say(op, String::from("sets its issuer flags"));
        }
        if let Some(w) = o.master_weight {
            if w == 0 {
                let prose = "Its own key won't sign for it any more: only its other signers will. With none, it's locked for good.";
                self.push(
                    op,
                    loud("Locks out its key!", "Master key"),
                    "weight 0".into(),
                    account.clone(),
                    prose,
                );
                self.warn(op, "locks out this account's key");
            } else {
                let prose = "How much its own key counts, against its thresholds.";
                self.push(
                    op,
                    loud("Master key!", "Master key"),
                    format!("weight {w}"),
                    account.clone(),
                    prose,
                );
                self.warn(op, "changes who can sign for this account");
            }
        }
        if o.low.is_some() || o.medium.is_some() || o.high.is_some() {
            let set: Vec<String> = [("low", o.low), ("medium", o.medium), ("high", o.high)]
                .iter()
                .filter_map(|(name, t)| t.map(|t| format!("{name} {t}")))
                .collect();
            let prose = "What its signers' weights must add up to: low for a few operations, medium for most, high to change its signers or close it.";
            self.push(op, loud("Thresholds!", "Thresholds"), set.join(", "), account.clone(), prose);
            self.warn(op, "changes who can sign for this account");
        }
        if let Some(domain) = &o.home_domain {
            let value = if domain.is_empty() { String::from("none") } else { domain.clone() };
            self.push(op, "Home domain", value, String::new(), "Where wallets look the account up.");
            self.say(op, String::from("sets its home domain"));
        }
        if let Some(s) = &o.signer {
            let key = s.key.strkey();
            if s.weight == 0 {
                let prose = "It can't sign for the account any more.";
                self.push(op, loud("Removes a signer!", "Removes a signer"), String::new(), key, prose);
                self.warn(op, "removes a signer");
            } else {
                let what = match &s.key {
                    SignerKey::Ed25519(_) => String::from(
                        "That key could sign for the account: with enough weight, alone, and spend everything it holds.",
                    ),
                    SignerKey::PreAuthTx(_) => String::from(
                        "The transaction with this hash is signed for the account, once, when it's sent.",
                    ),
                    SignerKey::HashX(_) => String::from(
                        "Whoever reveals the secret this is the hash of can sign for the account.",
                    ),
                    SignerKey::SignedPayload { payload, .. } => {
                        format!("That key signs for the account by signing {}.", hex(payload))
                    }
                };
                self.push(op, loud("New signer!", "New signer"), format!("weight {}", s.weight), key, &what);
                self.warn(op, "adds a signer");
            }
        }
        if self.pages.len() == before {
            self.push(op, "Options", "none".into(), String::new(), "It changes nothing.");
        }
    }

    fn invoke(&mut self, op: &Operation, invoke: &Invoke) {
        let actor = self.tx.source_of(op);
        let mut mono = Vec::new();
        let (heading, value) = match &invoke.function {
            HostFunction::Call { contract, function, args } => {
                self.unreadable = true;
                mono.push(contract.strkey());
                if let Some(asset) = self.asset_contract(contract) {
                    mono.push(format!("{}'s asset contract", self.name(&asset)));
                }
                mono.push(format!("{}()", symbol(function)));
                mono.push(format!("{args} argument{}", if *args == 1 { "" } else { "s" }));
                ("Contract call", String::from("maki can't read it"))
            }
            HostFunction::Create { preimage, executable, args } => {
                mono.push(match preimage {
                    Preimage::Address { address, .. } => format!("made by\n{}", self.address(address)),
                    Preimage::Asset(a) => format!("for {}", self.name(a)),
                });
                mono.push(self.executable(executable));
                // a Stellar asset's contract does what Stellar's own code does; any other, maki
                // can't tell
                if args.is_some() || !matches!(executable, Executable::StellarAsset) {
                    self.unreadable = true;
                    ("New contract", String::from("maki can't read it"))
                } else {
                    ("New contract", String::from("a Stellar asset's"))
                }
            }
            HostFunction::Upload { size } => ("Contract code", format!("{size} bytes")),
        };
        // who authorizes what: this account's authority goes with its signature where the
        // operation's source is this account
        let mut given = false;
        for a in &invoke.auth {
            let who = match a.credentials {
                Credentials::SourceAccount => {
                    given |= self.is_me(&actor);
                    self.who(&actor)
                }
                Credentials::Address { address, delegates, .. } => {
                    given |= address.is(self.me);
                    match delegates {
                        0 => self.address(&address),
                        n => format!("{}, and {n} signing for it,", self.address(&address)),
                    }
                }
            };
            let root = match &a.root {
                Authorized::Call { contract, function } => {
                    format!("{} {}()", contract.strkey(), symbol(function))
                }
                Authorized::Create { executable } => {
                    format!("a new contract, {}", self.executable(executable))
                }
            };
            let under = match a.calls {
                0 | 1 => String::new(),
                n => format!(", and {} call{} under it", n - 1, if n == 2 { "" } else { "s" }),
            };
            mono.push(format!("\n{who} authorizes\n{root}{under}"));
        }
        // what this account's authority is used for, maki can't read
        self.unreadable |= given;
        let prose = match (&invoke.function, given) {
            (HostFunction::Upload { .. }, false) => {
                "Code for contracts to run, uploaded: on its own, it can't act as this account.".to_string()
            }
            (_, true) => String::from(
                "It's given this account's authority: it can do as this account whatever its authorizations allow, which maki can't read.",
            ),
            (_, false) => {
                String::from("It isn't given this account's authority: it can't act as this account.")
            }
        };
        let mono = mono.join("\n");
        self.push(op, heading, value, mono, &prose);
        self.say(
            op,
            String::from(match invoke.function {
                HostFunction::Upload { .. } => "uploads contract code",
                HostFunction::Create { .. } => "makes a contract",
                HostFunction::Call { .. } if given => "calls a contract as this account",
                HostFunction::Call { .. } => "calls a contract",
            }),
        );
    }

    /// The asset a contract is the Stellar asset contract of, if it's XLM's or one maki knows.
    fn asset_contract(&self, contract: &Address) -> Option<Asset> {
        let Address::Contract(id) = contract else { return None };
        let network = self.network;
        let assets = KNOWN.iter().filter(|k| k.network == network).filter_map(|k| {
            let code = Code::from_text(k.code)?;
            Some(Asset::Credit { code, issuer: k.issuer })
        });
        core::iter::once(Asset::Native).chain(assets).find(|a| asset_contract(a, network) == *id)
    }

    fn address(&self, a: &Address) -> String {
        match a {
            Address::Account(k) => self.who(k),
            other => other.strkey(),
        }
    }

    fn executable(&self, e: &Executable) -> String {
        match e {
            Executable::Wasm(h) => format!("its code {}", hex(h)),
            Executable::StellarAsset => String::from("a Stellar asset's contract"),
            Executable::External { owner, tag } => format!("code {} of {}", symbol(tag), self.address(owner)),
        }
    }

    /// A footprint's contracts, for extending or restoring: what it reads, or what it writes.
    fn footprint(&self, reads: bool) -> String {
        let Some(data) = &self.tx.soroban else { return String::new() };
        let entries = if reads { &data.read_only } else { &data.read_write };
        lines(
            entries
                .iter()
                .map(|e| match e {
                    Entry::ContractData { contract, .. } => format!("data of {}", contract.strkey()),
                    Entry::ContractCode(h) => format!("code {}", hex(h)),
                    _ => String::from("an entry"),
                })
                .collect(),
        )
    }

    fn memo(&mut self) {
        let everyone =
            "Everyone can read it, on chain. An exchange may need it to know the payment is yours.";
        let p = match &self.tx.memo {
            Memo::None => return,
            Memo::Text(t) => match text(t) {
                Some(t) => page("Memo", "", t, everyone),
                None => page("Memo", "in hex", hex(t), everyone),
            },
            Memo::Id(id) => page("Memo", format!("ID {id}"), "", everyone),
            Memo::Hash(h) => page("Memo", "a hash", hex(h), everyone),
            Memo::Return(h) => {
                page("Memo", "returns a payment", hex(h), "The hash of the transaction it sends back.")
            }
        };
        self.pages.push(p);
    }

    fn conditions(&mut self) {
        let c = &self.tx.conditions;
        let time = c.time.filter(|t| t.min != 0 || t.max != 0);
        let ledgers = c.ledgers.filter(|l| l.min != 0 || l.max != 0);
        match time {
            Some(t) if t.max != 0 => {
                let prose = if t.min != 0 {
                    format!("Not before {}.", date(t.min))
                } else {
                    String::from("After that, it can't go through.")
                };
                self.pages.push(page("Valid until", date(t.max), "", prose));
            }
            Some(t) => {
                let prose =
                    "From then on it stays valid until it's sent, or its account's sequence moves past it.";
                self.pages.push(page("No time limit", format!("from {}", date(t.min)), "", prose));
            }
            None if ledgers.is_none_or(|l| l.max == 0) => {
                let prose = "It stays valid until it's sent, or its account's sequence moves past it.";
                self.pages.push(page("No time limit", "", "", prose));
            }
            None => {}
        }
        if let Some(l) = ledgers {
            let value = match (l.min, l.max) {
                (min, 0) => format!("from ledger {min}"),
                (0, max) => format!("before ledger {max}"),
                (min, max) => format!("ledgers {min} to {}", max - 1),
            };
            self.pages.push(page("Ledgers", value, "", "It can only go through in those."));
        }
        if let Some(min) = c.min_sequence {
            let prose = "It can go through while its account's sequence is anywhere from that up to its own, not just one below it.";
            self.pages.push(page("Sequence", format!("from {min}"), "", prose));
        }
        if c.min_age != 0 || c.min_ledger_gap != 0 {
            let mut waits = Vec::new();
            if c.min_age != 0 {
                waits.push(duration(c.min_age));
            }
            if c.min_ledger_gap != 0 {
                waits.push(format!("{} ledgers", c.min_ledger_gap));
            }
            let prose = "Only once that's passed since its account's sequence last changed.";
            self.pages.push(page("Waits", waits.join(", "), "", prose));
        }
        if !c.extra_signers.is_empty() {
            let n = c.extra_signers.len();
            let mono = c.extra_signers.iter().map(|s| s.strkey()).collect::<Vec<_>>().join("\n");
            let prose = "It goes through only with their signatures too.";
            self.pages.push(page("Signed by others", format!("{n} more"), mono, prose));
        }
    }
}

/// An account that may have an ID, as a page shows it: an account with an ID as its `M…` address,
/// and the account it is (this one, or its `G…` address).
fn muxed(m: &Muxed, me: &Key) -> String {
    let account = if m.key == *me { String::from("this account") } else { address(&m.key) };
    match m.id {
        None => account,
        Some(id) => {
            let which = if m.key == *me { account } else { format!("account\n{account}") };
            format!("{}\nwhich is {which}\nwith ID {id}", strkey::muxed(&m.key, id))
        }
    }
}

/// A claim's condition, in words.
fn condition(p: &Predicate) -> String {
    let inner = |q: &Predicate| match q {
        Predicate::And(..) | Predicate::Or(..) => format!("({})", condition(q)),
        _ => condition(q),
    };
    match p {
        Predicate::Unconditional => String::from("any time"),
        Predicate::Before(t) => format!("before {}", date(*t as u64)),
        Predicate::Within(s) => format!("within {}", duration(*s as u64)),
        Predicate::Not(q) => match &**q {
            Predicate::Before(t) => format!("from {}", date(*t as u64)),
            Predicate::Within(s) => format!("after {}", duration(*s as u64)),
            q => format!("unless {}", inner(q)),
        },
        Predicate::And(a, b) => format!("{} and {}", inner(a), inner(b)),
        Predicate::Or(a, b) => format!("{} or {}", inner(a), inner(b)),
    }
}

/// A contract's function name: as it is if it's a symbol's letters, digits and underscores, else
/// in hex.
fn symbol(s: &[u8]) -> String {
    if s.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        s.iter().map(|&b| b as char).collect()
    } else {
        hex(s)
    }
}

/// Whether this account is `envelope`'s to sign: it pays a fee bump, or it's the transaction's
/// source, or an operation's.
pub fn is_mine(envelope: &Envelope, me: &Key) -> bool {
    match &envelope.kind {
        Kind::FeeBump { source, .. } => source.key == *me,
        _ => {
            envelope.tx.source.key == *me
                || envelope.tx.operations.iter().any(|op| op.source.is_some_and(|s| s.key == *me))
        }
    }
}

/// The pages the owner goes through before `me` signs `envelope` for `network`, and the line
/// that goes with them.
pub fn review(envelope: &Envelope, me: &Key, network: Network) -> Result<Review, Error> {
    if !is_mine(envelope, me) {
        return Err(Error::NotMine);
    }
    let tx = &envelope.tx;
    let mut r = Reading {
        tx,
        me,
        network,
        pages: Vec::new(),
        unreadable: false,
        warnings: Vec::new(),
        said: Vec::new(),
        sent_xlm: 0,
        xlm_payments: 0,
        explained: Vec::new(),
        pools: Vec::new(),
    };
    // a pool's assets, from a trustline to it, before a deposit or withdrawal names it
    for op in &tx.operations {
        if let Body::ChangeTrust { line: TrustAsset::Pool { a, b, fee }, .. } = &op.body {
            r.pools.push((pool_id(a, b, *fee), *a, *b));
        }
    }
    // a sign-in (SEP-10): numbered 0, which no transaction can be, so it never goes through
    let sign_in = (tx.sequence == 0).then(|| {
        tx.operations.iter().find_map(|op| match &op.body {
            Body::ManageData { name, .. } if r.is_me(&tx.source_of(op)) => {
                name.strip_suffix(" auth").map(String::from)
            }
            _ => None,
        })
    });
    if sign_in.is_some() {
        let prose = "A transaction numbered 0 never goes through: signing it moves nothing. Sites ask for one to sign you in (SEP-10).";
        r.pages.push(page("Never on chain", "sequence 0", "", prose));
    }
    if let Kind::FeeBump { .. } = envelope.kind {
        let prose = if r.is_me(&tx.source.key) {
            "This account pays its own transaction's fee anew. What the transaction does follows."
        } else {
            "This account pays the fee of that account's transaction. What the transaction does follows."
        };
        r.pages.push(page("Fee bump", "pays the fee", r.who(&tx.source.key), prose));
    }
    for op in &tx.operations {
        r.operation(op);
    }
    r.memo();
    r.conditions();
    // the fee: the fee bump's, or the transaction's
    let ops = tx.operations.len();
    let (fee, payer) = match envelope.kind {
        Kind::FeeBump { fee, source, .. } => (fee as u128, source.key),
        _ => (tx.fee as u128, tx.source.key),
    };
    let operations = if ops == 1 { String::from("its operation") } else { format!("its {ops} operations") };
    let counted = match envelope.kind {
        Kind::FeeBump { .. } => format!("{operations} and the fee bump"),
        _ => operations,
    };
    let resources = match &tx.soroban {
        Some(d) => format!(
            " {} of it for the contract's resources, some back if unused.",
            xlm(d.resource_fee as u128)
        ),
        None => String::new(),
    };
    if r.is_me(&payer) {
        let prose = format!("The most it can cost, for {counted}.{resources}");
        r.pages.push(page("Max fee", xlm(fee), "", prose));
    } else {
        let prose = format!("Up to {}, not this account's.{resources}", xlm(fee));
        r.pages.push(page("Fee paid by", "another account", address(&payer), prose));
    }
    // whose transaction, on which network: its source's address, even when it's this account's
    let from = match tx.source.id {
        Some(id) => format!(
            "{}\nwhich is account\n{}\nwith ID {id}",
            strkey::muxed(&tx.source.key, id),
            address(&tx.source.key)
        ),
        None => address(&tx.source.key),
    };
    let on = format!("On {}; its sequence number is {}.", network.name(), tx.sequence);
    if r.is_me(&tx.source.key) {
        r.pages.push(page("From", "this account", from, on));
    } else if matches!(envelope.kind, Kind::FeeBump { .. }) {
        let prose =
            format!("{on} It's that account's transaction, signed by it; this account signs the fee bump.");
        r.pages.push(page("Transaction of", "another account", from, prose));
    } else {
        let prose = format!(
            "{on} It's that account's transaction; this account signs for what it does as this account."
        );
        r.pages.push(page("Another's!", "another account", from, prose));
    }
    if r.pages.len() > MAX_PAGES {
        return Err(Error::TooMuch);
    }
    Ok(Review { summary: r.summary(envelope, fee, sign_in.flatten()), pages: r.pages })
}

impl Reading<'_> {
    /// The line under the question: what it does that matters most, and the most the fee can be.
    fn summary(&self, envelope: &Envelope, fee: u128, sign_in: Option<String>) -> String {
        let what = if let Some(site) = sign_in {
            format!("signs in to {site}")
        } else if !self.warnings.is_empty() {
            format!(
                "{}!{}",
                self.warnings.join(", "),
                if self.unreadable { " And maki can't read all of it" } else { "" }
            )
        } else if self.unreadable {
            String::from("maki can't read all of it")
        } else if self.xlm_payments > 1 && self.xlm_payments == self.said.len() {
            format!("sends {} in {} payments", xlm(self.sent_xlm), self.xlm_payments)
        } else if self.said.is_empty() {
            String::from(match envelope.kind {
                Kind::FeeBump { .. } => "pays the fee of another's transaction",
                _ => "signs for another's transaction",
            })
        } else {
            let mut said: Vec<&str> = Vec::new();
            for s in &self.said {
                if !said.contains(&s.as_str()) {
                    said.push(s);
                }
            }
            said.join(", ")
        };
        let mut summary = if self.network == Network::Test { format!("testnet: {what}") } else { what };
        let payer = envelope.payer().key;
        summary.push_str(&match envelope.kind {
            _ if envelope.tx.sequence == 0 => String::from("; it can't go on chain"),
            Kind::FeeBump { .. } => format!("; fee bump up to {}", xlm(fee)),
            _ if self.is_me(&payer) => format!("; fee up to {}", xlm(fee)),
            _ => String::from("; another pays the fee"),
        });
        // the line under the question is short (the pages say it all): cut, if it must be, at a character
        if summary.len() > MAX_SUMMARY {
            let mut end = MAX_SUMMARY - '…'.len_utf8();
            while !summary.is_char_boundary(end) {
                end -= 1;
            }
            summary.truncate(end);
            summary.push('…');
        }
        summary
    }
}
