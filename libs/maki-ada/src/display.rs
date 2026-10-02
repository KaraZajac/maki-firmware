//! What the owner reads on maki's review screen before a Cardano transaction is signed, as pages:
//! the network; each payment, its ADA and its tokens and the address it goes to, in full; the
//! change, once maki has made its address itself; registering, delegating to a pool, delegating
//! votes and deregistering, and rewards withdrawn, all this account's own; tokens minted and burnt;
//! a donation to the treasury; metadata, which maki isn't shown; when it's valid, if that's out of
//! the ordinary; and the fee, which is all it costs beyond what it pays. A certificate or a
//! withdrawal that's another account's, change that isn't this account's, and anything for another
//! network are refused before anything is shown.
//!
//! What the coins it spends hold isn't in a body, and maki doesn't need it: Cardano takes a
//! transaction only if what it spends (and withdraws, and gets back in deposits) adds up exactly to
//! what it pays out, its deposits, its donation and its fee, so whatever isn't shown going
//! somewhere can't leave.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::address::{Address, Credential, Kind, RewardAccount, Stake, drep_id, pool_id};
use crate::body::{Body, Certificate, DRep, Datum, Output, Policy};
use crate::request::Key;
use crate::tokens::{self, Known};
use crate::{Hash28, Network, hex};

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
    /// The line under the question: what it does, and the fee.
    pub summary: String,
}

/// Why maki won't show a transaction for this account to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// It's for another network than maki was told: which.
    Network(&'static str),
    /// Something in it is another account's, or isn't this account's as the computer says: what.
    NotMine(&'static str),
    /// maki won't sign it, or can't show it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Network(why) | Error::NotMine(why) | Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The most pages maki's review screen takes (maki-wasm's `MAX_PAGES`).
pub const MAX_PAGES: usize = 128;
/// The most text the pages may hold, all told: maki's review screen takes 16 KiB with its
/// question, its line and its answers, which this leaves room for.
pub const MAX_TEXT: usize = 16 * 1024 - 512;

// What Cardano charges, as its parameters have it on both networks (Koios's `epoch_params`,
// mainnet's epoch 659 and Preprod's 316, on 2026-10-02). Governance can change them; they're used
// only to say what's out of the ordinary, never to sign.

/// The fee per byte of a transaction, in lovelace (`min_fee_a`).
pub const FEE_PER_BYTE: u64 = 44;
/// The fee every transaction pays besides, in lovelace (`min_fee_b`).
pub const FEE_BASE: u64 = 155_381;
/// The stake key deposit, in lovelace (`key_deposit`): what Shelley's registration pays without
/// saying.
pub const KEY_DEPOSIT: u64 = 2_000_000;

/// What a review checks a transaction against: the network the computer says it's for, and the
/// account's stake key, as maki made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub network: Network,
    /// The hash of the account's stake key (`2/0`): whose rewards, delegation and votes are this
    /// account's, and the second half of each of its addresses.
    pub stake: Hash28,
}

/// An output the computer says is change, with the hash of the payment key maki made for the
/// key it names: change only if it pays that key's address with the account's stake key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Own {
    pub output: usize,
    pub key: Key,
    pub payment: Hash28,
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

/// `n` with `places` decimals, exactly, without trailing zeros: `decimals(1500000, 6)` is `1.5`.
pub fn decimals(n: u128, places: u8) -> String { point(&n.to_string(), places) }

/// Lovelace, exactly, in ADA (test ADA on a test network): `1.5 ADA`.
pub fn ada(lovelace: u64, network: Network) -> String {
    format!("{} {}", decimals(lovelace as u128, 6), network.unit())
}

/// An amount of a token: in its own units if maki knows it, `5.25 USDM`, or in its smallest
/// units, `42 units`.
fn amount(n: u64, known: Option<&Known>) -> String {
    match known {
        Some(t) => format!("{} {}", decimals(n as u128, t.decimals), t.symbol),
        None if n == 1 => String::from("1 unit"),
        None => format!("{n} units"),
    }
}

/// CIP-67's CRC-8 (polynomial 0x07), which a label's checksum is.
fn crc8(bytes: &[u8]) -> u8 {
    let mut crc = 0u8;
    for &b in bytes {
        crc ^= b;
        for _ in 0..8 {
            crc = if crc & 0x80 != 0 { (crc << 1) ^ 0x07 } else { crc << 1 };
        }
    }
    crc
}

/// An asset name's CIP-67 label, and the rest of the name: four bytes, `[0000 | label (16 bits) |
/// its CRC-8 | 0000]`, as CIP-68's tokens begin (333 a fungible token's, 222 an NFT's).
pub fn label(name: &[u8]) -> Option<(u16, &[u8])> {
    let [a, b, c, d, rest @ ..] = name else { return None };
    if a >> 4 != 0 || d & 0x0f != 0 {
        return None;
    }
    let label = ((*a as u16) << 12) | ((*b as u16) << 4) | (*c as u16 >> 4);
    let checksum = ((c & 0x0f) << 4) | (d >> 4);
    (crc8(&label.to_be_bytes()) == checksum).then_some((label, rest))
}

/// Printable ASCII, as an asset name's text is shown: nothing else could pass for it.
fn printable(b: &[u8]) -> bool { !b.is_empty() && b.iter().all(|c| (0x20..0x7f).contains(c)) }

/// An asset name as the owner reads it, and how it's written: its text if it's printable ASCII,
/// CIP-67's label then its text (`(333) USDM`), its bytes in hex, or nothing for no name.
pub fn asset_name(name: &[u8]) -> (String, &'static str) {
    if name.is_empty() {
        return (String::new(), "its policy (it has no name)");
    }
    if printable(name) {
        return (name.iter().map(|&c| c as char).collect(), "its policy, then its name");
    }
    match label(name) {
        Some((l, rest)) if printable(rest) => (
            format!("({l}) {}", rest.iter().map(|&c| c as char).collect::<String>()),
            "its policy, then its name (CIP-67's label, then text)",
        ),
        _ => (hex(name), "its policy, then its name in hex"),
    }
}

/// A token's page beside an output's or a mint's: its amount, in its own units if maki knows it,
/// and if it doesn't, its policy and name.
fn token_page(heading: &str, network: Network, policy: &Hash28, name: &[u8], n: u64, prose: &str) -> Page {
    let known = tokens::known(network, policy, name);
    if known.is_some() {
        return page(heading, amount(n, known), "", prose);
    }
    let (text, how) = asset_name(name);
    let mono = if text.is_empty() { hex(policy) } else { format!("{}\n{text}", hex(policy)) };
    let what = format!("A token maki doesn't know, in its smallest units: {how}.");
    page(heading, amount(n, None), mono, if prose.is_empty() { what } else { format!("{prose} {what}") })
}

fn plural(n: u64, unit: &str) -> String { format!("{n} {unit}{}", if n == 1 { "" } else { "s" }) }

/// How many tokens: `a token`, `3 tokens`.
fn tokens(n: usize) -> String { if n == 1 { String::from("a token") } else { format!("{n} tokens") } }

fn count<N>(policies: &[Policy<N>]) -> usize { policies.iter().map(|p| p.tokens.len()).sum() }

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

/// A time (seconds since 1970) as the owner reads it: `2026-10-02 04:01:50 UTC`.
pub fn utc(secs: u64) -> String {
    let (y, m, d) = date(secs / 86_400);
    let s = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60)
}

const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

/// A span of time (seconds) in its two largest units, rounded down: `3 days`, `1 hour 30 minutes`.
pub fn span(secs: u64) -> String {
    let (days, hours, minutes) = (secs / DAY, secs % DAY / HOUR, secs % HOUR / 60);
    let parts = if days > 0 {
        [(days, "day"), (hours, "hour")]
    } else if hours > 0 {
        [(hours, "hour"), (minutes, "minute")]
    } else {
        [(minutes, "minute"), (secs % 60, "second")]
    };
    match parts {
        [(a, u), (0, _)] => plural(a, u),
        [(0, _), (b, v)] => plural(b, v),
        [(a, u), (b, v)] => format!("{} {}", plural(a, u), plural(b, v)),
    }
}

/// What the address of an output is, if it's out of the ordinary: a script's, a pointer, Byron's.
fn kind_of(a: &Address) -> &'static str {
    match a.kind {
        Kind::Byron { .. } => "A Byron address, from Cardano's first years.",
        Kind::Shelley { payment: Credential::Script(_), .. } => {
            "A script's address: what can be done with what's sent there is up to the script, which maki can't read."
        }
        Kind::Shelley { stake: Stake::Pointer { .. }, .. } => {
            "A pointer address, an old kind: it names its stake key by where that was registered on chain."
        }
        _ => "",
    }
}

struct Reading<'a> {
    body: &'a Body,
    network: Network,
    pages: Vec<Page>,
    /// What it does, as the line under the question says it.
    said: Vec<String>,
    /// What it does that the owner must not miss.
    warnings: Vec<String>,
    /// What its payments send, all told: ADA, and how many tokens.
    sent: u128,
    sent_tokens: usize,
}

impl Reading<'_> {
    fn ada(&self, lovelace: u64) -> String { ada(lovelace, self.network) }

    /// A payment: its ADA and the address, what's out of the ordinary about it, then a page for
    /// each token it carries.
    fn payment(&mut self, o: &Output, heading: &str) {
        let mut notes: Vec<String> = Vec::new();
        let kind = kind_of(&o.address);
        if !kind.is_empty() {
            notes.push(kind.into());
        }
        let script = o.pays_script();
        match o.datum {
            Some(Datum::Hash(_)) => notes.push(String::from("With a datum's hash, for a script to read.")),
            Some(Datum::Inline(n)) => {
                notes.push(format!("With {} of data for a script to read.", plural(n as u64, "byte")))
            }
            None if script => {
                self.warnings.push(String::from("may lock ADA in a script for good"));
                notes.push(String::from(
                    "Without a datum: a Plutus V1 or V2 script can never spend it, nor anyone else.",
                ));
            }
            None => {}
        }
        if let Some(n) = o.script {
            notes.push(format!(
                "With a script any transaction can use from here ({}).",
                plural(n as u64, "byte")
            ));
        }
        let n = count(&o.tokens);
        if n > 0 {
            notes.push(format!("And {}, on the next page{}.", tokens(n), if n == 1 { "" } else { "s" }));
        }
        self.sent += o.coin as u128;
        self.sent_tokens += n;
        self.pages.push(page(heading, self.ada(o.coin), o.address.text(), notes.join(" ")));
        let heading = format!("{heading}: token");
        for p in &o.tokens {
            for t in &p.tokens {
                self.pages.push(token_page(&heading, self.network, &p.id, &t.name, t.amount, ""));
            }
        }
    }

    /// Change, back to the account: its ADA, and how many tokens, which needn't each be gone
    /// through.
    fn change(&mut self, o: &Output, own: &Own, heading: &str) {
        let chain = if own.key.role == crate::RECEIVE { "receiving" } else { "change" };
        let with = match count(&o.tokens) {
            0 => String::new(),
            n => format!(", with {}", tokens(n)),
        };
        self.pages.push(page(
            heading,
            self.ada(o.coin),
            "",
            format!("Back to this account: its {chain} address #{}{with}.", own.key.index),
        ));
    }

    fn register(&mut self, deposit: Option<u64>) {
        let (value, prose) = match deposit {
            Some(d) => (
                format!("{} deposit", self.ada(d)),
                String::from(
                    "This account's stake key, so it can delegate and earn rewards. The deposit comes back when the key is deregistered.",
                ),
            ),
            None => (
                String::from("key deposit"),
                format!(
                    "This account's stake key, so it can delegate and earn rewards. It pays Cardano's key deposit ({} as of 2026), which this kind of certificate doesn't state: it comes back when the key is deregistered.",
                    self.ada(KEY_DEPOSIT)
                ),
            ),
        };
        self.said.push(String::from("registers its stake key"));
        self.pages.push(page("Register", value, "", prose));
    }

    fn delegate(&mut self, pool: &Hash28) {
        self.said.push(String::from("delegates to a pool"));
        self.pages.push(page(
            "Delegate",
            "to a stake pool",
            pool_id(pool),
            "This account's stake counts toward that pool, which earns it rewards; its ADA stays its own, to spend. Check the pool's ID.",
        ));
    }

    fn vote(&mut self, drep: &DRep) {
        self.said.push(String::from("delegates its votes"));
        let p = match drep {
            DRep::Credential(c @ Credential::Key(_)) => page(
                "Delegate votes",
                "to a DRep",
                drep_id(c),
                "That DRep votes as this account's stake on Cardano's governance; its ADA stays its own. Check the DRep's ID.",
            ),
            DRep::Credential(c @ Credential::Script(_)) => page(
                "Delegate votes",
                "to a script DRep",
                drep_id(c),
                "A script decides how that DRep votes, as this account's stake, on Cardano's governance; its ADA stays its own. Check the DRep's ID.",
            ),
            DRep::Abstain => page(
                "Delegate votes",
                "always abstain",
                "",
                "This account's stake abstains from every vote on Cardano's governance; its ADA stays its own.",
            ),
            DRep::NoConfidence => page(
                "Delegate votes",
                "no confidence",
                "",
                "This account's stake votes no confidence in Cardano's constitutional committee, on every vote it can; its ADA stays its own.",
            ),
        };
        self.pages.push(p);
    }

    fn certificate(&mut self, c: &Certificate) {
        match c {
            Certificate::Register { deposit, .. } => self.register(*deposit),
            Certificate::Deregister { refund, .. } => {
                let value = match refund {
                    Some(r) => format!("{} back", self.ada(*r)),
                    None => String::from("deposit back"),
                };
                self.said.push(String::from("deregisters its stake key"));
                self.pages.push(page(
                    "Deregister",
                    value,
                    "",
                    "This account's stake key: it stops earning rewards, and its delegation and votes end. Its deposit comes back into this transaction, to go where its outputs say.",
                ));
            }
            Certificate::Delegate { pool, .. } => self.delegate(pool),
            Certificate::Vote { drep, .. } => self.vote(drep),
            Certificate::DelegateAndVote { pool, drep, .. } => {
                self.delegate(pool);
                self.vote(drep);
            }
            Certificate::RegisterAndDelegate { pool, deposit, .. } => {
                self.register(Some(*deposit));
                self.delegate(pool);
            }
            Certificate::RegisterAndVote { drep, deposit, .. } => {
                self.register(Some(*deposit));
                self.vote(drep);
            }
            Certificate::RegisterDelegateAndVote { pool, drep, deposit, .. } => {
                self.register(Some(*deposit));
                self.delegate(pool);
                self.vote(drep);
            }
        }
    }

    fn mint(&mut self) {
        let (mut minted, mut burnt) = (false, false);
        for p in &self.body.mint {
            for t in &p.tokens {
                let (heading, prose) = if t.amount > 0 {
                    minted = true;
                    ("Mint", "New tokens under its policy: where they go, the outputs say.")
                } else {
                    burnt = true;
                    ("Burn", "Tokens destroyed for good, out of what this transaction spends.")
                };
                let page = token_page(heading, self.network, &p.id, &t.name, t.amount.unsigned_abs(), prose);
                self.pages.push(page);
            }
        }
        if minted {
            self.said.push(String::from("mints tokens"));
        }
        if burnt {
            self.warnings.push(String::from("burns tokens"));
        }
    }

    /// When it's valid, if that's out of the ordinary: never expiring, already expired, valid for
    /// more than a day, not valid until later. Judged by maki's clock (seconds since 1970) if it
    /// has one; if not, said.
    fn validity(&mut self, now: Option<u64>) {
        let net = self.network;
        match (self.body.ttl, now) {
            (None, _) => self.pages.push(page(
                "Valid until",
                "no limit",
                "",
                "Whoever has it can send it at any time, as long as the coins it spends haven't been.",
            )),
            (Some(ttl), Some(now)) => {
                let until = net.slot_time(ttl);
                if until <= now {
                    self.warnings.push(String::from("already expired"));
                    self.pages.push(page(
                        "Expired!",
                        utc(until),
                        "",
                        format!("It was valid until slot {ttl}, which is past by maki's clock: Cardano won't take it."),
                    ));
                } else if until - now > DAY {
                    self.pages.push(page(
                        "Valid for",
                        span(until - now),
                        "",
                        format!("Whoever has it can send it until {} (slot {ttl}).", utc(until)),
                    ));
                }
            }
            (Some(ttl), None) => self.pages.push(page(
                "Valid until",
                utc(net.slot_time(ttl)),
                "",
                format!("Slot {ttl}: maki can't tell how far off that is, without the time."),
            )),
        }
        if let Some(start) = self.body.valid_from {
            let from = net.slot_time(start);
            match now {
                Some(now) if from <= now => {}
                Some(_) => self.pages.push(page(
                    "Not before",
                    utc(from),
                    "",
                    format!("Cardano takes it only from slot {start}: whoever has it can send it then."),
                )),
                None => self.pages.push(page(
                    "Valid from",
                    utc(from),
                    "",
                    format!("Slot {start}: Cardano takes it only from then."),
                )),
            }
        }
    }

    /// The fee, and whether it's more than twice what a transaction of this size needs (when maki
    /// can tell: metadata, which it isn't shown, adds to the size).
    fn fee(&mut self, witnesses: usize) {
        // signed: the transaction's list, the body, the witness set (a key and a signature, 101
        // bytes each, in a map, a list and maybe a set's tag), validity, no metadata
        let size = 1 + self.body.size as u64 + (1 + 1 + 3 + 3) + 101 * witnesses as u64 + 1 + 1;
        let needed = FEE_PER_BYTE * size + FEE_BASE;
        let fee = self.body.fee;
        if self.body.metadata.is_none() && fee > 2 * needed {
            self.warnings.push(String::from("pays a high fee"));
            self.pages.push(page(
                "High fee!",
                self.ada(fee),
                "",
                format!(
                    "More than twice what Cardano asks of a transaction this size, about {}.",
                    self.ada(needed)
                ),
            ));
        } else {
            self.pages.push(page(
                "Fee",
                self.ada(fee),
                "",
                "All it costs beyond what it pays: Cardano takes it only if the coins it spends, which maki can't see, add up exactly to what goes out.",
            ));
        }
    }
}

/// Whether an output pays `own`'s address: the payment key maki made, with the account's stake
/// key, on the network (nothing for a script, and no datum, since change is just ADA and tokens).
fn is_change(o: &Output, own: &Own, account: &Account) -> bool {
    o.address == Address::base(account.network, &own.payment, &account.stake)
        && o.datum.is_none()
        && o.script.is_none()
}

/// The pages the owner goes through before the account signs `body` with `witnesses` keys, and the
/// line that goes with them. `change` is the outputs the computer says are change, with the keys
/// maki made for them; `now` is maki's clock (seconds since 1970), if it has one.
pub fn review(
    body: &Body,
    account: &Account,
    change: &[Own],
    witnesses: usize,
    now: Option<u64>,
) -> Result<Review, Error> {
    let network = account.network;
    let wrong = match network {
        Network::Mainnet => Error::Network("for a test network, not Cardano's own"),
        Network::Preprod => Error::Network("for Cardano's own network, not a test network"),
    };
    if body.network.is_some_and(|n| n != network.id())
        || body.outputs.iter().any(|o| o.address.network != network.id())
        || body.withdrawals.iter().any(|(a, _)| a.network != network.id())
    {
        return Err(wrong);
    }
    let mine = Credential::Key(account.stake);
    if body.certificates.iter().any(|c| *c.stake() != mine) {
        return Err(Error::NotMine("a certificate for another stake key than this account's"));
    }
    if body.withdrawals.iter().any(|(a, _)| *a != RewardAccount::new(network, &account.stake)) {
        return Err(Error::NotMine("a withdrawal of rewards that aren't this account's"));
    }
    for own in change {
        let o = body
            .outputs
            .get(own.output)
            .ok_or(Error::Invalid("change said to be an output it doesn't have"))?;
        if !is_change(o, own, account) {
            return Err(Error::NotMine(
                "an output said to be change that doesn't pay this account's address for that key",
            ));
        }
    }
    let mut r = Reading {
        body,
        network,
        pages: Vec::new(),
        said: Vec::new(),
        warnings: Vec::new(),
        sent: 0,
        sent_tokens: 0,
    };
    let mut net = match network {
        Network::Mainnet => page("Network", "Cardano", "", ""),
        Network::Preprod => {
            page("Network", network.name(), "", "Cardano's test network, whose ADA is worth nothing.")
        }
    };
    if !body.names_network() {
        let other = match network {
            Network::Mainnet => {
                "Nothing in it says which network it's for: made for Cardano's own, it would work on a test network too."
            }
            Network::Preprod => {
                "Nothing in it says which network it's for: made for a test network, it would work on Cardano's own too."
            }
        };
        net.prose = if net.prose.is_empty() { other.into() } else { format!("{} {other}", net.prose) };
    }
    r.pages.push(net);
    let mine = |i: usize| change.iter().find(|c| c.output == i);
    let payments = (0..body.outputs.len()).filter(|&i| mine(i).is_none()).count();
    let mut n = 0;
    for (i, o) in body.outputs.iter().enumerate() {
        if mine(i).is_none() {
            n += 1;
            let heading = if payments > 1 { format!("Send {n}/{payments}") } else { String::from("Send") };
            r.payment(o, &heading);
        }
    }
    if payments > 0 {
        // what's sent, all told (no more than all the ADA there is: the body's been held to that)
        let mut sent = format!("sends {} {}", decimals(r.sent, 6), network.unit());
        if r.sent_tokens > 0 {
            sent.push_str(&format!(" and {}", tokens(r.sent_tokens)));
        }
        if payments > 1 {
            sent.push_str(&format!(" in {payments} payments"));
        }
        r.said.push(sent);
    }
    let mut n = 0;
    for (i, o) in body.outputs.iter().enumerate() {
        if let Some(own) = mine(i) {
            n += 1;
            let heading = if change.len() > 1 {
                format!("Change {n}/{}", change.len())
            } else {
                String::from("Change")
            };
            r.change(o, own, &heading);
        }
    }
    for c in &body.certificates {
        r.certificate(c);
    }
    for (_, amount) in &body.withdrawals {
        r.said.push(format!("withdraws {} of rewards", r.ada(*amount)));
        r.pages.push(page(
            "Withdraw",
            r.ada(*amount),
            "",
            "This account's rewards, taken into this transaction: they go where its outputs say.",
        ));
    }
    r.mint();
    if let Some(d) = body.donation {
        r.warnings.push(format!("donates {} to the treasury", r.ada(d)));
        r.pages.push(page("Donate", r.ada(d), "", "To Cardano's treasury, for good."));
    }
    if let Some(t) = body.treasury {
        r.pages.push(page(
            "Treasury",
            r.ada(t),
            "",
            "Cardano takes it only while its treasury holds exactly this: a check, nothing paid.",
        ));
    }
    if body.metadata.is_some() {
        r.said.push(String::from("with metadata"));
        r.pages.push(page(
            "Metadata",
            "maki can't read it",
            "",
            "It carries data maki isn't shown, for anyone to read on chain: a message, or something an app reads. Only its hash is in what's signed.",
        ));
    }
    r.validity(now);
    r.fee(witnesses);
    let what = if !r.warnings.is_empty() {
        // each once, however many times it's met
        let mut w: Vec<&str> = Vec::new();
        for x in &r.warnings {
            if !w.contains(&x.as_str()) {
                w.push(x);
            }
        }
        format!("{}!", w.join(", "))
    } else if r.said.is_empty() {
        String::from("sends only change")
    } else {
        r.said.join(", ")
    };
    let mut summary = format!("{what}; fee {}", r.ada(body.fee));
    // the line under the question is short (the pages say it all): cut, if it must be, at a character
    if summary.len() > MAX_SUMMARY {
        let mut end = MAX_SUMMARY - '…'.len_utf8();
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary.push('…');
    }
    let text: usize =
        r.pages.iter().map(|p| p.heading.len() + p.value.len() + p.mono.len() + p.prose.len() + 4).sum();
    if r.pages.len() > MAX_PAGES || text > MAX_TEXT {
        return Err(Error::Invalid("more than maki's screen can show: send fewer outputs or tokens at once"));
    }
    Ok(Review { pages: r.pages, summary })
}
