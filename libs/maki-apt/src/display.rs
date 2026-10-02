//! What the owner reads on maki's review screen before an Aptos transaction is signed, as pages: the
//! network; what it does (APT, coins and fungible assets sent and to whom, staking with a delegation
//! pool, an object handed over), each amount exact, in APT or the units of an asset maki knows, and
//! an asset it doesn't know by what says which it is; when it expires; and the most the fee can be.
//! A call maki can't read is flagged with its function and arguments, as far as they can be read. A
//! transaction for another network or account, or one that would change who controls this account,
//! is refused before anything is shown.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::call::{Asset, Call, Payment, Staking};
use crate::tx::{Replay, StructTag, Transaction};
use crate::{Address, Network, address, assets};

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
    /// maki won't sign it: why.
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
/// The most text a page shows (maki's review screen's limit).
pub const MAX_SHOWN: usize = 4096;
/// How much of each argument of a call maki can't read is shown, in bytes: an address's worth.
pub const ARGUMENT_SHOWN: usize = 32;
/// How long before it expires Aptos takes an orderless transaction, in seconds
/// (transaction_validation.move's `MAX_EXP_TIME_SECONDS_FOR_ORDERLESS_TXNS`).
pub const ORDERLESS_WINDOW: u64 = 100;
/// From then on (the year 10000), a transaction doesn't expire, as people count time.
pub const NEVER: u64 = 253_402_300_800;

// What staking with a delegation pool is, as Aptos's framework and its staking configuration have it
// on both networks (read through Aptos Labs' fullnodes on 2026-10-02). Governance can change these;
// the pages say what they're for.

/// How long a delegation pool's lockup runs before it starts again: unlocked APT can be withdrawn
/// when the one it's in ends (`recurring_lockup_duration_secs`, 14 days).
pub const LOCKUP_DAYS: u64 = 14;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

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

/// Octas, exactly, in APT: `1.5 APT`.
pub fn apt(octas: u128) -> String { format!("{} APT", decimals(octas, 8)) }

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

/// A time (seconds since 1970) as the owner reads it: `2026-10-02 04:00:20 UTC`.
pub fn utc(secs: u64) -> String {
    let (y, m, d) = date(secs / DAY);
    let s = secs % DAY;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / HOUR, s / MINUTE % 60, s % 60)
}

fn plural(n: u64, unit: &str) -> String { format!("{n} {unit}{}", if n == 1 { "" } else { "s" }) }

/// A span of time (seconds) in its two largest units, rounded down: `3 days`, `6 hours`, `1 hour 30
/// minutes`.
pub fn span(secs: u64) -> String {
    let (days, hours, minutes) = (secs / DAY, secs % DAY / HOUR, secs % HOUR / MINUTE);
    let parts = if days > 0 {
        [(days, "day"), (hours, "hour")]
    } else if hours > 0 {
        [(hours, "hour"), (minutes, "minute")]
    } else {
        [(minutes, "minute"), (secs % MINUTE, "second")]
    };
    match parts {
        [(a, u), (0, _)] => plural(a, u),
        [(0, _), (b, v)] => plural(b, v),
        [(a, u), (b, v)] => format!("{} {}", plural(a, u), plural(b, v)),
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text cut to what a page shows, at a character, saying so.
fn clip(mut text: String) -> String {
    if text.len() > MAX_SHOWN {
        let mut end = MAX_SHOWN - '…'.len_utf8();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

/// The type an NFT (a digital asset, Aptos's token objects) has: `0x4::token::Token`.
fn is_token(t: &StructTag) -> bool {
    let mut four = [0u8; 32];
    four[31] = 4;
    t.is(&four, "token", "Token")
}

struct Reading<'a> {
    tx: &'a Transaction,
    me: &'a Address,
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
    /// An amount of `asset` as a page says it: in its own units if maki knows it, else in its
    /// smallest units.
    fn amount(&self, asset: &Asset, n: u128) -> String {
        match assets::known(self.network, asset) {
            Some(k) => format!("{} {}", decimals(n, k.decimals), k.symbol),
            None => format!("{n} units"),
        }
    }

    fn send(&mut self, asset: &Asset, payments: &[Payment]) {
        let known = assets::known(self.network, asset).is_some();
        let (what, a_what) = match asset {
            Asset::Coin(_) => ("coin", "a coin"),
            _ => ("asset", "an asset"),
        };
        for p in payments {
            let mut prose = Vec::new();
            if !known {
                prose.push(format!("In its smallest units: maki doesn't know the {what}."));
            }
            if p.to == *self.me {
                prose.push(String::from("To this account itself."));
            }
            let amount = self.amount(asset, p.amount as u128);
            self.pages.push(page("Send", amount, address(&p.to), prose.join(" ")));
        }
        let total: u128 = payments.iter().map(|p| p.amount as u128).sum();
        let mut sent = self.amount(asset, total);
        if !known {
            sent = format!("{sent} of {a_what} maki doesn't know");
        }
        self.said.push(match payments.len() {
            0 => String::from("sends nothing"),
            1 => format!("sends {sent}"),
            n => format!("sends {sent} in {n} payments"),
        });
        if payments.is_empty() {
            self.pages.push(page("Nothing", "no payments", "", "It pays nothing but the fee."));
        }
        if known {
            return;
        }
        match asset {
            Asset::Coin(t) => match assets::lookalike(self.network, t) {
                Some(k) => {
                    let s = k.symbol;
                    self.warnings.push(format!("not the {s} maki knows"));
                    let prose = format!(
                        "Anyone can make a coin and name it as {s} is: this one isn't the {s} maki knows."
                    );
                    self.pages.push(page(
                        &format!("Another {s}!"),
                        "not the one maki knows",
                        clip(t.to_string()),
                        prose,
                    ));
                }
                None => self.pages.push(page(
                    "Coin",
                    "one maki doesn't know",
                    clip(t.to_string()),
                    "Check its type: anyone can make a coin, and call it anything.",
                )),
            },
            Asset::Fungible(a) => self.pages.push(page(
                "Asset",
                "one maki doesn't know",
                address(a),
                "Check its address: anyone can make an asset, and call it anything.",
            )),
            Asset::Apt => {}
        }
    }

    fn stake(&mut self, action: Staking, pool: &Address, amount: u64) {
        let amount = apt(amount as u128);
        let (heading, said, prose) = match action {
            Staking::Add => (
                "Stake",
                "stakes",
                format!(
                    "With that delegation pool: it stays this account's, and earns rewards. Getting it back takes unlocking it, then withdrawing it once the pool's lockup ends, within {LOCKUP_DAYS} days. While its validator is active, a fee of about one epoch's rewards is taken, and mostly made back by the epoch's end."
                ),
            ),
            // a pool keeps 10 APT at least on each side of a delegator's (`MIN_COINS_ON_SHARES_POOL`)
            Staking::Unlock => (
                "Unstake",
                "unstakes",
                format!(
                    "Unlocked from that delegation pool: it earns rewards until the pool's lockup ends, within {LOCKUP_DAYS} days, and can be withdrawn then. A pool keeps 10 APT at least of a delegator's staked and unlocked, so it may unlock a little more, or all of it."
                ),
            ),
            Staking::Reactivate => (
                "Restake",
                "restakes",
                String::from(
                    "APT unlocked and not yet withdrawn, staked with that delegation pool again: it won't come free when the lockup ends, and goes on earning rewards.",
                ),
            ),
            Staking::Withdraw => (
                "Withdraw",
                "withdraws",
                String::from(
                    "Unlocked APT whose lockup has ended comes back to this account from that delegation pool, to spend.",
                ),
            ),
        };
        self.said.push(format!("{said} {amount}"));
        self.pages.push(page(heading, amount, address(pool), prose));
    }

    fn object(&mut self, object: &Address, to: &Address, kind: &Option<StructTag>) {
        let (value, warning) = match kind {
            Some(t) if is_token(t) => ("a digital asset", "hands over a digital asset"),
            _ => ("an object", "hands over an object"),
        };
        let mut prose =
            String::from("Whoever it goes to owns it, and everything it holds: maki can't see what that is.");
        if let Some(t) = kind.as_ref().filter(|t| !is_token(t)) {
            prose = format!("{prose} Its type: {t}.");
        }
        self.warnings.push(String::from(warning));
        self.pages.push(page(
            "Hands over!",
            value,
            format!("{}\nto {}", address(object), address(to)),
            clip(prose),
        ));
    }

    /// A call maki can't read: its function, type arguments and arguments, each argument's bytes as
    /// far as an address's worth.
    fn other(&mut self) {
        self.unreadable = true;
        let f = &self.tx.function;
        let mut mono = f.to_string();
        if let Some((first, rest)) = f.type_args.split_first() {
            mono.push_str(&format!("<{first}"));
            for t in rest {
                mono.push_str(&format!(", {t}"));
            }
            mono.push('>');
        }
        for (i, a) in f.args.iter().enumerate() {
            let line = if a.len() > ARGUMENT_SHOWN {
                format!("\n{}: {}… ({} bytes)", i + 1, hex(&a[..ARGUMENT_SHOWN]), a.len())
            } else {
                format!("\n{}: {}", i + 1, hex(a))
            };
            mono.push_str(&line);
        }
        self.pages.push(page(
            "Call",
            "maki can't read it",
            clip(mono),
            "maki can't tell what it does, or what its arguments mean. It may act as this account, and move anything this account holds.",
        ));
    }

    /// When it expires, always, and what maki's clock (if it has one) makes of it: already past,
    /// further off than an hour, or (for an orderless transaction) too far off for Aptos to take it
    /// yet.
    fn expiry(&mut self, now: Option<u64>) {
        let t = self.tx.expiration;
        let orderless = matches!(self.tx.replay, Replay::Nonce(_));
        let p = match now {
            Some(now) if t <= now => {
                self.warnings.push(String::from("already expired"));
                page("Expired!", utc(t), "", "That's past, by maki's clock: Aptos won't take it.")
            }
            Some(now) if orderless && t - now > ORDERLESS_WINDOW => {
                self.warnings.push(String::from("can only be sent later"));
                page(
                    "Expires late!",
                    utc(t),
                    "",
                    "Aptos takes an orderless transaction only in the 100 seconds before it expires: whoever has this one can send it then, whatever else this account sends, and not before.",
                )
            }
            _ if orderless => page(
                "Valid until",
                utc(t),
                "",
                "It's orderless: whoever has it can send it once before then, whatever else this account sends. Aptos takes it only in the 100 seconds before it expires.",
            ),
            _ if t >= NEVER => page(
                "No time limit",
                "never expires",
                "",
                "Whoever has it can send it whenever they like, unless this account sends another first.",
            ),
            Some(now) if t - now > HOUR => page(
                "Valid for",
                span(t - now),
                "",
                format!(
                    "Whoever has it can send it until {}, unless this account sends another first.",
                    utc(t)
                ),
            ),
            _ => page(
                "Valid until",
                utc(t),
                "",
                "Whoever has it can send it until then, unless this account sends another first.",
            ),
        };
        self.pages.push(p);
    }

    /// The most the fee can be: all of its gas, at its price.
    fn fee(&self) -> (Page, u128) {
        let max = self.tx.max_fee() as u128;
        let prose = format!(
            "Up to {} gas units, at {} octas each. Aptos charges this account only for the gas it uses.",
            self.tx.max_gas_amount, self.tx.gas_unit_price
        );
        (page("Max fee", apt(max), "", prose), max)
    }
}

/// The pages the owner goes through before `me` signs `tx`, on `network`, and the line that goes
/// with them. `now` is maki's clock (seconds since 1970), if it has one.
pub fn review(tx: &Transaction, me: &Address, network: Network, now: Option<u64>) -> Result<Review, Error> {
    if tx.sender != *me {
        return Err(Error::NotMine);
    }
    if tx.chain_id != network.chain_id() {
        return Err(Error::Invalid(match (network, tx.chain_id) {
            (Network::Mainnet, 2) => "a transaction for Aptos's testnet, not its own network",
            (Network::Testnet, 1) => "a transaction for Aptos's own network, not its testnet",
            _ => "a transaction for another Aptos network",
        }));
    }
    if let Call::Control(why) = tx.call {
        return Err(Error::Invalid(why));
    }
    let mut r = Reading {
        tx,
        me,
        network,
        pages: Vec::new(),
        said: Vec::new(),
        warnings: Vec::new(),
        unreadable: false,
    };
    r.pages.push(match network {
        Network::Mainnet => page("Network", "Aptos", "", ""),
        Network::Testnet => {
            page("Network", "Aptos testnet", "", "Aptos's test network, whose APT is worth nothing.")
        }
    });
    match &tx.call {
        Call::Send { asset, payments, .. } => r.send(asset, payments),
        Call::Stake { action, pool, amount } => r.stake(*action, pool, *amount),
        Call::Object { object, to, kind } => r.object(object, to, kind),
        Call::Other => r.other(),
        // refused above
        Call::Control(_) => {}
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
    let mut summary = format!("{what}; fee up to {}", apt(max));
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
