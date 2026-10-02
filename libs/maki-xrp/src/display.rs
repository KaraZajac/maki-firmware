//! What the owner reads on maki's review screen before an XRP Ledger transaction is signed, as
//! pages: XRP and tokens sent, how much and to whom, with the destination tag an exchange needs;
//! a partial payment, which may deliver far less, said loudly; trust lines, offers, checks and
//! escrows; what hands the account over (a regular key, a signer list, its own key turned off)
//! or empties it (deleting it), loudly; memos; the fee, and how long the transaction stays good.
//! Each type is held to what rippled checks of it first (its `preflight`), so what the ledger
//! would refuse, maki refuses, saying why. A type maki doesn't read, or a field, is flagged: never
//! skipped.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Network;
use crate::address::{self, AccountId};
use crate::codec::fields::*;
use crate::codec::{Amount, Currency, Decimal, Field, Object, Step};
use crate::tokens;
use crate::tx::{FULLY_CANONICAL_SIG, Transaction};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`): a few
/// words at the top, the thing to check in bold (one line), fixed-width text (an address, across
/// as many lines as it takes), and prose.
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

/// What the owner goes through, and the line under the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub pages: Vec<Page>,
    /// The line under the question: what it does, and the fee.
    pub summary: String,
}

/// Why maki won't show a transaction for this account to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Another account's: its address.
    NotMine(String),
    /// For another key than this account's to sign.
    Key,
    /// For a delegate to sign for the account.
    Delegate,
    /// For another network: its NetworkID.
    Network(u32),
    /// The XRP Ledger would refuse it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotMine(account) => write!(f, "not this account's: it's {account}'s"),
            Error::Key => f.write_str("for another key than this account's to sign"),
            Error::Delegate => f.write_str("for a delegate to sign, not this account"),
            Error::Network(id) => write!(
                f,
                "for another network (network {id}): maki signs for the XRP Ledger and its test network"
            ),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// Seconds from the Unix epoch to the ledger's, 2000-01-01, which its times count from.
pub const LEDGER_EPOCH: u64 = 946_684_800;
/// The most fee xrpl.js sets (its client's `maxFeeXRP`): a fee over it is a mistake, or worse.
pub const HIGH_FEE: u64 = 2_000_000;

// Payment's flags
const NO_RIPPLE_DIRECT: u32 = 0x0001_0000;
const PARTIAL_PAYMENT: u32 = 0x0002_0000;
const LIMIT_QUALITY: u32 = 0x0004_0000;
// TrustSet's
const SET_AUTH: u32 = 0x0001_0000;
const SET_NO_RIPPLE: u32 = 0x0002_0000;
const CLEAR_NO_RIPPLE: u32 = 0x0004_0000;
const SET_FREEZE: u32 = 0x0010_0000;
const CLEAR_FREEZE: u32 = 0x0020_0000;
const SET_DEEP_FREEZE: u32 = 0x0040_0000;
const CLEAR_DEEP_FREEZE: u32 = 0x0080_0000;
// OfferCreate's
const PASSIVE: u32 = 0x0001_0000;
const IMMEDIATE_OR_CANCEL: u32 = 0x0002_0000;
const FILL_OR_KILL: u32 = 0x0004_0000;
const SELL: u32 = 0x0008_0000;
const HYBRID: u32 = 0x0010_0000;
// AccountSet's: each sets or clears one of its settings, as SetFlag and ClearFlag do
const ACCOUNT_SET_FLAGS: [(u32, u32, bool); 6] = [
    (0x0001_0000, REQUIRE_DEST, true),
    (0x0002_0000, REQUIRE_DEST, false),
    (0x0004_0000, REQUIRE_AUTH, true),
    (0x0008_0000, REQUIRE_AUTH, false),
    (0x0010_0000, DISALLOW_XRP, true),
    (0x0020_0000, DISALLOW_XRP, false),
];

// AccountSet's settings (SetFlag and ClearFlag)
const REQUIRE_DEST: u32 = 1;
const REQUIRE_AUTH: u32 = 2;
const DISALLOW_XRP: u32 = 3;
const DISABLE_MASTER: u32 = 4;
const NO_FREEZE: u32 = 6;
const NFTOKEN_MINTER_FLAG: u32 = 10;
const CLAWBACK: u32 = 16;

/// What each of AccountSet's settings is, as a page names it, and what setting it and clearing
/// it do. The master key, the NFT minter, and settings that can't be undone have pages of their
/// own.
const SETTINGS: &[(u32, &str, &str, &str)] = &[
    (
        REQUIRE_DEST,
        "destination tags",
        "Payments to this account will need a destination tag.",
        "Payments to this account won't need a destination tag.",
    ),
    (
        REQUIRE_AUTH,
        "authorized holders",
        "Only accounts it authorizes may hold the tokens it issues.",
        "Any account may hold the tokens it issues.",
    ),
    (
        DISALLOW_XRP,
        "no XRP, please",
        "Asks others not to send it XRP: wallets may heed it, the ledger doesn't.",
        "Takes back its ask not to be sent XRP.",
    ),
    (
        5,
        "its last transaction",
        "The account keeps its last transaction's ID, for transactions that name it.",
        "The account stops keeping its last transaction's ID.",
    ),
    (
        7,
        "a global freeze",
        "Freezes every token it issues: they can only go back to it.",
        "Ends its freeze on the tokens it issues.",
    ),
    (
        8,
        "rippling by default",
        "Trust lines to it let payments ripple through them, as an issuer's should.",
        "Trust lines to it won't let payments ripple through them.",
    ),
    (9, "deposit authorization", "Only accounts it authorizes can pay it.", "Any account can pay it."),
    (12, "no NFT offers", "Turns away offers for its NFTs.", "Takes offers for its NFTs again."),
    (13, "no checks", "Turns away checks written to it.", "Takes checks written to it again."),
    (
        14,
        "no payment channels",
        "Turns away payment channels opened to it.",
        "Takes payment channels opened to it again.",
    ),
    (15, "no trust lines", "Turns away trust lines opened to it.", "Takes trust lines opened to it again."),
    (
        17,
        "escrow of its tokens",
        "Lets the tokens it issues be held in escrow.",
        "Stops the tokens it issues being held in escrow.",
    ),
];

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

/// Drops, exactly, in XRP: `0.000012 XRP`.
pub fn xrp(drops: u64) -> String { format!("{} XRP", decimals(drops as u128, 6)) }

/// A token's amount, exactly, as a plain decimal: 16 digits and up to 80 zeros after them, or
/// up to 96 places after the point.
pub fn value(d: &Decimal) -> String {
    if d.mantissa == 0 {
        return "0".into();
    }
    if d.exponent >= 0 {
        return format!("{}{}", d.mantissa, "0".repeat(d.exponent as usize));
    }
    decimals(d.mantissa as u128, d.exponent.unsigned_abs().min(255) as u8)
}

/// How a currency's code reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Code {
    /// A standard code: three letters (or digits and some symbols) in the middle of zeros.
    Standard(String),
    /// A code of the token's own that's text: its letters, then zeros.
    Text(String),
    /// Any other code, in hex.
    Hex(String),
}

impl Code {
    /// As a page shows it.
    pub fn text(&self) -> &str {
        match self {
            Code::Standard(s) | Code::Text(s) | Code::Hex(s) => s,
        }
    }
}

/// The standard code for XRP, which no token may use.
const BAD_CURRENCY: Currency = {
    let mut c = [0u8; 20];
    c[12] = b'X';
    c[13] = b'R';
    c[14] = b'P';
    c
};

/// A currency's code, as xrpl.js reads one: three ISO 4217 letters (or digits and the symbols it
/// allows) as a standard code; text as a code of its own (as wallets show them); else hex.
pub fn code(c: &Currency) -> Code {
    let iso = |b: u8| b.is_ascii_alphanumeric() || b"?!@#$%^&*(){}[]|".contains(&b);
    if c[..12].iter().all(|&b| b == 0) && c[15..].iter().all(|&b| b == 0) && *c != BAD_CURRENCY {
        if c[12..15].iter().all(|&b| iso(b)) {
            return Code::Standard(c[12..15].iter().map(|&b| b as char).collect());
        }
    } else if c[0] != 0 {
        let len = c.iter().position(|&b| b == 0).unwrap_or(20);
        if c[..len].iter().all(|&b| b.is_ascii_graphic()) && c[len..].iter().all(|&b| b == 0) {
            return Code::Text(c[..len].iter().map(|&b| b as char).collect());
        }
    }
    Code::Hex(hex(c))
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02X}")).collect() }

/// A time the ledger gives (seconds since 2000-01-01), in UTC: `2025-09-28 03:34:38 UTC`.
pub fn utc(ledger_seconds: u32) -> String {
    let seconds = LEDGER_EPOCH + ledger_seconds as u64;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // days since 1970-01-01 to a date (Howard Hinnant's civil_from_days)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC", rest / 3_600, rest % 3_600 / 60, rest % 60)
}

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

fn is_zero(a: &Amount) -> bool {
    match a {
        Amount::Xrp(d) => *d == 0,
        Amount::Issued { value, .. } => value.mantissa == 0,
        Amount::Mpt { units, .. } => *units == 0,
    }
}

fn is_xrp(a: &Amount) -> bool { matches!(a, Amount::Xrp(_)) }

/// Whether an amount's token uses XRP's own standard code, which the ledger refuses.
fn bad_currency(a: &Amount) -> bool {
    matches!(a, Amount::Issued { currency, .. } if *currency == BAD_CURRENCY)
}

/// Whether two amounts are of one asset: XRP, a token of one issuer, or one MPT issuance.
fn same_asset(a: &Amount, b: &Amount) -> bool {
    match (a, b) {
        (Amount::Xrp(_), Amount::Xrp(_)) => true,
        (Amount::Issued { currency: c, issuer: i, .. }, Amount::Issued { currency: d, issuer: j, .. }) => {
            c == d && i == j
        }
        (Amount::Mpt { issuance: x, .. }, Amount::Mpt { issuance: y, .. }) => x == y,
        _ => false,
    }
}

/// Whether two amounts are of the same token as rippled's `equalTokens` has it: a token's
/// currency, whoever issues it.
fn same_token(a: &Amount, b: &Amount) -> bool {
    match (a, b) {
        (Amount::Issued { currency: c, .. }, Amount::Issued { currency: d, .. }) => c == d,
        _ => same_asset(a, b),
    }
}

/// Whether `a` is more than `b`, both of one asset and neither negative.
fn more(a: &Amount, b: &Amount) -> bool {
    match (a, b) {
        (Amount::Xrp(x), Amount::Xrp(y)) => x > y,
        (Amount::Mpt { units: x, .. }, Amount::Mpt { units: y, .. }) => x > y,
        (Amount::Issued { value: x, .. }, Amount::Issued { value: y, .. }) => {
            match (x.mantissa, y.mantissa) {
                (0, _) => false,
                (_, 0) => true,
                // both 16 digits: the exponent says which is more, then the digits
                _ => (x.exponent, x.mantissa) > (y.exponent, y.mantissa),
            }
        }
        _ => false,
    }
}

/// An amount, as a page says it: XRP; a token's amount and the name maki knows it by, or its
/// code (an unknown token's page, after, says whose); an MPT's in its smallest units.
pub fn amount(a: &Amount) -> String {
    match a {
        Amount::Xrp(drops) => xrp(*drops),
        Amount::Issued { value: v, currency, issuer } => format!("{} {}", value(v), symbol(currency, issuer)),
        Amount::Mpt { units, .. } => format!("{units} units of an MPT"),
    }
}

/// What an amount of a token is said in: its symbol, if maki knows it, else its code (or
/// "tokens", for a code that's neither letters nor text). Never XRP: a token called that is said
/// to be one.
fn symbol(currency: &Currency, issuer: &AccountId) -> String {
    if let Some(t) = tokens::known(currency, issuer) {
        return t.symbol.into();
    }
    match code(currency) {
        Code::Standard(s) | Code::Text(s) if s.eq_ignore_ascii_case("xrp") => format!("tokens called {s}"),
        Code::Standard(s) | Code::Text(s) => s,
        Code::Hex(_) => "tokens".into(),
    }
}

struct Reading<'a> {
    tx: &'a Transaction,
    f: &'a Object,
    me: AccountId,
    pages: Vec<Page>,
    /// What it does that the owner must not miss.
    warnings: Vec<String>,
    /// Something maki can't read.
    unreadable: bool,
    /// The fields read, each shown or checked: any other is flagged.
    read: Vec<Field>,
    /// The tokens a page has said whose they are: each once.
    tokens: Vec<Vec<u8>>,
    /// What it does, for the summary.
    what: String,
}

fn invalid(why: &'static str) -> Error { Error::Invalid(why) }

impl<'a> Reading<'a> {
    /// Marks `field` read: shown, or checked.
    fn read(&mut self, field: Field) { self.read.push(field) }

    fn read_u32(&mut self, field: Field) -> Option<u32> {
        self.read(field);
        self.f.u32(field)
    }

    fn read_amount(&mut self, field: Field) -> Option<Amount> {
        self.read(field);
        self.f.amount(field).copied()
    }

    fn read_account(&mut self, field: Field) -> Option<AccountId> {
        self.read(field);
        self.f.account(field).copied()
    }

    fn read_bytes(&mut self, field: Field) -> Option<&'a [u8]> {
        self.read(field);
        self.f.bytes(field)
    }

    fn warn(&mut self, warning: &str) {
        if !self.warnings.iter().any(|w| w == warning) {
            self.warnings.push(warning.into());
        }
    }

    /// An account, as a page shows it: this account, or its address.
    fn who(&self, account: &AccountId) -> String {
        if *account == self.me { "this account".into() } else { address::encode(account) }
    }

    /// The transaction's flags, refused if any isn't its type's (`allowed`) or every
    /// transaction's.
    fn flags(&mut self, allowed: u32) -> Result<u32, Error> {
        self.read(FLAGS);
        if self.tx.flags & !(allowed | FULLY_CANONICAL_SIG) != 0 {
            return Err(invalid("a flag this transaction can't have: the XRP Ledger would refuse it"));
        }
        Ok(self.tx.flags)
    }

    /// The page saying whose a token is, the first time an amount of it comes up.
    fn token(&mut self, a: &Amount) {
        let key = match a {
            Amount::Xrp(_) => return,
            Amount::Issued { currency, issuer, .. } => [&currency[..], &issuer[..]].concat(),
            Amount::Mpt { issuance, .. } => issuance.to_vec(),
        };
        if self.tokens.contains(&key) {
            return;
        }
        self.tokens.push(key);
        let p = match a {
            Amount::Issued { currency, issuer, .. } => {
                let by = self.who(issuer);
                if let Some(t) = tokens::known(currency, issuer) {
                    page("Token", t.symbol, by, format!("Issued by {}.", t.by))
                } else {
                    let c = code(currency);
                    if c.text().eq_ignore_ascii_case("xrp") {
                        self.warn("which aren't XRP");
                        self.pages.push(page(
                            "Not XRP!",
                            format!("a token called {}", c.text()),
                            format!("{}\n{by}", hex(currency)),
                            "XRP has no issuer: this is a token someone issued, and worth what they stand behind.",
                        ));
                    }
                    let mono = match &c {
                        Code::Standard(s) => format!("{s}\n{by}"),
                        Code::Text(s) => format!("{s}\n{}\n{by}", hex(currency)),
                        Code::Hex(h) => format!("{h}\n{by}"),
                    };
                    page(
                        "Token",
                        "one maki doesn't know",
                        mono,
                        "Anyone can issue a token by any name: check it's from the issuer you mean.",
                    )
                }
            }
            Amount::Mpt { issuance, .. } => {
                let sequence = u32::from_be_bytes([issuance[0], issuance[1], issuance[2], issuance[3]]);
                let issuer: AccountId = issuance[4..].try_into().unwrap_or([0; 20]);
                page(
                    "Token",
                    "an MPT maki doesn't know",
                    format!("issuance {sequence}\nby {}", self.who(&issuer)),
                    "Its amount is in its smallest units: maki can't see its decimals, or its name.",
                )
            }
            Amount::Xrp(_) => return,
        };
        self.pages.push(p);
    }

    fn tag_page(&mut self) {
        if let Some(tag) = self.read_u32(DESTINATION_TAG) {
            self.pages.push(page(
                "Destination tag",
                tag.to_string(),
                "",
                "The recipient's tag for it: an exchange's tells them whose deposit it is. Check it's the one you were given.",
            ));
        }
    }

    fn invoice_page(&mut self) {
        if let Some(id) = self.read_bytes(INVOICE_ID).map(hex) {
            self.pages.push(page("Invoice", "", id, "The recipient's ID for what it pays for."));
        }
    }

    fn expiration_page(&mut self, prose: &str) -> Result<(), Error> {
        if let Some(t) = self.read_u32(EXPIRATION) {
            if t == 0 {
                return Err(invalid("an expiration of 0: the XRP Ledger would refuse it"));
            }
            self.pages.push(page("Expires", utc(t), "", prose));
        }
        Ok(())
    }

    /// The credentials it shows its recipient, as rippled checks them: one to eight, none twice.
    fn credentials(&mut self) -> Result<(), Error> {
        self.read(CREDENTIAL_IDS);
        let Some(ids) = self.f.hashes(CREDENTIAL_IDS) else { return Ok(()) };
        if ids.is_empty() || ids.len() > 8 {
            return Err(invalid("credentials, but not 1 to 8 of them: the XRP Ledger would refuse it"));
        }
        if ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id)) {
            return Err(invalid("a credential given twice: the XRP Ledger would refuse it"));
        }
        let mono = ids.iter().map(|id| hex(id)).collect::<Vec<_>>().join("\n");
        self.pages.push(page(
            "Credentials",
            format!("{} of this account's", ids.len()),
            mono,
            "Shown to the recipient, which takes deposits only from accounts with them.",
        ));
        Ok(())
    }

    /// The permissioned domain whose order books it's limited to.
    fn domain(&mut self) -> Result<(), Error> {
        if let Some(id) = self.read_bytes(DOMAIN_ID) {
            if id.iter().all(|&b| b == 0) {
                return Err(invalid("a permissioned domain of 0: the XRP Ledger would refuse it"));
            }
            let id = hex(id);
            self.pages.push(page(
                "Domain",
                "a permissioned one",
                id,
                "It trades only through the offers of the accounts that domain admits.",
            ));
        }
        Ok(())
    }

    fn payment(&mut self) -> Result<(), Error> {
        let amount = self.read_amount(AMOUNT).ok_or(invalid("a payment without an amount"))?;
        let dest = self.read_account(DESTINATION).ok_or(invalid("a payment without a destination"))?;
        let send_max = self.read_amount(SEND_MAX);
        let deliver_min = self.read_amount(DELIVER_MIN);
        self.read(PATHS);
        let paths: Vec<Vec<Step>> = self.f.paths(PATHS).map(|p| p.to_vec()).unwrap_or_default();
        let mpt = matches!(amount, Amount::Mpt { .. });
        let flags = self.flags(if mpt {
            PARTIAL_PAYMENT
        } else {
            NO_RIPPLE_DIRECT | PARTIAL_PAYMENT | LIMIT_QUALITY
        })?;
        let partial = flags & PARTIAL_PAYMENT != 0;
        // what rippled checks of a payment first (Payment::preflight)
        let source = send_max.unwrap_or(amount);
        if dest == [0; 20] {
            return Err(invalid("a payment to no account: the XRP Ledger would refuse it"));
        }
        if is_zero(&amount) || send_max.as_ref().is_some_and(is_zero) {
            return Err(invalid("a payment of nothing: the XRP Ledger would refuse it"));
        }
        if bad_currency(&amount) || bad_currency(&source) {
            return Err(invalid("a token with XRP's own code: the XRP Ledger would refuse it"));
        }
        // multi-purpose tokens go directly, as themselves, until the ledger's next rules
        if mpt && !paths.is_empty() {
            return Err(invalid("an MPT sent through paths: the XRP Ledger would refuse it"));
        }
        if mpt && !same_asset(&source, &amount) || !mpt && matches!(source, Amount::Mpt { .. }) {
            return Err(invalid("an MPT paid for with something else: the XRP Ledger would refuse it"));
        }
        if dest == self.me && same_token(&source, &amount) && paths.is_empty() {
            return Err(invalid("a payment to itself, in what it pays with: the XRP Ledger would refuse it"));
        }
        // XRP sent as XRP goes straight there, whole
        if is_xrp(&source) && is_xrp(&amount) {
            if send_max.is_some() {
                return Err(invalid("XRP sent as XRP, with a most it costs: the XRP Ledger would refuse it"));
            }
            if !paths.is_empty() {
                return Err(invalid("XRP sent as XRP, through paths: the XRP Ledger would refuse it"));
            }
            if partial {
                return Err(invalid("XRP sent as XRP, as a partial payment: the XRP Ledger would refuse it"));
            }
            if flags & (LIMIT_QUALITY | NO_RIPPLE_DIRECT) != 0 {
                return Err(invalid("XRP sent as XRP, with routing flags: the XRP Ledger would refuse it"));
            }
        }
        if let Some(min) = &deliver_min {
            if !partial {
                return Err(invalid(
                    "a least to deliver, in a payment that isn't partial: the XRP Ledger would refuse it",
                ));
            }
            if is_zero(min) || !same_asset(min, &amount) {
                return Err(invalid(
                    "a least to deliver of nothing, or of another token: the XRP Ledger would refuse it",
                ));
            }
            if more(min, &amount) {
                return Err(invalid("a least to deliver over what it sends: the XRP Ledger would refuse it"));
            }
        }
        if paths.len() > 6 || paths.iter().any(|p| p.len() > 8) {
            return Err(invalid("more paths than the XRP Ledger takes: 6, of 8 steps"));
        }
        if paths.is_empty() && flags & NO_RIPPLE_DIRECT != 0 {
            return Err(invalid("no paths, and not straight there either: the XRP Ledger would refuse it"));
        }
        let to = self.who(&dest);
        let shown = self::amount(&amount);
        if dest == self.me {
            self.pages.push(page(
                "Convert",
                shown.clone(),
                to,
                "Into this account: a trade on the ledger's exchange, paid for as below.",
            ));
            self.what = format!("converts to {shown}");
        } else {
            self.pages.push(page("Send", shown.clone(), to, ""));
            self.what = format!("sends {shown}");
        }
        self.token(&amount);
        self.tag_page();
        if partial {
            let least = match &deliver_min {
                Some(min) => format!("as little as {}", self::amount(min)),
                None => String::from("far less, even next to nothing"),
            };
            self.pages.push(page(
                "Partial payment!",
                "may deliver less",
                "",
                format!("{shown} is the most it delivers: the recipient may get {least}."),
            ));
            self.warn("may deliver far less");
        }
        if let Some(max) = &send_max {
            self.pages.push(page(
                "Costs at most",
                self::amount(max),
                "",
                "What this account may pay for it, at most, through the order books and trust lines on its way.",
            ));
            self.token(max);
        }
        let mut routing = Vec::new();
        if flags & NO_RIPPLE_DIRECT != 0 {
            routing.push("Only along the paths given, not straight to the recipient.");
        }
        if flags & LIMIT_QUALITY != 0 {
            routing.push("Only at a rate as good as the most it costs for what it sends, or better.");
        }
        if !paths.is_empty() {
            let n = paths.len();
            let mut prose = String::from("Through others' offers and trust lines, on its way.");
            for r in routing {
                prose.push(' ');
                prose.push_str(r);
            }
            self.pages.push(page("Paths", format!("{n} path{}", if n == 1 { "" } else { "s" }), "", prose));
        } else if !routing.is_empty() {
            self.pages.push(page("Paths", "the direct one", "", routing.join(" ")));
        }
        self.invoice_page();
        self.credentials()?;
        self.domain()
    }

    fn trust_set(&mut self) -> Result<(), Error> {
        let limit = self
            .read_amount(LIMIT_AMOUNT)
            .ok_or(invalid("a trust line without a limit: the XRP Ledger would refuse it"))?;
        let flags = self.flags(
            SET_AUTH
                | SET_NO_RIPPLE
                | CLEAR_NO_RIPPLE
                | SET_FREEZE
                | CLEAR_FREEZE
                | SET_DEEP_FREEZE
                | CLEAR_DEEP_FREEZE,
        )?;
        let Amount::Issued { value: v, currency, issuer } = limit else {
            return Err(invalid(
                "a trust line for something other than a token: the XRP Ledger would refuse it",
            ));
        };
        if bad_currency(&limit) {
            return Err(invalid("a token with XRP's own code: the XRP Ledger would refuse it"));
        }
        if issuer == self.me {
            return Err(invalid("a trust line to itself: the XRP Ledger would refuse it"));
        }
        if flags & (SET_NO_RIPPLE | CLEAR_NO_RIPPLE) == SET_NO_RIPPLE | CLEAR_NO_RIPPLE
            || flags & (SET_FREEZE | SET_DEEP_FREEZE) != 0 && flags & (CLEAR_FREEZE | CLEAR_DEEP_FREEZE) != 0
        {
            return Err(invalid("a setting turned both on and off: the XRP Ledger would refuse it"));
        }
        let name = symbol(&currency, &issuer);
        let by = self.who(&issuer);
        let (value_text, prose) = if v.mantissa == 0 {
            (
                String::from("limit 0"),
                format!(
                    "This account takes no more {name} from this issuer: once it holds none, the line closes and its reserve comes back."
                ),
            )
        } else {
            (
                format!("up to {} {name}", value(&v)),
                format!(
                    "This account takes {name} from this issuer, up to that much. While the line's open, some of its XRP is held in reserve."
                ),
            )
        };
        self.what =
            if v.mantissa == 0 { format!("closes its {name} line") } else { format!("trusts {name}") };
        self.pages.push(page("Trust line", value_text, by, prose));
        self.token(&limit);
        for (field, way) in [(QUALITY_IN, "coming in"), (QUALITY_OUT, "going out")] {
            if let Some(q) = self.read_u32(field) {
                let rate = if q == 0 { String::from("1 (face value)") } else { decimals(q as u128, 9) };
                self.pages.push(page(
                    "Quality",
                    format!("{rate} {way}"),
                    "",
                    format!("What this account counts a unit of {name} {way} through this line as."),
                ));
            }
        }
        let issuer_text = self.who(&issuer);
        let setting: [(u32, &str, &str, String); 7] = [
            (
                SET_AUTH,
                "Authorizes",
                "them to hold its tokens",
                format!("This account issues {name}: {issuer_text} may hold it."),
            ),
            (
                SET_NO_RIPPLE,
                "No rippling",
                "through this line",
                String::from("Payments can't move between this line and this account's others."),
            ),
            (
                CLEAR_NO_RIPPLE,
                "Rippling!",
                "through this line",
                format!(
                    "Payments may move through it: what this account holds of {name} can shift to other lines of the same code, other issuers'."
                ),
            ),
            (
                SET_FREEZE,
                "Freezes",
                "the line",
                format!("{issuer_text} can only send its {name} back to this account."),
            ),
            (CLEAR_FREEZE, "Unfreezes", "the line", String::from("Its freeze on the line ends.")),
            (
                SET_DEEP_FREEZE,
                "Freezes deep",
                "the line",
                format!("{issuer_text} can neither send nor take {name} on it."),
            ),
            (
                CLEAR_DEEP_FREEZE,
                "Unfreezes deep",
                "the line",
                String::from("Its deep freeze on the line ends."),
            ),
        ];
        for (flag, heading, value, prose) in setting {
            if flags & flag != 0 {
                self.pages.push(page(heading, value, "", prose));
            }
        }
        if flags & CLEAR_NO_RIPPLE != 0 {
            self.warn("lets payments ripple through it");
        }
        Ok(())
    }

    fn offer_create(&mut self) -> Result<(), Error> {
        let gets = self.read_amount(TAKER_GETS).ok_or(invalid("an offer without what it gives"))?;
        let pays = self.read_amount(TAKER_PAYS).ok_or(invalid("an offer without what it takes"))?;
        let flags = self.flags(PASSIVE | IMMEDIATE_OR_CANCEL | FILL_OR_KILL | SELL | HYBRID)?;
        if flags & HYBRID != 0 && !self.f.has(DOMAIN_ID) {
            return Err(invalid("a hybrid offer without its domain: the XRP Ledger would refuse it"));
        }
        if flags & (IMMEDIATE_OR_CANCEL | FILL_OR_KILL) == IMMEDIATE_OR_CANCEL | FILL_OR_KILL {
            return Err(invalid(
                "an offer both immediate-or-cancel and fill-or-kill: the XRP Ledger would refuse it",
            ));
        }
        if is_zero(&gets) || is_zero(&pays) {
            return Err(invalid("an offer of nothing: the XRP Ledger would refuse it"));
        }
        if is_xrp(&gets) && is_xrp(&pays) || same_asset(&gets, &pays) {
            return Err(invalid("an offer of a thing for itself: the XRP Ledger would refuse it"));
        }
        if bad_currency(&gets) || bad_currency(&pays) {
            return Err(invalid("a token with XRP's own code: the XRP Ledger would refuse it"));
        }
        if matches!(gets, Amount::Mpt { .. }) || matches!(pays, Amount::Mpt { .. }) {
            return Err(invalid("an offer of an MPT: the XRP Ledger takes none yet"));
        }
        let (give, take) = (self::amount(&gets), self::amount(&pays));
        let mut how = String::from(
            "On the ledger's exchange, until it's taken, cancelled or expires: whoever takes it gets this from this account.",
        );
        let terms = [
            (SELL, " It sells all of it, even for more than it asks."),
            (PASSIVE, " It waits to be taken: it doesn't take an offer at its own rate."),
            (IMMEDIATE_OR_CANCEL, " Only what trades at once: the rest is cancelled."),
            (FILL_OR_KILL, " All of it at once, or nothing."),
            (HYBRID, " In the open order books as well as its domain's."),
        ];
        for (flag, t) in terms {
            if flags & flag != 0 {
                how.push_str(t);
            }
        }
        self.pages.push(page("Offers", give.clone(), "", how));
        self.token(&gets);
        self.pages.push(page(
            "For",
            take.clone(),
            "",
            "What this account gets for it, at that rate or better.",
        ));
        self.token(&pays);
        self.expiration_page("It's gone then, whatever's left of it.")?;
        if let Some(seq) = self.read_u32(OFFER_SEQUENCE) {
            if seq == 0 {
                return Err(invalid("an offer to cancel numbered 0: the XRP Ledger would refuse it"));
            }
            self.pages.push(page(
                "Replaces",
                format!("offer #{seq}"),
                "",
                "It cancels this account's offer with that sequence number first.",
            ));
        }
        self.domain()?;
        self.what = format!("offers {give} for {take}");
        Ok(())
    }

    fn offer_cancel(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let seq = self.read_u32(OFFER_SEQUENCE).unwrap_or(0);
        if seq == 0 {
            return Err(invalid("an offer to cancel numbered 0: the XRP Ledger would refuse it"));
        }
        self.pages.push(page(
            "Cancel offer",
            format!("#{seq}"),
            "",
            "This account's offer with that sequence number, if it's still there.",
        ));
        self.what = format!("cancels offer #{seq}");
        Ok(())
    }

    fn account_set(&mut self) -> Result<(), Error> {
        let flags = self.flags(ACCOUNT_SET_FLAGS.iter().fold(0, |m, f| m | f.0))?;
        let set = self.read_u32(SET_FLAG).unwrap_or(0);
        let clear = self.read_u32(CLEAR_FLAG).unwrap_or(0);
        if set != 0 && set == clear {
            return Err(invalid("a setting both set and cleared: the XRP Ledger would refuse it"));
        }
        // each setting it changes, and whether it's set (true) or cleared
        let mut changes: Vec<(u32, bool)> = Vec::new();
        if set != 0 {
            changes.push((set, true));
        }
        if clear != 0 {
            changes.push((clear, false));
        }
        for &(flag, setting, on) in &ACCOUNT_SET_FLAGS {
            if flags & flag != 0 {
                changes.push((setting, on));
            }
        }
        for s in [REQUIRE_DEST, REQUIRE_AUTH, DISALLOW_XRP] {
            if changes.contains(&(s, true)) && changes.contains(&(s, false)) {
                return Err(invalid("a setting both set and cleared: the XRP Ledger would refuse it"));
            }
        }
        // a setting named twice (by a flag and by SetFlag) is one change
        let mut once: Vec<(u32, bool)> = Vec::new();
        for c in changes {
            if !once.contains(&c) {
                once.push(c);
            }
        }
        let minter = self.read_account(NFTOKEN_MINTER);
        if set == NFTOKEN_MINTER_FLAG && minter.is_none() || clear == NFTOKEN_MINTER_FLAG && minter.is_some()
        {
            return Err(invalid(
                "an NFT minter without its setting, or cleared with one: the XRP Ledger would refuse it",
            ));
        }
        if minter.is_some() && set != NFTOKEN_MINTER_FLAG {
            // only that setting takes a minter: without it, rippled leaves it be
            self.read.retain(|f| *f != NFTOKEN_MINTER);
        }
        for (flag, on) in once {
            self.setting(flag, on, minter.as_ref());
        }
        let transfer = self.read_u32(TRANSFER_RATE);
        if let Some(rate) = transfer {
            if rate != 0 && !(1_000_000_000..=2_000_000_000).contains(&rate) {
                return Err(invalid(
                    "a transfer fee over 100%, or a rate under 1: the XRP Ledger would refuse it",
                ));
            }
            let fee = if rate <= 1_000_000_000 {
                String::from("none")
            } else {
                format!("{}%", decimals((rate - 1_000_000_000) as u128, 7))
            };
            self.pages.push(page(
                "Transfer fee",
                fee,
                "",
                "What this account keeps, of the tokens it issues, when others pay each other in them.",
            ));
        }
        if let Some(size) = self.f.u8(TICK_SIZE) {
            self.read(TICK_SIZE);
            if size != 0 && !(3..=15).contains(&size) {
                return Err(invalid("a tick size that isn't 3 to 15: the XRP Ledger would refuse it"));
            }
            let value = if size == 0 { String::from("none") } else { format!("{size} digits") };
            self.pages.push(page(
                "Tick size",
                value,
                "",
                "How finely offers in the tokens it issues are priced.",
            ));
        }
        if let Some(domain) = self.read_bytes(DOMAIN).map(|d| d.to_vec()) {
            if domain.len() > 256 {
                return Err(invalid("a domain longer than 256 bytes: the XRP Ledger would refuse it"));
            }
            let p = match (domain.is_empty(), text(&domain)) {
                (true, _) => page("Domain", "taken away", "", "The account no longer says where it's from."),
                (false, Some(t)) => {
                    page("Domain", "", t, "Where this account says it's from: anyone can read it.")
                }
                (false, None) => page(
                    "Domain",
                    "in hex",
                    hex(&domain),
                    "Where this account says it's from: anyone can read it.",
                ),
            };
            self.pages.push(p);
        }
        if let Some(key) = self.read_bytes(MESSAGE_KEY).map(|k| k.to_vec()) {
            let valid = key.len() == 33 && matches!(key[0], 0x02 | 0x03 | 0xed);
            if !key.is_empty() && !valid {
                return Err(invalid("a message key that isn't a key: the XRP Ledger would refuse it"));
            }
            let p = if key.is_empty() {
                page("Message key", "taken away", "", "")
            } else {
                page("Message key", "", hex(&key), "A public key for messages to this account.")
            };
            self.pages.push(p);
        }
        for (field, heading, prose) in [
            (EMAIL_HASH, "Email hash", "For a picture beside its address (Gravatar's): anyone can read it."),
            (WALLET_LOCATOR, "Wallet locator", "Kept on the account; the ledger does nothing with it."),
        ] {
            if let Some(h) = self.read_bytes(field) {
                let p = if h.iter().all(|&b| b == 0) {
                    page(heading, "taken away", "", "")
                } else {
                    page(heading, "", hex(h), prose)
                };
                self.pages.push(p);
            }
        }
        if let Some(size) = self.read_u32(WALLET_SIZE) {
            self.pages.push(page(
                "Wallet size",
                size.to_string(),
                "",
                "Kept on the account; the ledger does nothing with it.",
            ));
        }
        if self.pages.is_empty() {
            self.pages.push(page(
                "Settings",
                "no change",
                "",
                "It changes nothing: it only takes a sequence number, and pays the fee.",
            ));
            self.what = String::from("changes nothing");
        } else if self.warnings.is_empty() {
            // what's loud says what it does
            self.what = String::from("changes the account's settings");
        }
        Ok(())
    }

    /// A page for one of AccountSet's settings, set (`on`) or cleared.
    fn setting(&mut self, flag: u32, on: bool, minter: Option<&AccountId>) {
        let heading = if on { "Sets" } else { "Clears" };
        match (flag, on) {
            (DISABLE_MASTER, true) => {
                self.warn("turns off this account's own key");
                self.pages.push(page(
                    "Turns off its key!",
                    "this account's own key",
                    "",
                    "From then on only its regular key or its signer list can sign for it: lose those, and the account is lost.",
                ));
            }
            (DISABLE_MASTER, false) => self.pages.push(page(
                heading,
                "own key turned off",
                "",
                "Turns this account's own key back on.",
            )),
            (NFTOKEN_MINTER_FLAG, true) => {
                self.warn("lets another mint its NFTs");
                let who = minter.map(|m| self.who(m)).unwrap_or_default();
                self.pages.push(page(
                    "NFT minter!",
                    "may mint as this account",
                    who,
                    "That account may mint NFTs this account issues, until it's taken away.",
                ));
            }
            (NFTOKEN_MINTER_FLAG, false) => self.pages.push(page(
                heading,
                "its NFT minter",
                "",
                "No other account may mint NFTs this account issues.",
            )),
            (NO_FREEZE, true) => {
                self.warn("gives up freezing, for good");
                self.pages.push(page(
                    "For good!",
                    "no freezing",
                    "",
                    "It gives up freezing the tokens it issues, and can never take it back.",
                ));
            }
            (CLAWBACK, true) => {
                self.warn("lets it claw back its tokens, for good");
                self.pages.push(page(
                    "For good!",
                    "clawback",
                    "",
                    "It may claw back the tokens it issues from their holders, and can never take that back.",
                ));
            }
            (NO_FREEZE | CLAWBACK, false) => self.pages.push(page(
                heading,
                "a setting for good",
                "",
                "It can't be cleared: the ledger leaves it as it is.",
            )),
            _ => match SETTINGS.iter().find(|s| s.0 == flag) {
                Some(&(_, name, set, cleared)) => {
                    self.pages.push(page(heading, name, "", if on { set } else { cleared }))
                }
                None => {
                    self.unreadable = true;
                    self.pages.push(page(heading, format!("setting {flag}"), "", "One maki doesn't know."));
                }
            },
        }
    }

    fn set_regular_key(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        match self.read_account(REGULAR_KEY) {
            Some(key) if key == self.me => {
                return Err(invalid("its own key as its regular key: the XRP Ledger would refuse it"));
            }
            Some(key) => {
                self.warn("lets another key sign for it");
                self.pages.push(page(
                    "Hands over!",
                    "a key to this account",
                    address::encode(&key),
                    "That address's key can sign for this account, as its own key can, until it's taken away.",
                ));
            }
            None => {
                self.pages.push(page(
                    "Regular key",
                    "taken away",
                    "",
                    "Only this account's own key, or its signer list, can sign for it then.",
                ));
                self.what = String::from("takes its regular key away");
            }
        }
        Ok(())
    }

    fn signer_list_set(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let quorum = self.read_u32(SIGNER_QUORUM).unwrap_or(0);
        self.read(SIGNER_ENTRIES);
        let entries = self.f.array(SIGNER_ENTRIES);
        match (quorum, entries) {
            (0, None) => {
                self.pages.push(page(
                    "Signer list",
                    "taken away",
                    "",
                    "No other accounts can sign for this one together then.",
                ));
                self.what = String::from("takes its signer list away");
                Ok(())
            }
            (q, Some(entries)) if q > 0 => {
                if entries.is_empty() || entries.len() > 32 {
                    return Err(invalid(
                        "a signer list without 1 to 32 signers: the XRP Ledger would refuse it",
                    ));
                }
                let mut signers: Vec<(AccountId, u16, Option<String>)> = Vec::new();
                for (f, entry) in entries {
                    let allowed = [ACCOUNT, SIGNER_WEIGHT, WALLET_LOCATOR];
                    if *f != SIGNER_ENTRY || entry.fields.iter().any(|(k, _)| !allowed.contains(k)) {
                        return Err(invalid(
                            "a signer list with something else in it: the XRP Ledger would refuse it",
                        ));
                    }
                    let (Some(account), Some(weight)) = (entry.account(ACCOUNT), entry.u16(SIGNER_WEIGHT))
                    else {
                        return Err(invalid(
                            "a signer without its account or weight: the XRP Ledger would refuse it",
                        ));
                    };
                    if *account == self.me {
                        return Err(invalid(
                            "a signer list with this account in it: the XRP Ledger would refuse it",
                        ));
                    }
                    if weight == 0 {
                        return Err(invalid("a signer of no weight: the XRP Ledger would refuse it"));
                    }
                    if signers.iter().any(|s| s.0 == *account) {
                        return Err(invalid("a signer twice: the XRP Ledger would refuse it"));
                    }
                    signers.push((*account, weight, entry.bytes(WALLET_LOCATOR).map(hex)));
                }
                let total: u64 = signers.iter().map(|s| s.1 as u64).sum();
                if total < q as u64 {
                    return Err(invalid("a quorum its signers can't reach: the XRP Ledger would refuse it"));
                }
                let mono = signers
                    .iter()
                    .map(|(a, w, locator)| {
                        let mut line = format!("{}, weight {w}", address::encode(a));
                        if let Some(l) = locator {
                            line.push_str(&format!("\nlocator {l}"));
                        }
                        line
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let n = signers.len();
                self.warn(&format!("lets {n} other key{} sign for it", if n == 1 { "" } else { "s" }));
                self.pages.push(page(
                    "Hands over!",
                    format!("to {n} signer{}", if n == 1 { "" } else { "s" }),
                    mono,
                    format!(
                        "Signers whose weights add up to {q} can sign for this account together, as its own key can, until the list is taken away."
                    ),
                ));
                Ok(())
            }
            _ => Err(invalid(
                "a signer list without its quorum, or a quorum without its list: the XRP Ledger would refuse it",
            )),
        }
    }

    fn account_delete(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let dest = self.read_account(DESTINATION).ok_or(invalid("a deletion without a destination"))?;
        if dest == self.me {
            return Err(invalid("an account deleted into itself: the XRP Ledger would refuse it"));
        }
        self.warn(&format!("deletes this account, all its XRP to {}", address::encode(&dest)));
        self.pages.push(page(
            "Deletes it!",
            "this account",
            address::encode(&dest),
            "All its XRP goes to this address, less the fee, and the account is gone from the ledger.",
        ));
        self.tag_page();
        self.credentials()
    }

    fn check_create(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let dest = self.read_account(DESTINATION).ok_or(invalid("a check without a destination"))?;
        let max = self.read_amount(SEND_MAX).ok_or(invalid("a check without its amount"))?;
        if dest == self.me {
            return Err(invalid("a check to itself: the XRP Ledger would refuse it"));
        }
        if is_zero(&max) {
            return Err(invalid("a check for nothing: the XRP Ledger would refuse it"));
        }
        if bad_currency(&max) {
            return Err(invalid("a token with XRP's own code: the XRP Ledger would refuse it"));
        }
        let shown = self::amount(&max);
        self.pages.push(page(
            "Check",
            format!("up to {shown}"),
            address::encode(&dest),
            "They may cash it for up to that, from this account, until it expires or is cancelled.",
        ));
        self.token(&max);
        self.tag_page();
        self.expiration_page("It can't be cashed after then.")?;
        self.invoice_page();
        self.what = format!("writes a check for up to {shown}");
        Ok(())
    }

    fn check_cash(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let id = self.read_bytes(CHECK_ID).map(hex).unwrap_or_default();
        let (exact, least) = (self.read_amount(AMOUNT), self.read_amount(DELIVER_MIN));
        let (least, a) = match (exact, least) {
            (Some(a), None) => ("", a),
            (None, Some(a)) => ("at least ", a),
            _ => {
                return Err(invalid(
                    "a check cashed for an amount and a least, or neither: the XRP Ledger would refuse it",
                ));
            }
        };
        if id.bytes().all(|b| b == b'0') {
            return Err(invalid("a check numbered 0: the XRP Ledger would refuse it"));
        }
        if is_zero(&a) || bad_currency(&a) {
            return Err(invalid(
                "a check cashed for nothing, or in XRP's own code: the XRP Ledger would refuse it",
            ));
        }
        let shown = format!("{least}{}", self::amount(&a));
        self.pages.push(page(
            "Cash check",
            shown.clone(),
            id,
            "From the account that wrote it, into this one.",
        ));
        self.token(&a);
        self.what = format!("cashes a check for {shown}");
        Ok(())
    }

    fn check_cancel(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let id = self.read_bytes(CHECK_ID).map(hex).unwrap_or_default();
        if id.bytes().all(|b| b == b'0') {
            return Err(invalid("a check numbered 0: the XRP Ledger would refuse it"));
        }
        self.pages.push(page("Cancel check", "", id, "The check is gone: it can't be cashed."));
        self.what = String::from("cancels a check");
        Ok(())
    }

    fn escrow_create(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let dest = self.read_account(DESTINATION).ok_or(invalid("an escrow without a destination"))?;
        let a = self.read_amount(AMOUNT).ok_or(invalid("an escrow without an amount"))?;
        let (finish, cancel) = (self.read_u32(FINISH_AFTER), self.read_u32(CANCEL_AFTER));
        let condition = self.read_bytes(CONDITION).map(|c| c.to_vec());
        if is_zero(&a) || bad_currency(&a) {
            return Err(invalid(
                "an escrow of nothing, or in XRP's own code: the XRP Ledger would refuse it",
            ));
        }
        if finish.is_none() && cancel.is_none() {
            return Err(invalid("an escrow without a time: the XRP Ledger would refuse it"));
        }
        if let (Some(f), Some(c)) = (finish, cancel) {
            if c <= f {
                return Err(invalid(
                    "an escrow cancelled before it can be released: the XRP Ledger would refuse it",
                ));
            }
        }
        if finish.is_none() && condition.is_none() {
            return Err(invalid(
                "an escrow released at once, with no time or condition: the XRP Ledger would refuse it",
            ));
        }
        if condition.as_deref().is_some_and(|c| !condition_ok(c)) {
            return Err(invalid("an escrow's condition the XRP Ledger can't read: it would refuse it"));
        }
        let shown = self::amount(&a);
        self.pages.push(page(
            "Escrow",
            shown.clone(),
            self.who(&dest),
            "Held by the ledger, out of this account, until it's released to them or cancelled back.",
        ));
        self.token(&a);
        self.tag_page();
        if let Some(t) = finish {
            self.pages.push(page("Release after", utc(t), "", "It can't be released to them before then."));
        }
        if let Some(c) = condition {
            self.pages.push(page(
                "Condition",
                "",
                hex(&c),
                "It's released only with the fulfilment that matches: whoever has it can release it.",
            ));
        }
        if let Some(t) = cancel {
            self.pages.push(page(
                "Cancel after",
                utc(t),
                "",
                "If it isn't released by then, it can be cancelled, back to this account.",
            ));
        } else {
            self.pages.push(page(
                "No cancelling",
                "it can't come back",
                "",
                "With no time to cancel it, it stays in escrow until it's released to them.",
            ));
        }
        self.what = format!("escrows {shown}");
        Ok(())
    }

    fn escrow_finish(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let owner = self.read_account(OWNER).ok_or(invalid("an escrow without its owner"))?;
        let seq = self.read_u32(OFFER_SEQUENCE).unwrap_or(0);
        let (condition, fulfillment) = (
            self.read_bytes(CONDITION).map(|c| c.to_vec()),
            self.read_bytes(FULFILLMENT).map(|f| f.to_vec()),
        );
        if condition.is_some() != fulfillment.is_some() {
            return Err(invalid(
                "a condition without its fulfilment, or one without the other: the XRP Ledger would refuse it",
            ));
        }
        self.pages.push(page(
            "Release escrow",
            format!("#{seq}"),
            self.who(&owner),
            "Pays out that account's escrow, made with that sequence number, to its destination.",
        ));
        if let (Some(c), Some(f)) = (condition, fulfillment) {
            self.pages.push(page(
                "Fulfilment",
                "",
                format!("{}\nfor condition\n{}", hex(&f), hex(&c)),
                "The escrow's secret, which releases it: anyone can read it, once it's sent.",
            ));
        }
        self.credentials()?;
        self.what = format!("releases escrow #{seq}");
        Ok(())
    }

    fn escrow_cancel(&mut self) -> Result<(), Error> {
        self.flags(0)?;
        let owner = self.read_account(OWNER).ok_or(invalid("an escrow without its owner"))?;
        let seq = self.read_u32(OFFER_SEQUENCE).unwrap_or(0);
        self.pages.push(page(
            "Cancel escrow",
            format!("#{seq}"),
            self.who(&owner),
            "Returns that account's escrow, made with that sequence number, to it, once its time to cancel has come.",
        ));
        self.what = format!("cancels escrow #{seq}");
        Ok(())
    }

    /// A type maki doesn't read: what it is, and its fields, flagged.
    fn unknown(&mut self) {
        self.unreadable = true;
        // its own fields, by name: the common ones are on pages of their own
        let shown = [
            TRANSACTION_TYPE,
            ACCOUNT,
            SEQUENCE,
            TICKET_SEQUENCE,
            FEE,
            SIGNING_PUB_KEY,
            LAST_LEDGER_SEQUENCE,
            MEMOS,
            SOURCE_TAG,
            ACCOUNT_TXN_ID,
        ];
        let mut mono = String::from(self.tx.name);
        for (k, _) in &self.f.fields {
            if shown.contains(k) {
                continue;
            }
            // flags of 0 say nothing
            if *k != FLAGS || self.tx.flags != 0 {
                mono.push('\n');
                mono.push_str(&k.to_string());
            }
            self.read.push(*k);
        }
        self.pages.push(page(
            "Transaction",
            "maki can't read it",
            mono,
            "maki can't say what it does. Signed, it can do anything this account can.",
        ));
        self.what = format!("{}, which maki can't read", self.tx.name);
    }

    /// The memos, each as text if it's text, held to rippled's rules for them: memos alone, of
    /// a type and format in a URL's characters, a kilobyte in all.
    fn memos(&mut self) -> Result<(), Error> {
        self.read(MEMOS);
        let Some(memos) = self.f.array(MEMOS) else { return Ok(()) };
        let mut size = 0;
        let url = |b: u8| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b);
        for (f, memo) in memos {
            if *f != MEMO {
                return Err(invalid("memos with something else among them: the XRP Ledger would refuse it"));
            }
            size += 2;
            for (k, v) in &memo.fields {
                let crate::codec::Value::Blob(b) = v else {
                    return Err(invalid("a memo with something else in it: the XRP Ledger would refuse it"));
                };
                if ![MEMO_TYPE, MEMO_DATA, MEMO_FORMAT].contains(k) {
                    return Err(invalid("a memo with something else in it: the XRP Ledger would refuse it"));
                }
                if *k != MEMO_DATA && !b.iter().all(|&c| url(c)) {
                    return Err(invalid(
                        "a memo's type or format not in a URL's characters: the XRP Ledger would refuse it",
                    ));
                }
                size += 1 + crate::codec::length(b.len()).len() + b.len();
            }
        }
        if size > 1024 {
            return Err(invalid("memos over a kilobyte: the XRP Ledger would refuse them"));
        }
        let n = memos.len();
        for (i, (_, memo)) in memos.iter().enumerate() {
            let heading = if n == 1 { String::from("Memo") } else { format!("Memo {}", i + 1) };
            let data = memo.bytes(MEMO_DATA);
            let (value, mono) = match data {
                None => ("no data", String::new()),
                Some(d) => match text(d) {
                    Some(t) => ("", String::from(t)),
                    None => ("in hex", hex(d)),
                },
            };
            let mut prose = String::from("Everyone can read it, on the ledger.");
            for (field, what) in [(MEMO_TYPE, "type"), (MEMO_FORMAT, "format")] {
                if let Some(t) = memo.bytes(field).and_then(text) {
                    prose.push_str(&format!(" Its {what}: {t}."));
                }
            }
            self.pages.push(page(&heading, value, mono, prose));
        }
        Ok(())
    }
}

/// Whether `c` is a condition rippled reads (`Condition::deserialize`): PREIMAGE-SHA-256's, the
/// one kind it takes, in DER: its fingerprint (32 bytes) and its cost (a preimage's length, at
/// most 128), written in their short forms.
fn condition_ok(c: &[u8]) -> bool {
    let [0xa0, len, 0x80, 0x20, rest @ ..] = c else { return false };
    if *len >= 0x80 || *len as usize != c.len() - 2 || rest.len() < 32 + 3 {
        return false;
    }
    let cost = &rest[32..];
    let n = cost[1] as usize;
    if cost[0] != 0x81 || !(1..=5).contains(&n) || cost.len() != 2 + n || cost[2] & 0x80 != 0 {
        return false;
    }
    if n == 5 && cost[2] != 0 {
        return false;
    }
    cost[2..].iter().fold(0u64, |v, &b| (v << 8) | b as u64) <= 128
}

/// The pages the owner goes through before the account with public key `key` signs `tx`, on
/// `network` as the computer says, and the line that goes with them. Refused, before anything is
/// shown, if it isn't this account's to sign, or the ledger would refuse it.
pub fn review(tx: &Transaction, key: &[u8; 33], network: Network) -> Result<Review, Error> {
    let f = &tx.fields;
    if let Some(id) = f.u32(NETWORK_ID) {
        return Err(Error::Network(id));
    }
    let me = address::account_id(key);
    if tx.account != me {
        return Err(Error::NotMine(address::encode(&tx.account)));
    }
    if tx.key != *key {
        return Err(Error::Key);
    }
    if f.has(DELEGATE) {
        return Err(Error::Delegate);
    }
    let mut r = Reading {
        tx,
        f,
        me,
        pages: Vec::new(),
        warnings: Vec::new(),
        unreadable: false,
        read: Vec::from([
            TRANSACTION_TYPE,
            ACCOUNT,
            SIGNING_PUB_KEY,
            FEE,
            SEQUENCE,
            TICKET_SEQUENCE,
            LAST_LEDGER_SEQUENCE,
        ]),
        tokens: Vec::new(),
        what: String::new(),
    };
    match tx.name {
        "Payment" => r.payment()?,
        "TrustSet" => r.trust_set()?,
        "OfferCreate" => r.offer_create()?,
        "OfferCancel" => r.offer_cancel()?,
        "AccountSet" => r.account_set()?,
        "SetRegularKey" => r.set_regular_key()?,
        "SignerListSet" => r.signer_list_set()?,
        "AccountDelete" => r.account_delete()?,
        "CheckCreate" => r.check_create()?,
        "CheckCash" => r.check_cash()?,
        "CheckCancel" => r.check_cancel()?,
        "EscrowCreate" => r.escrow_create()?,
        "EscrowFinish" => r.escrow_finish()?,
        "EscrowCancel" => r.escrow_cancel()?,
        _ => r.unknown(),
    }
    r.memos()?;
    if let Some(tag) = r.read_u32(SOURCE_TAG) {
        r.pages.push(page("Source tag", tag.to_string(), "", "This account's own tag for it."));
    }
    if let Some(id) = r.read_bytes(ACCOUNT_TXN_ID).map(hex) {
        r.pages.push(page(
            "Only after",
            "",
            id,
            "It's good only if this account's last transaction was this one.",
        ));
    }
    // anything left, maki didn't read: flagged, by name
    let unread: Vec<String> =
        f.fields.iter().filter(|(k, _)| !r.read.contains(k)).map(|(k, _)| k.to_string()).collect();
    if !unread.is_empty() {
        r.unreadable = true;
        r.pages.push(page(
            "Not read",
            "maki can't read these",
            unread.join("\n"),
            "maki can't say what they do.",
        ));
    }
    let seq = match tx.ticket {
        Some(t) => format!("Ticket {t}"),
        None => format!("Sequence {}", tx.sequence),
    };
    let until = match tx.last_ledger {
        Some(l) => format!("{seq}; good until ledger {l}."),
        None => format!("{seq}. No last ledger: it stays good until it's sent, or that number's used."),
    };
    if tx.fee > HIGH_FEE {
        r.warn("a fee over 2 XRP");
        r.pages.push(page(
            "Fee!",
            xrp(tx.fee),
            "",
            format!("Far more than the ledger asks: xrpl.js never sets more than 2 XRP. Burnt, not paid to anyone. {until}"),
        ));
    } else {
        r.pages.push(page("Fee", xrp(tx.fee), "", until));
    }
    if network == Network::Test {
        let there = match tx.ticket {
            Some(t) => format!("holds ticket {t}"),
            None => format!("is at sequence {}", tx.sequence),
        };
        let until = tx.last_ledger.map(|l| format!(", until ledger {l}")).unwrap_or_default();
        r.pages.insert(
            0,
            page(
                "Network",
                network.name(),
                "",
                format!(
                    "So the computer says. An XRP Ledger transaction doesn't name its network: signed, it's good on the main network too, while this account there {there}{until}."
                ),
            ),
        );
    }
    let mut summary = r.what.clone();
    if !r.warnings.is_empty() {
        let w = r.warnings.join(", ");
        summary = if summary.is_empty() { format!("{w}!") } else { format!("{summary}, {w}!") };
    }
    // a type maki reads, but not all of (one it doesn't read says so already)
    if r.unreadable && type_read(tx.name) {
        summary = if r.warnings.is_empty() {
            format!("{summary}; maki can't read all of it")
        } else {
            format!("{summary} And maki can't read all of it")
        };
    }
    summary = format!("{summary}; fee {}", xrp(tx.fee));
    if network == Network::Test {
        summary = format!("testnet: {summary}");
    }
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

/// Whether maki reads transactions of this type.
pub fn type_read(name: &str) -> bool {
    matches!(
        name,
        "Payment"
            | "TrustSet"
            | "OfferCreate"
            | "OfferCancel"
            | "AccountSet"
            | "SetRegularKey"
            | "SignerListSet"
            | "AccountDelete"
            | "CheckCreate"
            | "CheckCash"
            | "CheckCancel"
            | "EscrowCreate"
            | "EscrowFinish"
            | "EscrowCancel"
    )
}
