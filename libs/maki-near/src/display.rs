//! What the owner reads on maki's review screen before a NEAR transaction is signed, as pages: the
//! network; each action in turn (NEAR and tokens sent and to whom, calls and what they're given,
//! keys added and deleted, staking, contracts deployed, published and used), every amount exact, in
//! NEAR or in a token's own units if maki knows it; and the most the fee can be, saying what maki
//! can't know of it. A key with full access, a key for calls, code put on the account, maki's own
//! key deleted and the account deleted are called out; a call maki can't read is flagged, with
//! what it can and can't do; and what NEAR would refuse, or what's another network's, is refused.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::account::{self, Kind};
use crate::fees::{self, MAX_GAS_PRICE, MIN_GAS_PRICE};
use crate::json::{self, Value};
use crate::tokens::{self, Token};
use crate::tx::{Action, Code, Permission, PublicKey, Transaction};
use crate::{Key, Network, account_id, base58};

/// A page of a review, as maki's review screen lays it out (`maki_app::wallet::Page`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// A few words at the top: what this page is about.
    pub heading: String,
    /// The thing to check, in bold: an amount.
    pub value: String,
    /// Fixed-width text, across as many lines as it takes: an account, a key.
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
    /// It's this account's, for another of its keys: maki's signature wouldn't be one NEAR takes.
    NotMaki,
    /// maki won't sign it, or can't show it: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotMine => f.write_str("another account's transaction, not this one's to sign"),
            Error::NotMaki => f.write_str("for another of this account's keys, not maki's"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;
/// The most text a page shows (maki's review screen's limit): arguments longer than that, maki
/// can't show.
pub const MAX_SHOWN: usize = 4096;
/// The most pages maki's review screen takes.
pub const MAX_PAGES: usize = 128;

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

/// YoctoNEAR, exactly, in NEAR: `1.5 NEAR`.
pub fn near(yocto: u128) -> String { format!("{} NEAR", decimals(yocto, 24)) }

/// Gas, exactly, in Tgas (10^12 gas): `30 Tgas`.
pub fn tgas(gas: u64) -> String { format!("{} Tgas", decimals(gas as u128, 12)) }

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// A contract's code hash, as NEAR shows it: the SHA-256 of its code, in base58.
fn code_hash(code: &[u8]) -> String { base58::encode(&Sha256::digest(code)) }

/// A key page's prose, and for a post-quantum key, how it's shown.
fn listed_by_hash(key: &PublicKey, prose: &str) -> String {
    match key {
        PublicKey::MlDsa65(_) => {
            format!("{prose} It's a post-quantum key, which NEAR lists by its hash, as here.")
        }
        _ => String::from(prose),
    }
}

/// Sentences, those there are, one after another.
fn sentences(parts: &[&str]) -> String {
    parts.iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ")
}

/// A token transfer, as NEP-141 has it: `ft_transfer` (`receiver_id`, `amount`, and a `memo` or
/// not), or `ft_transfer_call`, with the `msg` the receiver's contract is called with.
struct Transfer {
    receiver: String,
    amount: u128,
    memo: Option<String>,
    msg: Option<String>,
}

/// A token amount as NEP-141 writes it: a string of digits, with no zero before them (but zero).
fn amount(v: &Value) -> Option<u128> {
    let Value::String(s) = v else { return None };
    let b = s.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    s.parse().ok()
}

/// A string, or nothing (`null` or not there).
fn optional_string(v: Option<&Value>) -> Option<Option<String>> {
    match v {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        _ => None,
    }
}

fn get<'v>(members: &'v [(String, Value)], name: &str) -> Option<&'v Value> {
    members.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

/// A transfer's arguments, if they're exactly NEP-141's: no name maki doesn't know, each of the
/// kind it should be, and the receiver a name NEAR takes. Anything else, maki doesn't spell out.
fn read_transfer(members: &[(String, Value)], call: bool) -> Option<Transfer> {
    let names: &[&str] =
        if call { &["receiver_id", "amount", "memo", "msg"] } else { &["receiver_id", "amount", "memo"] };
    if members.iter().any(|(n, _)| !names.contains(&n.as_str())) {
        return None;
    }
    let receiver = match get(members, "receiver_id")? {
        Value::String(r) if account::valid(r) => r.clone(),
        _ => return None,
    };
    let amount = amount(get(members, "amount")?)?;
    let memo = optional_string(get(members, "memo"))?;
    let msg = match (call, get(members, "msg")) {
        (true, Some(Value::String(m))) => Some(m.clone()),
        (false, None) => None,
        _ => return None,
    };
    Some(Transfer { receiver, amount, memo, msg })
}

/// A storage deposit's arguments (NEP-145's `storage_deposit`): for which account (this one, if
/// none's named), and whether only what registering takes is kept.
struct Storage {
    account: Option<String>,
    registration_only: bool,
}

fn read_storage(members: &[(String, Value)]) -> Option<Storage> {
    if members.iter().any(|(n, _)| n != "account_id" && n != "registration_only") {
        return None;
    }
    let account = optional_string(get(members, "account_id"))?;
    if account.as_ref().is_some_and(|a| !account::valid(a)) {
        return None;
    }
    let registration_only = match get(members, "registration_only") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        _ => return None,
    };
    Some(Storage { account, registration_only })
}

struct Reading<'a> {
    tx: &'a Transaction,
    /// This account's name.
    me: String,
    key: &'a Key,
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
    /// An account, as a page shows it: this account, or its name.
    fn who(&self, id: &str) -> String { if id == self.me { "this account".into() } else { id.into() } }

    /// Whether it's maki's own key.
    fn makis(&self, key: &PublicKey) -> bool { *key == PublicKey::Ed25519(*self.key) }

    /// A name a transaction for NEAR's own network can't have: one of the test network's.
    fn check_network(&self, id: &str) -> Result<(), Error> {
        if self.network == Network::Mainnet && account::is_testnet(id) {
            return Err(Error::Invalid(
                "it names an account of NEAR's test network: it's for testnet, not NEAR's own network",
            ));
        }
        Ok(())
    }

    fn action(&mut self, a: &Action) -> Result<(), Error> {
        let receiver = self.tx.receiver.as_str();
        match a {
            Action::Transfer { deposit } => {
                let kind = account::kind(receiver);
                let mut prose = String::from(match kind {
                    _ if receiver == self.me => "To this account itself: only the fee is spent.",
                    Kind::Named => "",
                    Kind::Implicit => {
                        "To an account named by its key: if it's new, sending makes it, held by that key."
                    }
                    Kind::Ethereum => {
                        "To an Ethereum address's account: if it's new, sending makes it, held by that address's key."
                    }
                    Kind::Code => "To an account named by the code and state it was made with.",
                });
                if matches!(kind, Kind::Implicit | Kind::Ethereum)
                    && self.tx.actions.len() > 1
                    && receiver != self.me
                {
                    prose.push_str(
                        " With more in this transaction, NEAR won't make it: it must be there already.",
                    );
                }
                let amount = near(*deposit);
                self.said.push(format!("sends {amount}"));
                self.pages.push(page("Send", amount, self.who(receiver), prose));
            }
            Action::FunctionCall { method, args, deposit, .. } => self.call(method, args, *deposit)?,
            Action::Stake { stake, key } => {
                if *stake == 0 {
                    self.said.push(String::from("unstakes"));
                    self.pages.push(page(
                        "Unstake",
                        "all of it",
                        key.listed(),
                        "As a validator: what this account has locked for it unlocks a few epochs later.",
                    ));
                } else {
                    let amount = near(*stake);
                    self.said.push(format!("stakes {amount}"));
                    self.pages.push(page(
                        "Stake",
                        amount,
                        key.listed(),
                        "As a validator, with that key: NEAR locks this much of this account's NEAR in all, not this much more. Most stake through a pool's contract instead.",
                    ));
                }
            }
            Action::AddKey { key, permission } => {
                if self.makis(key) {
                    return Err(Error::Invalid(
                        "it adds maki's own key, which this account already has: NEAR would refuse it",
                    ));
                }
                match permission {
                    Permission::FullAccess => {
                        self.warnings.push(String::from("gives a key full control"));
                        self.pages.push(page(
                            "Full access!",
                            "a new key",
                            key.listed(),
                            listed_by_hash(
                                key,
                                "Whoever holds that key can do anything this account can, as maki can: send all it holds, add keys, delete it.",
                            ),
                        ));
                    }
                    Permission::FunctionCall { allowance, receiver: contract, methods } => {
                        if methods.iter().any(|m| m.chars().any(char::is_control)) {
                            return Err(Error::Invalid("a method name maki can't show"));
                        }
                        let which = if methods.is_empty() {
                            String::from("any of its methods")
                        } else {
                            format!("only {}", methods.join(", "))
                        };
                        let limit = match allowance {
                            None => String::from("with no limit"),
                            Some(a) => format!("up to {} in all", near(*a)),
                        };
                        self.warnings.push(String::from("lets a key make calls as this account"));
                        self.pages.push(page(
                            "Key for calls!",
                            "a new key",
                            key.listed(),
                            listed_by_hash(
                                key,
                                &format!(
                                    "It can sign calls to {} as this account, without asking: {which}. It can't attach NEAR to them, but it pays their gas from this account's NEAR, {limit}.",
                                    self.who(contract)
                                ),
                            ),
                        ));
                    }
                }
            }
            Action::DeleteKey { key } => {
                if self.makis(key) {
                    self.warnings.push(String::from("deletes maki's own key"));
                    self.pages.push(page(
                        "Delete key!",
                        "maki's own",
                        key.listed(),
                        "maki can't sign for this account after this. Unless it has another full-access key, no one can use it again, and all it holds stays there for good.",
                    ));
                } else {
                    self.said.push(String::from("deletes a key"));
                    self.pages.push(page(
                        "Delete key",
                        "",
                        key.listed(),
                        listed_by_hash(key, "That key can't sign for this account any more."),
                    ));
                }
            }
            Action::DeleteAccount { beneficiary } => {
                if *beneficiary == self.me {
                    return Err(Error::Invalid(
                        "it deletes this account and gives what it holds to itself: NEAR would burn it all",
                    ));
                }
                self.warnings.push(String::from("deletes this account"));
                self.pages.push(page(
                    "Delete account!",
                    "all its NEAR to",
                    beneficiary.as_str(),
                    "This account is deleted, and all its NEAR goes to that account (burnt, if it doesn't exist). Tokens it holds aren't moved: they stay with their contracts, under this account's name.",
                ));
            }
            Action::DeployContract { code } => {
                self.warnings.push(String::from("puts code on this account"));
                self.pages.push(page(
                    "Deploy!",
                    "a contract",
                    format!("{} bytes, code hash\n{}", code.len(), code_hash(code)),
                    "Code maki can't read, run as this account in place of any it had: whoever calls it can have it do anything this account can.",
                ));
            }
            Action::DeployGlobalContract { code, by_account } => {
                let burnt = near(code.len() as u128 * fees::PUBLISH_PER_BYTE);
                let prose = if *by_account {
                    "Under this account's name: accounts that use it run whatever this account publishes there, now and later. NEAR burns that much of this account's NEAR to keep it, for good."
                } else {
                    "For any account to use by its hash. NEAR burns that much of this account's NEAR to keep it, for good."
                };
                self.said.push(format!("publishes a contract, burning {burnt}"));
                self.pages.push(page(
                    "Publish",
                    format!("burns {burnt}"),
                    format!("{} bytes, code hash\n{}", code.len(), code_hash(code)),
                    prose,
                ));
            }
            Action::UseGlobalContract(Code::Hash(hash)) => {
                self.warnings.push(String::from("puts code on this account"));
                self.pages.push(page(
                    "Deploy!",
                    "published code",
                    format!("code hash\n{}", base58::encode(hash)),
                    "Code published on NEAR that maki can't read, run as this account in place of any it had: whoever calls it can have it do anything this account can.",
                ));
            }
            Action::UseGlobalContract(Code::Account(owner)) if *owner == self.me => {
                self.warnings.push(String::from("puts code on this account"));
                self.pages.push(page(
                    "Deploy!",
                    "its own published code",
                    "this account",
                    "Whatever code this account publishes under its name, now and later, runs as this account: maki can't read it.",
                ));
            }
            Action::UseGlobalContract(Code::Account(owner)) => {
                self.warnings.push(String::from("lets another account change this account's code"));
                self.pages.push(page(
                    "Deploy!",
                    "another's code",
                    owner.as_str(),
                    "Whatever code that account publishes, now and later, runs as this account: that account decides what this one does, and can change it any time.",
                ));
            }
            // refused before anything's read: see `review`
            Action::CreateAccount => {}
        }
        Ok(())
    }

    /// A call: a token transfer or a storage deposit spelled out, in the token's units if maki
    /// knows it; anything else flagged, with what it's given.
    fn call(&mut self, method: &str, args: &[u8], deposit: u128) -> Result<(), Error> {
        if method.chars().any(char::is_control) {
            return Err(Error::Invalid("a method name maki can't show"));
        }
        let token = tokens::known(self.network, &self.tx.receiver);
        let value = json::parse(args);
        let members = value.as_ref().and_then(Value::members);
        match (method, members) {
            ("ft_transfer" | "ft_transfer_call", Some(m)) => {
                if let Some(t) = read_transfer(m, method == "ft_transfer_call") {
                    return self.token_transfer(t, token, deposit);
                }
            }
            ("storage_deposit", Some(m)) => {
                if let Some(s) = read_storage(m) {
                    return self.storage_deposit(s, token, deposit);
                }
            }
            _ => {}
        }
        self.unreadable = true;
        let prose = match token {
            Some(t) => format!(
                "A call to {}'s contract that maki can't spell out: it may move this account's {}.",
                t.symbol, t.symbol
            ),
            None => String::from(
                "maki can't tell what it does: that's the contract's to decide, with what it's given. It can't act as this account anywhere else.",
            ),
        };
        self.pages.push(page(
            "Contract call",
            "maki can't read it",
            format!("{}\nmethod {method}", self.who(&self.tx.receiver)),
            prose,
        ));
        if !args.is_empty() {
            let (how, shown) = match (value.is_some(), text(args)) {
                // whitespace between JSON's tokens: tabs and returns, which maki's screen doesn't
                // draw, are as good as spaces
                (true, _) => ("in JSON", String::from_utf8_lossy(args).replace(['\t', '\r'], " ")),
                (false, Some(t)) => ("as text", String::from(t)),
                (false, None) => ("in hex", hex(args)),
            };
            if shown.len() > MAX_SHOWN {
                return Err(Error::Invalid("a call's arguments too long to show on maki's screen"));
            }
            self.pages.push(page("Arguments", how, shown, ""));
        }
        self.attached(deposit);
        Ok(())
    }

    /// NEAR sent with a call, to the contract.
    fn attached(&mut self, deposit: u128) {
        if deposit == 0 {
            return;
        }
        let amount = near(deposit);
        let prose = if deposit == 1 {
            "To the contract, with the call: the least there is, which contracts ask for to know the account's own key signed."
        } else {
            "To the contract, with the call."
        };
        self.said.push(format!("sends {amount}"));
        self.pages.push(page("Send", amount, self.who(&self.tx.receiver), prose));
    }

    fn token_transfer(&mut self, t: Transfer, token: Option<&Token>, deposit: u128) -> Result<(), Error> {
        self.check_network(&t.receiver)?;
        let to = self.who(&t.receiver);
        let then = match t.msg.as_deref() {
            None => "",
            Some("") => {
                "Then the token's contract calls that account's contract, which decides what's done with them, and may send some back."
            }
            Some(_) => {
                "Then the token's contract calls that account's contract with the message that follows: it decides what's done with them, and may send some back."
            }
        };
        match token {
            Some(tok) => {
                if deposit != 1 {
                    return Err(Error::Invalid(
                        "a token transfer without exactly 1 yoctoNEAR attached: its contract would refuse it",
                    ));
                }
                if t.amount == 0 {
                    return Err(Error::Invalid("a token transfer of nothing: its contract would refuse it"));
                }
                if t.receiver == self.me {
                    return Err(Error::Invalid(
                        "tokens sent to the account they're from: its contract would refuse it",
                    ));
                }
                let amount = format!("{} {}", decimals(t.amount, tok.decimals), tok.symbol);
                let yocto =
                    format!("With 1 yoctoNEAR to {}'s contract, as NEAR's token transfers need.", tok.symbol);
                self.said.push(format!("sends {amount}"));
                self.pages.push(page("Send", amount, to, sentences(&[then, &yocto])));
            }
            None => {
                self.unreadable = true;
                let what = "Of a token maki doesn't know, if that's what the contract is: maki can't tell what it does.";
                self.pages.push(page("Send", format!("{} units", t.amount), to, sentences(&[what, then])));
            }
        }
        self.message("Memo", t.memo.as_deref(), "Everyone can read it, on chain.");
        self.message(
            "Message",
            t.msg.as_deref(),
            "For the receiving contract: everyone can read it, on chain.",
        );
        if token.is_none() {
            self.pages.push(page(
                "Token",
                "one maki doesn't know",
                self.who(&self.tx.receiver),
                "Check its contract's account: maki can't tell what the contract does.",
            ));
            self.attached(deposit);
        }
        Ok(())
    }

    /// A memo, or a message for a contract: as text if it can be shown as it is, else in hex.
    fn message(&mut self, heading: &str, m: Option<&str>, prose: &str) {
        let Some(m) = m.filter(|m| !m.is_empty()) else { return };
        let p = match text(m.as_bytes()) {
            Some(t) => page(heading, "", t, prose),
            None => page(heading, "in hex", hex(m.as_bytes()), prose),
        };
        self.pages.push(p);
    }

    fn storage_deposit(&mut self, s: Storage, token: Option<&Token>, deposit: u128) -> Result<(), Error> {
        if let Some(a) = &s.account {
            self.check_network(a)?;
        }
        let whose = match &s.account {
            Some(a) => self.who(a),
            None => String::from("this account"),
        };
        let amount = near(deposit);
        let mut prose = match token {
            Some(t) => format!(
                "So {whose} can hold {}: its contract keeps the NEAR for that account's storage, and gives it back when the account leaves.",
                t.symbol
            ),
            None => {
                self.unreadable = true;
                format!(
                    "For {whose}'s storage in that contract, if that's what it does with it: maki doesn't know the contract."
                )
            }
        };
        if s.registration_only {
            prose.push_str(" Anything more than registering takes comes back.");
        }
        self.said.push(format!("deposits {amount} for storage"));
        self.pages.push(page("Storage deposit", amount, self.who(&self.tx.receiver), prose));
        Ok(())
    }

    /// The most the fee can be, and the page that says what it's for and what maki can't know.
    fn fee(&self) -> (Page, u128) {
        let gas = fees::gas(self.tx);
        let max = gas as u128 * MAX_GAS_PRICE;
        let mut prose = format!(
            "For up to {} of gas, at the most NEAR's gas price can be: 0.002 NEAR a Tgas. It's usually at its lowest, 0.0001 NEAR a Tgas: {}.",
            tgas(gas),
            near(gas as u128 * MIN_GAS_PRICE)
        );
        if self.tx.prepaid_gas() > 0 {
            prose.push_str(" Gas a call doesn't use comes back.");
        }
        // NEAR makes an account NEAR's sent to, if it's one sending makes, only when that's all the
        // transaction does
        let receiver = &self.tx.receiver;
        let makes = matches!(self.tx.actions.as_slice(), [Action::Transfer { .. }])
            && *receiver != self.me
            && account::kind(receiver) != Kind::Named;
        if makes {
            prose.push_str(&format!(
                " If the account it's sent to is new, making it costs {} more.",
                near(fees::creation_surcharge())
            ));
        }
        (page("Max fee", near(max), "", prose), max)
    }
}

/// The pages the owner goes through before maki signs `tx` with `key`, for its implicit account,
/// on `network`, and the line that goes with them.
pub fn review(tx: &Transaction, key: &Key, network: Network) -> Result<Review, Error> {
    let me = account_id(key);
    if tx.signer != me {
        return Err(Error::NotMine);
    }
    if tx.key != PublicKey::Ed25519(*key) {
        return Err(Error::NotMaki);
    }
    let mut r = Reading {
        tx,
        me,
        key,
        network,
        pages: Vec::new(),
        said: Vec::new(),
        warnings: Vec::new(),
        unreadable: false,
    };
    // what NEAR would refuse, or another network's, before anything's shown
    r.check_network(&tx.receiver)?;
    match (network, tokens::network_of(&tx.receiver)) {
        (Network::Testnet, Some(Network::Mainnet)) => {
            return Err(Error::Invalid(
                "it's for a token's contract on NEAR's own network: it's for that network, not testnet",
            ));
        }
        (Network::Mainnet, Some(Network::Testnet)) => {
            return Err(Error::Invalid(
                "it's for a token's contract on NEAR's test network: it's for testnet, not NEAR's own network",
            ));
        }
        _ => {}
    }
    for a in &tx.actions {
        match a {
            // only an account's parent makes it (`near` makes `alice.near`), and an implicit
            // account's sub-accounts would be longer than any name NEAR takes
            Action::CreateAccount => {
                return Err(Error::Invalid(
                    "it makes an account, which only that account's parent can: NEAR would refuse it",
                ));
            }
            Action::Transfer { .. } | Action::FunctionCall { .. } => {}
            // keys, code, stake and deleting: only an account acts on itself so
            _ if tx.receiver != r.me => {
                return Err(Error::Invalid(
                    "it acts on another account as only that account can: NEAR would refuse it",
                ));
            }
            Action::AddKey { permission: Permission::FunctionCall { receiver, .. }, .. } => {
                r.check_network(receiver)?
            }
            Action::DeleteAccount { beneficiary } => r.check_network(beneficiary)?,
            Action::UseGlobalContract(Code::Account(owner)) => r.check_network(owner)?,
            _ => {}
        }
    }
    r.pages.push(match network {
        Network::Mainnet => page("Network", "NEAR", "", ""),
        Network::Testnet => page(
            "Network",
            "NEAR testnet",
            "",
            "NEAR's test network, whose NEAR is worth nothing. A transaction doesn't name its network: made for NEAR's own, it would work there.",
        ),
    });
    for a in &tx.actions {
        r.action(a)?;
    }
    if tx.actions.is_empty() {
        r.said.push(String::from("does nothing"));
        r.pages.push(page("Nothing", "no actions", "", "It does nothing but pay the fee."));
    }
    let (fee, max) = r.fee();
    r.pages.push(fee);
    if r.pages.len() > MAX_PAGES {
        return Err(Error::Invalid("more than maki's screen can show"));
    }
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
    let mut summary = format!("{what}; fee up to {}", near(max));
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
