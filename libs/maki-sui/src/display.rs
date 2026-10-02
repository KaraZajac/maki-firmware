//! What the owner reads on maki's review screen before a Sui transaction is signed, as pages: the
//! network; what it does, as maki follows its coins from command to command (SUI and tokens sent,
//! exactly, and to whom, from coins or from the address balance; objects sent, by ID, since the
//! transaction doesn't say what they are; coins merged; stake added and withdrawn; a Move call maki
//! can't read flagged, with what it's given); when it expires, if that's out of the ordinary; and
//! the most the fee can be, and what pays it. Code published or upgraded, another account's fee to
//! pay or this one's paid by another, and anything that lets another key or account act for this
//! one are refused.
//!
//! A Move call can use only what it's given (Sui's objects are capabilities): the gas coin, the
//! account's objects and withdrawals, what earlier commands gave back. So the pages say what each
//! call maki can't read is given, and that it acts as this account, which a shared object's own
//! code may let it do more with.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::tokens::{self, Token};
use crate::tx::{
    Argument, Command, Expiration, FRAMEWORK, Input, MoveCall, Mutability, ObjectId, SYSTEM, SYSTEM_STATE,
    Transaction, TypeTag, WithdrawFrom, short_address,
};
use crate::{Address, Network, address, balance_field, mask};

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
// What maki's review screen takes (maki-wasm's limits).

/// Pages in a review, at most.
pub const MAX_PAGES: usize = 128;
/// A page's value, in bytes, at most.
pub const MAX_VALUE: usize = 128;
/// A page's fixed-width text, and its prose, in bytes, at most.
pub const MAX_TEXT: usize = 4096;
/// All of a review's text together, in bytes, at most.
pub const MAX_REVIEW: usize = 16 * 1024;

/// A SUI in MIST: SUI counts in billionths.
pub const MIST_PER_SUI: u64 = 1_000_000_000;

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

/// MIST, exactly, in SUI: `1.5 SUI`.
pub fn sui(mist: u128) -> String { format!("{} SUI", decimals(mist, 9)) }

fn plural(n: usize, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }

/// A command's place, as the owner counts them: `1st`, `2nd`, `11th`.
fn nth(at: u16) -> String {
    let n = at as u32 + 1;
    let suffix = match (n % 10, n % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

/// A sentence: its first letter capital (but maki's name, which never is), and a full stop.
fn sentence(s: &str) -> String {
    if s.starts_with("maki ") {
        return format!("{s}.");
    }
    let mut c = s.chars();
    match c.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), c.as_str()),
        None => String::new(),
    }
}

/// What Move wraps an amount of a coin in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    /// `Coin<T>`: an object, which can be sent.
    Coin,
    /// `Balance<T>`: an amount, inside something else.
    Balance,
    /// `Withdrawal<Balance<T>>`: the right to take an amount from an address balance.
    Withdrawal,
}

/// Where funds come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// The gas coin: what pays the fee, together.
    Gas,
    /// One of this account's objects (input `i`): a coin, if it's used as one.
    Object(u16),
    /// This account's address balance (input `i`: a withdrawal, or a coin reservation).
    Balance(u16),
    /// Split off other funds.
    Split,
    /// What command `c`, a call maki can't read, gave back.
    Made(u16),
    /// Made empty, by the framework.
    Zero,
}

/// A coin, a balance or a withdrawal, as maki follows it through the commands.
#[derive(Debug, Clone)]
struct Funds {
    /// The funds it was split from, all the way back: what says which coin it is.
    root: usize,
    /// The coin's type, if the transaction says (kept on the root).
    kind: Option<TypeTag>,
    /// How much it holds now, if maki can tell.
    amount: Option<u128>,
    origin: Origin,
    /// What Move wraps it in; None for one of this account's objects not yet used as a coin, or
    /// what a call gave back.
    wrapper: Option<Wrapper>,
    /// Used up: taken by value.
    gone: bool,
}

/// What a command's argument is.
#[derive(Debug, Clone)]
enum Value {
    /// Funds maki follows.
    Funds(usize),
    /// Input `i`, as it was given: bytes, a shared object, an object to receive.
    Input(u16),
    /// What command `c` gave back (its `n`th), which maki can't see.
    Made(u16, u16),
    /// Values gathered into a vector.
    Vector(Vec<Value>),
}

/// What a command gave back: what maki knows of it, or that it can't tell.
#[derive(Debug, Clone)]
enum Results {
    Known(Vec<Value>),
    Unknown,
}

/// What's sent somewhere.
#[derive(Debug, Clone, Copy)]
enum Sent {
    /// Funds, as they were when sent.
    Funds { funds: usize, amount: Option<u128> },
    /// One of this account's objects, whole (input `i`).
    Object(u16),
    /// What command `c` gave back.
    Made(u16),
}

/// Where it's sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To {
    Address(Address),
    /// An address command `c` works out, which maki can't see.
    Made(u16),
}

/// Something a call maki can't read is given.
#[derive(Debug, Clone, Copy)]
enum Given {
    Funds { funds: usize, amount: Option<u128> },
    Object(u16),
    Shared(u16),
    Receiving(u16),
    Made(u16),
    Bytes,
}

/// What the transaction does, as maki follows it.
#[derive(Debug, Clone)]
enum Event {
    /// Sent to an address: as an object, or into its address balance.
    Send { what: Sent, to: To, into_balance: bool },
    /// Merged into other funds.
    Merge { into: usize, from: Vec<Sent> },
    /// SUI staked with a validator.
    Stake { what: Sent, validator: To },
    /// Staked SUI (input `i`) withdrawn.
    Unstake(u16),
    /// A call maki can't read: the command, and what it's given.
    Call { at: u16, given: Vec<Given> },
}

const INVALID_ARGUMENT: Error = Error::Invalid("a command given what it can't take: Sui would refuse it");
const GONE: Error = Error::Invalid("a coin used after it's used up: Sui would refuse it");
const GAS_USED_UP: Error = Error::Invalid("the gas coin used up, other than to be sent: Sui would refuse it");

/// Follows a transaction's coins through its commands.
struct Reading<'a> {
    tx: &'a Transaction,
    me: &'a Address,
    network: Network,
    funds: Vec<Funds>,
    /// The funds each input is, if it's funds.
    inputs: Vec<Option<usize>>,
    results: Vec<Results>,
    /// What commands gave back that maki can't see, once used as funds: those funds.
    made: Vec<((u16, u16), usize)>,
    events: Vec<Event>,
    /// Something maki can't read.
    unreadable: bool,
    /// Whether the transaction names its network, as maki has checked it.
    names_network: bool,
}

impl<'a> Reading<'a> {
    fn new(tx: &'a Transaction, me: &'a Address, network: Network) -> Result<Reading<'a>, Error> {
        let mut r = Reading {
            tx,
            me,
            network,
            funds: Vec::new(),
            inputs: Vec::new(),
            results: Vec::new(),
            made: Vec::new(),
            events: Vec::new(),
            unreadable: false,
            names_network: tx.expiration.chain().is_some()
                || tx.gas.payment.iter().any(|o| o.reservation().is_some()),
        };
        // the gas coin, first: SUI
        r.root(Origin::Gas, Some(TypeTag::sui()), None, Some(Wrapper::Coin));
        for (i, input) in tx.inputs.iter().enumerate() {
            let i = i as u16;
            let funds = match input {
                Input::Owned(o) => Some(match o.reservation() {
                    Some(reserved) => {
                        let kind = r.reserved(&o.id)?;
                        if kind.is_none() {
                            r.unreadable = true;
                        }
                        r.root(Origin::Balance(i), kind, Some(reserved.amount as u128), Some(Wrapper::Coin))
                    }
                    None => r.root(Origin::Object(i), None, None, None),
                }),
                Input::Withdrawal(w) => {
                    if let WithdrawFrom::Allowance { .. } = w.from {
                        return Err(Error::Invalid(
                            "it spends another account's funds, by an allowance: maki doesn't sign those",
                        ));
                    }
                    r.network_of(&w.coin)?;
                    let amount = Some(w.amount as u128);
                    Some(r.root(Origin::Balance(i), Some(w.coin.clone()), amount, Some(Wrapper::Withdrawal)))
                }
                _ => None,
            };
            r.inputs.push(funds);
        }
        Ok(r)
    }

    fn root(
        &mut self,
        origin: Origin,
        kind: Option<TypeTag>,
        amount: Option<u128>,
        wrapper: Option<Wrapper>,
    ) -> usize {
        let at = self.funds.len();
        self.funds.push(Funds { root: at, kind, amount, origin, wrapper, gone: false });
        at
    }

    /// The coin a reservation draws on, by the field it names: this account's SUI, or a token maki
    /// knows, on this network; or None if maki can't tell (Sui holds it to the sender's own). One
    /// that names this account's field on the other network is that network's.
    fn reserved(&mut self, id: &ObjectId) -> Result<Option<TypeTag>, Error> {
        let coins = || tokens::SUI.iter().chain(tokens::TOKENS).map(Token::type_tag);
        let field = mask(id, &self.network.chain());
        if let Some(t) = coins().find(|t| balance_field(self.me, t) == field) {
            self.network_of(&t)?;
            self.names_network = true;
            return Ok(Some(t));
        }
        let other = other(self.network);
        let elsewhere = mask(id, &other.chain());
        if coins().any(|t| balance_field(self.me, &t) == elsewhere) {
            return Err(wrong_network(other));
        }
        Ok(None)
    }

    /// A token's type says which network it's on, whatever the computer says: one of the other
    /// network's is refused (real money passed off as play money, or the other way round).
    fn network_of(&self, t: &TypeTag) -> Result<(), Error> {
        match tokens::network_of(t) {
            Some(n) if n != self.network => Err(wrong_network(n)),
            _ => Ok(()),
        }
    }

    fn value(&self, a: Argument) -> Result<Value, Error> {
        Ok(match a {
            Argument::Gas => Value::Funds(0),
            Argument::Input(i) => match self.inputs[i as usize] {
                Some(f) => Value::Funds(f),
                None => Value::Input(i),
            },
            Argument::Result(c) => match &self.results[c as usize] {
                Results::Known(v) if v.len() == 1 => v[0].clone(),
                Results::Known(_) => return Err(INVALID_ARGUMENT),
                Results::Unknown => Value::Made(c, 0),
            },
            Argument::Nested(c, n) => match &self.results[c as usize] {
                Results::Known(v) => v.get(n as usize).cloned().ok_or(INVALID_ARGUMENT)?,
                Results::Unknown => Value::Made(c, n),
            },
        })
    }

    fn arg(&self, call: &MoveCall, n: usize) -> Result<Value, Error> { self.value(call.arguments[n]) }

    /// The funds `v` is, used as funds Move wraps as `wrapper`.
    fn funds(&mut self, v: &Value, wrapper: Wrapper) -> Result<usize, Error> {
        let f = match v {
            Value::Funds(f) => *f,
            Value::Made(c, n) => match self.made.iter().find(|(k, _)| *k == (*c, *n)) {
                Some((_, f)) => *f,
                None => {
                    let f = self.root(Origin::Made(*c), None, None, None);
                    self.made.push(((*c, *n), f));
                    f
                }
            },
            _ => return Err(INVALID_ARGUMENT),
        };
        if self.funds[f].gone {
            return Err(GONE);
        }
        match self.funds[f].wrapper {
            None => self.funds[f].wrapper = Some(wrapper),
            Some(w) if w == wrapper => {}
            Some(_) => return Err(INVALID_ARGUMENT),
        }
        Ok(f)
    }

    /// Takes funds by value: they're used up. The gas coin can be taken only to be sent.
    fn take(&mut self, f: usize) -> Result<(), Error> {
        if f == 0 {
            return Err(GAS_USED_UP);
        }
        self.funds[f].gone = true;
        Ok(())
    }

    /// Says which coin funds are: a call of a coin's function names its type.
    fn name(&mut self, f: usize, t: &TypeTag) -> Result<(), Error> {
        self.network_of(t)?;
        let root = self.funds[f].root;
        match &self.funds[root].kind {
            None => self.funds[root].kind = Some(t.clone()),
            Some(k) if k == t => {}
            Some(_) => return Err(Error::Invalid("one coin used as two kinds of coin: Sui would refuse it")),
        }
        Ok(())
    }

    /// An amount, as a command takes it: eight bytes of input (a u64), or what a call works out.
    fn amount(&self, a: Argument) -> Result<Option<u128>, Error> {
        match self.value(a)? {
            Value::Input(i) => match &self.tx.inputs[i as usize] {
                Input::Pure(b) => {
                    let b: [u8; 8] = b.as_slice().try_into().map_err(|_| INVALID_ARGUMENT)?;
                    Ok(Some(u64::from_le_bytes(b) as u128))
                }
                _ => Err(INVALID_ARGUMENT),
            },
            Value::Made(..) => Ok(None),
            _ => Err(INVALID_ARGUMENT),
        }
    }

    /// An address, as a command takes it: 32 bytes of input, or what a call works out.
    fn recipient(&mut self, a: Argument) -> Result<To, Error> {
        match self.value(a)? {
            Value::Input(i) => match &self.tx.inputs[i as usize] {
                Input::Pure(b) => Ok(To::Address(b.as_slice().try_into().map_err(|_| INVALID_ARGUMENT)?)),
                _ => Err(INVALID_ARGUMENT),
            },
            Value::Made(c, _) => {
                self.unreadable = true;
                Ok(To::Made(c))
            }
            _ => Err(INVALID_ARGUMENT),
        }
    }

    /// Funds split off `from`: one of each of `amounts`, which maki may not see.
    fn split(&mut self, from: usize, amounts: &[Option<u128>]) -> Result<Vec<Value>, Error> {
        let mut out = Vec::new();
        for a in amounts {
            self.funds[from].amount = match (self.funds[from].amount, a) {
                (Some(have), Some(a)) => Some(
                    have.checked_sub(*a)
                        .ok_or(Error::Invalid("more split off a coin than it holds: Sui would refuse it"))?,
                ),
                _ => None,
            };
            let Funds { root, wrapper, .. } = self.funds[from];
            let at = self.funds.len();
            self.funds.push(Funds {
                root,
                kind: None,
                amount: *a,
                origin: Origin::Split,
                wrapper,
                gone: false,
            });
            out.push(Value::Funds(at));
        }
        Ok(out)
    }

    /// Funds merged into `into`: one kind of coin, all of them.
    fn merge(&mut self, into: usize, from: &[usize]) -> Result<(), Error> {
        let mut merged = Vec::new();
        for &f in from {
            if f == into {
                return Err(Error::Invalid("a coin merged into itself: Sui would refuse it"));
            }
            self.take(f)?;
            let (a, b) = (self.funds[into].root, self.funds[f].root);
            match (self.funds[a].kind.clone(), self.funds[b].kind.clone()) {
                (Some(x), Some(y)) if x != y => {
                    return Err(Error::Invalid("coins of two kinds merged: Sui would refuse it"));
                }
                (Some(x), None) => self.funds[b].kind = Some(x),
                (None, Some(y)) => self.funds[a].kind = Some(y),
                _ => {}
            }
            self.funds[into].amount = match (self.funds[into].amount, self.funds[f].amount) {
                (Some(x), Some(y)) => Some(x + y),
                _ => None,
            };
            merged.push(self.sent(f));
        }
        self.events.push(Event::Merge { into, from: merged });
        Ok(())
    }

    /// Funds as they're sent: an object of this account's not used as a coin, or funds.
    fn sent(&self, f: usize) -> Sent {
        match self.funds[f] {
            Funds { origin: Origin::Object(i), wrapper: None, .. } => Sent::Object(i),
            Funds { amount, .. } => Sent::Funds { funds: f, amount },
        }
    }

    /// Something sent whole, as an object: a coin, an object of this account's, or what a call
    /// gave back.
    fn send_whole(&mut self, v: &Value) -> Result<Sent, Error> {
        match v {
            Value::Funds(f) => {
                let f = *f;
                if self.funds[f].gone {
                    return Err(GONE);
                }
                // a balance or a withdrawal isn't an object, to send
                if matches!(self.funds[f].wrapper, Some(Wrapper::Balance) | Some(Wrapper::Withdrawal)) {
                    return Err(INVALID_ARGUMENT);
                }
                let s = self.sent(f);
                self.funds[f].gone = true;
                Ok(s)
            }
            Value::Made(c, _) => {
                self.unreadable = true;
                Ok(Sent::Made(*c))
            }
            _ => Err(INVALID_ARGUMENT),
        }
    }

    fn command(&mut self, at: u16, c: &Command) -> Result<Results, Error> {
        Ok(match c {
            Command::SplitCoins { coin, amounts } => {
                let v = self.value(*coin)?;
                let from = self.funds(&v, Wrapper::Coin)?;
                let amounts = amounts.iter().map(|a| self.amount(*a)).collect::<Result<Vec<_>, _>>()?;
                Results::Known(self.split(from, &amounts)?)
            }
            Command::MergeCoins { into, coins } => {
                let v = self.value(*into)?;
                let into = self.funds(&v, Wrapper::Coin)?;
                let mut from = Vec::new();
                for c in coins {
                    let v = self.value(*c)?;
                    from.push(self.funds(&v, Wrapper::Coin)?);
                }
                self.merge(into, &from)?;
                Results::Known(Vec::new())
            }
            Command::TransferObjects { objects, to } => {
                let to = self.recipient(*to)?;
                for o in objects {
                    let v = self.value(*o)?;
                    let what = self.send_whole(&v)?;
                    self.events.push(Event::Send { what, to, into_balance: false });
                }
                Results::Known(Vec::new())
            }
            Command::MakeMoveVec { elements, .. } => {
                let mut values = Vec::new();
                for e in elements {
                    let v = self.value(*e)?;
                    if let Value::Funds(f) = v {
                        if self.funds[f].gone {
                            return Err(GONE);
                        }
                        self.take(f)?;
                    }
                    values.push(v);
                }
                Results::Known(alloc::vec![Value::Vector(values)])
            }
            Command::MoveCall(call) => self.call(at, call)?,
            // refused before maki reads any of it
            Command::Publish { .. } | Command::Upgrade { .. } => return Err(INVALID_ARGUMENT),
        })
    }

    /// A coin, a balance or a withdrawal turned into another of the same funds, of the call's
    /// type: a withdrawal redeemed, a coin's balance, a balance as a coin.
    fn rewrap(&mut self, call: &MoveCall, from: Wrapper, to: Wrapper) -> Result<Results, Error> {
        let v = self.arg(call, 0)?;
        let f = self.funds(&v, from)?;
        self.name(f, &call.types[0])?;
        self.funds[f].wrapper = Some(to);
        Ok(Results::Known(alloc::vec![Value::Funds(f)]))
    }

    /// A call: of the framework's functions maki knows, followed; any other, flagged.
    fn call(&mut self, at: u16, call: &MoveCall) -> Result<Results, Error> {
        if call.package == FRAMEWORK && call.module == "address_alias" {
            return Err(Error::Invalid(
                "it changes which keys can sign for this account: maki won't sign that",
            ));
        }
        if call.package == FRAMEWORK
            && call.module == "allowance"
            && (call.function == "new" || call.function == "propose_for_app")
        {
            return Err(Error::Invalid("it lets another account spend from this one: maki won't sign that"));
        }
        let framework = |module: &str, function: &str, args: usize| {
            call.package == FRAMEWORK
                && call.module == module
                && call.function == function
                && call.types.len() == 1
                && call.arguments.len() == args
        };
        if framework("coin", "redeem_funds", 1) {
            return self.rewrap(call, Wrapper::Withdrawal, Wrapper::Coin);
        }
        if framework("balance", "redeem_funds", 1) {
            return self.rewrap(call, Wrapper::Withdrawal, Wrapper::Balance);
        }
        if framework("coin", "into_balance", 1) {
            return self.rewrap(call, Wrapper::Coin, Wrapper::Balance);
        }
        if framework("coin", "from_balance", 1) {
            return self.rewrap(call, Wrapper::Balance, Wrapper::Coin);
        }
        for (module, wrapper) in [("coin", Wrapper::Coin), ("balance", Wrapper::Balance)] {
            let t = call.types.first();
            if framework(module, "send_funds", 2) {
                let v = self.arg(call, 0)?;
                let f = self.funds(&v, wrapper)?;
                self.name(f, &call.types[0])?;
                let to = self.recipient(call.arguments[1])?;
                let what = self.sent(f);
                self.take(f)?;
                self.events.push(Event::Send { what, to, into_balance: true });
                return Ok(Results::Known(Vec::new()));
            }
            if framework(module, "destroy_zero", 1) {
                let v = self.arg(call, 0)?;
                let f = self.funds(&v, wrapper)?;
                self.name(f, &call.types[0])?;
                if self.funds[f].amount.is_some_and(|a| a != 0) {
                    return Err(Error::Invalid("a coin that isn't empty destroyed: Sui would refuse it"));
                }
                self.take(f)?;
                return Ok(Results::Known(Vec::new()));
            }
            if framework(module, "zero", 0) {
                if let Some(t) = t {
                    self.network_of(t)?;
                    let f = self.root(Origin::Zero, Some(t.clone()), Some(0), Some(wrapper));
                    return Ok(Results::Known(alloc::vec![Value::Funds(f)]));
                }
            }
            if framework(module, "split", 2) {
                let v = self.arg(call, 0)?;
                let f = self.funds(&v, wrapper)?;
                self.name(f, &call.types[0])?;
                let a = self.amount(call.arguments[1])?;
                return Ok(Results::Known(self.split(f, &[a])?));
            }
            if framework(module, "join", 2) {
                let (v, w) = (self.arg(call, 0)?, self.arg(call, 1)?);
                let into = self.funds(&v, wrapper)?;
                let from = self.funds(&w, wrapper)?;
                self.name(into, &call.types[0])?;
                self.merge(into, &[from])?;
                // a balance's join gives back the sum, which maki needn't see
                return Ok(if wrapper == Wrapper::Balance {
                    Results::Unknown
                } else {
                    Results::Known(Vec::new())
                });
            }
            if framework(module, "value", 1) {
                let v = self.arg(call, 0)?;
                let f = self.funds(&v, wrapper)?;
                self.name(f, &call.types[0])?;
                return Ok(Results::Unknown);
            }
        }
        if framework("coin", "take", 2) {
            let v = self.arg(call, 0)?;
            let f = self.funds(&v, Wrapper::Balance)?;
            self.name(f, &call.types[0])?;
            let a = self.amount(call.arguments[1])?;
            let parts = self.split(f, &[a])?;
            for p in &parts {
                if let Value::Funds(p) = p {
                    self.funds[*p].wrapper = Some(Wrapper::Coin);
                }
            }
            return Ok(Results::Known(parts));
        }
        if framework("coin", "put", 2) {
            let (v, w) = (self.arg(call, 0)?, self.arg(call, 1)?);
            let into = self.funds(&v, Wrapper::Balance)?;
            let from = self.funds(&w, Wrapper::Coin)?;
            self.name(into, &call.types[0])?;
            self.merge(into, &[from])?;
            return Ok(Results::Known(Vec::new()));
        }
        if framework("funds_accumulator", "withdrawal_split", 2) {
            let coin = call.types[0].balance_of().ok_or(INVALID_ARGUMENT)?.clone();
            let v = self.arg(call, 0)?;
            let f = self.funds(&v, Wrapper::Withdrawal)?;
            self.name(f, &coin)?;
            // the part's limit is a u256: past a u64, it's more than any withdrawal holds
            let part = match self.arg(call, 1)? {
                Value::Input(i) => match &self.tx.inputs[i as usize] {
                    Input::Pure(b) if b.len() == 32 => {
                        let mut low = [0u8; 16];
                        low.copy_from_slice(&b[..16]);
                        if b[16..].iter().any(|&x| x != 0) {
                            return Err(Error::Invalid(
                                "more split off a withdrawal than it holds: Sui would refuse it",
                            ));
                        }
                        Some(u128::from_le_bytes(low))
                    }
                    _ => return Err(INVALID_ARGUMENT),
                },
                Value::Made(..) => None,
                _ => return Err(INVALID_ARGUMENT),
            };
            return Ok(Results::Known(self.split(f, &[part])?));
        }
        if framework("funds_accumulator", "withdrawal_join", 2) {
            let coin = call.types[0].balance_of().ok_or(INVALID_ARGUMENT)?.clone();
            let (v, w) = (self.arg(call, 0)?, self.arg(call, 1)?);
            let into = self.funds(&v, Wrapper::Withdrawal)?;
            let from = self.funds(&w, Wrapper::Withdrawal)?;
            self.name(into, &coin)?;
            self.merge(into, &[from])?;
            return Ok(Results::Known(Vec::new()));
        }
        if framework("transfer", "public_transfer", 2) {
            let v = self.arg(call, 0)?;
            if matches!(v, Value::Funds(0)) {
                return Err(GAS_USED_UP);
            }
            // a coin, by its type, `0x2::coin::Coin<T>`
            if let (Value::Funds(f), TypeTag::Struct(s)) = (&v, &call.types[0]) {
                if s.address == FRAMEWORK && s.module == "coin" && s.name == "Coin" && s.params.len() == 1 {
                    let f = self.funds(&Value::Funds(*f), Wrapper::Coin)?;
                    self.name(f, &s.params[0])?;
                }
            }
            let to = self.recipient(call.arguments[1])?;
            let what = self.send_whole(&v)?;
            self.events.push(Event::Send { what, to, into_balance: false });
            return Ok(Results::Known(Vec::new()));
        }
        let system = |function: &str, args: usize| {
            call.package == SYSTEM
                && call.module == "sui_system"
                && call.function == function
                && call.types.is_empty()
                && call.arguments.len() == args
        };
        if system("request_add_stake", 3) && self.is_system_state(call.arguments[0])? {
            let v = self.arg(call, 1)?;
            let f = self.funds(&v, Wrapper::Coin)?;
            self.name(f, &TypeTag::sui())?;
            let what = self.sent(f);
            self.take(f)?;
            let validator = self.recipient(call.arguments[2])?;
            self.events.push(Event::Stake { what, validator });
            return Ok(Results::Known(Vec::new()));
        }
        if system("request_withdraw_stake", 2) && self.is_system_state(call.arguments[0])? {
            if let Value::Funds(f) = self.arg(call, 1)? {
                if let Funds { origin: Origin::Object(i), wrapper: None, gone: false, .. } = self.funds[f] {
                    self.funds[f].gone = true;
                    self.events.push(Event::Unstake(i));
                    return Ok(Results::Known(Vec::new()));
                }
            }
        }
        self.unknown(at, call)
    }

    /// Whether an argument is Sui's system state, to change, as staking takes it.
    fn is_system_state(&self, a: Argument) -> Result<bool, Error> {
        Ok(match self.value(a)? {
            Value::Input(i) => matches!(&self.tx.inputs[i as usize],
                Input::Shared { id, mutability: Mutability::Mutable, .. } if *id == SYSTEM_STATE),
            _ => false,
        })
    }

    /// A call maki can't read: what it's given, flagged. Funds it's given, it may take some or all
    /// of: maki can't tell how much is left of them after.
    fn unknown(&mut self, at: u16, call: &MoveCall) -> Result<Results, Error> {
        self.unreadable = true;
        for t in &call.types {
            self.network_of(t)?;
        }
        // what it's given, a vector's values among them: those went into the vector, and are
        // the vector's now
        let mut values = Vec::new();
        for a in &call.arguments {
            values.push((self.value(*a)?, false));
        }
        let mut flat = Vec::new();
        while let Some((v, in_vector)) = values.pop() {
            match v {
                Value::Vector(vs) => values.extend(vs.into_iter().map(|v| (v, true))),
                v => flat.push((v, in_vector)),
            }
        }
        flat.reverse();
        let mut given = Vec::new();
        for (v, in_vector) in flat {
            given.push(match v {
                Value::Funds(f) => {
                    if self.funds[f].gone && !in_vector {
                        return Err(GONE);
                    }
                    let g = match self.sent(f) {
                        Sent::Object(i) => Given::Object(i),
                        _ => Given::Funds { funds: f, amount: self.funds[f].amount },
                    };
                    self.funds[f].amount = None;
                    g
                }
                Value::Input(i) => match &self.tx.inputs[i as usize] {
                    Input::Shared { .. } => Given::Shared(i),
                    Input::Receiving(_) => Given::Receiving(i),
                    _ => Given::Bytes,
                },
                Value::Made(c, _) => Given::Made(c),
                Value::Vector(_) => Given::Bytes,
            });
        }
        self.events.push(Event::Call { at, given });
        Ok(Results::Unknown)
    }
}

fn other(n: Network) -> Network {
    match n {
        Network::Mainnet => Network::Testnet,
        Network::Testnet => Network::Mainnet,
    }
}

fn wrong_network(n: Network) -> Error {
    Error::Invalid(match n {
        Network::Mainnet => "a transaction for Sui's own network, not its test network",
        Network::Testnet => "a transaction for Sui's test network, not its own",
    })
}

/// An amount of a coin, as a page says it: in the coin's own units if maki knows it, else in its
/// smallest units.
fn amount_of(network: Network, kind: Option<&TypeTag>, amount: u128) -> String {
    match kind.and_then(|k| tokens::known(network, k)) {
        Some(t) => format!("{} {}", decimals(amount, t.decimals), t.symbol),
        None => format!("{amount} units"),
    }
}

/// Turns what maki followed into pages.
struct Writing<'a> {
    r: &'a Reading<'a>,
    pages: Vec<Page>,
    /// Something sent that maki can't show in full.
    unreadable: bool,
}

impl Writing<'_> {
    fn kind(&self, f: usize) -> Option<&TypeTag> { self.r.funds[self.r.funds[f].root].kind.as_ref() }

    fn token(&self, f: usize) -> Option<&'static Token> {
        self.kind(f).and_then(|k| tokens::known(self.r.network, k))
    }

    /// Where funds came from, all the way back.
    fn source(&self, f: usize) -> Origin { self.r.funds[self.r.funds[f].root].origin }

    /// An input object's ID.
    fn object(&self, i: u16) -> String {
        match &self.r.tx.inputs[i as usize] {
            Input::Owned(o) | Input::Receiving(o) => address(&o.id),
            Input::Shared { id, .. } => address(id),
            _ => String::new(),
        }
    }

    /// A call, as `0x2::coin::send_funds`.
    fn call_name(&self, at: u16) -> String {
        match &self.r.tx.commands[at as usize] {
            Command::MoveCall(c) => format!("{}::{}::{}", short_address(&c.package), c.module, c.function),
            _ => String::new(),
        }
    }

    /// What's in the gas coin: what pays the fee.
    fn gas(&self) -> String {
        let tx = self.r.tx;
        if tx.pays_from_balance() {
            return format!(
                "{} of this account's address balance, set aside for the fee",
                sui(tx.gas.budget as u128)
            );
        }
        let reserved: u128 =
            tx.gas.payment.iter().filter_map(|o| o.reservation()).map(|r| r.amount as u128).sum();
        let coins = match tx.gas.payment.iter().filter(|o| o.reservation().is_none()).count() {
            0 => None,
            1 => Some(String::from("this account's coin")),
            n => Some(format!("{n} of this account's coins")),
        };
        match (coins, reserved) {
            (Some(c), 0) => c,
            (Some(c), r) => format!("{c} and {} of its address balance", sui(r)),
            (None, r) => format!("{} of this account's address balance", sui(r)),
        }
    }

    /// Where funds came from, as a page says it ("from this account's address balance"), if it
    /// says.
    fn from(&self, f: usize) -> Option<String> {
        match self.source(f) {
            Origin::Object(i) => Some(format!("from coin {}", self.object(i))),
            Origin::Balance(_) => Some(String::from("from this account's address balance")),
            Origin::Made(c) => {
                Some(format!("from what the {} command ({}) gave back", nth(c), self.call_name(c)))
            }
            Origin::Gas | Origin::Split | Origin::Zero => None,
        }
    }

    /// What's sent, as a page's value, and what its prose says of it.
    fn what(&self, s: &Sent) -> (String, Vec<String>) {
        match *s {
            Sent::Funds { funds: 0, .. } => {
                let merged: usize = self
                    .r
                    .events
                    .iter()
                    .map(|e| match e {
                        Event::Merge { into: 0, from } => from.len(),
                        _ => 0,
                    })
                    .sum();
                let and = match merged {
                    0 => String::new(),
                    n => format!(" and the {} merged into it", plural(n, "coin", "coins")),
                };
                let all = if self.r.tx.pays_from_balance() {
                    format!(
                        "what it sets aside for the fee from this account's address balance ({}){and}, less the fee",
                        sui(self.r.tx.gas.budget as u128)
                    )
                } else {
                    // after coins split off it, what's left
                    let split = self.r.funds.iter().any(|f| f.root == 0 && f.origin == Origin::Split);
                    let left = if split { " left" } else { "" };
                    format!("all the SUI{left} in {}{and}, less the fee", self.gas())
                };
                (String::from("the whole gas coin"), alloc::vec![all])
            }
            Sent::Funds { funds, amount } => {
                let kind = self.kind(funds);
                let whole = matches!(self.r.funds[funds].origin, Origin::Object(_));
                let value = match (amount, whole) {
                    (Some(a), _) => amount_of(self.r.network, kind, a),
                    (None, true) => String::from("a whole coin"),
                    (None, false) => String::from("maki can't tell"),
                };
                let mut said = Vec::new();
                match (kind, self.token(funds)) {
                    (Some(k), None) => said.push(format!("of {k}, which maki doesn't know: in its smallest units")),
                    (None, _) if amount.is_some() => said.push(String::from(
                        "the transaction doesn't say which coin this is, so maki can't tell what these units are",
                    )),
                    _ => {}
                }
                said.extend(self.from(funds));
                match (amount, whole) {
                    (None, true) => {
                        said.push(String::from("all it holds: the transaction doesn't say how much"))
                    }
                    (None, false) => said.push(String::from(
                        "maki can't tell how much: a call works it out, or may have taken some of it",
                    )),
                    _ => {}
                }
                (value, said)
            }
            Sent::Object(i) => (
                String::from("an object"),
                alloc::vec![format!("{}: the transaction doesn't say what it is", self.object(i))],
            ),
            Sent::Made(c) => (
                String::from("maki can't tell"),
                alloc::vec![format!(
                    "something the {} command ({}) gave back: maki can't see what",
                    nth(c),
                    self.call_name(c)
                )],
            ),
        }
    }

    /// Funds in a word or two, as a merge or a call lists them: `1.5 SUI from its address
    /// balance`, `coin 0x…`.
    fn brief(&self, funds: usize, amount: Option<u128>) -> String {
        if funds == 0 {
            return format!("the gas coin ({})", self.gas());
        }
        if let Origin::Object(i) = self.r.funds[funds].origin {
            return format!("coin {}", self.object(i));
        }
        let how_much = match amount {
            Some(a) => amount_of(self.r.network, self.kind(funds), a),
            None => String::from("an amount maki can't tell"),
        };
        match self.source(funds) {
            Origin::Gas => format!("{how_much} split off the gas coin"),
            Origin::Object(i) => format!("{how_much} split off coin {}", self.object(i)),
            Origin::Balance(_) => format!("{how_much} from its address balance"),
            Origin::Made(c) => format!("{how_much} from what the {} command gave back", nth(c)),
            Origin::Split | Origin::Zero => how_much,
        }
    }

    /// Whether what's sent is shown in full: SUI or a token in its own units, all of the gas coin,
    /// or an object by its ID.
    fn readable(&self, s: &Sent) -> bool {
        match *s {
            Sent::Funds { funds: 0, .. } => true,
            Sent::Funds { funds, amount } => amount.is_some() && self.kind(funds).is_some(),
            Sent::Object(_) => true,
            Sent::Made(_) => false,
        }
    }

    fn to(&self, to: &To) -> String {
        match to {
            To::Address(a) if a == self.r.me => String::from("this account"),
            To::Address(a) => address(a),
            To::Made(c) => format!(
                "an address the {} command ({}) works out: maki can't see it",
                nth(*c),
                self.call_name(*c)
            ),
        }
    }

    fn event(&mut self, e: &Event) {
        match e {
            Event::Send { what, to, into_balance } => {
                let mine = *to == To::Address(*self.r.me);
                // what's left of funds going back into this account's own address balance: nothing
                // moves
                if mine && *into_balance && matches!(what, Sent::Funds { amount: Some(0), .. }) {
                    return;
                }
                // what goes back to this account itself, it keeps: maki needn't read it all
                self.unreadable |= !mine && !self.readable(what);
                let (value, mut said) = self.what(what);
                if *into_balance {
                    let into = match (mine, said.last().map(String::as_str)) {
                        (true, _) => "into its own address balance",
                        (false, Some("from this account's address balance")) => "into theirs",
                        (false, _) => "into their address balance",
                    };
                    // "from this account's address balance, into theirs"
                    match said.last_mut() {
                        Some(last) if last.starts_with("from ") => {
                            last.push_str(", ");
                            last.push_str(into);
                        }
                        _ => said.push(String::from(into)),
                    }
                }
                let prose: Vec<String> = said.iter().map(|s| sentence(s)).collect();
                self.pages.push(page("Send", value, self.to(to), prose.join(" ")));
            }
            Event::Merge { into, from } => {
                let into = match self.r.funds[*into].origin {
                    Origin::Gas => String::from("the gas coin"),
                    Origin::Object(i) => format!("coin {}", self.object(i)),
                    Origin::Balance(_) => String::from("what it takes from its address balance"),
                    Origin::Made(c) => format!("what the {} command gave back", nth(c)),
                    Origin::Split | Origin::Zero => String::from("a coin this transaction makes"),
                };
                let lines: Vec<String> = from
                    .iter()
                    .map(|s| match *s {
                        Sent::Funds { funds, amount } => self.brief(funds, amount),
                        Sent::Object(i) => self.object(i),
                        Sent::Made(c) => format!("what the {} command gave back", nth(c)),
                    })
                    .collect();
                self.pages.push(page(
                    "Merge",
                    plural(from.len(), "coin", "coins"),
                    lines.join("\n"),
                    format!("Into {into}: they stay this account's."),
                ));
            }
            Event::Stake { what, validator } => {
                self.unreadable |= !self.readable(what);
                let (value, said) = self.what(what);
                let mut prose: Vec<String> = said.iter().map(|s| sentence(s)).collect();
                prose.push(String::from(
                    "With this validator. It stays this account's, as staked SUI, earning rewards from the next epoch; unstaking brings it back with them.",
                ));
                self.pages.push(page("Stake", value, self.to(validator), prose.join(" ")));
            }
            Event::Unstake(i) => self.pages.push(page(
                "Unstake",
                "staked SUI",
                self.object(*i),
                "It comes back to this account, with its rewards. The transaction doesn't say how much it is.",
            )),
            Event::Call { at, given } => {
                let Command::MoveCall(call) = &self.r.tx.commands[*at as usize] else { return };
                let mut mono = format!("{}::{}::{}", address(&call.package), call.module, call.function);
                for t in &call.types {
                    mono.push_str(&format!("\n<{t}>"));
                }
                let mut parts: Vec<String> = Vec::new();
                let mut bytes = 0;
                for g in given {
                    match *g {
                        Given::Funds { funds, amount } => parts.push(self.brief(funds, amount)),
                        Given::Object(i) => parts.push(format!("its object {}", self.object(i))),
                        Given::Shared(i) => parts.push(format!("shared object {}", self.object(i))),
                        Given::Receiving(i) => parts.push(format!("object {}, sent to one of its objects", self.object(i))),
                        Given::Made(c) => parts.push(format!("what the {} command gave back", nth(c))),
                        Given::Bytes => bytes += 1,
                    }
                }
                if bytes > 0 {
                    parts.push(plural(bytes, "value", "values"));
                }
                let given = match parts.len() {
                    0 => None,
                    1 => Some(parts.remove(0)),
                    2 => Some(format!("{} and {}", parts[0], parts[1])),
                    n => {
                        let last = parts.remove(n - 1);
                        Some(format!("{}, and {last}", parts.join(", ")))
                    }
                };
                let prose = match given {
                    Some(given) => format!(
                        "maki can't tell what it does. It acts as this account, and is given {given}: it may do anything with those, and whatever a shared object's code lets this account do."
                    ),
                    None => String::from(
                        "maki can't tell what it does. It acts as this account, and is given nothing: it may do whatever a shared object's code lets this account do.",
                    ),
                };
                self.pages.push(page("Move call", "maki can't read it", mono, prose));
            }
        }
    }

    /// What the line under the question says it does, if maki can read all of it.
    fn summary(&self) -> String {
        let me = To::Address(*self.r.me);
        let mut said: Vec<String> = Vec::new();
        let sends: Vec<&Sent> = self
            .r
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Send { what, to, .. } if *to != me => Some(what),
                _ => None,
            })
            .collect();
        match sends.as_slice() {
            [] => {}
            [one] => said.push(match **one {
                Sent::Funds { funds, amount: Some(a) } if funds != 0 && self.token(funds).is_none() => {
                    format!("sends {a} units of a coin maki doesn't know")
                }
                _ => format!("sends {}", self.what(one).0),
            }),
            all => {
                // payments of one coin maki knows, each exact: their sum
                let mut total: Option<(Option<&TypeTag>, u128)> = None;
                let mut same = true;
                for s in all {
                    match **s {
                        Sent::Funds { funds, amount: Some(a) }
                            if funds != 0 && self.token(funds).is_some() =>
                        {
                            match &mut total {
                                None => total = Some((self.kind(funds), a)),
                                Some((k, sum)) if *k == self.kind(funds) => *sum += a,
                                _ => same = false,
                            }
                        }
                        _ => same = false,
                    }
                }
                let objects = all.iter().all(|s| matches!(s, Sent::Object(_)));
                said.push(match total {
                    Some((k, sum)) if same => {
                        format!("sends {} in {} payments", amount_of(self.r.network, k, sum), all.len())
                    }
                    _ if objects => format!("sends {} objects", all.len()),
                    _ => format!("{} payments", all.len()),
                });
            }
        }
        for e in &self.r.events {
            match e {
                Event::Stake { what, .. } => said.push(format!("stakes {}", self.what(what).0)),
                Event::Unstake(_) => said.push(String::from("unstakes")),
                _ => {}
            }
        }
        if said.is_empty() {
            let merges = self.r.events.iter().any(|e| matches!(e, Event::Merge { .. }));
            let kept = self.r.events.iter().any(|e| matches!(e, Event::Send { .. }));
            said.push(String::from(match (kept, merges) {
                (true, _) => "moves coins within this account",
                (false, true) => "merges coins",
                (false, false) => "sends nothing",
            }));
        }
        said.join(", ")
    }
}

/// When it expires, if that's out of the ordinary: after an epoch it names, or in more epochs than
/// the one or two a transaction paid from an address balance is valid in.
fn expiry(e: &Expiration) -> Option<Page> {
    match e {
        Expiration::None => None,
        Expiration::Epoch(n) => Some(page(
            "Valid until",
            format!("epoch {n}"),
            "",
            "Sui takes it until that epoch ends (an epoch is about a day): maki can't tell how far off that is.",
        )),
        Expiration::During { min, max, .. } => {
            if e.is_replay_protected() {
                return None;
            }
            let when = match (min, max) {
                (Some(a), Some(b)) => format!("epochs {a} to {b}"),
                (Some(a), None) => format!("from epoch {a}"),
                (None, Some(b)) => format!("until epoch {b}"),
                (None, None) => String::from("any epoch"),
            };
            Some(page(
                "Valid in",
                when,
                "",
                "Whoever has it can send it then, while the objects it uses are as they are now.",
            ))
        }
    }
}

/// The pages the owner goes through before `me` signs `tx` on `network`, and the line that goes
/// with them.
pub fn review(tx: &Transaction, me: &Address, network: Network) -> Result<Review, Error> {
    if tx.sender != *me {
        return Err(if tx.gas.owner == *me {
            Error::Invalid(
                "another account's transaction, with this one to pay its fee: maki doesn't sponsor others'",
            )
        } else {
            Error::NotMine
        });
    }
    if tx.gas.owner != *me {
        return Err(Error::Invalid(
            "its fee is paid by another account: maki signs only transactions this account pays for",
        ));
    }
    if let Some(chain) = tx.expiration.chain() {
        if *chain != network.chain() {
            return Err(match Network::of_chain(chain) {
                Some(n) => wrong_network(n),
                None => {
                    Error::Invalid("a transaction for another Sui network than its own or its test network")
                }
            });
        }
    }
    if tx.commands.iter().any(|c| matches!(c, Command::Publish { .. })) {
        return Err(Error::Invalid(
            "it publishes Move code: maki can't show what code does, so it doesn't sign that",
        ));
    }
    if tx.commands.iter().any(|c| matches!(c, Command::Upgrade { .. })) {
        return Err(Error::Invalid(
            "it upgrades Move code: maki can't show what code does, so it doesn't sign that",
        ));
    }
    // a fee paid by a coin reservation draws on this account's SUI, on this network
    let sui_field = balance_field(me, &TypeTag::sui());
    for o in &tx.gas.payment {
        if o.reservation().is_some() && mask(&o.id, &network.chain()) != sui_field {
            return Err(if mask(&o.id, &other(network).chain()) == sui_field {
                wrong_network(other(network))
            } else {
                Error::Invalid(
                    "a fee paid by a coin reservation that isn't this account's SUI: Sui would refuse it",
                )
            });
        }
    }
    let mut r = Reading::new(tx, me, network)?;
    for (at, c) in tx.commands.iter().enumerate() {
        let results = r.command(at as u16, c)?;
        r.results.push(results);
    }
    let mut w = Writing { r: &r, pages: Vec::new(), unreadable: false };
    w.pages.push(match network {
        Network::Mainnet => page("Network", "Sui", "", ""),
        Network::Testnet => page(
            "Network",
            "Sui testnet",
            "",
            if r.names_network {
                "Sui's test network, whose SUI is worth nothing."
            } else {
                "Sui's test network, whose SUI is worth nothing. The transaction doesn't name its network: made with coins of Sui's own, it would spend them there."
            },
        ),
    });
    for e in &r.events {
        w.event(e);
    }
    if tx.commands.is_empty() {
        w.pages.push(page("Nothing", "no commands", "", "It does nothing but pay the fee."));
    }
    if let Some(p) = expiry(&tx.expiration) {
        w.pages.push(p);
    }
    let fee = if tx.is_gasless() {
        w.pages.push(page("Fee", "none", "", "Sui lets this go without a fee: a gasless transfer."));
        String::from("no fee")
    } else {
        let budget = sui(tx.gas.budget as u128);
        let from =
            if tx.pays_from_balance() { String::from("this account's address balance") } else { w.gas() };
        w.pages.push(page(
            "Max fee",
            budget.clone(),
            "",
            format!(
                "The most gas and storage can cost, at {} MIST a unit of gas; what isn't used stays this account's. Paid from {from}.",
                tx.gas.price
            ),
        ));
        format!("fee up to {budget}")
    };
    let what =
        if r.unreadable || w.unreadable { String::from("maki can't read all of it") } else { w.summary() };
    let mut summary = format!("{what}; {fee}");
    // the line under the question is short (the pages say it all): cut, if it must be, at a character
    if summary.len() > MAX_SUMMARY {
        let mut end = MAX_SUMMARY - '…'.len_utf8();
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary.push('…');
    }
    let pages = w.pages;
    fits(&pages, &summary)?;
    Ok(Review { pages, summary })
}

/// Whether a review fits maki's review screen.
fn fits(pages: &[Page], summary: &str) -> Result<(), Error> {
    let text: usize =
        pages.iter().map(|p| p.heading.len() + p.value.len() + p.mono.len() + p.prose.len() + 4).sum();
    // the question and its answers go with them
    let fits = pages.len() <= MAX_PAGES
        && pages
            .iter()
            .all(|p| p.value.len() <= MAX_VALUE && p.mono.len() <= MAX_TEXT && p.prose.len() <= MAX_TEXT)
        && text + summary.len() + 64 <= MAX_REVIEW;
    if fits { Ok(()) } else { Err(Error::Invalid("too much to show on maki's screen")) }
}
