//! What the owner reads on maki's review screen before a Solana transaction is signed: each
//! instruction in turn, as pages. SOL and tokens sent, how much and to whom (a token's recipient
//! as their wallet's address when the transaction proves the token account is theirs); what pays
//! the fee, and the most it can be; anything maki can't read, flagged, with whether it can act as
//! this account. This account's signature lets each instruction that's given it act as it; one
//! that isn't given it can't.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::message::{Account, Instruction, Message};
use crate::program::{self, *};
use crate::{Key, address, tokens};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub pages: Vec<Page>,
    /// The line under the question: what it sends, and the most the fee can be.
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// This account isn't one of the transaction's signers: it isn't its to sign.
    NotSigner,
    /// Solana would refuse it, so maki does: why.
    Invalid(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotSigner => f.write_str("this account doesn't sign it"),
            Error::Invalid(why) => f.write_str(why),
        }
    }
}

/// The longest summary: what maki's review screen takes under its question.
pub const MAX_SUMMARY: usize = 128;

/// Lamports per signature: Solana's base fee.
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
/// Compute units: the most a transaction may ask for, and what each instruction gets when it
/// doesn't say (at most: Solana gives its own programs less).
pub const MAX_COMPUTE_UNITS: u64 = 1_400_000;
pub const DEFAULT_COMPUTE_UNITS: u64 = 200_000;

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

/// Lamports, exactly, in SOL: `0.000005 SOL`.
pub fn sol(lamports: u128) -> String { format!("{} SOL", decimals(lamports, 9)) }

fn u32_at(d: &[u8], at: usize) -> u32 { u32::from_le_bytes(d[at..at + 4].try_into().unwrap()) }
fn u64_at(d: &[u8], at: usize) -> u64 { u64::from_le_bytes(d[at..at + 8].try_into().unwrap()) }
fn key_at(d: &[u8], at: usize) -> Key { d[at..at + 32].try_into().unwrap() }

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Text a page can show as it is: UTF-8, without control characters but newlines.
fn text(bytes: &[u8]) -> Option<&str> {
    core::str::from_utf8(bytes).ok().filter(|t| !t.chars().any(|c| c.is_control() && c != '\n'))
}

/// The fee: how many signatures (the transaction's and those programs check for it), and the
/// compute units and their price.
struct Fee {
    signatures: u64,
    units: u64,
    micro_lamports: u64,
}

impl Fee {
    fn base(&self) -> u128 { self.signatures as u128 * LAMPORTS_PER_SIGNATURE as u128 }

    /// The priority fee: the units' price, rounded up to a lamport, as Solana charges it.
    fn priority(&self) -> u128 { (self.units as u128 * self.micro_lamports as u128).div_ceil(1_000_000) }
}

/// A token account the transaction proves is someone's: an associated token account it opens
/// (or makes sure of), which is theirs for that token by how its address is made.
struct Proven {
    account: Key,
    owner: Key,
    mint: Key,
}

struct Reading<'a> {
    m: &'a Message,
    me: &'a Key,
    pages: Vec<Page>,
    /// Something maki can't read, or an account it can't see.
    unreadable: bool,
    /// What it does that the owner must not miss.
    warnings: Vec<&'static str>,
    /// What it sends from this account: SOL in lamports, and each payment as it's said; and
    /// the tokens it burns.
    lamports: u128,
    sent: Vec<String>,
    burnt: Vec<String>,
    proven: Vec<Proven>,
}

fn account_index(ix: &Instruction, i: usize) -> Result<u8, Error> {
    ix.accounts
        .get(i)
        .copied()
        .ok_or(Error::Invalid("an instruction without the accounts it needs: Solana would refuse it"))
}

impl Reading<'_> {
    fn is_me(&self, index: u8) -> bool {
        matches!(self.m.account(index), Some(Account::Key(k)) if k == self.me)
    }

    /// The account's key, if the message has it (not a lookup table's entry).
    fn key(&self, index: u8) -> Option<Key> { self.m.key(index).copied() }

    /// An account, as a page shows it: this account, an address, or a lookup table's entry,
    /// which maki can't see (and so can't show the owner).
    fn who(&mut self, index: u8) -> String {
        match self.m.account(index) {
            Some(Account::Key(k)) if k == self.me => "this account".into(),
            Some(Account::Key(k)) => address(k),
            Some(Account::Table { table, entry }) => {
                self.unreadable = true;
                format!("an address maki can't see: entry {entry} of lookup table {}", address(table))
            }
            None => "?".into(),
        }
    }

    /// A key given as data (a new owner, a delegate), as a page shows it.
    fn named(&self, key: &Key) -> String {
        if key == self.me {
            "this account".into()
        } else {
            program::name(key).map(String::from).unwrap_or_else(|| address(key))
        }
    }

    fn fee(&self) -> Result<Fee, Error> {
        let (mut units, mut price, mut heap, mut data) = (None, None, None, None);
        let mut signatures = self.m.signers as u64;
        let mut others = 0u64;
        for ix in &self.m.instructions {
            let program = self.m.keys[ix.program as usize];
            if program != COMPUTE_BUDGET {
                others += 1;
                if [ED25519_VERIFY, SECP256K1_VERIFY, SECP256R1_VERIFY].contains(&program) {
                    signatures += ix.data.first().copied().unwrap_or(0) as u64;
                }
                continue;
            }
            // each at most once, as Solana has it
            let d = &ix.data;
            let (slot, value) = match (d.first(), d.len()) {
                (Some(1), 5) => (&mut heap, u32_at(d, 1) as u64),
                (Some(2), 5) => (&mut units, u32_at(d, 1) as u64),
                (Some(3), 9) => (&mut price, u64_at(d, 1)),
                (Some(4), 5) => (&mut data, u32_at(d, 1) as u64),
                _ => return Err(Error::Invalid("a compute budget instruction Solana would refuse")),
            };
            if slot.replace(value).is_some() {
                return Err(Error::Invalid(
                    "a compute budget instruction given twice: Solana would refuse it",
                ));
            }
        }
        let units = units.unwrap_or(DEFAULT_COMPUTE_UNITS * others).min(MAX_COMPUTE_UNITS);
        Ok(Fee { signatures, units, micro_lamports: price.unwrap_or(0) })
    }

    /// The token accounts the transaction opens (or makes sure of) for their owners, each proven
    /// by its address; one that isn't the owner's, Solana would refuse.
    fn prove(&mut self) -> Result<(), Error> {
        for ix in &self.m.instructions {
            if self.m.keys[ix.program as usize] != ASSOCIATED_TOKEN
                || !matches!(ix.data.as_slice(), [] | [0] | [1])
            {
                continue;
            }
            let [account, owner, mint, token_program] =
                [1, 2, 3, 5].map(|i| account_index(ix, i).map(|a| self.key(a)));
            if let (Some(account), Some(owner), Some(mint), Some(token_program)) =
                (account?, owner?, mint?, token_program?)
            {
                if program::associated_token_account(&owner, &token_program, &mint) != Some(account) {
                    return Err(Error::Invalid(
                        "a token account that isn't its owner's: Solana would refuse it",
                    ));
                }
                self.proven.push(Proven { account, owner, mint });
            }
        }
        Ok(())
    }

    /// Whose token account `index` is, and for which token, if the transaction proves it.
    fn proven(&self, index: u8) -> Option<&Proven> {
        let k = self.key(index)?;
        self.proven.iter().find(|p| p.account == k)
    }

    fn instruction(&mut self, at: usize, ix: &Instruction) -> Result<(), Error> {
        match self.m.keys[ix.program as usize] {
            SYSTEM => self.system(at, ix),
            // what it asks for is in the fee
            COMPUTE_BUDGET => Ok(()),
            p @ (TOKEN | TOKEN_2022) => self.token(ix, &p),
            ASSOCIATED_TOKEN => self.associated(ix),
            MEMO | MEMO_1 => {
                let p = match text(&ix.data) {
                    Some(t) => page("Memo", "", t, "Everyone can read it, on chain."),
                    None => page("Memo", "in hex", hex(&ix.data), "Everyone can read it, on chain."),
                };
                self.pages.push(p);
                Ok(())
            }
            p => {
                self.unknown(ix, &p);
                Ok(())
            }
        }
    }

    fn system(&mut self, at: usize, ix: &Instruction) -> Result<(), Error> {
        let d = &ix.data;
        let kind = if d.len() >= 4 { Some(u32_at(d, 0)) } else { None };
        match (kind, d.len()) {
            // Transfer: lamports
            (Some(2), 12) => {
                let (from, to) = (account_index(ix, 0)?, account_index(ix, 1)?);
                let lamports = u64_at(d, 4) as u128;
                let to = self.who(to);
                let prose = if self.is_me(from) {
                    self.lamports += lamports;
                    self.sent.push(sol(lamports));
                    String::new()
                } else {
                    format!("From {}, not this account.", self.who(from))
                };
                self.pages.push(page("Send", sol(lamports), to, prose));
            }
            // CreateAccount: lamports, space, owner
            (Some(0), 52) => {
                let (funder, new) = (account_index(ix, 0)?, account_index(ix, 1)?);
                let (lamports, space, owner) = (u64_at(d, 4) as u128, u64_at(d, 12), key_at(d, 20));
                let paid = if self.is_me(funder) {
                    self.lamports += lamports;
                    self.sent.push(sol(lamports));
                    String::from("this account")
                } else {
                    self.who(funder)
                };
                let new = self.who(new);
                let prose = format!("{space} bytes, owned by {}; {paid} pays for it.", self.named(&owner));
                self.pages.push(page("New account", sol(lamports), new, prose));
            }
            // Assign: a new owner
            (Some(1), 36) => {
                let account = account_index(ix, 0)?;
                let owner = self.named(&key_at(d, 4));
                if self.is_me(account) {
                    self.warnings.push("hands this account over");
                    self.pages.push(page(
                        "Hands over!",
                        "this account",
                        owner,
                        "That program would own this account, and everything in it.",
                    ));
                } else {
                    let account = self.who(account);
                    self.pages.push(page("Assign", "an account", format!("{account}\nto {owner}"), ""));
                }
            }
            // AdvanceNonceAccount: first, it's a durable nonce, which keeps the transaction valid
            (Some(4), 4) => {
                let nonce = account_index(ix, 0)?;
                let nonce = self.who(nonce);
                if at == 0 {
                    self.pages.insert(0, page("No time limit", "a durable nonce", nonce, "It stays valid until it's sent or its nonce moves on; others last a minute or two."));
                } else {
                    self.pages.push(page("Nonce", "moves on", nonce, ""));
                }
            }
            _ => self.unknown(ix, &SYSTEM),
        }
        Ok(())
    }

    /// A token amount as a page says it: in the token's own units if maki knows it (or the
    /// instruction says its decimals), else in its smallest units.
    fn tokens(&self, amount: u64, mint: Option<&Key>, decimals: Option<u8>) -> Result<String, Error> {
        let known = mint.and_then(tokens::known);
        if let (Some(t), Some(d)) = (known, decimals) {
            if t.decimals != d {
                return Err(Error::Invalid("the wrong decimals for its token: Solana would refuse it"));
            }
        }
        Ok(match (known, decimals) {
            (Some(t), _) => format!("{} {}", self::decimals(amount as u128, t.decimals), t.symbol),
            (None, Some(d)) => format!("{} tokens", self::decimals(amount as u128, d)),
            (None, None) => format!("{amount} units"),
        })
    }

    /// Where tokens go, as a page shows it: whose account (proven), or the token account.
    fn recipient(&mut self, account: u8, mint: Option<&Key>) -> (String, String) {
        if let Some(p) = self.proven(account) {
            if mint.is_none_or(|m| *m == p.mint) {
                let token = tokens::known(&p.mint).map(|t| t.symbol).unwrap_or("token");
                return if p.owner == *self.me {
                    ("this account".into(), format!("To this account's own {token} account."))
                } else {
                    (address(&p.owner), format!("To their {token} account."))
                };
            }
        }
        (self.who(account), String::from("To a token account: maki can't see whose."))
    }

    fn token(&mut self, ix: &Instruction, program: &Key) -> Result<(), Error> {
        let d = &ix.data;
        let a = |i| account_index(ix, i);
        match (d.first(), d.len()) {
            // Transfer: an amount (and no token, or decimals)
            (Some(3), 9) => {
                let (dest, authority) = (a(1)?, a(2)?);
                let mint = self.proven(dest).map(|p| p.mint);
                let amount = self.tokens(u64_at(d, 1), mint.as_ref(), None)?;
                if mint.is_none_or(|m| tokens::known(&m).is_none()) {
                    self.unreadable = true;
                }
                let (to, mut prose) = self.recipient(dest, None);
                if mint.is_none() {
                    prose.push_str(" The transfer doesn't say which token: maki can't tell.");
                }
                self.send_tokens(authority, amount, to, prose, mint.as_ref());
            }
            // TransferChecked: an amount and decimals; the mint's checked against both accounts
            (Some(12), 10) => {
                let (mint, dest, authority) = (a(1)?, a(2)?, a(3)?);
                let mint = self.key(mint);
                if mint.is_none() {
                    self.unreadable = true;
                }
                let amount = self.tokens(u64_at(d, 1), mint.as_ref(), Some(d[9]))?;
                let (to, prose) = self.recipient(dest, mint.as_ref());
                self.send_tokens(authority, amount, to, prose, mint.as_ref());
            }
            // Approve / ApproveChecked: a delegate may spend up to an amount
            (Some(4), 9) | (Some(13), 10) => {
                let checked = d[0] == 13;
                let (source, delegate, owner) =
                    if checked { (a(0)?, a(2)?, a(3)?) } else { (a(0)?, a(1)?, a(2)?) };
                let mint = if checked { self.key(a(1)?) } else { self.proven(source).map(|p| p.mint) };
                if mint.is_none_or(|m| tokens::known(&m).is_none()) && !checked {
                    self.unreadable = true;
                }
                let amount = self.tokens(u64_at(d, 1), mint.as_ref(), checked.then(|| d[9]))?;
                let delegate = self.who(delegate);
                let source = self.who(source);
                let whose = if self.is_me(owner) {
                    String::new()
                } else {
                    format!(" Its owner: {}.", self.who(owner))
                };
                if self.is_me(owner) {
                    self.warnings.push("lets another spend tokens");
                }
                self.pages.push(page(
                    "Approve!",
                    format!("up to {amount}"),
                    delegate,
                    format!(
                        "That address may spend them from token account {source}, without asking.{whose}"
                    ),
                ));
                if let (Some(m), None) = (mint, mint.and_then(|m| tokens::known(&m))) {
                    self.pages.push(page("Token", "one maki doesn't know", address(&m), ""));
                }
            }
            // Revoke
            (Some(5), 1) => {
                let source = a(0)?;
                let source = self.who(source);
                self.pages.push(page(
                    "Revoke",
                    "no more spending",
                    source,
                    "Whoever was approved to spend from this token account can't.",
                ));
            }
            // SetAuthority: a kind of authority, and who has it now (or no one)
            (Some(6), 3) | (Some(6), 35) => {
                let (target, current) = (a(0)?, a(1)?);
                let what = match d[1] {
                    0 => "minting",
                    1 => "freezing",
                    2 => "the account",
                    3 => "closing it",
                    _ => "control",
                };
                let to = match (d[2], d.len()) {
                    (0, 3) => String::from("no one"),
                    (1, 35) => self.named(&key_at(d, 3)),
                    _ => return Err(Error::Invalid("a token instruction Solana would refuse")),
                };
                if self.is_me(current) {
                    self.warnings.push("hands control over");
                }
                let target = self.who(target);
                self.pages.push(page(
                    "Hands over!",
                    what,
                    format!("of {target}\nto {to}"),
                    "Whoever it goes to decides, from then on.",
                ));
            }
            // Burn / BurnChecked: tokens destroyed
            (Some(8), 9) | (Some(15), 10) => {
                let (account, mint, owner) = (a(0)?, a(1)?, a(2)?);
                let mint = self.key(mint);
                let amount = self.tokens(u64_at(d, 1), mint.as_ref(), (d[0] == 15).then(|| d[9]))?;
                if mint.is_none_or(|m| tokens::known(&m).is_none()) && d[0] == 8 {
                    self.unreadable = true;
                }
                if self.is_me(owner) {
                    self.burnt.push(amount.clone());
                }
                let account = self.who(account);
                self.pages.push(page(
                    "Burn",
                    amount,
                    account,
                    "Destroyed, from this token account: no one gets them.",
                ));
            }
            // CloseAccount: its SOL goes to an address: its rent, or all of it if it's wrapped SOL
            (Some(9), 1) => {
                let (account, dest, owner) = (a(0)?, a(1)?, a(2)?);
                if self.is_me(owner) && !self.is_me(dest) {
                    self.warnings.push("sends a token account's SOL to another");
                }
                let dest = self.who(dest);
                let account = self.who(account);
                let prose =
                    format!("The SOL it holds goes to {dest}: its rent, or all of it if it's wrapped SOL.");
                self.pages.push(page("Close", "a token account", account, prose));
            }
            // SyncNative: wrapped SOL counted again
            (Some(17), 1) => {
                let account = a(0)?;
                let account = self.who(account);
                self.pages.push(page("Wrapped SOL", "brought up to date", account, ""));
            }
            // InitializeAccount3: an owner
            (Some(18), 33) => {
                let (account, mint) = (a(0)?, a(1)?);
                let token =
                    self.key(mint).and_then(|m| tokens::known(&m)).map(|t| t.symbol).unwrap_or("a token");
                let owner = self.named(&key_at(d, 1));
                let account = self.who(account);
                self.pages.push(page("New token account", token, format!("{account}\nowned by {owner}"), ""));
            }
            _ => self.unknown(ix, program),
        }
        Ok(())
    }

    fn send_tokens(
        &mut self,
        authority: u8,
        amount: String,
        to: String,
        mut prose: String,
        mint: Option<&Key>,
    ) {
        if self.is_me(authority) {
            self.sent.push(amount.clone());
        } else {
            prose = format!("{prose} From {}'s tokens, not this account's.", self.who(authority));
        }
        self.pages.push(page("Send", amount, to, prose));
        if let Some(m) = mint.filter(|m| tokens::known(m).is_none()) {
            self.pages.push(page("Token", "one maki doesn't know", address(m), "Check its mint's address."));
        }
    }

    fn associated(&mut self, ix: &Instruction) -> Result<(), Error> {
        if !matches!(ix.data.as_slice(), [] | [0] | [1]) {
            self.unknown(ix, &ASSOCIATED_TOKEN);
            return Ok(());
        }
        let (funder, account) = (account_index(ix, 0)?, account_index(ix, 1)?);
        let Some(p) = self.proven(account) else {
            // an account from a lookup table: maki can't say whose
            let account = self.who(account);
            self.pages.push(page("New token account", "maki can't see whose", account, ""));
            return Ok(());
        };
        let (owner, mint) = (p.owner, p.mint);
        let token = tokens::known(&mint).map(|t| t.symbol);
        let whose = if owner == *self.me { String::from("this account") } else { address(&owner) };
        let rent = if self.is_me(funder) {
            " If it's new, this account pays its rent: about 0.002 SOL, back when it's closed."
        } else {
            ""
        };
        let mono = match token {
            Some(_) => whose,
            None => format!("{whose}\ntoken {}", address(&mint)),
        };
        self.pages.push(page(
            "New token account",
            token.unwrap_or("a token maki doesn't know"),
            mono,
            format!("For its owner's tokens.{rent}"),
        ));
        Ok(())
    }

    fn unknown(&mut self, ix: &Instruction, program: &Key) {
        self.unreadable = true;
        let given = ix.accounts.iter().any(|&a| self.is_me(a));
        let prose = if given {
            "It's given this account's signature: it can do anything this account can."
        } else {
            "It isn't given this account's signature: it can't act as this account."
        };
        let name = program::name(program).map(String::from).unwrap_or_else(|| address(program));
        let (n, len) = (ix.accounts.len(), ix.data.len());
        let mono = format!(
            "{name}\n{n} account{}, {len} byte{}",
            if n == 1 { "" } else { "s" },
            if len == 1 { "" } else { "s" }
        );
        self.pages.push(page("Program", "maki can't read it", mono, prose));
    }
}

/// The pages the owner goes through before `me` signs `m`, and the line that goes with them.
pub fn review(m: &Message, me: &Key) -> Result<Review, Error> {
    if !m.signer_keys().contains(me) {
        return Err(Error::NotSigner);
    }
    let mut r = Reading {
        m,
        me,
        pages: Vec::new(),
        unreadable: false,
        warnings: Vec::new(),
        lamports: 0,
        sent: Vec::new(),
        burnt: Vec::new(),
        proven: Vec::new(),
    };
    r.prove()?;
    let fee = r.fee()?;
    for (at, ix) in m.instructions.iter().enumerate() {
        r.instruction(at, ix)?;
    }
    if m.instructions.is_empty() {
        r.pages.push(page("Nothing", "no instructions", "", "It does nothing but pay the fee."));
    }
    let others: Vec<String> = m.signer_keys().iter().filter(|k| *k != me).map(address).collect();
    if !others.is_empty() {
        let n = others.len();
        r.pages.push(page(
            "Signed by others",
            format!("{n} more"),
            others.join("\n"),
            "It needs their signatures as well as this account's.",
        ));
    }
    let max = fee.base() + fee.priority();
    let payer = m.keys[0];
    let how = format!(
        "{} for {} signature{}, up to {} for priority.",
        sol(fee.base()),
        fee.signatures,
        if fee.signatures == 1 { "" } else { "s" },
        sol(fee.priority())
    );
    if payer == *me {
        r.pages.push(page("Max fee", sol(max), "", how));
    } else {
        r.pages.push(page(
            "Fee paid by",
            "someone else",
            address(&payer),
            format!("Up to {}, not this account's. {how}", sol(max)),
        ));
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
        let mut said = Vec::new();
        match r.sent.len() {
            0 => {}
            1 => said.push(format!("sends {}", r.sent[0])),
            n if r.sent.iter().all(|s| s.ends_with(" SOL")) => {
                said.push(format!("sends {} in {n} payments", sol(r.lamports)))
            }
            n => said.push(format!("{n} payments")),
        }
        said.extend(r.burnt.iter().map(|b| format!("burns {b}")));
        if said.is_empty() { String::from("sends nothing") } else { said.join(", ") }
    };
    let mut summary = if payer == *me {
        format!("{what}; fee up to {}", sol(max))
    } else {
        format!("{what}; another pays the fee")
    };
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

/// The site a Sign In With Solana message is for: the host its first line names (`example.com
/// wants you to sign in with your Solana account:`), without a scheme or port. None for any
/// other message.
pub fn sign_in_site(message: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(message).ok()?;
    let first = text.lines().next()?;
    let authority = first.strip_suffix(" wants you to sign in with your Solana account:")?;
    let authority = authority.split_once("://").map(|(_, rest)| rest).unwrap_or(authority);
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The pages for a message from `site` for `me` to sign: a warning first when it's a sign-in for
/// another site (the phishing that copies a real site's sign-in) or another account, then the
/// message. A transaction is refused: signed as a message, it's signed blind.
pub fn message_pages(site: &str, me: &Key, message: &[u8]) -> Result<Vec<Page>, Error> {
    if Message::parse(message).is_ok() {
        return Err(Error::Invalid("that's a transaction, not a message: maki won't sign it as one"));
    }
    let mut pages = Vec::new();
    if let Some(other) = sign_in_site(message).filter(|s| s != site) {
        pages.push(page(
            "Wrong site!",
            "a sign-in for",
            other,
            "Not the site asking: it may be copying that site's sign-in.",
        ));
    }
    if sign_in_site(message).is_some() {
        let named = core::str::from_utf8(message).ok().and_then(|t| t.lines().nth(1)).unwrap_or("");
        if named != address(me) {
            pages.push(page("Wrong account!", "a sign-in for", named, "Not this account."));
        }
    }
    pages.push(match text(message) {
        Some(t) => page("Message", "", t, ""),
        None => page("Message", "in hex", hex(message), ""),
    });
    Ok(pages)
}
