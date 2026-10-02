//! What the computer asks the Cardano app to sign: a transaction's body as it will go on chain,
//! and what maki needs beside it and can't read from it: which of the account's keys witness it
//! (the coins it spends name only the transactions that made them, not whose they are), and which
//! of its outputs are change, by the key each pays. maki makes those keys itself, checks that each
//! change output pays that key's address with the account's stake key, and signs with each
//! witnessing key; anything else in the body it shows as what it is.
//!
//! The bytes (numbers little-endian):
//!
//! ```text
//! witnesses   u8    1 to MAX_WITNESSES, each:
//!   role      u8    0 (receiving) or 1 (change): a payment key; or 2, the stake key
//!   index     u32   below 2^31; the stake key's is 0
//! change      u8    0 to MAX_CHANGE, each:
//!   output    u16   its place among the body's outputs
//!   role      u8    0 or 1: the payment key it pays (with the account's stake key)
//!   index     u32   below 2^31
//! body              the rest: the transaction body's CBOR, exactly as it will go on chain
//! ```

use alloc::vec::Vec;

use crate::body::MAX_BODY;
use crate::{CHANGE, Error, HARDENED, RECEIVE, STAKING};

/// The most keys that witness one transaction: each witness (a key and its signature, 96 bytes)
/// comes back in one answer, which with its status must fit a message of 4096 bytes.
pub const MAX_WITNESSES: usize = 42;
/// The most outputs that can be change: more, and a transaction isn't gone through with any care.
pub const MAX_CHANGE: usize = 64;
/// The biggest request: the keys, the change, and the biggest body.
pub const MAX_REQUEST: usize = 1 + MAX_WITNESSES * 5 + 1 + MAX_CHANGE * 7 + MAX_BODY;

/// A key of the account's, below it: `m/1852'/1815'/account'/role/index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// 0 for receiving, 1 for change, 2 for staking.
    pub role: u8,
    pub index: u32,
}

impl Key {
    /// The account's stake key: `2/0` (CIP-11).
    pub const STAKE: Key = Key { role: STAKING, index: 0 };

    /// A payment key, on the receiving or the change chain, at an index that isn't hardened.
    pub fn payment(role: u8, index: u32) -> Option<Key> {
        (matches!(role, RECEIVE | CHANGE) && index < HARDENED).then_some(Key { role, index })
    }

    /// A key that may witness a transaction: a payment key, or the stake key.
    pub fn witness(role: u8, index: u32) -> Option<Key> {
        let key = Key { role, index };
        (key == Key::STAKE).then_some(key).or_else(|| Key::payment(role, index))
    }
}

/// An output the computer says is change: its place, and the payment key it pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub output: usize,
    pub key: Key,
}

/// A transaction to sign, as the computer sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// The keys that witness it, in the order their witnesses come back.
    pub witnesses: Vec<Key>,
    /// The outputs that are change.
    pub change: Vec<Change>,
    /// The body, exactly as it will go on chain: what's read, shown, and hashed to be signed.
    pub body: &'a [u8],
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.b.len())
            .ok_or(Error::Invalid("a request cut short: not one maki takes"))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes([self.u8()?, self.u8()?])) }

    fn u32(&mut self) -> Result<u32, Error> {
        let mut n = [0u8; 4];
        n.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(n))
    }
}

impl<'a> Request<'a> {
    /// A request, read whole: its keys and its change, each once, then the body (read by `Body`).
    pub fn parse(bytes: &'a [u8]) -> Result<Request<'a>, Error> {
        if bytes.len() > MAX_REQUEST {
            return Err(Error::TooBig);
        }
        let mut r = Reader { b: bytes, at: 0 };
        let n = r.u8()? as usize;
        if n == 0 {
            return Err(Error::Invalid("no key asked to sign it"));
        }
        if n > MAX_WITNESSES {
            return Err(Error::Invalid("more keys asked to sign it than an answer holds: 42 at most"));
        }
        let mut witnesses: Vec<Key> = Vec::with_capacity(n);
        for _ in 0..n {
            let (role, index) = (r.u8()?, r.u32()?);
            let key = Key::witness(role, index).ok_or(Error::Invalid(
                "a key that isn't one of the account's to sign with: a payment key (0 or 1, below 2^31) or its stake key (2/0)",
            ))?;
            if witnesses.contains(&key) {
                return Err(Error::Invalid("a key asked to sign it twice"));
            }
            witnesses.push(key);
        }
        let n = r.u8()? as usize;
        if n > MAX_CHANGE {
            return Err(Error::Invalid("more change than maki goes through: 64 outputs at most"));
        }
        let mut change: Vec<Change> = Vec::with_capacity(n);
        for _ in 0..n {
            let (output, role, index) = (r.u16()? as usize, r.u8()?, r.u32()?);
            let key = Key::payment(role, index)
                .ok_or(Error::Invalid("change at a key that isn't a payment key's: 0 or 1, below 2^31"))?;
            if change.iter().any(|c| c.output == output) {
                return Err(Error::Invalid("an output said to be change twice"));
            }
            change.push(Change { output, key });
        }
        let body = &bytes[r.at..];
        if body.is_empty() {
            return Err(Error::Invalid("no transaction body"));
        }
        Ok(Request { witnesses, change, body })
    }

    /// The request as the computer writes it: what `parse` reads.
    pub fn write(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(2 + self.witnesses.len() * 5 + self.change.len() * 7 + self.body.len());
        out.push(self.witnesses.len() as u8);
        for k in &self.witnesses {
            out.push(k.role);
            out.extend_from_slice(&k.index.to_le_bytes());
        }
        out.push(self.change.len() as u8);
        for c in &self.change {
            out.extend_from_slice(&(c.output as u16).to_le_bytes());
            out.push(c.key.role);
            out.extend_from_slice(&c.key.index.to_le_bytes());
        }
        out.extend_from_slice(self.body);
        out
    }
}
