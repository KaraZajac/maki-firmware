//! A transaction's message: what a Solana signature signs. Legacy messages and version 0 (with
//! address lookup tables), read as Solana's runtime reads them and held to what it accepts
//! (`sanitize`): anything it would refuse, maki refuses to show.

use alloc::vec::Vec;

/// A key, or an address: 32 bytes (an Ed25519 public key, or an address a program owns).
pub type Key = [u8; 32];

/// The most a message can be: a whole transaction, its signatures too, goes in one packet of 1232
/// bytes.
pub const MAX_MESSAGE: usize = 1232;

/// The most accounts a message names: an instruction's are indices of a byte.
pub const MAX_ACCOUNTS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Longer than any transaction.
    TooBig,
    /// Cut short, or with bytes after it.
    Length,
    /// A length that isn't in its shortest form.
    Encoding,
    /// A version maki doesn't know.
    Version,
    /// The header's counts don't fit its keys, or no signer can pay the fee.
    Header,
    /// An account index past its accounts, or a program that can't be one.
    Index,
    /// A key given twice, or a lookup table used for nothing.
    Duplicate,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::TooBig => "bigger than a Solana transaction can be",
            Error::Length => "not a Solana transaction: cut short, or with more after it",
            Error::Encoding => "not a Solana transaction: a length not in its shortest form",
            Error::Version => "a Solana transaction version maki doesn't know",
            Error::Header => "not a Solana transaction: its signers don't add up",
            Error::Index => "not a Solana transaction: an account that isn't there",
            Error::Duplicate => "not a Solana transaction: an account named twice",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Which account is the program.
    pub program: u8,
    /// The accounts it's given, as indices.
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Addresses a version 0 message takes from an address lookup table (an account on chain, which
/// maki can't see): which of its entries, writable ones and read-only ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub table: Key,
    pub writable: Vec<u8>,
    pub readonly: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// None for a legacy message, Some(0) for version 0.
    pub version: Option<u8>,
    /// How many of the keys sign (the first ones), how many of those only read, and how many of
    /// the others only read (the last ones).
    pub signers: u8,
    pub readonly_signers: u8,
    pub readonly_others: u8,
    pub keys: Vec<Key>,
    pub blockhash: Key,
    pub instructions: Vec<Instruction>,
    pub lookups: Vec<Lookup>,
}

/// An account an instruction names: one of the message's keys, or an entry of a lookup table,
/// whose address maki can't see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Account<'a> {
    Key(&'a Key),
    Table { table: &'a Key, entry: u8 },
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Length)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn key(&mut self) -> Result<Key, Error> { Ok(self.take(32)?.try_into().unwrap()) }

    /// A count (compact-u16, "short vec"): seven bits a byte, the least significant first, at
    /// most three bytes, and in its shortest form, as Solana reads it.
    fn count(&mut self) -> Result<usize, Error> {
        let mut n = 0u32;
        for i in 0..3 {
            let b = self.u8()?;
            // a zero after the first byte is a longer way of writing a smaller count
            if b == 0 && i > 0 {
                return Err(Error::Encoding);
            }
            n |= ((b & 0x7f) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return if n <= u16::MAX as u32 { Ok(n as usize) } else { Err(Error::Encoding) };
            }
        }
        Err(Error::Encoding)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.count()?;
        Ok(self.take(n)?.to_vec())
    }
}

impl Message {
    /// A message, read whole: legacy or version 0, and nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<Message, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::TooBig);
        }
        let mut r = Reader { b: bytes, at: 0 };
        let first = r.u8()?;
        let (version, signers) = if first & 0x80 != 0 {
            if first & 0x7f != 0 {
                return Err(Error::Version);
            }
            (Some(0), r.u8()?)
        } else {
            (None, first)
        };
        let (readonly_signers, readonly_others) = (r.u8()?, r.u8()?);
        let mut keys = Vec::new();
        for _ in 0..r.count()? {
            keys.push(r.key()?);
        }
        let blockhash = r.key()?;
        let mut instructions = Vec::new();
        for _ in 0..r.count()? {
            let program = r.u8()?;
            let accounts = r.bytes()?;
            let data = r.bytes()?;
            instructions.push(Instruction { program, accounts, data });
        }
        let mut lookups = Vec::new();
        if version.is_some() {
            for _ in 0..r.count()? {
                let table = r.key()?;
                let writable = r.bytes()?;
                let readonly = r.bytes()?;
                lookups.push(Lookup { table, writable, readonly });
            }
        }
        if r.at != bytes.len() {
            return Err(Error::Length);
        }
        let m = Message { version, signers, readonly_signers, readonly_others, keys, blockhash, instructions, lookups };
        m.sanitize()?;
        Ok(m)
    }

    /// What Solana's runtime checks of a message before it runs it (`sanitize`), and that no
    /// account is named twice, which it refuses too.
    fn sanitize(&self) -> Result<(), Error> {
        let n = self.keys.len();
        // a signer that writes, to pay the fee; and the signers and read-only others don't overlap
        if self.readonly_signers >= self.signers || self.signers as usize + self.readonly_others as usize > n {
            return Err(Error::Header);
        }
        let mut loaded = 0;
        for l in &self.lookups {
            if l.writable.is_empty() && l.readonly.is_empty() {
                return Err(Error::Duplicate);
            }
            loaded += l.writable.len() + l.readonly.len();
        }
        let total = n + loaded;
        if total > MAX_ACCOUNTS {
            return Err(Error::Index);
        }
        for ix in &self.instructions {
            // programs are the message's own keys, never the fee payer, nor from a table
            if ix.program == 0 || ix.program as usize >= n {
                return Err(Error::Index);
            }
            if ix.accounts.iter().any(|&a| a as usize >= total) {
                return Err(Error::Index);
            }
        }
        for (i, k) in self.keys.iter().enumerate() {
            if self.keys[..i].contains(k) {
                return Err(Error::Duplicate);
            }
        }
        for (i, l) in self.lookups.iter().enumerate() {
            let entries = || l.writable.iter().chain(l.readonly.iter());
            for (j, e) in entries().enumerate() {
                if entries().take(j).any(|x| x == e) || self.lookups[..i].iter().any(|o| o.table == l.table && (o.writable.contains(e) || o.readonly.contains(e))) {
                    return Err(Error::Duplicate);
                }
            }
        }
        Ok(())
    }

    /// Every account the message names: its keys, then the lookup tables' entries, the writable
    /// ones first (table by table), then the read-only ones.
    pub fn accounts(&self) -> usize { self.keys.len() + self.lookups.iter().map(|l| l.writable.len() + l.readonly.len()).sum::<usize>() }

    /// The account at `index`.
    pub fn account(&self, index: u8) -> Option<Account<'_>> {
        let mut i = index as usize;
        if i < self.keys.len() {
            return Some(Account::Key(&self.keys[i]));
        }
        i -= self.keys.len();
        for l in &self.lookups {
            if i < l.writable.len() {
                return Some(Account::Table { table: &l.table, entry: l.writable[i] });
            }
            i -= l.writable.len();
        }
        for l in &self.lookups {
            if i < l.readonly.len() {
                return Some(Account::Table { table: &l.table, entry: l.readonly[i] });
            }
            i -= l.readonly.len();
        }
        None
    }

    /// The key at `index`, if it's one of the message's own (not a table's).
    pub fn key(&self, index: u8) -> Option<&Key> { self.keys.get(index as usize) }

    /// Whether the account at `index` signs.
    pub fn is_signer(&self, index: u8) -> bool { index < self.signers }

    /// Whether the message lets the account at `index` be written.
    pub fn is_writable(&self, index: u8) -> bool {
        let (i, n, s) = (index as usize, self.keys.len(), self.signers as usize);
        if i < s {
            i < s - self.readonly_signers as usize
        } else if i < n {
            i < n - self.readonly_others as usize
        } else {
            i - n < self.lookups.iter().map(|l| l.writable.len()).sum::<usize>()
        }
    }

    /// The signers' keys; the first pays the fee.
    pub fn signer_keys(&self) -> &[Key] { &self.keys[..self.signers as usize] }
}
