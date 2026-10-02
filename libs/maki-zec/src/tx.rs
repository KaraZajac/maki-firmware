//! Zcash's version 5 transactions (ZIP-225), as zcashd, zebrad and librustzcash write them, read
//! strictly: transparent ones alone. A header (version 5, with the overwintered flag), the
//! version group, the consensus branch, the lock time and the expiry height; the transparent
//! inputs and outputs, as Bitcoin writes them; then the shielded parts' counts, which must all be
//! nothing: maki can't see into Sapling's spends and outputs or Orchard's actions, so a transaction
//! with any is refused, by name.

use alloc::vec::Vec;

use crate::{Error, MAX_MONEY};

/// Version 5's header: the version, and the overwintered flag (bit 31) every version since has.
pub const VERSION_5: u32 = 0x8000_0005;
/// Version 4's (Sapling's) and version 6's (ZIP-229's, NU6.3's), which maki doesn't read.
pub const VERSION_4: u32 = 0x8000_0004;
pub const VERSION_6: u32 = 0x8000_0006;
/// Version 5's version group.
pub const VERSION_GROUP: u32 = 0x26a7_270a;
/// The consensus branch of the network upgrade in force on both of Zcash's networks: NU6.3's
/// (ZIP-258; main network from block 3,428,143, July 2026; test network from 4,134,000), as
/// zcash_protocol, zebrad and the chains themselves have it on 2026-10-02. A transaction commits
/// to it, so a signature for one upgrade's rules is nothing under another's. NU7's (ZIP-259) comes
/// next: on the test network at block 4,465,026; on the main network at a height not yet set.
pub const BRANCH_ID: u32 = 0x37a5_165b;
/// Its upgrade's name, for saying which rules maki follows.
pub const UPGRADE: &str = "NU6.3";
/// Expiry heights stop below this (ZIP-203): from it on, an expiry is refused.
pub const EXPIRY_LIMIT: u32 = 500_000_000;
/// The most inputs: each takes a signature of up to 73 bytes in the answer, and 56 of those, with
/// the answer's status, fit a message.
pub const MAX_INPUTS: usize = 56;
/// The most outputs: more than this, and a transaction isn't gone through page by page with any
/// care.
pub const MAX_OUTPUTS: usize = 64;
/// The longest script maki reads (the script interpreter's `MAX_SCRIPT_SIZE`).
pub const MAX_SCRIPT: usize = 10_000;

/// The network upgrade a consensus branch is, for those version 5 transactions have had: none is
/// in force but `BRANCH_ID`'s.
pub fn upgrade(branch: u32) -> Option<&'static str> {
    match branch {
        0xc2d6_d0b4 => Some("NU5"),
        0xc8e7_1055 => Some("NU6"),
        0x4dec_4df0 => Some("NU6.1"),
        0x5437_f330 => Some("NU6.2"),
        BRANCH_ID => Some(UPGRADE),
        _ => None,
    }
}

/// A transparent input: the coin it spends. (Its script is empty: the transaction is unsigned.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// The coin's transaction, its ID's bytes as Zcash hashes them (explorers show them reversed).
    pub txid: [u8; 32],
    /// Which of its outputs.
    pub index: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// In zatoshis.
    pub value: u64,
    pub script: Vec<u8>,
}

/// A transparent version 5 transaction, unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub branch_id: u32,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Reader<'a> { Reader { b, at: 0 } }

    pub(crate) fn done(&self) -> bool { self.at == self.b.len() }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Length)?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.array()?)) }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.array()?)) }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }

    /// CompactSize, as Zcash reads it: in its shortest form, or it's no transaction.
    pub(crate) fn compact(&mut self) -> Result<u64, Error> {
        let (n, least) = match self.u8()? {
            n @ 0..=0xfc => return Ok(n as u64),
            0xfd => (self.u16()? as u64, 0xfd),
            0xfe => (self.u32()? as u64, 0x1_0000),
            _ => (self.u64()?, 0x1_0000_0000),
        };
        if n < least {
            return Err(Error::Length);
        }
        Ok(n)
    }
}

/// CompactSize, in its shortest form.
pub fn write_compact(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

impl TxOut {
    /// An output as a transaction writes it: the value, then the script after its length.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        write_compact(out, self.script.len());
        out.extend_from_slice(&self.script);
    }
}

impl Transaction {
    /// A transaction, read whole: version 5, the consensus branch in force, unsigned, transparent
    /// alone, nothing after it.
    pub fn parse(bytes: &[u8]) -> Result<Transaction, Error> {
        let mut r = Reader::new(bytes);
        let header = r.u32()?;
        if header != VERSION_5 {
            return Err(Error::Version(header));
        }
        if r.u32()? != VERSION_GROUP {
            return Err(Error::Group);
        }
        let branch_id = r.u32()?;
        if branch_id != BRANCH_ID {
            return Err(Error::Branch(branch_id));
        }
        let (lock_time, expiry_height) = (r.u32()?, r.u32()?);
        if expiry_height >= EXPIRY_LIMIT {
            return Err(Error::Expiry);
        }
        let n = r.compact()?;
        if n > MAX_INPUTS as u64 {
            return Err(Error::TooMany);
        }
        let mut inputs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (txid, index) = (r.array()?, r.u32()?);
            if r.compact()? != 0 {
                return Err(Error::Signed);
            }
            inputs.push(TxIn { txid, index, sequence: r.u32()? });
        }
        let n = r.compact()?;
        if n > MAX_OUTPUTS as u64 {
            return Err(Error::TooMany);
        }
        let mut outputs = Vec::with_capacity(n as usize);
        for _ in 0..n {
            // signed in Zcash's encoding: a negative one is beyond MAX_MONEY here
            let value = r.u64()?;
            if value > MAX_MONEY {
                return Err(Error::Amount);
            }
            let len = r.compact()?;
            if len > MAX_SCRIPT as u64 {
                return Err(Error::Length);
            }
            outputs.push(TxOut { value, script: r.take(len as usize)?.to_vec() });
        }
        for what in ["Sapling spends", "Sapling outputs", "Orchard actions"] {
            if r.compact()? != 0 {
                return Err(Error::Shielded(what));
            }
        }
        if !r.done() {
            return Err(Error::Length);
        }
        Ok(Transaction { branch_id, lock_time, expiry_height, inputs, outputs })
    }

    /// The transaction as Zcash writes it, each input's script `script_sigs` has for it (empty if
    /// it has none): `parse`'s other way, unsigned, and the signed transaction to send.
    pub fn write(&self, script_sigs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.inputs.len() * 150 + self.outputs.len() * 34);
        for n in [VERSION_5, VERSION_GROUP, self.branch_id, self.lock_time, self.expiry_height] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        write_compact(&mut out, self.inputs.len());
        for (i, input) in self.inputs.iter().enumerate() {
            out.extend_from_slice(&input.txid);
            out.extend_from_slice(&input.index.to_le_bytes());
            let script: &[u8] = script_sigs.get(i).map_or(&[], |s| s);
            write_compact(&mut out, script.len());
            out.extend_from_slice(script);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_compact(&mut out, self.outputs.len());
        for o in &self.outputs {
            o.write(&mut out);
        }
        // no Sapling spends or outputs, no Orchard actions
        out.extend_from_slice(&[0, 0, 0]);
        out
    }

    /// The transaction, unsigned, as it came.
    pub fn bytes(&self) -> Vec<u8> { self.write(&[]) }
}
