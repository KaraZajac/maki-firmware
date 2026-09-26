//! Bitcoin transactions: just enough to read the one a PSBT carries and the ones its inputs spend.

use alloc::vec::Vec;

use crate::hash::sha256d;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    /// the previous transaction's id, in its internal byte order
    pub prev_txid: [u8; 32],
    pub prev_vout: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    /// satoshis
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

/// Bounds on what maki will read: generous for any real transaction, and far from anything that
/// could exhaust its memory.
const MAX_COUNT: u64 = 10_000;
const MAX_SCRIPT: u64 = 10_000;

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self { Cursor { data, pos: 0 } }

    pub(crate) fn done(&self) -> bool { self.pos == self.data.len() }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError("length overflows"))?;
        let s = self.data.get(self.pos..end).ok_or(ParseError("ends early"))?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn peek(&self, n: usize) -> Option<&'a [u8]> { self.data.get(self.pos..self.pos + n) }

    pub(crate) fn u8(&mut self) -> Result<u8, ParseError> { Ok(self.take(1)?[0]) }

    pub(crate) fn u32(&mut self) -> Result<u32, ParseError> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }

    pub(crate) fn u64(&mut self) -> Result<u64, ParseError> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }

    /// CompactSize, minimally encoded.
    pub(crate) fn varint(&mut self) -> Result<u64, ParseError> {
        let (v, min) = match self.u8()? {
            n @ 0..=0xfc => return Ok(n as u64),
            0xfd => (u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64, 0xfd),
            0xfe => (self.u32()? as u64, 0x1_0000),
            _ => (self.u64()?, 0x1_0000_0000),
        };
        if v < min {
            return Err(ParseError("CompactSize not minimal"));
        }
        Ok(v)
    }

    pub(crate) fn bytes(&mut self, max: u64) -> Result<&'a [u8], ParseError> {
        let n = self.varint()?;
        if n > max {
            return Err(ParseError("too long"));
        }
        self.take(n as usize)
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

impl TxOut {
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
        write_varint(out, self.script_pubkey.len() as u64);
        out.extend_from_slice(&self.script_pubkey);
    }
}

impl Tx {
    /// A transaction in either serialization; witnesses are read past, not kept.
    pub fn parse(bytes: &[u8]) -> Result<Tx, ParseError> {
        let mut c = Cursor::new(bytes);
        let version = c.u32()? as i32;
        let segwit = c.peek(2) == Some(&[0x00, 0x01]);
        if segwit {
            c.take(2)?;
        }
        let n_in = c.varint()?;
        if n_in == 0 || n_in > MAX_COUNT {
            return Err(ParseError("input count"));
        }
        let mut inputs = Vec::with_capacity(n_in as usize);
        for _ in 0..n_in {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(c.take(32)?);
            let prev_vout = c.u32()?;
            let script_sig = c.bytes(MAX_SCRIPT)?.to_vec();
            let sequence = c.u32()?;
            inputs.push(TxIn { prev_txid, prev_vout, script_sig, sequence });
        }
        let n_out = c.varint()?;
        if n_out == 0 || n_out > MAX_COUNT {
            return Err(ParseError("output count"));
        }
        let mut outputs = Vec::with_capacity(n_out as usize);
        for _ in 0..n_out {
            let value = c.u64()?;
            let script_pubkey = c.bytes(MAX_SCRIPT)?.to_vec();
            outputs.push(TxOut { value, script_pubkey });
        }
        if segwit {
            for _ in 0..n_in {
                let items = c.varint()?;
                if items > MAX_COUNT {
                    return Err(ParseError("witness count"));
                }
                for _ in 0..items {
                    c.bytes(MAX_SCRIPT * 100)?;
                }
            }
        }
        let lock_time = c.u32()?;
        if !c.done() {
            return Err(ParseError("bytes after the transaction"));
        }
        Ok(Tx { version, inputs, outputs, lock_time })
    }

    /// Serialized without witnesses: what the txid hashes, and what a PSBT carries.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.version as u32).to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.prev_txid);
            out.extend_from_slice(&i.prev_vout.to_le_bytes());
            write_varint(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            o.write(&mut out);
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The transaction id, in internal byte order (explorers show it reversed).
    pub fn txid(&self) -> [u8; 32] { sha256d(&self.serialize()) }
}
