//! PSBT version 0 (BIP174): read, and written back with signatures added. Everything maki
//! doesn't use is kept as it came, so wallet software gets back what it sent, plus signatures.

use alloc::vec::Vec;

use crate::tx::{write_varint, Cursor, ParseError, Tx};

pub const MAGIC: &[u8; 5] = b"psbt\xff";

// the key types maki reads
pub const GLOBAL_UNSIGNED_TX: u8 = 0x00;
pub const GLOBAL_VERSION: u8 = 0xfb;
pub const IN_NON_WITNESS_UTXO: u8 = 0x00;
pub const IN_WITNESS_UTXO: u8 = 0x01;
pub const IN_PARTIAL_SIG: u8 = 0x02;
pub const IN_SIGHASH_TYPE: u8 = 0x03;
pub const IN_REDEEM_SCRIPT: u8 = 0x04;
pub const IN_WITNESS_SCRIPT: u8 = 0x05;
pub const IN_BIP32_DERIVATION: u8 = 0x06;
pub const IN_TAP_KEY_SIG: u8 = 0x13;
pub const IN_TAP_SCRIPT_SIG: u8 = 0x14;
pub const IN_TAP_LEAF_SCRIPT: u8 = 0x15;
pub const IN_TAP_BIP32_DERIVATION: u8 = 0x16;
pub const IN_TAP_INTERNAL_KEY: u8 = 0x17;
pub const IN_TAP_MERKLE_ROOT: u8 = 0x18;
pub const OUT_BIP32_DERIVATION: u8 = 0x02;
pub const OUT_TAP_INTERNAL_KEY: u8 = 0x05;
pub const OUT_TAP_BIP32_DERIVATION: u8 = 0x07;

/// A PSBT is at most this big: the largest message maki takes in.
pub const MAX_PSBT: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Psbt {
    pub global: Vec<Pair>,
    pub inputs: Vec<Vec<Pair>>,
    pub outputs: Vec<Vec<Pair>>,
    /// the transaction being signed, from the global map
    pub tx: Tx,
}

fn read_map(c: &mut Cursor) -> Result<Vec<Pair>, ParseError> {
    let mut pairs: Vec<Pair> = Vec::new();
    loop {
        let key_len = c.varint()?;
        if key_len == 0 {
            return Ok(pairs);
        }
        if key_len > 10_000 {
            return Err(ParseError("key too long"));
        }
        let key = c.take(key_len as usize)?.to_vec();
        let value = c.bytes(MAX_PSBT as u64)?.to_vec();
        if pairs.iter().any(|p| p.key == key) {
            return Err(ParseError("duplicate key"));
        }
        pairs.push(Pair { key, value });
    }
}

fn write_map(out: &mut Vec<u8>, pairs: &[Pair]) {
    for p in pairs {
        write_varint(out, p.key.len() as u64);
        out.extend_from_slice(&p.key);
        write_varint(out, p.value.len() as u64);
        out.extend_from_slice(&p.value);
    }
    out.push(0x00);
}

impl Psbt {
    pub fn parse(bytes: &[u8]) -> Result<Psbt, ParseError> {
        if bytes.len() > MAX_PSBT {
            return Err(ParseError("too big"));
        }
        let mut c = Cursor::new(bytes);
        if c.take(5)? != MAGIC {
            return Err(ParseError("not a PSBT"));
        }
        let global = read_map(&mut c)?;
        if let Some(v) = global.iter().find(|p| p.key == [GLOBAL_VERSION]) {
            if v.value != [0, 0, 0, 0] {
                return Err(ParseError("only PSBT version 0"));
            }
        }
        let tx_pair = global.iter().find(|p| p.key == [GLOBAL_UNSIGNED_TX]).ok_or(ParseError("no transaction"))?;
        let tx = Tx::parse(&tx_pair.value)?;
        if tx.inputs.iter().any(|i| !i.script_sig.is_empty()) {
            return Err(ParseError("transaction already has signatures"));
        }
        let mut inputs = Vec::with_capacity(tx.inputs.len());
        for _ in 0..tx.inputs.len() {
            inputs.push(read_map(&mut c)?);
        }
        let mut outputs = Vec::with_capacity(tx.outputs.len());
        for _ in 0..tx.outputs.len() {
            outputs.push(read_map(&mut c)?);
        }
        if !c.done() {
            return Err(ParseError("bytes after the PSBT"));
        }
        Ok(Psbt { global, inputs, outputs, tx })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        write_map(&mut out, &self.global);
        for m in &self.inputs {
            write_map(&mut out, m);
        }
        for m in &self.outputs {
            write_map(&mut out, m);
        }
        out
    }

    /// Whether an input or output carries taproot data (BIP371): only then is the taproot
    /// account worth deriving to check the PSBT against.
    pub fn has_taproot(&self) -> bool {
        let tap_in = |p: &Pair| matches!(p.key.first(), Some(&(IN_TAP_KEY_SIG..=IN_TAP_MERKLE_ROOT)));
        let tap_out = |p: &Pair| matches!(p.key.first(), Some(&(OUT_TAP_INTERNAL_KEY | OUT_TAP_BIP32_DERIVATION)));
        self.inputs.iter().flatten().any(tap_in) || self.outputs.iter().flatten().any(tap_out)
    }

    /// An input's value for a key that's just its type.
    pub fn input(&self, i: usize, key_type: u8) -> Option<&[u8]> {
        self.inputs.get(i)?.iter().find(|p| p.key == [key_type]).map(|p| p.value.as_slice())
    }

    /// Set a pair in an input's map, replacing one with the same key.
    pub fn set_input(&mut self, i: usize, key: Vec<u8>, value: Vec<u8>) {
        let map = &mut self.inputs[i];
        match map.iter_mut().find(|p| p.key == key) {
            Some(p) => p.value = value,
            None => map.push(Pair { key, value }),
        }
    }
}

/// A BIP32 derivation value: the master key's fingerprint, then the path.
pub fn parse_derivation(value: &[u8]) -> Option<([u8; 4], Vec<u32>)> {
    if value.len() < 4 || (value.len() - 4) % 4 != 0 {
        return None;
    }
    let fp = [value[0], value[1], value[2], value[3]];
    let path = value[4..].chunks(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    Some((fp, path))
}

/// A taproot BIP32 derivation value (BIP371): the leaf hashes the key signs for, then the master
/// key's fingerprint and the path. The number of leaves, the fingerprint and the path.
pub fn parse_tap_derivation(value: &[u8]) -> Option<(u64, [u8; 4], Vec<u32>)> {
    let mut c = Cursor::new(value);
    let leaves = c.varint().ok()?;
    if leaves > 1_000 {
        return None;
    }
    c.take(leaves as usize * 32).ok()?;
    let rest = c.take(value.len() - c.position()).ok()?;
    let (fp, path) = parse_derivation(rest)?;
    Some((leaves, fp, path))
}
