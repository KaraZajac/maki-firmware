//! What the computer asks the Kaspa app to sign: a Kaspa transaction as it will be sent, without
//! its signatures, and what maki needs beside it to check it (a PSBT's idea): each input's coin, the
//! amount and script it holds (which only the computer can see), and the key of this wallet's that
//! coin is at; and, for an output that pays this wallet, which of its keys. Read strictly: anything
//! Kaspa would refuse, maki refuses before it's shown.
//!
//! The bytes, numbers little-endian as Kaspa's own encodings have them:
//!
//! ```text
//! version         u16   0, or 1 (Toccata's)
//! inputs          u8    1 to MAX_INPUTS, each:
//!   txid          32    the coin's transaction, its ID's bytes as Kaspa hashes and shows them
//!   index         u32   which of its outputs
//!   sequence      u64
//!   sig op count  u8    version 0: the signature checks it commits to (this wallet's: 1)
//!   budget        u16   version 1, instead: the compute it commits to
//!   amount        u64   what the coin holds, in sompi
//!   script        u16 version, u8 length, the script: what the coin pays
//!   chain         u8    the coin's key, m/44'/111111'/0'/chain/index: 0 receive, 1 change
//!   index         u32   below 2^31
//! outputs         u8    1 to MAX_OUTPUTS, each:
//!   value         u64   in sompi
//!   script        u16 version, u8 length, the script: what it pays
//!   covenant      u8    version 1 only: 0 (maki takes no output bound to a covenant)
//!   ours          u8    0 a payment; 1 this wallet's, then its key's chain (u8) and index (u32)
//! lock time       u64
//! subnetwork      20    zeros: the native subnetwork
//! gas             u64   0
//! payload         u16 length, then the bytes: MAX_PAYLOAD at most
//! ```

use alloc::vec::Vec;

use crate::{Error, MAX_SOMPI};

/// The most a request can be: a message's 4096 bytes, less the `T` and the network before it. It
/// holds 41 of this wallet's coins paying two outputs; a wallet spending more makes more than one
/// transaction, as Kaspa's own do when a transaction's mass would be too great.
pub const MAX_REQUEST: usize = 4094;
/// The most inputs: each takes a signature of 65 bytes, which with the answer's status must fit a
/// message.
pub const MAX_INPUTS: usize = 63;
/// The most outputs: more than this, and a transaction isn't gone through page by page with any
/// care.
pub const MAX_OUTPUTS: usize = 64;
/// The most data maki shows: 4096 characters of a page in hex.
pub const MAX_PAYLOAD: usize = 2048;
/// The native subnetwork's ID: a plain transaction's.
pub const NATIVE: [u8; 20] = [0; 20];

/// Where a key of the account's is: `m/44'/111111'/0'/chain/index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derivation {
    /// 0 for receiving, 1 for change.
    pub chain: u8,
    pub index: u32,
}

/// A script public key: what a coin pays, and what an output will.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub version: u16,
    pub script: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The coin it spends: the transaction it's from, and which of its outputs.
    pub txid: [u8; 32],
    pub index: u32,
    pub sequence: u64,
    /// Version 0: how many signature checks it commits to. (In a version 1 transaction, 0.)
    pub sig_op_count: u8,
    /// Version 1: the compute it commits to, which no signature covers. (In version 0, 0.)
    pub compute_budget: u16,
    /// What the coin holds, and what it pays: the computer's word, checked against `key`.
    pub amount: u64,
    pub script: Script,
    pub key: Derivation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub script: Script,
    /// The key of this wallet's it pays, if the computer says it's change.
    pub ours: Option<Derivation>,
}

/// A transaction to sign, as the computer sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: u16,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u64,
    pub subnetwork: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
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

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Error> { Ok(self.take(1)?[0]) }

    fn u16(&mut self) -> Result<u16, Error> { Ok(u16::from_le_bytes(self.array()?)) }

    fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.array()?)) }

    fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }

    fn flag(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Flag),
        }
    }

    fn script(&mut self) -> Result<Script, Error> {
        let version = self.u16()?;
        let n = self.u8()? as usize;
        Ok(Script { version, script: self.take(n)?.to_vec() })
    }

    fn derivation(&mut self) -> Result<Derivation, Error> {
        let (chain, index) = (self.u8()?, self.u32()?);
        Derivation::new(chain, index).ok_or(Error::Path)
    }
}

impl Derivation {
    /// A key on the receive (0) or change (1) chain, at an unhardened index.
    pub fn new(chain: u8, index: u32) -> Option<Derivation> {
        (chain <= 1 && index < maki_hd::HARDENED).then_some(Derivation { chain, index })
    }
}

/// The amounts added up, each and the sum no more than `MAX_SOMPI`.
pub(crate) fn total(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts
        .try_fold(0u64, |sum, a| sum.checked_add(a).filter(|&s| a <= MAX_SOMPI && s <= MAX_SOMPI))
        .ok_or(Error::Amount)
}

impl Request {
    /// A request, read whole, and held to what Kaspa takes (`check`).
    pub fn parse(bytes: &[u8]) -> Result<Request, Error> {
        if bytes.len() > MAX_REQUEST {
            return Err(Error::TooBig);
        }
        let mut r = Reader { b: bytes, at: 0 };
        let version = r.u16()?;
        if version > 1 {
            return Err(Error::Version);
        }
        let n = r.u8()? as usize;
        if n > MAX_INPUTS {
            return Err(Error::TooMany);
        }
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let (txid, index, sequence) = (r.array()?, r.u32()?, r.u64()?);
            let (sig_op_count, compute_budget) = if version == 0 { (r.u8()?, 0) } else { (0, r.u16()?) };
            let (amount, script, key) = (r.u64()?, r.script()?, r.derivation()?);
            inputs.push(Input { txid, index, sequence, sig_op_count, compute_budget, amount, script, key });
        }
        let n = r.u8()? as usize;
        if n > MAX_OUTPUTS {
            return Err(Error::TooMany);
        }
        let mut outputs = Vec::with_capacity(n);
        for j in 0..n {
            let (value, script) = (r.u64()?, r.script()?);
            if version >= 1 && r.flag()? {
                return Err(Error::Covenant(j));
            }
            let ours = if r.flag()? { Some(r.derivation()?) } else { None };
            outputs.push(Output { value, script, ours });
        }
        let (lock_time, subnetwork, gas) = (r.u64()?, r.array()?, r.u64()?);
        let n = r.u16()? as usize;
        if n > MAX_PAYLOAD {
            return Err(Error::Payload);
        }
        let payload = r.take(n)?.to_vec();
        if r.at != bytes.len() {
            return Err(Error::Length);
        }
        let request = Request { version, inputs, outputs, lock_time, subnetwork, gas, payload };
        request.check()?;
        Ok(request)
    }

    /// What Kaspa checks of a transaction by itself, and of the coins it spends (rusty-kaspa's
    /// `validate_tx_in_isolation`, and the amounts of `validate_populated_transaction_and_get_fee`),
    /// and what this format holds: a known version; inputs and outputs, not too many; no coin spent
    /// twice, and none holding nothing; no output of nothing; amounts within what there can be, and
    /// outputs no more than the inputs hold; keys on the account's chains; the native subnetwork,
    /// without gas; data no more than maki shows.
    pub fn check(&self) -> Result<(), Error> {
        if self.version > 1 {
            return Err(Error::Version);
        }
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(Error::Empty);
        }
        if self.inputs.len() > MAX_INPUTS || self.outputs.len() > MAX_OUTPUTS {
            return Err(Error::TooMany);
        }
        let mut keys = self.inputs.iter().map(|i| i.key).chain(self.outputs.iter().filter_map(|o| o.ours));
        if keys.any(|k| Derivation::new(k.chain, k.index).is_none()) {
            return Err(Error::Path);
        }
        for (i, input) in self.inputs.iter().enumerate() {
            if self.inputs[..i].iter().any(|e| e.txid == input.txid && e.index == input.index) {
                return Err(Error::Duplicate(i));
            }
            // no output can pay nothing, so no coin holds nothing
            if input.amount == 0 {
                return Err(Error::Amount);
            }
        }
        if let Some(j) = self.outputs.iter().position(|o| o.value == 0) {
            return Err(Error::Zero(j));
        }
        self.fee()?;
        if self.subnetwork != NATIVE {
            return Err(Error::Subnetwork);
        }
        if self.gas != 0 {
            return Err(Error::Gas);
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(Error::Payload);
        }
        Ok(())
    }

    /// The request as the computer sends it, `parse`'s other way, for one `check` passes (scripts of
    /// up to 255 bytes, as the format has them): a version 1 output always says it's bound to no
    /// covenant.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let script = |out: &mut Vec<u8>, s: &Script| {
            out.extend_from_slice(&s.version.to_le_bytes());
            out.push(s.script.len() as u8);
            out.extend_from_slice(&s.script);
        };
        let key = |out: &mut Vec<u8>, k: &Derivation| {
            out.push(k.chain);
            out.extend_from_slice(&k.index.to_le_bytes());
        };
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.inputs.len() as u8);
        for i in &self.inputs {
            out.extend_from_slice(&i.txid);
            out.extend_from_slice(&i.index.to_le_bytes());
            out.extend_from_slice(&i.sequence.to_le_bytes());
            if self.version == 0 {
                out.push(i.sig_op_count);
            } else {
                out.extend_from_slice(&i.compute_budget.to_le_bytes());
            }
            out.extend_from_slice(&i.amount.to_le_bytes());
            script(&mut out, &i.script);
            key(&mut out, &i.key);
        }
        out.push(self.outputs.len() as u8);
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_le_bytes());
            script(&mut out, &o.script);
            if self.version >= 1 {
                out.push(0);
            }
            match &o.ours {
                Some(k) => {
                    out.push(1);
                    key(&mut out, k);
                }
                None => out.push(0),
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out.extend_from_slice(&self.subnetwork);
        out.extend_from_slice(&self.gas.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// What the inputs hold, less what the outputs pay: the fee.
    pub fn fee(&self) -> Result<u64, Error> {
        let spent = total(self.inputs.iter().map(|i| i.amount))?;
        let paid = total(self.outputs.iter().map(|o| o.value))?;
        spent.checked_sub(paid).ok_or(Error::NegativeFee)
    }
}
