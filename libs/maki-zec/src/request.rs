//! What the computer asks the Zcash app to sign: a transaction exactly as it will be sent, without
//! its signatures (version 5, ZIP-225, as zcashd and librustzcash write it), and what maki needs
//! beside it to check it (a PSBT's idea, as Kaspa's app has it): what each input's coin holds and the
//! script it pays (which only the computer can see), and the key of this wallet's that coin is at;
//! and for each output, how it's to be shown: a payment, by its address; this wallet's change, by its
//! key; or a payment to a key's hash shown as the TEX address the owner gave (ZIP-320). Read
//! strictly: anything Zcash would refuse, maki refuses before it's shown.
//!
//! The bytes, numbers little-endian:
//!
//! ```text
//! transaction     u16 length, then the transaction (`tx::Transaction`)
//! for each of its inputs, in order:
//!   amount        u64   what its coin holds, in zatoshis
//!   script        u8 length, then the script its coin pays
//!   chain         u8    the coin's key, m/44'/133'/0'/chain/index: 0 receive, 1 change
//!   index         u32   below 2^31
//! for each of its outputs, in order:
//!   shown         u8    0 a payment, by its t-address; 1 this wallet's change, then its key's chain (u8) and
//!                       index (u32); 2 a payment to a key's hash, by its TEX address
//! ```

use alloc::vec::Vec;

use crate::tx::{MAX_INPUTS, MAX_OUTPUTS, Reader, Transaction};
use crate::{Error, MAX_MONEY};

/// The most a request can be: a message's 4096 bytes, less the `T` and the network before it. It
/// holds 49 of this wallet's coins paying two outputs; a wallet spending more makes more than one
/// transaction.
pub const MAX_REQUEST: usize = 4094;

/// Where a key of the account's is: `m/44'/133'/0'/chain/index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derivation {
    /// 0 for receiving, 1 for change.
    pub chain: u8,
    pub index: u32,
}

impl Derivation {
    /// A key on the receive (0) or change (1) chain, at an unhardened index.
    pub fn new(chain: u8, index: u32) -> Option<Derivation> {
        (chain <= 1 && index < maki_hd::HARDENED).then_some(Derivation { chain, index })
    }
}

/// What an input spends, as the computer says: the coin's amount and script, and the key of this
/// wallet's it's at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    pub amount: u64,
    pub script: Vec<u8>,
    pub key: Derivation,
}

/// How an output is to be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    /// A payment, by its t-address (or as data, if that's what it is).
    Payment,
    /// This wallet's change, at this key.
    Change(Derivation),
    /// A payment to a key's hash, by its TEX address (ZIP-320): how the owner gave it.
    Tex,
}

/// A transaction to sign, as the computer sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub tx: Transaction,
    /// What each input spends, in order.
    pub coins: Vec<Coin>,
    /// How each output is shown, in order.
    pub outputs: Vec<Shown>,
}

/// The amounts added up, each and the sum no more than `MAX_MONEY`.
pub(crate) fn total(mut amounts: impl Iterator<Item = u64>) -> Result<u64, Error> {
    amounts
        .try_fold(0u64, |sum, a| sum.checked_add(a).filter(|&s| a <= MAX_MONEY && s <= MAX_MONEY))
        .ok_or(Error::Amount)
}

fn derivation(r: &mut Reader) -> Result<Derivation, Error> {
    let (chain, index) = (r.u8()?, r.u32()?);
    Derivation::new(chain, index).ok_or(Error::Path)
}

impl Request {
    /// A request, read whole, and held to what Zcash takes (`check`).
    pub fn parse(bytes: &[u8]) -> Result<Request, Error> {
        if bytes.len() > MAX_REQUEST {
            return Err(Error::TooBig);
        }
        let mut r = Reader::new(bytes);
        let n = r.u16()? as usize;
        let tx = Transaction::parse(r.take(n)?)?;
        let mut coins = Vec::with_capacity(tx.inputs.len());
        for _ in 0..tx.inputs.len() {
            let amount = r.u64()?;
            let n = r.u8()? as usize;
            let script = r.take(n)?.to_vec();
            coins.push(Coin { amount, script, key: derivation(&mut r)? });
        }
        let mut outputs = Vec::with_capacity(tx.outputs.len());
        for _ in 0..tx.outputs.len() {
            outputs.push(match r.u8()? {
                0 => Shown::Payment,
                1 => Shown::Change(derivation(&mut r)?),
                2 => Shown::Tex,
                _ => return Err(Error::Flag),
            });
        }
        if !r.done() {
            return Err(Error::Length);
        }
        let request = Request { tx, coins, outputs };
        request.check()?;
        Ok(request)
    }

    /// What Zcash checks of a transaction by itself (zcashd's `CheckTransaction`, zebrad's
    /// `check::`), and of the coins it spends, and what this format holds: inputs and outputs, not
    /// too many, and what each input spends and each output's showing; no coin spent twice, and no
    /// coinbase's null coin; amounts within what there can be, and outputs no more than the inputs
    /// hold; keys on the account's chains. (`Transaction::parse` has checked the version, the
    /// consensus branch, the expiry height, and that it's transparent alone.)
    pub fn check(&self) -> Result<(), Error> {
        let tx = &self.tx;
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return Err(Error::Empty);
        }
        if tx.inputs.len() > MAX_INPUTS || tx.outputs.len() > MAX_OUTPUTS {
            return Err(Error::TooMany);
        }
        if self.coins.len() != tx.inputs.len() || self.outputs.len() != tx.outputs.len() {
            return Err(Error::Length);
        }
        let changes = self.outputs.iter().filter_map(|s| match s {
            Shown::Change(k) => Some(*k),
            _ => None,
        });
        if self
            .coins
            .iter()
            .map(|c| c.key)
            .chain(changes)
            .any(|k| Derivation::new(k.chain, k.index).is_none())
        {
            return Err(Error::Path);
        }
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.txid == [0; 32] && input.index == u32::MAX {
                return Err(Error::Coinbase(i));
            }
            if tx.inputs[..i].iter().any(|e| e.txid == input.txid && e.index == input.index) {
                return Err(Error::Duplicate(i));
            }
        }
        self.fee()?;
        Ok(())
    }

    /// The request as the computer sends it, `parse`'s other way, for one `check` passes (scripts
    /// of up to 255 bytes, as the format has them).
    pub fn bytes(&self) -> Vec<u8> {
        let tx = self.tx.bytes();
        let mut out = Vec::with_capacity(tx.len() + 2 + self.coins.len() * 40 + self.outputs.len() * 6);
        out.extend_from_slice(&(tx.len() as u16).to_le_bytes());
        out.extend_from_slice(&tx);
        let key = |out: &mut Vec<u8>, k: &Derivation| {
            out.push(k.chain);
            out.extend_from_slice(&k.index.to_le_bytes());
        };
        for c in &self.coins {
            out.extend_from_slice(&c.amount.to_le_bytes());
            out.push(c.script.len() as u8);
            out.extend_from_slice(&c.script);
            key(&mut out, &c.key);
        }
        for s in &self.outputs {
            match s {
                Shown::Payment => out.push(0),
                Shown::Change(k) => {
                    out.push(1);
                    key(&mut out, k);
                }
                Shown::Tex => out.push(2),
            }
        }
        out
    }

    /// What the inputs hold, less what the outputs pay: the fee.
    pub fn fee(&self) -> Result<u64, Error> {
        let spent = total(self.coins.iter().map(|c| c.amount))?;
        let paid = total(self.tx.outputs.iter().map(|o| o.value))?;
        spent.checked_sub(paid).ok_or(Error::NegativeFee)
    }
}
