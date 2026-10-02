//! Transactions: parsed from the exact bytes that get signed, and signed.

use alloc::vec::Vec;

use crate::account::{Account, keccak256};
use crate::rlp::{self, Item};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// EIP-155: a chain ID, and one gas price
    Legacy,
    /// EIP-1559, type 2: a tip and a cap on the fee
    Eip1559,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Rlp(rlp::Error),
    /// Not a transaction type maki signs (EIP-2930, blobs, pre-EIP-155 ones, and ZKsync's and
    /// Celo's own among them).
    Unsupported(&'static str),
    Shape(&'static str),
    /// The maximum fee overflows: gas limit times the fee per gas.
    Fee,
    Key,
}

impl From<rlp::Error> for Error {
    fn from(e: rlp::Error) -> Self { Error::Rlp(e) }
}

impl core::fmt::Display for Error {
    /// Why maki won't sign, for the computer to show.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Rlp(e) => write!(f, "not a transaction maki can read: {}", e),
            Error::Unsupported(what) => write!(f, "maki doesn't sign {}", what),
            Error::Shape(what) => write!(f, "not a transaction maki can read: {}", what),
            Error::Fee => write!(f, "the maximum fee is out of range"),
            Error::Key => write!(f, "couldn't make the signature"),
        }
    }
}

/// A transaction as maki shows it, from the bytes it signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub kind: Kind,
    pub chain_id: u64,
    pub nonce: u64,
    /// EIP-1559's tip; legacy: the gas price, as is `max_fee_per_gas`
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// None: deploys a contract
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    /// EIP-1559: addresses the transaction declares it touches
    pub access_list: usize,
    /// what's signed over, and the items the signed transaction starts with
    unsigned: Vec<u8>,
    head: Vec<u8>,
}

fn to(i: &Item) -> Result<Option<[u8; 20]>, Error> {
    match i.bytes()? {
        [] => Ok(None),
        b if b.len() == 20 => Ok(Some(b.try_into().unwrap())),
        _ => Err(Error::Shape("a recipient that isn't an address")),
    }
}

/// The items again, as they were: decoding is strict, so encoding gives the same bytes.
fn encode(out: &mut Vec<u8>, i: &Item) {
    match i {
        Item::Bytes(b) => rlp::encode_bytes(out, b),
        Item::List(l) => {
            let mut payload = Vec::new();
            for i in l {
                encode(&mut payload, i);
            }
            rlp::encode_list(out, &payload);
        }
    }
}

/// An access list: `[[address, [storage key, ...]], ...]`. Returns how many addresses.
fn access_list(i: &Item) -> Result<usize, Error> {
    let entries = i.list()?;
    for e in entries {
        match e.list()? {
            [address, keys] if address.bytes()?.len() == 20 => {
                if keys.list()?.iter().any(|k| k.bytes().map(|b| b.len() != 32).unwrap_or(true)) {
                    return Err(Error::Shape("an access list storage key that isn't 32 bytes"));
                }
            }
            _ => return Err(Error::Shape("an access list entry that isn't [address, keys]")),
        }
    }
    Ok(entries.len())
}

impl Tx {
    /// An unsigned transaction: EIP-1559 (`0x02 || rlp([...])`), or legacy EIP-155
    /// (`rlp([nonce, gas price, gas, to, value, data, chain ID, 0, 0])`).
    pub fn parse(bytes: &[u8]) -> Result<Tx, Error> {
        match bytes.first() {
            Some(0x02) => {
                let item = rlp::decode(&bytes[1..])?;
                let f = item.list()?;
                let [chain_id, nonce, tip, max_fee, gas, recipient, value, data, list] = f else {
                    return Err(Error::Shape("an EIP-1559 transaction has 9 fields unsigned"));
                };
                let mut head = Vec::new();
                for i in f {
                    encode(&mut head, i);
                }
                Ok(Tx {
                    kind: Kind::Eip1559,
                    chain_id: chain_id.u64()?,
                    nonce: nonce.u64()?,
                    max_priority_fee_per_gas: tip.u128()?,
                    max_fee_per_gas: max_fee.u128()?,
                    gas_limit: gas.u64()?,
                    to: to(recipient)?,
                    value: value.u128()?,
                    data: data.bytes()?.to_vec(),
                    access_list: access_list(list)?,
                    unsigned: bytes.to_vec(),
                    head,
                })
            }
            Some(0xc0..=0xff) => {
                let item = rlp::decode(bytes)?;
                let f = item.list()?;
                let [nonce, price, gas, recipient, value, data, chain_id, zero_r, zero_s] = f else {
                    return Err(Error::Unsupported("a transaction without a chain ID (before EIP-155)"));
                };
                if !zero_r.bytes()?.is_empty() || !zero_s.bytes()?.is_empty() {
                    return Err(Error::Shape("an unsigned legacy transaction ends in chain ID, 0, 0"));
                }
                let chain_id = chain_id.u64()?;
                if chain_id == 0 {
                    return Err(Error::Unsupported("a transaction for chain 0"));
                }
                let mut head = Vec::new();
                for i in &f[..6] {
                    encode(&mut head, i);
                }
                let price = price.u128()?;
                Ok(Tx {
                    kind: Kind::Legacy,
                    chain_id,
                    nonce: nonce.u64()?,
                    max_priority_fee_per_gas: price,
                    max_fee_per_gas: price,
                    gas_limit: gas.u64()?,
                    to: to(recipient)?,
                    value: value.u128()?,
                    data: data.bytes()?.to_vec(),
                    access_list: 0,
                    unsigned: bytes.to_vec(),
                    head,
                })
            }
            Some(0x01) => Err(Error::Unsupported("EIP-2930 transactions")),
            Some(0x03) => Err(Error::Unsupported("blob transactions")),
            // networks' own kinds, said so: each pays or is signed in a way maki wouldn't show
            Some(0x71) => {
                Err(Error::Unsupported("ZKsync's own transactions (EIP-712): send an EIP-1559 one"))
            }
            Some(0x7b) => Err(Error::Unsupported("Celo's fee-currency transactions: pay the fee in CELO")),
            _ => Err(Error::Unsupported("that kind of transaction")),
        }
    }

    /// The most it can cost in fees: gas limit times the fee cap, in wei.
    pub fn max_fee(&self) -> Result<u128, Error> {
        (self.gas_limit as u128).checked_mul(self.max_fee_per_gas).ok_or(Error::Fee)
    }

    /// What's signed: the Keccak hash of the transaction as it came.
    pub fn sighash(&self) -> [u8; 32] { keccak256(&self.unsigned) }

    /// r, s and v: v the recovery ID for EIP-1559, EIP-155's chain-bound value for legacy.
    fn rsv(&self, account: &Account) -> Result<([u8; 32], [u8; 32], u64), Error> {
        self.max_fee()?;
        let (r, s, recid) = account.sign(&self.sighash()).map_err(|_| Error::Key)?;
        let v = match self.kind {
            Kind::Eip1559 => recid as u64,
            Kind::Legacy => self
                .chain_id
                .checked_mul(2)
                .and_then(|v| v.checked_add(35 + recid as u64))
                .ok_or(Error::Fee)?,
        };
        Ok((r, s, v))
    }

    /// The signature alone, as QR-code wallets hand it back (ERC-4527's eth-signature): r, s, then
    /// v in as few bytes as it takes (one, the parity, for EIP-1559).
    pub fn signature(&self, account: &Account) -> Result<Vec<u8>, Error> {
        let (r, s, v) = self.rsv(account)?;
        let v = v.to_be_bytes();
        let from = v.iter().position(|&b| b != 0).unwrap_or(7);
        Ok([&r[..], &s[..], &v[from..]].concat())
    }

    /// The signed transaction, ready to broadcast (`eth_sendRawTransaction`).
    pub fn sign(&self, account: &Account) -> Result<Vec<u8>, Error> {
        let (r, s, v) = self.rsv(account)?;
        let mut payload = self.head.clone();
        rlp::encode_uint(&mut payload, &v.to_be_bytes());
        rlp::encode_uint(&mut payload, &r);
        rlp::encode_uint(&mut payload, &s);
        let mut out = Vec::new();
        if self.kind == Kind::Eip1559 {
            out.push(0x02);
        }
        rlp::encode_list(&mut out, &payload);
        Ok(out)
    }
}
