//! What maki is asked to sign, and shows its owner before it does: a Monero transaction as maki
//! desktop describes it, from its own wallet or from a view-only wallet's unsigned file. The
//! outputs it spends (each with its ring, as the chain has them) and what they pay: each payment
//! to an address, the change coming back, the fee. maki makes everything else itself, the
//! outputs' keys, the range proof and the signatures (`spend`, with `keys`); this module is only
//! the request's bytes and what the owner reads, so the Monero app can show it without keys.
//!
//! All numbers are little-endian:
//!
//! ```text
//! version u8 (1)      network u8 (0 Monero, 1 testnet, 2 stagenet)      account u32
//! fee u64             change u64
//! payments u8, each:  amount u64, address (u8 length, then its characters)
//! inputs u8, ring size u8, each input:
//!     amount u64, transaction key [32], index u64, subaddress u32, real u8,
//!     ring size members, each: global index u64, key [32], commitment [32]
//! ```
//!
//! `account` is the subaddress account (Monero's "major" index) the inputs were paid to and the
//! change goes back to (its address 0); an input's `subaddress` is its minor index there. Its
//! transaction key is the public key its transaction derives it with: the transaction's own, or,
//! in one paying several subaddresses, the output's additional key. The ring is in order of the
//! chain's global output indices, the real output at `real`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{Kind, Network};

pub const VERSION: u8 = 1;
/// Outputs a transaction may have (Bulletproofs+ covers 16), payments and change together.
pub const MAX_OUTPUTS: usize = 16;
/// Inputs maki spends at once: the request is then about 19 KiB.
pub const MAX_INPUTS: usize = 16;
/// Monero's rings have had 16 members since its fifteenth hard fork.
pub const MAX_RING: usize = 16;
/// Piconero in a monero.
pub const ATOMIC: u64 = 1_000_000_000_000;

/// Why a request isn't one maki signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestError {
    /// Cut short, too long, or a version maki doesn't know.
    Malformed,
    Network,
    /// A payment's address isn't one, or is another network's.
    Address(usize),
    /// A payment of nothing.
    Zero(usize),
    /// A payment ID, with more than one place paid: whose would it be?
    PaymentId,
    /// Too many outputs, or none; too many inputs, or none.
    Count,
    /// A ring out of order, of different sizes, or with the spent output outside it.
    Ring(usize),
    /// What's spent doesn't add up to what's paid, the change and the fee.
    Sum,
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RequestError::Malformed => write!(f, "not a request maki can read"),
            RequestError::Network => write!(f, "a network maki doesn't know"),
            RequestError::Address(i) => write!(f, "payment {} isn't to an address of this network", i + 1),
            RequestError::Zero(i) => write!(f, "payment {} pays nothing", i + 1),
            RequestError::PaymentId => write!(f, "a payment ID goes with one address alone"),
            RequestError::Count => {
                write!(f, "1 to {MAX_INPUTS} inputs, and up to {MAX_OUTPUTS} outputs with the change")
            }
            RequestError::Ring(i) => {
                write!(f, "input {}'s ring isn't in the chain's order, or doesn't hold it", i + 1)
            }
            RequestError::Sum => write!(f, "the inputs don't add up to the payments, change and fee"),
        }
    }
}

/// Where a payment goes, as its address says: the address's public spend and view keys, and the
/// payment ID an integrated address carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub kind: Kind,
    pub spend: [u8; 32],
    pub view: [u8; 32],
    pub payment_id: Option<[u8; 8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub address: String,
    pub amount: u64,
    pub destination: Destination,
}

/// A ring member: an output as the chain has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Member {
    pub global: u64,
    pub key: [u8; 32],
    pub commitment: [u8; 32],
}

/// An output of this wallet's, spent: `ring[real]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub amount: u64,
    pub tx_key: [u8; 32],
    pub index: u64,
    pub subaddress: u32,
    pub real: usize,
    pub ring: Vec<Member>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub network: Network,
    pub account: u32,
    pub fee: u64,
    pub change: u64,
    pub payments: Vec<Payment>,
    pub inputs: Vec<Input>,
}

fn network_byte(n: Network) -> u8 {
    match n {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Stagenet => 2,
    }
}

fn network_of(b: u8) -> Option<Network> {
    match b {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet),
        2 => Some(Network::Stagenet),
        _ => None,
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RequestError> {
        if self.0.len() < n {
            return Err(RequestError::Malformed);
        }
        let (taken, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, RequestError> { Ok(self.take(1)?[0]) }

    fn u32(&mut self) -> Result<u32, RequestError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RequestError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn b32(&mut self) -> Result<[u8; 32], RequestError> { Ok(self.take(32)?.try_into().unwrap()) }
}

impl Request {
    /// A request from its bytes, checked: the payments' addresses read, every ring in the chain's
    /// order, and the sums right.
    pub fn parse(bytes: &[u8]) -> Result<Request, RequestError> {
        let mut r = Reader(bytes);
        if r.u8()? != VERSION {
            return Err(RequestError::Malformed);
        }
        let network = network_of(r.u8()?).ok_or(RequestError::Network)?;
        let account = r.u32()?;
        let fee = r.u64()?;
        let change = r.u64()?;
        let n = r.u8()? as usize;
        let mut payments = Vec::with_capacity(n);
        for i in 0..n {
            let amount = r.u64()?;
            let len = r.u8()? as usize;
            let address = core::str::from_utf8(r.take(len)?).map_err(|_| RequestError::Address(i))?;
            let destination = match read_destination(address) {
                Some((net, d)) if net == network => d,
                _ => return Err(RequestError::Address(i)),
            };
            if amount == 0 {
                return Err(RequestError::Zero(i));
            }
            payments.push(Payment { address: address.into(), amount, destination });
        }
        let n = r.u8()? as usize;
        let ring_size = r.u8()? as usize;
        if ring_size == 0 || ring_size > MAX_RING {
            return Err(RequestError::Ring(0));
        }
        let mut inputs = Vec::with_capacity(n);
        for i in 0..n {
            let amount = r.u64()?;
            let tx_key = r.b32()?;
            let index = r.u64()?;
            let subaddress = r.u32()?;
            let real = r.u8()? as usize;
            let mut ring = Vec::with_capacity(ring_size);
            for _ in 0..ring_size {
                ring.push(Member { global: r.u64()?, key: r.b32()?, commitment: r.b32()? });
            }
            if real >= ring_size || ring.windows(2).any(|w| w[0].global >= w[1].global) {
                return Err(RequestError::Ring(i));
            }
            inputs.push(Input { amount, tx_key, index, subaddress, real, ring });
        }
        if !r.0.is_empty() {
            return Err(RequestError::Malformed);
        }
        let request = Request { network, account, fee, change, payments, inputs };
        request.check()?;
        Ok(request)
    }

    fn check(&self) -> Result<(), RequestError> {
        if self.payments.is_empty()
            || self.outputs() > MAX_OUTPUTS
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_INPUTS
        {
            return Err(RequestError::Count);
        }
        // a payment ID is encrypted to the one place paid, so it's there alone (as wallet2 has it)
        if self.payments.iter().any(|p| p.destination.payment_id.is_some())
            && self.payments.iter().any(|p| p.destination != self.payments[0].destination)
        {
            return Err(RequestError::PaymentId);
        }
        let spent = self.inputs.iter().try_fold(0u64, |t, i| t.checked_add(i.amount));
        let paid = self
            .payments
            .iter()
            .try_fold(self.fee, |t, p| t.checked_add(p.amount))
            .and_then(|t| t.checked_add(self.change));
        match (spent, paid) {
            (Some(s), Some(p)) if s == p => Ok(()),
            _ => Err(RequestError::Sum),
        }
    }

    /// The transaction's outputs: the payments, and the change, or (with none, and one payment)
    /// an output of nothing to an address nobody has, as wallet2 adds: every transaction has two.
    pub fn outputs(&self) -> usize {
        self.payments.len() + usize::from(self.change > 0 || self.payments.len() == 1)
    }

    /// Its bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ring_size = self.inputs.first().map_or(0, |i| i.ring.len());
        let mut out =
            Vec::with_capacity(32 + self.payments.len() * 120 + self.inputs.len() * (64 + ring_size * 72));
        out.push(VERSION);
        out.push(network_byte(self.network));
        out.extend_from_slice(&self.account.to_le_bytes());
        out.extend_from_slice(&self.fee.to_le_bytes());
        out.extend_from_slice(&self.change.to_le_bytes());
        out.push(self.payments.len() as u8);
        for p in &self.payments {
            out.extend_from_slice(&p.amount.to_le_bytes());
            out.push(p.address.len() as u8);
            out.extend_from_slice(p.address.as_bytes());
        }
        out.push(self.inputs.len() as u8);
        out.push(ring_size as u8);
        for i in &self.inputs {
            out.extend_from_slice(&i.amount.to_le_bytes());
            out.extend_from_slice(&i.tx_key);
            out.extend_from_slice(&i.index.to_le_bytes());
            out.extend_from_slice(&i.subaddress.to_le_bytes());
            out.push(i.real as u8);
            for m in &i.ring {
                out.extend_from_slice(&m.global.to_le_bytes());
                out.extend_from_slice(&m.key);
                out.extend_from_slice(&m.commitment);
            }
        }
        out
    }

    /// What leaves the wallet: every payment, and the fee.
    pub fn spent(&self) -> u64 { self.payments.iter().map(|p| p.amount).sum::<u64>() + self.fee }

    /// A fee over a tenth of what's paid is called out, as a mistake looks.
    pub fn fee_is_high(&self) -> bool {
        let paid: u64 = self.payments.iter().map(|p| p.amount).sum();
        self.fee.saturating_mul(10) > paid
    }

    /// The pages the owner goes through before signing: each payment with its whole address (and
    /// the payment ID an integrated one carries), the change coming back, then the fee.
    pub fn pages(&self) -> Vec<Page> {
        let n = self.payments.len();
        let mut pages = Vec::with_capacity(n + 2);
        for (i, p) in self.payments.iter().enumerate() {
            let heading = if n > 1 { format!("Send {}/{n}", i + 1) } else { String::from("Send") };
            let prose = match p.destination.payment_id {
                Some(id) => format!("payment ID {}", hex(&id)),
                None => String::new(),
            };
            pages.push(Page {
                heading,
                value: amount(p.amount, self.network),
                mono: p.address.clone(),
                prose,
            });
        }
        if self.change > 0 {
            let back = if self.account == 0 {
                String::from("back to you")
            } else {
                format!("back to account {}", self.account)
            };
            pages.push(Page {
                heading: String::from("Change"),
                value: amount(self.change, self.network),
                mono: back,
                prose: String::new(),
            });
        }
        pages.push(Page {
            heading: String::from(if self.fee_is_high() { "High fee!" } else { "Fee" }),
            value: amount(self.fee, self.network),
            mono: String::new(),
            prose: String::new(),
        });
        pages
    }

    /// The line that goes with sign and reject.
    pub fn summary(&self) -> String { format!("Total {}", amount(self.spent(), self.network)) }
}

/// A screen's worth of review: a heading, the thing to check in bold (an amount), fixed-width
/// text under it (an address), and small words (a payment ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
}

/// The unit amounts are shown in: test networks' coins are marked as such.
pub fn unit(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "XMR",
        Network::Testnet => "tXMR",
        Network::Stagenet => "sXMR",
    }
}

/// An amount, exactly, in monero without trailing zeros: `0.5 XMR`, `1 XMR`, `0.000012 XMR`.
pub fn amount(piconero: u64, network: Network) -> String {
    let whole = piconero / ATOMIC;
    let frac = piconero % ATOMIC;
    if frac == 0 {
        return format!("{whole} {}", unit(network));
    }
    let digits = format!("{frac:012}");
    format!("{whole}.{} {}", digits.trim_end_matches('0'), unit(network))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [DIGITS[(b >> 4) as usize] as char, DIGITS[(b & 15) as usize] as char])
        .collect()
}

/// A payment's address: a standard one, a subaddress, or an integrated address (a standard one
/// with a payment ID), and its network. None if it isn't one of those, or its check fails.
pub fn read_destination(text: &str) -> Option<(Network, Destination)> {
    if let Some((network, kind, spend, view)) = crate::read_address(text) {
        return Some((network, Destination { kind, spend, view, payment_id: None }));
    }
    let data = crate::base58::decode(text)?;
    if data.len() != 77 || crate::keccak(&data[..73])[..4] != data[73..] {
        return None;
    }
    let network = [Network::Mainnet, Network::Testnet, Network::Stagenet]
        .into_iter()
        .find(|n| n.integrated_tag() == data[0])?;
    Some((
        network,
        Destination {
            kind: Kind::Standard,
            spend: data[1..33].try_into().unwrap(),
            view: data[33..65].try_into().unwrap(),
            payment_id: Some(data[65..73].try_into().unwrap()),
        },
    ))
}
