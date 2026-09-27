//! What maki's screen says about a transaction or a message: shared by the firmware and the fake
//! maki, so both say the same thing.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::account::checksum;
use crate::tx::{Error, Tx};

/// A screen's worth: a heading at the top, the thing to check in bold, and fixed-width text
/// under it across as many lines as it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
}

fn page(heading: &str, value: String, mono: String) -> Page { Page { heading: heading.into(), value, mono } }

/// The networks maki knows by name, and the coin each counts in. Any other shows its chain ID,
/// and amounts in "coins": maki can't say which.
pub fn network(chain_id: u64) -> (String, &'static str) {
    let (name, unit) = match chain_id {
        1 => ("ethereum", "ETH"),
        10 => ("optimism", "ETH"),
        56 => ("bnb chain", "BNB"),
        137 => ("polygon", "POL"),
        8453 => ("base", "ETH"),
        42161 => ("arbitrum", "ETH"),
        11155111 => ("sepolia", "ETH"),
        17000 => ("holesky", "ETH"),
        84532 => ("base sepolia", "ETH"),
        n => return (format!("chain {}", n), "coins"),
    };
    (name.into(), unit)
}

/// An amount of wei, exactly, in whole coins without trailing zeros: `0.05 ETH`.
pub fn amount(wei: u128, unit: &str) -> String {
    let (whole, frac) = (wei / 1_000_000_000_000_000_000, wei % 1_000_000_000_000_000_000);
    if frac == 0 {
        return format!("{} {}", whole, unit);
    }
    format!("{}.{} {}", whole, format!("{:018}", frac).trim_end_matches('0'), unit)
}

/// A fee per gas in gwei, exactly.
fn gwei(wei: u128) -> String {
    let (whole, frac) = (wei / 1_000_000_000, wei % 1_000_000_000);
    if frac == 0 {
        return format!("{}", whole);
    }
    format!("{}.{}", whole, format!("{:09}", frac).trim_end_matches('0'))
}

/// A 256-bit number, in decimal.
fn decimal(n: &[u8; 32]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &byte in n {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 10) as u8;
            carry /= 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return String::from("0");
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// A contract call maki can spell out, or can't.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// no call: only coins sent
    None,
    /// deploys a contract of this many bytes
    Deploy(usize),
    /// ERC-20 `transfer(to, amount)`
    Transfer { to: [u8; 20], amount: [u8; 32] },
    /// ERC-20 `approve(spender, amount)`: the spender may take up to the amount, later
    Approve { spender: [u8; 20], amount: [u8; 32] },
    /// ERC-721/1155 `setApprovalForAll(operator, approved)`: every item of the collection
    ApproveAll { operator: [u8; 20], approved: bool },
    Unknown { selector: [u8; 4], len: usize },
}

/// An ABI address argument: 12 zero bytes, then the address.
fn address_arg(word: &[u8]) -> Option<[u8; 20]> {
    (word.len() == 32 && word[..12].iter().all(|&b| b == 0)).then(|| word[12..].try_into().unwrap())
}

pub fn call(tx: &Tx) -> Call {
    if tx.to.is_none() {
        return Call::Deploy(tx.data.len());
    }
    let d = &tx.data;
    if d.is_empty() {
        return Call::None;
    }
    let mut selector = [0u8; 4];
    selector[..d.len().min(4)].copy_from_slice(&d[..d.len().min(4)]);
    if d.len() == 68 {
        let (a, b) = (&d[4..36], &d[36..68]);
        match (selector, address_arg(a)) {
            ([0xa9, 0x05, 0x9c, 0xbb], Some(to)) => return Call::Transfer { to, amount: b.try_into().unwrap() },
            ([0x09, 0x5e, 0xa7, 0xb3], Some(spender)) => return Call::Approve { spender, amount: b.try_into().unwrap() },
            ([0xa2, 0x2c, 0xb4, 0x65], Some(operator)) if b[..31].iter().all(|&x| x == 0) && b[31] <= 1 => {
                return Call::ApproveAll { operator, approved: b[31] == 1 }
            }
            _ => {}
        }
    }
    Call::Unknown { selector, len: d.len() }
}

/// The pages the owner goes through before signing, and the line that goes with sign and
/// reject (the most that can leave the account in coins).
pub fn review(tx: &Tx) -> Result<(Vec<Page>, String), Error> {
    let (name, unit) = network(tx.chain_id);
    let max_fee = tx.max_fee()?;
    let contract = tx.to.map(|a| checksum(&a)).unwrap_or_default();
    let mut pages = vec![page("Network", name, format!("chain ID {}", tx.chain_id))];
    let c = call(tx);
    if tx.value > 0 || c == Call::None {
        let to = if tx.to.is_some() { contract.clone() } else { String::from("the new contract") };
        pages.push(page("Send", amount(tx.value, unit), to));
    }
    match c {
        Call::None => {}
        Call::Deploy(len) => pages.push(page("New contract", format!("{} bytes of code", len), String::new())),
        Call::Transfer { to, amount } => {
            pages.push(page("Send tokens", String::from("to"), checksum(&to)));
            pages.push(page("Token amount", String::from("in its smallest units"), decimal(&amount)));
            pages.push(page("Token", String::from("its contract"), contract.clone()));
        }
        Call::Approve { spender, amount } => {
            let how_much = if amount == [0xff; 32] { String::from("any amount") } else { decimal(&amount) };
            pages.push(page("Approve!", String::from("lets it spend tokens"), checksum(&spender)));
            pages.push(page("Up to", String::from("in its smallest units"), how_much));
            pages.push(page("Token", String::from("its contract"), contract.clone()));
        }
        Call::ApproveAll { operator, approved: true } => {
            pages.push(page("Approve all!", String::from("takes every item"), checksum(&operator)));
            pages.push(page("Collection", String::from("its contract"), contract.clone()));
        }
        Call::ApproveAll { operator, approved: false } => {
            pages.push(page("Revoke", String::from("no more access"), checksum(&operator)));
            pages.push(page("Collection", String::from("its contract"), contract.clone()));
        }
        Call::Unknown { selector, len } => {
            let hex: String = selector.iter().map(|b| format!("{:02x}", b)).collect();
            pages.push(page("Contract call", String::from("maki can't read it"), format!("{}\nfunction {}\n{} bytes", contract, hex, len)));
        }
    }
    pages.push(page(
        "Max fee",
        amount(max_fee, unit),
        format!("{} gas\n{} gwei", tx.gas_limit, gwei(tx.max_fee_per_gas)),
    ));
    let total = tx.value.checked_add(max_fee).ok_or(Error::Fee)?;
    Ok((pages, format!("up to {}", amount(total, unit))))
}

/// A message to sign, as the owner reads it: text if it's text, else hex.
pub fn message(message: &[u8]) -> Page {
    match core::str::from_utf8(message) {
        Ok(text) if !text.chars().any(|c| c.is_control() && c != '\n') => page("Message", String::new(), text.into()),
        _ => page("Message", String::from("in hex"), message.iter().map(|b| format!("{:02x}", b)).collect()),
    }
}
