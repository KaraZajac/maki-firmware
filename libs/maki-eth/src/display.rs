//! What maki's screen says about a transaction or a message: shared by the firmware and the fake
//! maki, so both say the same thing.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::account::checksum;
use crate::json::Value;
use crate::tokens;
use crate::tx::{Error, Tx};
use crate::typed::{self, TypedData};

/// A screen's worth: a heading at the top, the thing to check in bold, fixed-width text under it
/// across as many lines as it takes, and prose (small words, wrapped) for what it means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub heading: String,
    pub value: String,
    pub mono: String,
    pub prose: String,
}

fn page(heading: &str, value: String, mono: String) -> Page {
    Page { heading: heading.into(), value, mono, prose: String::new() }
}

/// A network maki knows by name: what maki calls it, the coin it counts in (its own, with 18
/// decimals in transactions, as every one here has), and whether it charges fees outside the gas.
pub struct Network {
    pub chain_id: u64,
    pub name: &'static str,
    pub unit: &'static str,
    /// An OP Stack chain's: on top of the gas, an L1 data fee for posting the transaction to
    /// Ethereum, and an operator fee, both at rates the network sets when the transaction goes
    /// in. Nothing in a transaction caps them ("It is currently not possible to limit the
    /// maximum L1 Data Fee that a transaction is willing to pay": docs.optimism.io, Transaction
    /// fees), so maki can say the most the gas costs there, not the most the fee is. Celo is an
    /// OP Stack chain that sets both to zero, always (docs.celo.org, Transaction fees), and isn't
    /// one of these.
    pub fees_outside_gas: bool,
}

const fn net(chain_id: u64, name: &'static str, unit: &'static str, fees_outside_gas: bool) -> Network {
    Network { chain_id, name, unit, fees_outside_gas }
}

/// The networks maki knows, each checked on 2026-10-02 against the chain's own documentation and
/// against chainlist's source (github.com/ethereum-lists/chains, `_data/chains/eip155-<id>.json`),
/// and asked for its chain ID (`eth_chainId`). Every one takes the transactions maki signs
/// (EIP-1559, and legacy ones with EIP-155's chain ID) and counts its coin in 18 decimals. Whether
/// one charges fees outside the gas was read off its receipts (an `l1Fee`) and its fee oracle
/// (`getL1Fee`, `getOperatorFee` at 0x420…0F), and from its documentation. maki desktop knows
/// the same mainnets (desktop/src/shared/ethereum.ts), with their servers.
pub const NETWORKS: [Network; 25] = [
    net(1, "ethereum", "ETH", false),
    net(10, "optimism", "ETH", true),
    net(56, "bnb chain", "BNB", false),
    net(137, "polygon", "POL", false),
    net(8453, "base", "ETH", true),
    net(42161, "arbitrum", "ETH", false),
    // build.avax.network: the C-Chain, on chain ID 43114
    net(43114, "avalanche", "AVAX", false),
    // docs.robinhood.com/chain: an Arbitrum chain, whose L1 data fee is part of the gas
    net(4663, "robinhood chain", "ETH", false),
    // hyperliquid.gitbook.io, HyperEVM. Chainlist has 999 as Wanchain's test network, which also
    // answers to 999 (asked 2026-10-02): a signature for one is good on the other. maki names
    // HyperEVM, where a chain 999 transaction spends something of worth.
    net(999, "hyperevm", "HYPE", false),
    // docs.monad.xyz: it charges the gas limit, not the gas used: still at most the max fee
    net(143, "monad", "MON", false),
    // docs.mantle.xyz: since Arsia, the gas, an L1 data fee and an operator fee
    net(5000, "mantle", "MNT", true),
    // docs.plasma.org: total fee = gas used × gas price
    net(9745, "plasma", "XPL", false),
    // web3.okx.com, X Layer: an OP Stack chain. Its L1 and operator fees were zero on
    // 2026-10-02, but nothing published says they'll stay so
    net(196, "x layer", "OKB", true),
    // docs.arc.io: USDC is Arc's coin, with 18 decimals as a coin (and 6 as an ERC-20)
    net(5042, "arc", "USDC", false),
    // docs.world.org: "an L2 (execution) fee and an L1 (security) fee"
    net(480, "world chain", "ETH", true),
    // docs.inkonchain.com: an OP Stack chain
    net(57073, "ink", "ETH", true),
    // docs.linea.build: total fee = units of gas used × (base fee + priority fee)
    net(59144, "linea", "ETH", false),
    // docs.gnosischain.com: xDAI, a dollar, is its coin
    net(100, "gnosis", "xDAI", false),
    // docs.zksync.io: its own EIP-712 transactions (type 0x71) maki doesn't sign; EIP-1559 ones
    // pay for their data in the gas
    net(324, "zksync era", "ETH", false),
    // docs.celo.org: its L1 and operator fees are "configured to always be zero"
    net(42220, "celo", "CELO", false),
    // developers.uniswap.org/docs/unichain: an OP Stack chain
    net(130, "unichain", "ETH", true),
    net(11155111, "sepolia", "ETH", false),
    net(17000, "holesky", "ETH", false),
    // Holesky's successor as Ethereum's second test network (ethereum.org, Networks)
    net(560048, "hoodi", "ETH", false),
    net(84532, "base sepolia", "ETH", true),
];

/// The network with this chain ID, if maki knows it.
pub fn known_network(chain_id: u64) -> Option<&'static Network> {
    NETWORKS.iter().find(|n| n.chain_id == chain_id)
}

/// The networks maki knows by name, and the coin each counts in. Any other shows its chain ID,
/// and amounts in "coins": maki can't say which.
pub fn network(chain_id: u64) -> (String, &'static str) {
    match known_network(chain_id) {
        Some(n) => (n.name.into(), n.unit),
        None => (format!("chain {}", chain_id), "coins"),
    }
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
pub(crate) fn decimal(n: &[u8; 32]) -> String {
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
    Transfer {
        to: [u8; 20],
        amount: [u8; 32],
    },
    /// ERC-20 `approve(spender, amount)`: the spender may take up to the amount, later
    Approve {
        spender: [u8; 20],
        amount: [u8; 32],
    },
    /// ERC-721/1155 `setApprovalForAll(operator, approved)`: every item of the collection
    ApproveAll {
        operator: [u8; 20],
        approved: bool,
    },
    Unknown {
        selector: [u8; 4],
        len: usize,
    },
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
            ([0xa9, 0x05, 0x9c, 0xbb], Some(to)) => {
                return Call::Transfer { to, amount: b.try_into().unwrap() };
            }
            ([0x09, 0x5e, 0xa7, 0xb3], Some(spender)) => {
                return Call::Approve { spender, amount: b.try_into().unwrap() };
            }
            ([0xa2, 0x2c, 0xb4, 0x65], Some(operator)) if b[..31].iter().all(|&x| x == 0) && b[31] <= 1 => {
                return Call::ApproveAll { operator, approved: b[31] == 1 };
            }
            _ => {}
        }
    }
    Call::Unknown { selector, len: d.len() }
}

/// The token the transaction's contract is, if maki knows it on this network.
fn known(tx: &Tx) -> Option<&'static tokens::Token> {
    tx.to.as_ref().and_then(|to| tokens::known(tx.chain_id, to))
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
        Call::Deploy(len) => {
            pages.push(page("New contract", format!("{} bytes of code", len), String::new()))
        }
        Call::Transfer { to, amount } => match known(tx) {
            // a token maki knows by its contract: how much of it, in its own units
            Some(t) => {
                pages.push(page("Send tokens", tokens::amount(t, &amount), checksum(&to)));
                pages.push(page("Token", String::from(t.symbol), contract.clone()));
            }
            None => {
                pages.push(page("Send tokens", String::from("to"), checksum(&to)));
                pages.push(page("Token amount", String::from("in its smallest units"), decimal(&amount)));
                pages.push(page("Token", String::from("its contract"), contract.clone()));
            }
        },
        Call::Approve { spender, amount } => {
            let t = known(tx);
            let how_much = match t {
                _ if amount == [0xff; 32] => String::from("any amount"),
                Some(t) => tokens::amount(t, &amount),
                None => decimal(&amount),
            };
            pages.push(page("Approve!", String::from("lets it spend tokens"), checksum(&spender)));
            pages.push(page(
                "Up to",
                String::from(if t.is_some() { "of the token" } else { "in its smallest units" }),
                how_much,
            ));
            pages.push(page(
                "Token",
                String::from(t.map(|t| t.symbol).unwrap_or("its contract")),
                contract.clone(),
            ));
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
            pages.push(page(
                "Contract call",
                String::from("maki can't read it"),
                format!("{}\nfunction {}\n{} bytes", contract, hex, len),
            ));
        }
    }
    let gas = format!("{} gas\n{} gwei", tx.gas_limit, gwei(tx.max_fee_per_gas));
    let total = tx.value.checked_add(max_fee).ok_or(Error::Fee)?;
    if !known_network(tx.chain_id).is_some_and(|n| n.fees_outside_gas) {
        pages.push(page("Max fee", amount(max_fee, unit), gas));
        return Ok((pages, format!("up to {}", amount(total, unit))));
    }
    // the most the gas can cost; what the network adds on top, no one can say beforehand
    pages.push(page("Max gas fee", amount(max_fee, unit), gas));
    pages.push(Page {
        heading: String::from("L1 fee"),
        value: String::from("not capped"),
        mono: String::new(),
        prose: String::from(
            "This network can add fees on top of the gas: for putting the transaction on Ethereum, and \
             its operator's. It sets them when the transaction goes in, and nothing in a transaction \
             caps them.",
        ),
    });
    Ok((pages, format!("up to {} and L1 fees", amount(total, unit))))
}

/// A message to sign, as the owner reads it: text if it's text, else hex.
pub fn message(message: &[u8]) -> Page {
    match core::str::from_utf8(message) {
        Ok(text) if !text.chars().any(|c| c.is_control() && c != '\n') => {
            page("Message", String::new(), text.into())
        }
        _ => page("Message", String::from("in hex"), message.iter().map(|b| format!("{:02x}", b)).collect()),
    }
}

/// The site a Sign-In with Ethereum message (EIP-4361) is for: the host its first line names
/// (`example.com wants you to sign in with your Ethereum account:`), without a scheme or port.
/// None for any other message.
pub fn sign_in_site(message: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(message).ok()?;
    let first = text.lines().next()?;
    let authority = first.strip_suffix(" wants you to sign in with your Ethereum account:")?;
    let authority = authority.split_once("://").map(|(_, rest)| rest).unwrap_or(authority);
    // userinfo@host:port: the host is what matters
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The pages for a message from `site`: a warning first when it's a sign-in for another site
/// (the phishing that copies a real site's sign-in), then the message.
pub fn message_pages(site: &str, message_bytes: &[u8]) -> Vec<Page> {
    let mut pages = Vec::new();
    if let Some(other) = sign_in_site(message_bytes).filter(|s| s != site) {
        pages.push(page("Wrong site!", String::from("a sign-in for"), other));
    }
    pages.push(message(message_bytes));
    pages
}

/// The most pages typed data may take: more, and maki won't show it.
pub const MAX_TYPED_PAGES: usize = 48;

/// A Unix time, in seconds, as a UTC date and time: `2026-10-01 14:30 UTC`.
pub fn utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // days since 1970-01-01 to a date (Howard Hinnant's civil_from_days)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + (month <= 2) as i64;
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, rest / 3_600, rest % 3_600 / 60)
}

/// A deadline a permit gives, in seconds, for a page: the date, then the time (UTC), or "no end"
/// if it's the most the field holds or past the year 9999.
fn until(v: Option<&Value>, bits: u32) -> (String, String) {
    let Some(v) = v else { return (String::from("none given"), String::new()) };
    if typed::is_max(v, bits) {
        return (String::from("no end"), String::new());
    }
    match typed::integer_u64(v) {
        Some(s) if s < 253_402_300_800 => {
            let when = utc(s);
            let (date, time) = when.split_once(' ').unwrap_or((&when, ""));
            (String::from(date), String::from(time))
        }
        _ => (String::from("no end"), String::new()),
    }
}

fn address_text(v: Option<&Value>) -> String {
    match v.and_then(Value::as_str).and_then(typed::hex_bytes) {
        Some(b) if b.len() == 20 => checksum(&b.try_into().unwrap()),
        _ => String::from("none given"),
    }
}

/// A token amount a permit gives: "any amount" if it's the most the field holds.
fn allowance(v: Option<&Value>, bits: u32) -> String {
    match v {
        Some(v) if typed::is_max(v, bits) => String::from("any amount"),
        Some(v) => typed::integer_text(v).unwrap_or_default(),
        None => String::from("none given"),
    }
}

/// A permit's token, if maki knows its contract on the network the typed data names.
fn permit_token(td: &TypedData, contract: Option<&Value>) -> Option<&'static tokens::Token> {
    let bytes = contract.and_then(Value::as_str).and_then(typed::hex_bytes)?;
    tokens::known(td.chain_id()?, &bytes.try_into().ok()?)
}

/// How much a permit gives: "any amount", or so much of a token maki knows, or its smallest
/// units; and what that's in.
fn allowance_of(v: Option<&Value>, bits: u32, token: Option<&tokens::Token>) -> (String, String) {
    match (v, token) {
        (Some(v), _) if typed::is_max(v, bits) => (String::from("of the token"), String::from("any amount")),
        (Some(v), Some(t)) => match typed::integer_word(v) {
            Some(n) => (String::from("of the token"), tokens::amount(t, &n)),
            None => (String::from("in its smallest units"), allowance(Some(v), bits)),
        },
        _ => (String::from("in its smallest units"), allowance(v, bits)),
    }
}

/// A token's page: its symbol when maki knows it, and its contract either way.
fn token_page(heading: &str, contract: Option<&Value>, token: Option<&tokens::Token>) -> Page {
    page(heading, String::from(token.map(|t| t.symbol).unwrap_or("its contract")), address_text(contract))
}

/// Whether `name` is declared exactly so: these fields, of these types, in this order.
fn declared(td: &TypedData, name: &str, fields: &[(&str, &str)]) -> bool {
    td.fields(name).is_some_and(|f| {
        f.len() == fields.len() && f.iter().zip(fields).all(|(a, (n, t))| a.name == *n && a.ty == *t)
    })
}

const PERMIT: [(&str, &str); 5] = [
    ("owner", "address"),
    ("spender", "address"),
    ("value", "uint256"),
    ("nonce", "uint256"),
    ("deadline", "uint256"),
];
const PERMIT_DETAILS: [(&str, &str); 4] =
    [("token", "address"), ("amount", "uint160"), ("expiration", "uint48"), ("nonce", "uint48")];
const PERMIT_SINGLE: [(&str, &str); 3] =
    [("details", "PermitDetails"), ("spender", "address"), ("sigDeadline", "uint256")];
const PERMIT_BATCH: [(&str, &str); 3] =
    [("details", "PermitDetails[]"), ("spender", "address"), ("sigDeadline", "uint256")];
const TOKEN_PERMISSIONS: [(&str, &str); 2] = [("token", "address"), ("amount", "uint256")];
const PERMIT_TRANSFER: [(&str, &str); 4] = [
    ("permitted", "TokenPermissions"),
    ("spender", "address"),
    ("nonce", "uint256"),
    ("deadline", "uint256"),
];
const PERMIT_BATCH_TRANSFER: [(&str, &str); 4] = [
    ("permitted", "TokenPermissions[]"),
    ("spender", "address"),
    ("nonce", "uint256"),
    ("deadline", "uint256"),
];

/// A permit, spelled out: who may spend what, of which token, until when. Known by its types'
/// exact shape, not their names alone. None for anything else.
fn permit_pages(td: &TypedData) -> Option<Vec<Page>> {
    let m = &td.message;
    let spender = || address_text(m.get("spender"));
    let mut pages = Vec::new();
    match td.primary_type.as_str() {
        // EIP-2612: the token is the contract the domain names
        "Permit" if declared(td, "Permit", &PERMIT) => {
            let token = permit_token(td, td.domain.get("verifyingContract"));
            pages.push(page("Permit!", String::from("lets it spend tokens"), spender()));
            let (what, how_much) = allowance_of(m.get("value"), 256, token);
            pages.push(page("Up to", what, how_much));
            let (date, time) = until(m.get("deadline"), 256);
            pages.push(page("Until", date, time));
            pages.push(token_page("Token", td.domain.get("verifyingContract"), token));
        }
        // Uniswap's Permit2, allowances: for each token, how much and until when
        "PermitSingle" | "PermitBatch"
            if declared(td, "PermitDetails", &PERMIT_DETAILS)
                && (declared(td, "PermitSingle", &PERMIT_SINGLE)
                    || declared(td, "PermitBatch", &PERMIT_BATCH)) =>
        {
            pages.push(page("Permit!", String::from("lets it spend tokens"), spender()));
            let details: Vec<&Value> = match m.get("details")? {
                Value::Array(items) => items.iter().collect(),
                one => alloc::vec![one],
            };
            for (i, d) in details.iter().enumerate() {
                let n = if details.len() > 1 { format!(" {}", i + 1) } else { String::new() };
                let token = permit_token(td, d.get("token"));
                pages.push(token_page(&format!("Token{}", n), d.get("token"), token));
                let (what, how_much) = allowance_of(d.get("amount"), 160, token);
                pages.push(page(&format!("Up to{}", n), what, how_much));
                let (date, time) = match d.get("expiration").and_then(typed::integer_u64) {
                    // Permit2 takes 0 as the block it's used in
                    Some(0) => (String::from("its first use"), String::new()),
                    _ => until(d.get("expiration"), 48),
                };
                pages.push(page(&format!("Until{}", n), date, time));
            }
        }
        // Permit2, one-time transfers: it may take up to so much, once, before the deadline
        "PermitTransferFrom" | "PermitBatchTransferFrom"
            if declared(td, "TokenPermissions", &TOKEN_PERMISSIONS)
                && (declared(td, "PermitTransferFrom", &PERMIT_TRANSFER)
                    || declared(td, "PermitBatchTransferFrom", &PERMIT_BATCH_TRANSFER)) =>
        {
            pages.push(page("Transfer!", String::from("lets it take tokens"), spender()));
            let permitted: Vec<&Value> = match m.get("permitted")? {
                Value::Array(items) => items.iter().collect(),
                one => alloc::vec![one],
            };
            for (i, t) in permitted.iter().enumerate() {
                let n = if permitted.len() > 1 { format!(" {}", i + 1) } else { String::new() };
                let token = permit_token(td, t.get("token"));
                pages.push(token_page(&format!("Token{}", n), t.get("token"), token));
                let (what, how_much) = allowance_of(t.get("amount"), 256, token);
                pages.push(page(&format!("Up to{}", n), what, how_much));
            }
            let (date, time) = until(m.get("deadline"), 256);
            pages.push(page("Until", date, time));
        }
        _ => return None,
    }
    Some(pages)
}

/// Text as maki shows it: control characters (but new lines) as `\u{..}`.
fn shown_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() && c != '\n' { format!("\\u{{{:x}}}", c as u32) } else { String::from(c) })
        .collect()
}

/// A field's page: its path as the heading, what kind of value, and the value.
fn value_page(
    td: &TypedData,
    ty: &str,
    v: &Value,
    path: &str,
    pages: &mut Vec<Page>,
) -> Result<(), typed::Error> {
    if pages.len() > MAX_TYPED_PAGES {
        return Err(typed::Error::Shape(String::from("too much to show on maki")));
    }
    if let Some(open) = ty.rfind('[').filter(|_| ty.ends_with(']')) {
        let items = v.as_array().unwrap_or(&[]);
        if items.is_empty() {
            pages.push(page(path, String::from("an empty list"), String::new()));
        }
        for (i, item) in items.iter().enumerate() {
            value_page(td, &ty[..open], item, &format!("{}[{}]", path, i), pages)?;
        }
        return Ok(());
    }
    if td.fields(ty).is_some() {
        return match v {
            Value::Null => {
                pages.push(page(path, String::from("none"), String::new()));
                Ok(())
            }
            _ => struct_pages(td, ty, v, path, pages),
        };
    }
    let p = match ty {
        "address" => page(path, String::from("address"), address_text(Some(v))),
        "bool" => page(path, String::from(if *v == Value::Bool(true) { "yes" } else { "no" }), String::new()),
        "string" => page(path, String::from("text"), shown_text(v.as_str().unwrap_or(""))),
        _ if ty.starts_with("bytes") => {
            let bytes = v.as_str().and_then(typed::hex_bytes).unwrap_or_default();
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            page(path, format!("{} bytes", bytes.len()), hex)
        }
        _ => page(path, String::from("number"), typed::integer_text(v).unwrap_or_default()),
    };
    pages.push(p);
    Ok(())
}

fn struct_pages(
    td: &TypedData,
    ty: &str,
    v: &Value,
    path: &str,
    pages: &mut Vec<Page>,
) -> Result<(), typed::Error> {
    for f in td.fields(ty).unwrap_or(&[]) {
        let p = if path.is_empty() { f.name.clone() } else { format!("{}.{}", path, f.name) };
        value_page(td, &f.ty, v.get(&f.name).unwrap_or(&Value::Null), &p, pages)?;
    }
    Ok(())
}

/// Typed data (EIP-712) for the screen: the pages, then the ask's title and the line under it.
/// The network and the app it's for come first. A permit (EIP-2612, or Uniswap's Permit2) is
/// spelled out as what it lets someone do; anything else goes field by field, every one that's
/// signed.
pub fn typed_review(td: &TypedData) -> Result<(Vec<Page>, &'static str, &'static str), typed::Error> {
    let mut pages = Vec::new();
    match (td.chain_id(), td.domain.get("chainId")) {
        (Some(id), _) => {
            let (name, _) = network(id);
            pages.push(page("Network", name, format!("chain ID {}", id)));
        }
        (None, Some(v)) => {
            pages.push(page("Network", String::from("unknown"), typed::integer_text(v).unwrap_or_default()))
        }
        (None, None) => {}
    }
    let name = td.domain.get("name").and_then(Value::as_str).map(shown_text).unwrap_or_default();
    let mut about = String::new();
    if let Some(version) = td.domain.get("version").and_then(Value::as_str) {
        about.push_str(&format!("version {}\n", shown_text(version)));
    }
    about.push_str(&match td.domain.get("verifyingContract") {
        Some(c) => address_text(Some(c)),
        None => String::from("no contract named"),
    });
    pages.push(page("App", if name.is_empty() { String::from("unnamed") } else { name }, about));
    if let Some(permit) = permit_pages(td) {
        pages.extend(permit);
        return Ok((pages, "Sign permit?", "it can spend tokens"));
    }
    pages.push(page("Data", td.primary_type.clone(), String::new()));
    struct_pages(td, &td.primary_type, &td.message, "", &mut pages)?;
    if pages.len() > MAX_TYPED_PAGES {
        return Err(typed::Error::Shape(String::from("too much to show on maki")));
    }
    Ok((pages, "Sign data?", "apps may act on it"))
}
