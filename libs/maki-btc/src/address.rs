//! Addresses: how maki writes an output's script so the owner can check it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::bip32::base58check;
use crate::hash::hash160;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    /// testnet and signet: the same addresses
    Testnet,
    /// Litecoin: Bitcoin's transactions, signatures and PSBTs, with addresses of its own
    /// (`ltc1…`, `L…`, `M…`).
    Litecoin,
    /// Litecoin's test network (`tltc1…`).
    LitecoinTest,
    /// Dogecoin: Bitcoin's transactions before SegWit, which it never took: pay-to-key-hash
    /// addresses (`D…`), signed the old way.
    Dogecoin,
    /// Dogecoin's test network (`n…`).
    DogecoinTest,
    /// Bitcoin Cash: no SegWit either; its signatures commit to the amount spent, BIP143's way,
    /// with its own fork ID, and its addresses are CashAddr (`bitcoincash:q…`).
    BitcoinCash,
    /// Bitcoin Cash's test network (`bchtest:q…`).
    BitcoinCashTest,
    /// Dash: Bitcoin's transactions before SegWit, which it never took, with special transactions
    /// of its own (DIP-2: masternodes, Dash Platform): pay-to-key-hash addresses (`X…`, P2SH
    /// `7…`), signed the old way.
    Dash,
    /// Dash's test network (`y…`).
    DashTest,
    /// DigiByte: Bitcoin's transactions, SegWit and taproot among them, with addresses of its own
    /// (`dgb1…`, `D…`, P2SH `S…`), and DigiDollar's (2026), which maki can't show.
    DigiByte,
    /// DigiByte's test network (`dgbt1…`, `s…`).
    DigiByteTest,
}

impl Network {
    /// BIP44 coin type: 0 for bitcoin, 2 for litecoin, 3 for dogecoin, 5 for dash, 20 for
    /// digibyte, 145 for bitcoin cash, 1 for the test networks.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Bitcoin => 0,
            Network::Testnet
            | Network::LitecoinTest
            | Network::DogecoinTest
            | Network::BitcoinCashTest
            | Network::DashTest
            | Network::DigiByteTest => 1,
            Network::Litecoin => 2,
            Network::Dogecoin => 3,
            Network::Dash => 5,
            Network::DigiByte => 20,
            Network::BitcoinCash => 145,
        }
    }

    /// Bitcoin's network for a coin type: 0, or 1 for its test networks.
    pub fn from_coin_type(coin: u32) -> Option<Network> {
        match coin {
            0 => Some(Network::Bitcoin),
            1 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// SegWit's address prefix (bech32), on the networks that have SegWit.
    fn hrp(self) -> Option<bech32::Hrp> {
        match self {
            Network::Bitcoin => Some(bech32::hrp::BC),
            Network::Testnet => Some(bech32::hrp::TB),
            Network::Litecoin => Some(bech32::Hrp::parse_unchecked("ltc")),
            Network::LitecoinTest => Some(bech32::Hrp::parse_unchecked("tltc")),
            Network::DigiByte => Some(bech32::Hrp::parse_unchecked("dgb")),
            Network::DigiByteTest => Some(bech32::Hrp::parse_unchecked("dgbt")),
            _ => None,
        }
    }

    /// Whether it's a test network, whose coins are worth nothing.
    pub fn is_test(self) -> bool {
        matches!(
            self,
            Network::Testnet
                | Network::LitecoinTest
                | Network::DogecoinTest
                | Network::BitcoinCashTest
                | Network::DashTest
                | Network::DigiByteTest
        )
    }

    /// Whether its coins are spent with SegWit and taproot (Bitcoin, Litecoin, DigiByte), or the
    /// old way, to a key's hash (Dogecoin, Bitcoin Cash, Dash).
    pub fn has_segwit(self) -> bool { self.hrp().is_some() }

    /// Whether it's Bitcoin Cash's, whose signatures carry its fork ID (SIGHASH_FORKID).
    pub fn is_bitcoin_cash(self) -> bool { matches!(self, Network::BitcoinCash | Network::BitcoinCashTest) }

    /// Whether it's Dash's, whose transactions are its own (DIP-2): a version's top 16 bits are
    /// a special transaction's type, and from version 3 a special transaction carries a payload.
    pub fn is_dash(self) -> bool { matches!(self, Network::Dash | Network::DashTest) }

    /// Whether it's DigiByte's, which has DigiDollar's transactions beside Bitcoin's.
    pub fn is_digibyte(self) -> bool { matches!(self, Network::DigiByte | Network::DigiByteTest) }

    /// The version bytes of a BIP84 account key: zpub, or vpub on test networks. Litecoin's
    /// wallets (Litecoin Core, Electrum-LTC) take Bitcoin's.
    pub fn zpub_version(self) -> [u8; 4] {
        if self.is_test() { [0x04, 0x5f, 0x1c, 0xf6] } else { [0x04, 0xb2, 0x47, 0x46] }
    }

    /// The version bytes of an account key as descriptors write it: xpub, or tpub. (Dogecoin Core
    /// has its own, `dgub`; maki's descriptors are for maki desktop, which reads them as xpubs.)
    pub fn xpub_version(self) -> [u8; 4] {
        if self.is_test() { [0x04, 0x35, 0x87, 0xcf] } else { [0x04, 0x88, 0xb2, 0x1e] }
    }

    /// A pay-to-public-key-hash address's version byte (base58check).
    fn p2pkh_version(self) -> u8 {
        match self {
            Network::Bitcoin | Network::BitcoinCash => 0x00,
            Network::Testnet | Network::LitecoinTest | Network::BitcoinCashTest => 0x6f,
            Network::Litecoin => 0x30,
            Network::Dogecoin | Network::DigiByte => 0x1e,
            Network::DogecoinTest => 0x71,
            Network::Dash => 0x4c,
            Network::DashTest => 0x8c,
            Network::DigiByteTest => 0x7e,
        }
    }

    /// A pay-to-script-hash address's version byte: Litecoin's own (`M…`, `Q…`) and DigiByte's
    /// (`S…`), as their wallets show them, rather than the Bitcoin ones they also take.
    fn p2sh_version(self) -> u8 {
        match self {
            Network::Bitcoin | Network::BitcoinCash => 0x05,
            Network::Testnet | Network::DogecoinTest | Network::BitcoinCashTest => 0xc4,
            Network::Litecoin => 0x32,
            Network::LitecoinTest => 0x3a,
            Network::Dogecoin => 0x16,
            Network::Dash => 0x10,
            Network::DashTest => 0x13,
            Network::DigiByte => 0x3f,
            Network::DigiByteTest => 0x8c,
        }
    }

    /// CashAddr's prefix, on Bitcoin Cash's networks.
    fn cashaddr_prefix(self) -> Option<&'static str> {
        match self {
            Network::BitcoinCash => Some("bitcoincash"),
            Network::BitcoinCashTest => Some("bchtest"),
            _ => None,
        }
    }

    /// The most there will ever be of its coin, in its smallest unit: no amount can be larger.
    /// Dogecoin has no cap; Dogecoin Core's sanity limit is ten billion. Dash Core's is Bitcoin's
    /// 21 million (Dash's own supply stops short of it), DigiByte's 21 billion.
    pub fn max_money(self) -> u64 {
        match self {
            Network::Bitcoin
            | Network::Testnet
            | Network::BitcoinCash
            | Network::BitcoinCashTest
            | Network::Dash
            | Network::DashTest => 21_000_000 * 100_000_000,
            Network::Litecoin | Network::LitecoinTest => 84_000_000 * 100_000_000,
            Network::Dogecoin | Network::DogecoinTest => 10_000_000_000 * 100_000_000,
            Network::DigiByte | Network::DigiByteTest => 21_000_000_000 * 100_000_000,
        }
    }
}

/// The output script that pays a public key's hash (P2PKH), as Dogecoin, Bitcoin Cash and Dash
/// pay their accounts (and DigiByte its legacy one).
pub fn p2pkh_script(public_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(&hash160(public_key));
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// CashAddr (Bitcoin Cash's spec): the prefix, then a version byte (the kind: 0 P2PKH, 1 P2SH;
/// the size: 0 for 160 bits) and the hash in five-bit groups, then a 40-bit BCH checksum over the
/// prefix (its low five bits each), a zero and the groups.
pub fn cashaddr(prefix: &str, kind: u8, hash: &[u8; 20]) -> String {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn polymod(values: &[u8]) -> u64 {
        const GENERATOR: [u64; 5] = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470];
        let mut c: u64 = 1;
        for &d in values {
            let c0 = (c >> 35) as u8;
            c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64;
            for (i, g) in GENERATOR.iter().enumerate() {
                if c0 & (1 << i) != 0 {
                    c ^= g;
                }
            }
        }
        c ^ 1
    }
    let mut payload = Vec::with_capacity(21);
    payload.push(kind << 3);
    payload.extend_from_slice(hash);
    // eight bits at a time into five, the last group padded with zeros
    let mut groups = Vec::with_capacity(34);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in &payload {
        acc = acc << 8 | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            groups.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        groups.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut check: Vec<u8> = prefix.bytes().map(|b| b & 31).collect();
    check.push(0);
    check.extend_from_slice(&groups);
    check.extend_from_slice(&[0; 8]);
    let sum = polymod(&check);
    let mut out = String::with_capacity(prefix.len() + 1 + groups.len() + 8);
    out.push_str(prefix);
    out.push(':');
    for &g in &groups {
        out.push(CHARSET[g as usize] as char);
    }
    for i in 0..8 {
        out.push(CHARSET[(sum >> (5 * (7 - i)) & 31) as usize] as char);
    }
    out
}

/// The output script that pays a public key, native SegWit (P2WPKH).
pub fn p2wpkh_script(public_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(22);
    s.extend_from_slice(&[0x00, 0x14]);
    s.extend_from_slice(&hash160(public_key));
    s
}

/// A key's native SegWit address, on a network with SegWit (none on Dogecoin, Bitcoin Cash or
/// Dash).
pub fn p2wpkh_address(public_key: &[u8; 33], network: Network) -> Option<String> {
    address(&p2wpkh_script(public_key), network)
}

/// The output script that pays a taproot output key (P2TR): witness v1, the key's x.
pub fn p2tr_script(output_key: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.extend_from_slice(&[0x51, 0x20]);
    s.extend_from_slice(output_key);
    s
}

/// The address an output script pays, or None for a script with no standard address (shown to
/// the owner as raw script instead).
pub fn address(script: &[u8], network: Network) -> Option<String> {
    match script {
        // witness v0: P2WPKH (20 bytes) and P2WSH (32), where there's SegWit
        [0x00, len @ (0x14 | 0x20), program @ ..] if program.len() == *len as usize => {
            bech32::segwit::encode(network.hrp()?, bech32::segwit::VERSION_0, program).ok()
        }
        // witness v1, 32 bytes: taproot
        [0x51, 0x20, program @ ..] if program.len() == 32 => {
            bech32::segwit::encode(network.hrp()?, bech32::segwit::VERSION_1, program).ok()
        }
        // P2PKH: CashAddr on Bitcoin Cash, base58check elsewhere
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            Some(match network.cashaddr_prefix() {
                Some(prefix) => cashaddr(prefix, 0, hash.try_into().unwrap()),
                None => base58check(&[&[network.p2pkh_version()][..], hash].concat()),
            })
        }
        // P2SH
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => Some(match network.cashaddr_prefix() {
            Some(prefix) => cashaddr(prefix, 1, hash.try_into().unwrap()),
            None => base58check(&[&[network.p2sh_version()][..], hash].concat()),
        }),
        _ => None,
    }
}

/// An output's destination, as the owner sees it: its address, or its script in hex.
pub fn describe(script: &[u8], network: Network) -> String {
    match address(script, network) {
        Some(a) => a,
        None if script.first() == Some(&0x6a) => String::from("data (OP_RETURN), unspendable"),
        None => {
            let hex: String = script.iter().map(|b| format!("{:02x}", b)).collect();
            format!("script {}", hex)
        }
    }
}
