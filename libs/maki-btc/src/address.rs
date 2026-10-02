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
}

impl Network {
    /// BIP44 coin type: 0 for bitcoin, 2 for litecoin, 1 for the test networks.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Bitcoin => 0,
            Network::Testnet | Network::LitecoinTest => 1,
            Network::Litecoin => 2,
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

    fn hrp(self) -> bech32::Hrp {
        match self {
            Network::Bitcoin => bech32::hrp::BC,
            Network::Testnet => bech32::hrp::TB,
            Network::Litecoin => bech32::Hrp::parse_unchecked("ltc"),
            Network::LitecoinTest => bech32::Hrp::parse_unchecked("tltc"),
        }
    }

    /// Whether it's a test network, whose coins are worth nothing.
    pub fn is_test(self) -> bool { matches!(self, Network::Testnet | Network::LitecoinTest) }

    /// The version bytes of a BIP84 account key: zpub, or vpub on test networks. Litecoin's
    /// wallets (Litecoin Core, Electrum-LTC) take Bitcoin's.
    pub fn zpub_version(self) -> [u8; 4] {
        if self.is_test() { [0x04, 0x5f, 0x1c, 0xf6] } else { [0x04, 0xb2, 0x47, 0x46] }
    }

    /// The version bytes of an account key as descriptors write it: xpub, or tpub.
    pub fn xpub_version(self) -> [u8; 4] {
        if self.is_test() { [0x04, 0x35, 0x87, 0xcf] } else { [0x04, 0x88, 0xb2, 0x1e] }
    }

    /// A pay-to-public-key-hash address's version byte (base58check).
    fn p2pkh_version(self) -> u8 {
        match self {
            Network::Bitcoin => 0x00,
            Network::Testnet | Network::LitecoinTest => 0x6f,
            Network::Litecoin => 0x30,
        }
    }

    /// A pay-to-script-hash address's version byte: Litecoin's own (`M…`, `Q…`), as its wallets
    /// show them, rather than the Bitcoin ones it also takes.
    fn p2sh_version(self) -> u8 {
        match self {
            Network::Bitcoin => 0x05,
            Network::Testnet => 0xc4,
            Network::Litecoin => 0x32,
            Network::LitecoinTest => 0x3a,
        }
    }

    /// The most there will ever be of its coin, in its smallest unit: no amount can be larger.
    pub fn max_money(self) -> u64 {
        match self {
            Network::Bitcoin | Network::Testnet => 21_000_000 * 100_000_000,
            Network::Litecoin | Network::LitecoinTest => 84_000_000 * 100_000_000,
        }
    }
}

/// The output script that pays a public key, native SegWit (P2WPKH).
pub fn p2wpkh_script(public_key: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(22);
    s.extend_from_slice(&[0x00, 0x14]);
    s.extend_from_slice(&hash160(public_key));
    s
}

pub fn p2wpkh_address(public_key: &[u8; 33], network: Network) -> String {
    address(&p2wpkh_script(public_key), network).expect("P2WPKH always has an address")
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
        // witness v0: P2WPKH (20 bytes) and P2WSH (32)
        [0x00, len @ (0x14 | 0x20), program @ ..] if program.len() == *len as usize => {
            bech32::segwit::encode(network.hrp(), bech32::segwit::VERSION_0, program).ok()
        }
        // witness v1, 32 bytes: taproot
        [0x51, 0x20, program @ ..] if program.len() == 32 => {
            bech32::segwit::encode(network.hrp(), bech32::segwit::VERSION_1, program).ok()
        }
        // P2PKH
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            Some(base58check(&[&[network.p2pkh_version()][..], hash].concat()))
        }
        // P2SH
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            Some(base58check(&[&[network.p2sh_version()][..], hash].concat()))
        }
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
