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
}

impl Network {
    /// BIP44 coin type: 0 for bitcoin, 1 for the test networks.
    pub fn coin_type(self) -> u32 {
        match self {
            Network::Bitcoin => 0,
            Network::Testnet => 1,
        }
    }

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
        }
    }

    /// The version bytes of a BIP84 account key: zpub, or vpub on test networks.
    pub fn zpub_version(self) -> [u8; 4] {
        match self {
            Network::Bitcoin => [0x04, 0xb2, 0x47, 0x46],
            Network::Testnet => [0x04, 0x5f, 0x1c, 0xf6],
        }
    }

    /// The version bytes of an account key as descriptors write it: xpub, or tpub.
    pub fn xpub_version(self) -> [u8; 4] {
        match self {
            Network::Bitcoin => [0x04, 0x88, 0xb2, 0x1e],
            Network::Testnet => [0x04, 0x35, 0x87, 0xcf],
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
            let version = if network == Network::Bitcoin { 0x00 } else { 0x6f };
            Some(base58check(&[&[version][..], hash].concat()))
        }
        // P2SH
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            let version = if network == Network::Bitcoin { 0x05 } else { 0xc4 };
            Some(base58check(&[&[version][..], hash].concat()))
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
