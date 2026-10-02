//! Zcash's transparent addresses: t-addresses, Bitcoin's base58check with a two-byte prefix
//! (`t1…` a key's hash, `t3…` a script's; `tm…` and `t2…` on the test network), and TEX addresses
//! (ZIP-320: a key's hash in bech32m, `tex1…`), for payees that take coins from transparent
//! transactions only, as exchanges ask.

use alloc::string::String;
use alloc::vec::Vec;

use bech32::Bech32m;
use bech32::primitives::decode::CheckedHrpstring;

use crate::Network;
use crate::hash::{hash160, sha256d};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A t-address's prefix for a key's hash (pay-to-key-hash).
fn p2pkh_prefix(network: Network) -> [u8; 2] {
    match network {
        Network::Mainnet => [0x1c, 0xb8],
        Network::Testnet => [0x1d, 0x25],
    }
}

/// A t-address's prefix for a script's hash (pay-to-script-hash).
fn p2sh_prefix(network: Network) -> [u8; 2] {
    match network {
        Network::Mainnet => [0x1c, 0xbd],
        Network::Testnet => [0x1c, 0xba],
    }
}

/// A TEX address's human-readable part (ZIP-320).
fn tex_hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "tex",
        Network::Testnet => "textest",
    }
}

/// `payload` and the first four bytes of its double SHA-256, in base58.
pub fn base58check(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&sha256d(payload)[..4]);
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base 256 to base 58, least significant digit first
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    out
}

/// Base58check's payload, if `text` is base58 (and no longer than any address) and its checksum
/// holds.
pub fn from_base58check(text: &str) -> Option<Vec<u8>> {
    if text.len() > 64 {
        return None;
    }
    let zeros = text.bytes().take_while(|&b| b == b'1').count();
    // base 58 to base 256, least significant byte first
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes() {
        let mut carry = ALPHABET.iter().position(|&a| a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut data = alloc::vec![0u8; zeros];
    data.extend(bytes.iter().rev());
    if data.len() < 4 {
        return None;
    }
    let (payload, check) = data.split_at(data.len() - 4);
    (sha256d(payload)[..4] == *check).then(|| payload.to_vec())
}

/// The output script that pays a key's hash (P2PKH), as this wallet's coins pay its keys.
pub fn p2pkh_script(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[0x76, 0xa9, 0x14]);
    s.extend_from_slice(hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// The script a key's coins pay: its hash's P2PKH.
pub fn key_script(key: &[u8; 33]) -> Vec<u8> { p2pkh_script(&hash160(key)) }

/// The key's hash a P2PKH script pays, if it is one.
pub fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    match script {
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] => hash.try_into().ok(),
        _ => None,
    }
}

/// The script's hash a P2SH script pays, if it is one.
pub fn p2sh_hash(script: &[u8]) -> Option<[u8; 20]> {
    match script {
        [0xa9, 0x14, hash @ .., 0x87] => hash.try_into().ok(),
        _ => None,
    }
}

/// A key's t-address: `t1…`, `tm…` on the test network.
pub fn of_key(network: Network, key: &[u8; 33]) -> String { p2pkh(network, &hash160(key)) }

/// The t-address of a key's hash.
pub fn p2pkh(network: Network, hash: &[u8; 20]) -> String {
    base58check(&[&p2pkh_prefix(network)[..], hash].concat())
}

/// The t-address of a script's hash: `t3…`, `t2…` on the test network.
pub fn p2sh(network: Network, hash: &[u8; 20]) -> String {
    base58check(&[&p2sh_prefix(network)[..], hash].concat())
}

/// The TEX address of a key's hash (ZIP-320): `tex1…`, `textest1…` on the test network.
pub fn tex(network: Network, hash: &[u8; 20]) -> String {
    let hrp = bech32::Hrp::parse_unchecked(tex_hrp(network));
    // 20 bytes, well inside what bech32m encodes
    bech32::encode::<Bech32m>(hrp, hash).unwrap_or_default()
}

/// The address an output script pays, or None for a script that has none (data, or something
/// else).
pub fn of_script(network: Network, script: &[u8]) -> Option<String> {
    if let Some(hash) = p2pkh_hash(script) {
        return Some(p2pkh(network, &hash));
    }
    p2sh_hash(script).map(|hash| p2sh(network, &hash))
}

/// What an address names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A key's hash: a t-address (`t1…`).
    PublicKeyHash([u8; 20]),
    /// A script's hash: a t-address (`t3…`).
    ScriptHash([u8; 20]),
    /// A key's hash, for transparent coins only: a TEX address (`tex1…`).
    Tex([u8; 20]),
}

impl Kind {
    /// The output script that pays it.
    pub fn script(&self) -> Vec<u8> {
        match self {
            Kind::PublicKeyHash(hash) | Kind::Tex(hash) => p2pkh_script(hash),
            Kind::ScriptHash(hash) => {
                let mut s = Vec::with_capacity(23);
                s.extend_from_slice(&[0xa9, 0x14]);
                s.extend_from_slice(hash);
                s.push(0x87);
                s
            }
        }
    }
}

/// An address, read strictly: a t-address (its checksum, its length, a prefix one of Zcash's
/// networks has) or a TEX address (bech32m alone, all in one case, `tex` or `textest`, 20 bytes).
/// Its network, and what it names.
pub fn decode(text: &str) -> Option<(Network, Kind)> {
    if let Some(payload) = from_base58check(text) {
        let (prefix, hash) = payload.split_at_checked(2)?;
        let hash: [u8; 20] = hash.try_into().ok()?;
        for network in [Network::Mainnet, Network::Testnet] {
            if prefix == p2pkh_prefix(network) {
                return Some((network, Kind::PublicKeyHash(hash)));
            }
            if prefix == p2sh_prefix(network) {
                return Some((network, Kind::ScriptHash(hash)));
            }
        }
        return None;
    }
    // (all in one case, which bech32's reader holds it to)
    let checked = CheckedHrpstring::new::<Bech32m>(text).ok()?;
    let network = match checked.hrp().to_lowercase().as_str() {
        "tex" => Network::Mainnet,
        "textest" => Network::Testnet,
        _ => return None,
    };
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let hash: [u8; 20] = bytes.as_slice().try_into().ok()?;
    // and spelled as its 20 bytes spell it: no bits left over, none set in the padding
    (tex(network, &hash) == text.to_ascii_lowercase()).then_some((network, Kind::Tex(hash)))
}
