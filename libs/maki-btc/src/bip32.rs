//! BIP32's extended public key, as wallet software takes an account (the keys themselves are
//! maki's: `maki_hd`).

use alloc::string::String;
use alloc::vec::Vec;

pub use maki_hd::HARDENED;
use maki_hd::Public;

use crate::hash::sha256d;

/// An extended public key, base58check with the given version bytes: `xpub` (0488b21e), `zpub`
/// (04b24746) for BIP84, `tpub`/`vpub` on test networks; `depth` and `child_number` are where
/// `public` is.
pub fn xpub(version: [u8; 4], depth: u8, child_number: u32, public: &Public) -> String {
    let mut data = Vec::with_capacity(82);
    data.extend_from_slice(&version);
    data.push(depth);
    data.extend_from_slice(&public.parent_fingerprint);
    data.extend_from_slice(&child_number.to_be_bytes());
    data.extend_from_slice(&public.chain_code);
    data.extend_from_slice(&public.key);
    base58check(&data)
}

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 with a 4-byte double-SHA-256 checksum, as xpubs and legacy addresses are written.
pub fn base58check(payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend_from_slice(&sha256d(payload)[..4]);
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // base 256 to base 58
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

/// Base58check's payload, if the checksum holds.
pub fn from_base58check(text: &str) -> Option<Vec<u8>> {
    let zeros = text.bytes().take_while(|&b| b == b'1').count();
    // base 58 to base 256
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

/// Public key versions (SLIP-132's with BIP32's): the network each is for. Which script type a
/// wallet meant by one (a Zpub's P2WSH multisig) doesn't matter here: the descriptor says.
const PUBLIC_VERSIONS: [([u8; 4], crate::Network); 10] = {
    use crate::Network::{Bitcoin, Testnet};
    [
        ([0x04, 0x88, 0xb2, 0x1e], Bitcoin), // xpub
        ([0x04, 0x9d, 0x7c, 0xb2], Bitcoin), // ypub
        ([0x04, 0xb2, 0x47, 0x46], Bitcoin), // zpub
        ([0x02, 0x95, 0xb4, 0x3f], Bitcoin), // Ypub
        ([0x02, 0xaa, 0x7e, 0xd3], Bitcoin), // Zpub
        ([0x04, 0x35, 0x87, 0xcf], Testnet), // tpub
        ([0x04, 0x4a, 0x52, 0x62], Testnet), // upub
        ([0x04, 0x5f, 0x1c, 0xf6], Testnet), // vpub
        ([0x02, 0x42, 0x89, 0xef], Testnet), // Upub
        ([0x02, 0x57, 0x54, 0x83], Testnet), // Vpub
    ]
};

/// The version bytes of a P2WSH multisig key as SLIP-132 writes it, which Sparrow and Coldcard
/// take a cosigner's key in: Zpub, or Vpub on test networks.
pub fn multisig_version(network: crate::Network) -> [u8; 4] {
    match network {
        crate::Network::Bitcoin => [0x02, 0xaa, 0x7e, 0xd3],
        crate::Network::Testnet => [0x02, 0x57, 0x54, 0x83],
    }
}

/// An extended public key, someone else's: an account of another wallet's, as its xpub says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xpub {
    pub network: crate::Network,
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    /// compressed, and on the curve
    pub key: [u8; 33],
}

impl Xpub {
    /// An xpub (tpub, zpub, Zpub, …): None if it isn't one, or its key isn't a point.
    pub fn parse(text: &str) -> Option<Xpub> {
        let data = from_base58check(text)?;
        if data.len() != 78 {
            return None;
        }
        let network = PUBLIC_VERSIONS.iter().find(|(v, _)| data[..4] == *v)?.1;
        let key: [u8; 33] = data[45..78].try_into().ok()?;
        k256::PublicKey::from_sec1_bytes(&key).ok()?;
        Some(Xpub {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9].try_into().ok()?,
            child_number: u32::from_be_bytes(data[9..13].try_into().ok()?),
            chain_code: data[13..45].try_into().ok()?,
            key,
        })
    }

    /// Written with `version`'s bytes.
    pub fn encode(&self, version: [u8; 4]) -> String {
        let public = Public {
            key: self.key,
            chain_code: self.chain_code,
            parent_fingerprint: self.parent_fingerprint,
        };
        xpub(version, self.depth, self.child_number, &public)
    }

    /// Its own fingerprint: the first four bytes of its key's HASH160.
    pub fn fingerprint(&self) -> [u8; 4] { crate::hash::hash160(&self.key)[..4].try_into().unwrap() }

    /// BIP32's public derivation (CKDpub) of child `index`, which can't be hardened: None in the
    /// 2^-127 case that it's no key.
    pub fn child(&self, index: u32) -> Option<Xpub> {
        use hmac::{Hmac, Mac};
        use k256::elliptic_curve::PrimeField;
        use k256::elliptic_curve::group::prime::PrimeCurveAffine;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        if index >= HARDENED || self.depth == u8::MAX {
            return None;
        }
        let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&self.chain_code).ok()?;
        mac.update(&self.key);
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let tweak: k256::Scalar =
            Option::from(k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&i[..32])))?;
        let parent = k256::PublicKey::from_sec1_bytes(&self.key).ok()?;
        let child = (k256::ProjectivePoint::GENERATOR * tweak + parent.to_projective()).to_affine();
        if bool::from(child.is_identity()) {
            return None;
        }
        Some(Xpub {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: i[32..].try_into().ok()?,
            key: child.to_encoded_point(true).as_bytes().try_into().ok()?,
        })
    }
}
