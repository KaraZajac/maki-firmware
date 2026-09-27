//! BIP32: extended private keys, derivation, and the account key shared with wallet software.

use alloc::string::String;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{PublicKey, Scalar, SecretKey};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::hash::{hash160, sha256d};

pub const HARDENED: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key that falls outside the curve's order: BIP32 says to skip to the next index. With
    /// odds below 2^-127, maki doesn't try; it refuses.
    InvalidKey,
}

#[derive(Clone)]
pub struct Xpriv {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    key: SecretKey,
    /// the public key, compressed: made once, since a curve multiplication is what costs on
    /// maki's core
    public: [u8; 33],
}

fn public_of(key: &SecretKey) -> [u8; 33] {
    let point = key.public_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
}

type HmacSha512 = Hmac<Sha512>;

fn hmac512(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

impl Xpriv {
    /// The master key from a BIP39 seed.
    pub fn master(seed: &[u8]) -> Result<Xpriv, Error> {
        let mut i = hmac512(b"Bitcoin seed", &[seed]);
        let key = SecretKey::from_slice(&i[..32]).map_err(|_| Error::InvalidKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        i.zeroize();
        let public = public_of(&key);
        Ok(Xpriv { depth: 0, parent_fingerprint: [0; 4], child_number: 0, chain_code, key, public })
    }

    pub fn public_key(&self) -> [u8; 33] { self.public }

    pub fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public_key());
        [h[0], h[1], h[2], h[3]]
    }

    /// The child at `index` (at or above `HARDENED` for a hardened one).
    pub fn child(&self, index: u32) -> Result<Xpriv, Error> {
        let mut secret = self.key.to_bytes();
        let i = if index >= HARDENED {
            hmac512(&self.chain_code, &[&[0u8], &secret, &index.to_be_bytes()])
        } else {
            hmac512(&self.chain_code, &[&self.public, &index.to_be_bytes()])
        };
        secret.zeroize();
        let mut il = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        let tweak: Option<Scalar> = Scalar::from_repr(il.into()).into();
        il.zeroize();
        let tweak = tweak.ok_or(Error::InvalidKey)?;
        let child_scalar = tweak + *self.key.to_nonzero_scalar();
        let key = SecretKey::from_bytes(&child_scalar.to_bytes()).map_err(|_| Error::InvalidKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        let public = public_of(&key);
        Ok(Xpriv {
            depth: self.depth.checked_add(1).ok_or(Error::InvalidKey)?,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code,
            key,
            public,
        })
    }

    pub fn derive(&self, path: &[u32]) -> Result<Xpriv, Error> {
        let mut k = self.clone();
        for &i in path {
            k = k.child(i)?;
        }
        Ok(k)
    }

    /// The extended public key, base58check with the given version bytes: `xpub`
    /// (0488b21e), `zpub` (04b24746) for BIP84, `tpub`/`vpub` on testnet.
    pub fn xpub(&self, version: [u8; 4]) -> String {
        let mut data = Vec::with_capacity(82);
        data.extend_from_slice(&version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_number.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&self.public_key());
        base58check(&data)
    }

    /// The private key, to sign with: this crate's wallet, and other chains' (maki-eth).
    pub fn secret(&self) -> &SecretKey { &self.key }

    /// Replace the key (for maki-eth's accounts from a bare key, in tests). The chain code and
    /// the rest stay as they were.
    pub fn set_secret(&mut self, key: SecretKey) {
        self.public = public_of(&key);
        self.key = key;
    }
}

/// A public key from a compressed encoding, if it's on the curve.
pub fn parse_public_key(bytes: &[u8]) -> Option<PublicKey> { PublicKey::from_sec1_bytes(bytes).ok() }

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
