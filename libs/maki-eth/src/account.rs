//! The account: its key, its address, and signatures.

use alloc::format;
use alloc::string::String;

use k256::ecdsa::{RecoveryId, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use maki_btc::bip32::{Xpriv, HARDENED};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] { Keccak256::digest(data).into() }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Key,
    /// Account indexes stop short of the hardened range.
    Index,
}

/// Account `index`: `m/44'/60'/0'/0/index`.
#[derive(Clone)]
pub struct Account {
    pub index: u32,
    key: Xpriv,
    address: [u8; 20],
}

impl Account {
    pub fn from_seed(seed: &[u8], index: u32) -> Result<Account, Error> {
        if index >= HARDENED {
            return Err(Error::Index);
        }
        let master = Xpriv::master(seed).map_err(|_| Error::Key)?;
        let key = master.derive(&[44 | HARDENED, 60 | HARDENED, HARDENED, 0, index]).map_err(|_| Error::Key)?;
        let point = key.secret().public_key().to_encoded_point(false);
        let address = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
        Ok(Account { index, key, address })
    }

    /// An account from a bare private key, for tests and tools: maki's own come from the phrase.
    pub fn from_private_key(key: &[u8; 32]) -> Result<Account, Error> {
        // a BIP32 master whose key is this one: only its key is used
        let mut xpriv = Xpriv::master(&[0u8; 16]).map_err(|_| Error::Key)?;
        xpriv.set_secret(k256::SecretKey::from_slice(key).map_err(|_| Error::Key)?);
        let point = xpriv.secret().public_key().to_encoded_point(false);
        let address = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
        Ok(Account { index: 0, key: xpriv, address })
    }

    pub fn address(&self) -> [u8; 20] { self.address }

    /// The address as it's written: EIP-55.
    pub fn address_string(&self) -> String { checksum(&self.address) }

    /// A signature over a digest: r, s (low), and the recovery ID (0 or 1). Deterministic
    /// (RFC 6979).
    pub(crate) fn sign(&self, digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32], u8), Error> {
        let signer = SigningKey::from(self.key.secret());
        let (mut sig, mut recid) = signer.sign_prehash_recoverable(digest).map_err(|_| Error::Key)?;
        if let Some(low) = sig.normalize_s() {
            // the other s is the same point's other y
            sig = low;
            recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
        }
        let (r, s) = sig.split_bytes();
        Ok((r.into(), s.into(), recid.to_byte()))
    }

    /// EIP-191 `personal_sign`: r, s and v (27 or 28), 65 bytes.
    pub fn sign_message(&self, message: &[u8]) -> Result<[u8; 65], Error> {
        let (r, s, v) = self.sign(&message_hash(message))?;
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&r);
        out[32..64].copy_from_slice(&s);
        out[64] = 27 + v;
        Ok(out)
    }
}

/// What `personal_sign` signs: the message behind a prefix no transaction can start with.
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"\x19Ethereum Signed Message:\n");
    h.update(format!("{}", message.len()).as_bytes());
    h.update(message);
    h.finalize().into()
}

/// EIP-55: the address in hex, each letter upper-cased where the hash of the lower-case hex has
/// a nibble of 8 or more, a checksum typing mistakes rarely pass.
pub fn checksum(address: &[u8; 20]) -> String {
    let hex: String = address.iter().map(|b| format!("{:02x}", b)).collect();
    let hash = keccak256(hex.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in hex.chars().enumerate() {
        let nibble = (hash[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf;
        out.push(if c.is_ascii_alphabetic() && nibble >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}
