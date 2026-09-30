//! The account: its key, its address, and signatures.

use alloc::format;
use alloc::string::String;

use maki_hd::{HARDENED, Keys};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] { Keccak256::digest(data).into() }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Key,
    /// Account indexes stop short of the hardened range.
    Index,
    /// maki couldn't make a key or a signature: it's locked, or said no.
    Keys(maki_hd::Error),
}

/// Where account `index` is: `m/44'/60'/0'/0/index`, as MetaMask and Ledger make it.
pub fn path(index: u32) -> [u32; 5] { [44 | HARDENED, 60 | HARDENED, HARDENED, 0, index] }

/// Account `index`: `m/44'/60'/0'/0/index`. Its key is maki's (`maki_hd::Keys`): the account asks
/// for its public key once, and for each signature.
#[derive(Clone)]
pub struct Account<'k> {
    pub index: u32,
    keys: &'k dyn Keys,
    address: [u8; 20],
}

impl<'k> Account<'k> {
    pub fn new(keys: &'k dyn Keys, index: u32) -> Result<Account<'k>, Error> {
        if index >= HARDENED {
            return Err(Error::Index);
        }
        let point = keys.uncompressed(&path(index)).map_err(Error::Keys)?;
        let address = keccak256(&point[1..])[12..].try_into().unwrap();
        Ok(Account { index, keys, address })
    }

    pub fn address(&self) -> [u8; 20] { self.address }

    /// The address as it's written: EIP-55.
    pub fn address_string(&self) -> String { checksum(&self.address) }

    /// A signature over a digest: r, s (low), and the recovery ID (0 or 1). Deterministic
    /// (RFC 6979); maki checks it before it's returned.
    pub(crate) fn sign(&self, digest: &[u8; 32]) -> Result<([u8; 32], [u8; 32], u8), Error> {
        let (sig, recid) = self.keys.sign_ecdsa(&path(self.index), digest).map_err(Error::Keys)?;
        Ok((sig[..32].try_into().unwrap(), sig[32..].try_into().unwrap(), recid))
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
