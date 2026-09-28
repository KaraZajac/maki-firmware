//! An account's keys, as Ledger's Monero app makes them from the recovery phrase: the BIP32 key
//! at `m/44'/128'/account'/0/0` (secp256k1) hashed to the spend key, and that hashed to the view
//! key, as every Monero wallet makes a view key from a spend key. So the phrase gives the same
//! wallet on a Ledger, and the spend key's 25 words give it in any Monero wallet.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::keccak;

/// Monero's hash to a scalar: Keccak-256, reduced.
fn hash_to_scalar(data: &[u8]) -> Scalar { Scalar::from_bytes_mod_order(keccak(data)) }

/// An account's secret keys. Kept by maki-keys alone; gone from memory when dropped.
pub struct Keys {
    spend: Scalar,
    view: Scalar,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.spend.zeroize();
        self.view.zeroize();
    }
}

impl Keys {
    /// From the BIP32 private key at `m/44'/128'/account'/0/0`.
    pub fn from_bip32(key: &[u8; 32]) -> Keys { Keys::from_spend(hash_to_scalar(key)) }

    /// From a spend key, the view key made from it.
    pub fn from_spend(spend: Scalar) -> Keys {
        let view = hash_to_scalar(spend.as_bytes());
        Keys { spend, view }
    }

    /// The public spend and view keys: the account's own address's.
    pub fn public(&self) -> ([u8; 32], [u8; 32]) {
        (point(&self.spend).compress().to_bytes(), point(&self.view).compress().to_bytes())
    }

    /// Subaddress `minor` of account `major`: its public spend and view keys. Account 0's
    /// address 0 is the account's own address (`public`); every other is made from the view key,
    /// so only who holds it can tell they're the same wallet's.
    pub fn subaddress(&self, major: u32, minor: u32) -> ([u8; 32], [u8; 32]) {
        if (major, minor) == (0, 0) {
            return self.public();
        }
        let mut data = [0u8; 8 + 32 + 8];
        data[..8].copy_from_slice(b"SubAddr\0");
        data[8..40].copy_from_slice(self.view.as_bytes());
        data[40..44].copy_from_slice(&major.to_le_bytes());
        data[44..].copy_from_slice(&minor.to_le_bytes());
        let mut m = hash_to_scalar(&data);
        data.zeroize();
        let spend = point(&self.spend) + point(&m);
        m.zeroize();
        let view = self.view * spend;
        (spend.compress().to_bytes(), view.compress().to_bytes())
    }

    /// The spend key's 25 words: the backup Monero wallets restore from.
    pub fn words(&self) -> [&'static str; 25] { crate::words::encode(self.spend.as_bytes()) }

    /// The spend key, as 32 bytes (for the words, and tests).
    pub fn spend_bytes(&self) -> [u8; 32] { self.spend.to_bytes() }

    /// The view key, as 32 bytes.
    pub fn view_bytes(&self) -> [u8; 32] { self.view.to_bytes() }
}

fn point(s: &Scalar) -> EdwardsPoint { ED25519_BASEPOINT_POINT * s }
