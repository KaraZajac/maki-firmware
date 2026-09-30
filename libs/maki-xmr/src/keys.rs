//! An account's keys, as Ledger's Monero app makes them from the recovery phrase: the BIP32 key
//! at `m/44'/128'/account'/0/0` (secp256k1) hashed to the spend key, and that hashed to the view
//! key, as every Monero wallet makes a view key from a spend key. So the phrase gives the same
//! wallet on a Ledger, and the spend key's 25 words give it in any Monero wallet.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::sign::{self, hash_to_scalar};

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
        let mut m = self.subaddress_scalar(major, minor);
        let spend = point(&self.spend) + point(&m);
        m.zeroize();
        let view = self.view * spend;
        (spend.compress().to_bytes(), view.compress().to_bytes())
    }

    /// Subaddress `minor` of account `major`'s public spend and view keys, as points.
    pub(crate) fn subaddress_points(&self, major: u32, minor: u32) -> (EdwardsPoint, EdwardsPoint) {
        if (major, minor) == (0, 0) {
            return (point(&self.spend), point(&self.view));
        }
        let mut m = self.subaddress_scalar(major, minor);
        let spend = point(&self.spend) + point(&m);
        m.zeroize();
        (spend, self.view * spend)
    }

    /// What a subaddress's spend key adds to the account's: Hs("SubAddr" ‖ view key ‖ major ‖
    /// minor).
    pub(crate) fn subaddress_scalar(&self, major: u32, minor: u32) -> Scalar {
        let mut data = [0u8; 8 + 32 + 8];
        data[..8].copy_from_slice(b"SubAddr\0");
        data[8..40].copy_from_slice(self.view.as_bytes());
        data[40..44].copy_from_slice(&major.to_le_bytes());
        data[44..].copy_from_slice(&minor.to_le_bytes());
        let m = hash_to_scalar(&data);
        data.zeroize();
        m
    }

    /// The one-time secret of an output of this account's: output `index` of a transaction whose
    /// public key is `tx_key` (or, in a transaction paying more than one subaddress, the output's
    /// own additional key), paid to subaddress `minor` of account `major` (0 and 0: the account's
    /// own address). The output's key is this times G, if it is the account's; its key image is
    /// `sign::key_image` of it.
    pub fn output_secret(&self, tx_key: &EdwardsPoint, index: u64, major: u32, minor: u32) -> Scalar {
        let mut shared = sign::derivation(&self.view, tx_key);
        let mut secret = sign::output_scalar(&shared, index) + self.spend;
        shared.zeroize();
        if (major, minor) != (0, 0) {
            let mut m = self.subaddress_scalar(major, minor);
            secret += m;
            m.zeroize();
        }
        secret
    }

    /// Whether output `index` of a transaction with public key `tx_key` pays this account, by
    /// its view tag and then its key; the subaddress it pays is the caller's to say.
    pub fn owns(
        &self,
        tx_key: &EdwardsPoint,
        index: u64,
        view_tag: u8,
        key: &EdwardsPoint,
        major: u32,
        minor: u32,
    ) -> bool {
        let mut shared = sign::derivation(&self.view, tx_key);
        let tagged = sign::view_tag(&shared, index) == view_tag;
        shared.zeroize();
        if !tagged {
            return false;
        }
        let mut secret = self.output_secret(tx_key, index, major, minor);
        let ours = point(&secret) == *key;
        secret.zeroize();
        ours
    }

    /// An output of this account's, as maki reads it to spend: the amount its commitment hides
    /// and the commitment's mask, from the amount the transaction carries (encrypted), if that
    /// opens `commitment`.
    pub fn open_output(
        &self,
        tx_key: &EdwardsPoint,
        index: u64,
        encrypted_amount: &[u8; 8],
        commitment: &EdwardsPoint,
    ) -> Option<(u64, Scalar)> {
        let mut shared = sign::derivation(&self.view, tx_key);
        let mut scalar = sign::output_scalar(&shared, index);
        shared.zeroize();
        let amount = u64::from_le_bytes(sign::encrypt_amount(u64::from_le_bytes(*encrypted_amount), &scalar));
        let mask = sign::commitment_mask(&scalar);
        scalar.zeroize();
        (sign::commit(&mask, amount) == *commitment).then_some((amount, mask))
    }

    /// The mask of the commitment to output `index`'s amount, in a transaction whose public key
    /// (or the output's own) is `tx_key`, if the output is this account's: how maki opens a
    /// commitment to spend it. (A coinbase output's mask is 1.)
    pub fn output_mask(&self, tx_key: &EdwardsPoint, index: u64) -> Scalar {
        let mut shared = sign::derivation(&self.view, tx_key);
        let mut scalar = sign::output_scalar(&shared, index);
        shared.zeroize();
        let mask = sign::commitment_mask(&scalar);
        scalar.zeroize();
        mask
    }

    /// Output `index`'s key image, with what proves it's the key image of the output with key
    /// `key` (Monero's ring signature, of that key alone, over the image itself), as wallet2
    /// exports key images to a view-only wallet: None unless the output is this account's, paid
    /// to subaddress `minor` of account `major`. `aux` is fresh randomness.
    pub fn key_image_proof(
        &self,
        tx_key: &EdwardsPoint,
        index: u64,
        major: u32,
        minor: u32,
        key: &[u8; 32],
        aux: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 64])> {
        let point_key = sign::point(key)?;
        let mut secret = self.output_secret(tx_key, index, major, minor);
        if point(&secret) != point_key {
            secret.zeroize();
            return None;
        }
        let hp = sign::hash_to_point(key);
        let image = (secret * hp).compress().to_bytes();
        // k from the secret, what's signed and the randomness: fresh, and never repeated
        let mut data = [0u8; 32 + 32 + 32 + 20];
        data[..32].copy_from_slice(secret.as_bytes());
        data[32..64].copy_from_slice(&image);
        data[64..96].copy_from_slice(aux);
        data[96..].copy_from_slice(b"maki key image proof");
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&crate::keccak(&data));
        data[..32].copy_from_slice(&[0xa5; 32]);
        wide[32..].copy_from_slice(&crate::keccak(&data));
        data.zeroize();
        let mut k = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        // c = Hs(image ‖ k·G ‖ k·Hp(key)), r = k - c·x
        let mut buf = [0u8; 96];
        buf[..32].copy_from_slice(&image);
        buf[32..64].copy_from_slice(point(&k).compress().as_bytes());
        buf[64..].copy_from_slice((k * hp).compress().as_bytes());
        let c = hash_to_scalar(&buf);
        let r = k - c * secret;
        k.zeroize();
        secret.zeroize();
        let mut proof = [0u8; 64];
        proof[..32].copy_from_slice(c.as_bytes());
        proof[32..].copy_from_slice(r.as_bytes());
        Some((image, proof))
    }

    /// The spend key's 25 words: the backup Monero wallets restore from.
    pub fn words(&self) -> [&'static str; 25] { crate::words::encode(self.spend.as_bytes()) }

    /// The spend key, as 32 bytes (for the words, and tests).
    pub fn spend_bytes(&self) -> [u8; 32] { self.spend.to_bytes() }

    /// The view key, as 32 bytes.
    pub fn view_bytes(&self) -> [u8; 32] { self.view.to_bytes() }

    pub(crate) fn view(&self) -> &Scalar { &self.view }

    pub(crate) fn spend(&self) -> &Scalar { &self.spend }
}

fn point(s: &Scalar) -> EdwardsPoint { ED25519_BASEPOINT_POINT * s }
