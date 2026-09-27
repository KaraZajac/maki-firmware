//! maki's recovery phrase (ARCHITECTURE.md, "One recovery phrase").
//!
//! 24 BIP39 words from the TRNG, the root of everything that can't be made again: the wallet's
//! keys, derived the standard way so the phrase works in other wallets too, and the key that
//! encrypts maki's backup. The English word list is the one in the BIP; its SHA-256 is checked
//! in the tests.

#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

static ENGLISH: &str = include_str!("english.txt");

/// The 2048 words, in order.
pub fn wordlist() -> impl Iterator<Item = &'static str> { ENGLISH.lines() }

pub fn word(index: usize) -> Option<&'static str> { wordlist().nth(index) }

pub fn index_of(word: &str) -> Option<usize> { wordlist().position(|w| w == word) }

/// Words that start with `prefix`: what's left to pick from as letters are chosen. Every word is
/// fixed by its first four letters.
pub fn starting_with(prefix: &str) -> impl Iterator<Item = &'static str> + '_ {
    wordlist().filter(move |w| w.starts_with(prefix))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not 12, 15, 18, 21 or 24 words.
    Length,
    /// A word that isn't on the list.
    UnknownWord(usize),
    /// The words don't add up: one is wrong, or two are swapped. (Most mistakes, not all: the
    /// checksum is 8 bits for 24 words, so 1 in 256 slips through.)
    Checksum,
}

/// Entropy (16 to 32 bytes, a multiple of 4) as words.
pub fn to_words(entropy: &[u8]) -> Vec<&'static str> {
    assert!(entropy.len() % 4 == 0 && (16..=32).contains(&entropy.len()));
    let checksum_bits = entropy.len() / 4;
    let hash = Sha256::digest(entropy);
    let bit = |i: usize| -> u32 {
        let byte = if i < entropy.len() * 8 { entropy[i / 8] } else { hash[(i - entropy.len() * 8) / 8] };
        ((byte >> (7 - i % 8)) & 1) as u32
    };
    let total = entropy.len() * 8 + checksum_bits;
    (0..total / 11)
        .map(|w| {
            let index = (0..11).fold(0u32, |acc, b| (acc << 1) | bit(w * 11 + b)) as usize;
            word(index).unwrap()
        })
        .collect()
}

/// Words back to entropy, if they're a real phrase: the right count, all on the list, checksum.
pub fn to_entropy(words: &[&str]) -> Result<Vec<u8>, Error> {
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(Error::Length);
    }
    let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);
    for (i, w) in words.iter().enumerate() {
        let index = index_of(w).ok_or(Error::UnknownWord(i))?;
        bits.extend((0..11).rev().map(|b| (index >> b) & 1 == 1));
    }
    let checksum_bits = words.len() / 3;
    let entropy_bits = bits.len() - checksum_bits;
    let mut entropy: Vec<u8> = bits[..entropy_bits]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
        .collect();
    let hash = Sha256::digest(&entropy);
    let expected = (0..checksum_bits).all(|i| bits[entropy_bits + i] == ((hash[i / 8] >> (7 - i % 8)) & 1 == 1));
    if expected {
        Ok(entropy)
    } else {
        entropy.zeroize();
        Err(Error::Checksum)
    }
}

/// The BIP39 seed: PBKDF2-HMAC-SHA512 over the phrase, 2048 rounds, salted with "mnemonic" and
/// the passphrase (maki has none: an empty one). The words are ASCII, so the normalization the
/// BIP asks for changes nothing.
pub fn seed(words: &[&str], passphrase: &str) -> [u8; 64] {
    let mut phrase = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            phrase.push(' ');
        }
        phrase.push_str(w);
    }
    let mut salt = String::from("mnemonic");
    salt.push_str(passphrase);
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(phrase.as_bytes(), salt.as_bytes(), 2048, &mut out);
    phrase.zeroize();
    out
}

/// The FIDO authenticator's secrets, from the seed, so that what maki gave sites (credential
/// IDs, hmac-secret outputs) still works on a maki restored from the same phrase.
pub struct FidoKeys {
    /// AES-256: wraps the private key inside each credential ID maki gives out
    pub encryption: [u8; 32],
    /// HMAC-SHA256: authenticates those credential IDs
    pub authentication: [u8; 32],
    /// hmac-secret's CredRandom: 32 bytes used without user verification, then 32 with
    pub cred_random: [u8; 64],
}

impl Drop for FidoKeys {
    fn drop(&mut self) {
        self.encryption.zeroize();
        self.authentication.zeroize();
        self.cred_random.zeroize();
    }
}

/// HKDF-SHA256 over the seed, salt "maki", info "fido v1": 128 bytes, in `FidoKeys`' order.
pub fn fido_keys(seed: &[u8; 64]) -> FidoKeys {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"maki"), seed);
    let mut okm = [0u8; 128];
    hk.expand(b"fido v1", &mut okm).expect("128 bytes is a valid HKDF length");
    let keys = FidoKeys {
        encryption: okm[..32].try_into().unwrap(),
        authentication: okm[32..64].try_into().unwrap(),
        cred_random: okm[64..].try_into().unwrap(),
    };
    okm.zeroize();
    keys
}

/// An app's secret, for the app with this ID and developer key (the key that signs its
/// bundles) and a label of the app's choosing: HKDF-SHA256 over the seed, salt "maki", info
/// "app v1" and then the ID, the developer key and the label, the ID and label each after its
/// length in a byte. Different for every app, developer and label, and the same on any maki
/// restored from the phrase. `None` for an ID or label longer than 255 bytes.
pub fn app_secret(seed: &[u8; 64], app_id: &str, developer: &[u8; 32], label: &str) -> Option<[u8; 32]> {
    let (id, label) = (app_id.as_bytes(), label.as_bytes());
    let id_len = u8::try_from(id.len()).ok()?;
    let label_len = u8::try_from(label.len()).ok()?;
    let mut info = Vec::with_capacity(6 + 1 + id.len() + 32 + 1 + label.len());
    info.extend_from_slice(b"app v1");
    info.push(id_len);
    info.extend_from_slice(id);
    info.extend_from_slice(developer);
    info.push(label_len);
    info.extend_from_slice(label);
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"maki"), seed);
    let mut secret = [0u8; 32];
    hk.expand(&info, &mut secret).expect("32 bytes is a valid HKDF length");
    Some(secret)
}

/// The key that encrypts maki's backup: from the seed, so the phrase alone opens a backup and
/// the PIN plays no part in it (a backup file is what an attacker gets to guess PINs against).
pub fn backup_key(seed: &[u8; 64]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"maki"), seed);
    let mut key = [0u8; 32];
    hk.expand(b"backup v1", &mut key).expect("32 bytes is a valid HKDF length");
    key
}
