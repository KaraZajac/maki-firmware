//! Keys for maki's wallet apps (ARCHITECTURE.md, "Wallets are apps"): BIP32 from the recovery
//! phrase's seed, on the derivation paths a wallet uses, and the two signatures wallets need,
//! ECDSA (with its recovery ID, for Ethereum) and BIP340 Schnorr (tweaked the BIP86 way for a
//! taproot key spend). And Ed25519 keys by SLIP-10, for Solana, through `op` alone.
//!
//! `Keys` is all a wallet's code sees. maki-keys implements it from the seed (the `seed`
//! feature), and so do the fake maki, the simulator and tests; an app implements it with calls
//! to maki (`maki_app::wallet`), which keeps the seed and does the curve's arithmetic at native
//! speed, where an interpreted app can't. maki checks the paths an app may use and that the
//! owner said yes before it signs; `Keys` itself doesn't.

#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[cfg(feature = "seed")]
pub mod seed;

/// A path component at or above this is hardened (written `84'`).
pub const HARDENED: u32 = 0x8000_0000;
/// No wallet needs deeper paths than this (BIP44 is five deep).
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No keys to use: maki is locked, or has no phrase yet.
    Locked,
    /// A path the app may not use, or one deeper than `MAX_DEPTH`.
    Path,
    /// A key BIP32 can't make (odds below 2^-127), or a signature that didn't check out.
    Key,
    /// No yes from the owner to sign with, or the signatures they allowed are used up.
    NotAllowed,
    /// Anything else: maki couldn't be asked.
    Failed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Locked => "maki is locked",
            Error::Path => "a path this wallet may not use",
            Error::Key => "a key that couldn't be made",
            Error::NotAllowed => "not allowed to sign",
            Error::Failed => "maki couldn't be asked",
        })
    }
}

/// A public key at a path, with what an extended public key (BIP32) carries beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Public {
    /// Compressed (SEC1, 33 bytes).
    pub key: [u8; 33],
    pub chain_code: [u8; 32],
    /// The first four bytes of the parent key's HASH160 (zero for the master key).
    pub parent_fingerprint: [u8; 4],
}

/// How a Schnorr signature's key is tweaked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tweak {
    /// The key itself (BIP340).
    None,
    /// The key as a taproot output with no scripts commits to it (BIP86, BIP341's tweak with an
    /// empty script tree): what a taproot key spend signs with.
    Taproot,
}

/// The keys at a wallet's paths. Shared between threads (maki-keys answers several at once).
pub trait Keys: Send + Sync {
    /// The master key's fingerprint: the first four bytes of its HASH160, as descriptors and
    /// PSBTs name the seed their keys come from.
    fn fingerprint(&self) -> Result<[u8; 4], Error>;
    /// The public key and chain code at `path`.
    fn public(&self, path: &[u32]) -> Result<Public, Error>;
    /// The public key at `path`, uncompressed (`04 || x || y`): what an Ethereum address hashes.
    fn uncompressed(&self, path: &[u32]) -> Result<[u8; 65], Error>;
    /// The taproot output key (x only) the key at `path` makes with no scripts (BIP86).
    fn taproot_output(&self, path: &[u32]) -> Result<[u8; 32], Error>;
    /// An ECDSA signature over a 32-byte digest with the key at `path`: r and s (s low), and the
    /// recovery ID (0 or 1). Deterministic (RFC 6979).
    fn sign_ecdsa(&self, path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), Error>;
    /// A BIP340 Schnorr signature over a 32-byte message with the key at `path`, tweaked or not.
    fn sign_schnorr(&self, path: &[u32], digest: &[u8; 32], tweak: Tweak) -> Result<[u8; 64], Error>;
}

/// What's asked of a wallet's keys, numbered as maki's wallet functions and maki-keys number it.
pub mod op {
    /// The master key's fingerprint (4 bytes); no path.
    pub const FINGERPRINT: u8 = 0;
    /// The public key, compressed (33 bytes), its chain code (32) and its parent's fingerprint (4).
    pub const PUBLIC: u8 = 1;
    /// The public key, uncompressed (65 bytes).
    pub const UNCOMPRESSED: u8 = 2;
    /// The taproot output key it makes with no scripts (BIP86), x only (32 bytes).
    pub const TAPROOT: u8 = 3;
    /// An ECDSA signature over the digest: r and s (s low), then the recovery ID (65 bytes).
    pub const SIGN_ECDSA: u8 = 4;
    /// A BIP340 signature over the digest (64 bytes).
    pub const SIGN_SCHNORR: u8 = 5;
    /// A BIP340 signature over the digest with the key tweaked for a taproot key spend (64 bytes).
    pub const SIGN_TAPROOT: u8 = 6;
    /// Monero's keys from the key at `m/44'/128'/account'/0/0` (maki-xmr, as Ledger's Monero app
    /// makes them; Monero's coin type alone): the public spend and view keys (64 bytes).
    pub const MONERO_PUBLIC: u8 = 7;
    /// A Monero subaddress's public spend and view keys (64 bytes). The digest is its account and
    /// index, each a u32, little-endian.
    pub const MONERO_SUBADDRESS: u8 = 8;
    /// The Monero spend key's 25 words (UTF-8, a space between each), for maki to show its owner
    /// itself: never an app's.
    pub const MONERO_WORDS: u8 = 9;
    /// The Monero account's secret view key (32 bytes): what a computer finds the account's
    /// outputs with, and can't spend them. maki gives it once its owner says yes.
    pub const MONERO_VIEW_KEY: u8 = 10;
    /// An output of the account's key image, and what proves it (Monero's ring signature of one,
    /// 64 bytes): what a view-only wallet learns what's spent from. The digest is the output's
    /// transaction key (32 bytes), its index there (u64), the subaddress it was paid to (account
    /// and index, u32s) and its key (32), little-endian; refused unless it's the account's.
    pub const MONERO_KEY_IMAGE: u8 = 11;
    /// A Monero transaction, signed: the digest is what's to be paid (`maki_xmr::request`); the
    /// answer 0 and the signed transaction (`maki_xmr::spend::Signed`), or 1 and why not (UTF-8).
    /// maki makes everything that decides where the money goes: the outputs, the range proof and
    /// each input's signature.
    pub const MONERO_SIGN: u8 = 12;
    /// An Ed25519 public key (32 bytes), by SLIP-10 from the seed, every step of the path
    /// hardened: as Solana's wallets (Phantom, Solflare, Ledger's) derive theirs, at
    /// `m/44'/501'/account'/0'`.
    pub const ED25519_PUBLIC: u8 = 13;
    /// An Ed25519 signature (RFC 8032, 64 bytes) with that key. The digest is the whole message:
    /// Ed25519 hashes what it signs itself, so maki has all of it.
    pub const ED25519_SIGN: u8 = 14;
    /// A BIP-85 child seed's BIP39 words (UTF-8, a space between each), at a path `child_seed`
    /// reads: a phrase of its own for another wallet, made from maki's, for maki to show its
    /// owner itself: never an app's.
    pub const BIP85_WORDS: u8 = 15;
}

/// The words maki shows its owner for a wallet's backup, from the path's own kind: a BIP-85
/// child seed's (`op::BIP85_WORDS`) or a Monero account's (`op::MONERO_WORDS`).
pub fn words_op(path: &[u32]) -> u8 {
    if child_seed(path).is_some() { op::BIP85_WORDS } else { op::MONERO_WORDS }
}

/// BIP-85's purpose: keys under `m/83696968'` make entropy for other wallets (child seeds), and
/// sign nothing.
pub const BIP85: u32 = 83696968 | HARDENED;

/// A BIP-85 child seed's path, `m/83696968'/39'/0'/{words}'/{index}'` (a BIP39 phrase, in
/// English): its words (12, 18 or 24) and index. None for any other path.
pub fn child_seed(path: &[u32]) -> Option<(u32, u32)> {
    match *path {
        [BIP85, app, language, words, index]
            if app == 39 | HARDENED && language == HARDENED && index >= HARDENED =>
        {
            let words = words.checked_sub(HARDENED)?;
            matches!(words, 12 | 18 | 24).then_some((words, index - HARDENED))
        }
        _ => None,
    }
}

/// A path as people write it, `m/84'/0'/0'` (or `84h/0h/0h`, with or without the `m/`), as
/// numbers. None if it isn't one, or is deeper than `MAX_DEPTH`.
pub fn parse_path(text: &str) -> Option<Vec<u32>> {
    let text = text.trim();
    let rest = text.strip_prefix("m/").or_else(|| (text == "m").then_some("")).unwrap_or(text);
    let mut path = Vec::new();
    if rest.is_empty() {
        return Some(path);
    }
    for part in rest.split('/') {
        let (digits, hardened) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
            Some(d) => (d, true),
            None => (part, false),
        };
        if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        if n >= HARDENED {
            return None;
        }
        path.push(if hardened { n | HARDENED } else { n });
    }
    (path.len() <= MAX_DEPTH).then_some(path)
}

/// A path as people write it: `m/84'/0'/0'/0/5`.
pub fn format_path(path: &[u32]) -> String {
    let mut out = String::from("m");
    for &i in path {
        if i >= HARDENED {
            let _ = write!(out, "/{}'", i - HARDENED);
        } else {
            let _ = write!(out, "/{}", i);
        }
    }
    out
}

/// Whether `path` is `prefix` or below it.
pub fn under(path: &[u32], prefix: &[u32]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

/// Whether a wallet may declare `prefix`: a purpose and a coin type at least, both hardened, so
/// no wallet gets the whole tree, or every coin under a purpose.
pub fn prefix_ok(prefix: &[u32]) -> bool {
    prefix.len() >= 2 && prefix.len() <= MAX_DEPTH && prefix[0] >= HARDENED && prefix[1] >= HARDENED
}

/// The coin a path's coin type (SLIP-44) names, as an install screen says it (or BIP-85's child
/// seeds, which aren't a coin).
pub fn coin(prefix: &[u32]) -> Option<&'static str> {
    if prefix.first() == Some(&BIP85) {
        return Some("child seeds");
    }
    let coin_type = *prefix.get(1)?;
    if coin_type < HARDENED {
        return None;
    }
    Some(match coin_type - HARDENED {
        0 => "Bitcoin",
        1 => "test networks",
        2 => "Litecoin",
        3 => "Dogecoin",
        60 => "Ethereum",
        128 => "Monero",
        145 => "Bitcoin Cash",
        501 => "Solana",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_read_and_write() {
        assert_eq!(parse_path("m/84'/0'/0'"), Some(alloc::vec![84 | HARDENED, HARDENED, HARDENED]));
        assert_eq!(
            parse_path("84h/1h/0h/1/7"),
            Some(alloc::vec![84 | HARDENED, 1 | HARDENED, HARDENED, 1, 7])
        );
        assert_eq!(parse_path("m"), Some(alloc::vec![]));
        assert_eq!(parse_path("m/2147483648"), None);
        assert_eq!(parse_path("m/84'/x"), None);
        assert_eq!(parse_path("m/84''"), None);
        assert_eq!(parse_path("m/0/0/0/0/0/0/0/0/0"), None);
        assert_eq!(format_path(&parse_path("m/44'/60'/0'/0/3").unwrap()), "m/44'/60'/0'/0/3");
    }

    #[test]
    fn prefixes() {
        let p = parse_path("m/84'/0'").unwrap();
        assert!(prefix_ok(&p));
        assert!(!prefix_ok(&parse_path("m/84'").unwrap()));
        assert!(!prefix_ok(&parse_path("m/84'/0").unwrap()));
        assert!(under(&parse_path("m/84'/0'/0'/1/5").unwrap(), &p));
        assert!(!under(&parse_path("m/84'/1'/0'").unwrap(), &p));
        assert!(!under(&parse_path("m/84'").unwrap(), &p));
        assert_eq!(coin(&p), Some("Bitcoin"));
        assert_eq!(coin(&parse_path("m/44'/60'").unwrap()), Some("Ethereum"));
        assert_eq!(coin(&parse_path("m/44'/99999'").unwrap()), None);
    }
}
