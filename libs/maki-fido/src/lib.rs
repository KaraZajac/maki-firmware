//! maki's passkeys as the vault's FIDO authenticator (OpenSK) keeps them: resident credentials
//! in the PDDB dictionary `opensk` of the secret basis, one CBOR map per key from 1700, and the
//! global signature counter at 2047 (a u32, little-endian). maki-keys backs these up; the
//! Passkeys app lists them. Their keys, and hmac-secret's CredRandom, come from the recovery
//! phrase (`maki_seed::fido_keys`), so a restored maki needs only the phrase and these records.

#![no_std]

pub const DICT: &str = "opensk";
/// OpenSK's resident credentials: the first 150 keys of its range are used.
pub const CREDENTIALS: core::ops::Range<usize> = 1700..1850;
pub const COUNTER: usize = 2047;

// OpenSK's credential fields (ctap/data_formats.rs, PublicKeyCredentialSourceField)
const CREDENTIAL_ID: u64 = 0;
const RP_ID: u64 = 2;
const USER_DISPLAY_NAME: u64 = 4;
const USER_NAME: u64 = 8;

/// Whether a key of OpenSK's store goes in a backup.
pub fn backed_up(key: &str) -> bool {
    key.parse::<usize>().map(|k| CREDENTIALS.contains(&k) || k == COUNTER).unwrap_or(false)
}

/// The header at `at`: its major type, its argument, and where what follows it starts.
/// Definite lengths only, which is what OpenSK writes.
fn head(b: &[u8], at: usize) -> Option<(u8, u64, usize)> {
    let first = *b.get(at)?;
    let (major, info) = (first >> 5, first & 31);
    let (value, next) = match info {
        0..=23 => (info as u64, at + 1),
        24 => (*b.get(at + 1)? as u64, at + 2),
        25 => (u16::from_be_bytes(b.get(at + 1..at + 3)?.try_into().ok()?) as u64, at + 3),
        26 => (u32::from_be_bytes(b.get(at + 1..at + 5)?.try_into().ok()?) as u64, at + 5),
        27 => (u64::from_be_bytes(b.get(at + 1..at + 9)?.try_into().ok()?), at + 9),
        _ => return None,
    };
    Some((major, value, next))
}

/// Where the item at `at` ends.
fn skip(b: &[u8], at: usize, depth: u32) -> Option<usize> {
    if depth > 16 {
        return None;
    }
    let (major, value, next) = head(b, at)?;
    match major {
        // integers, and simple values and floats, whose bytes are the argument
        0 | 1 | 7 => Some(next),
        2 | 3 => {
            let end = next.checked_add(usize::try_from(value).ok()?)?;
            (end <= b.len()).then_some(end)
        }
        4 => (0..value).try_fold(next, |at, _| skip(b, at, depth + 1)),
        5 => (0..value.checked_mul(2)?).try_fold(next, |at, _| skip(b, at, depth + 1)),
        // a tag, then the item it tags
        6 => skip(b, next, depth + 1),
        _ => None,
    }
}

/// The string (byte or text) under integer key `key` of the map `cbor` is: its major type and
/// its bytes.
fn field(cbor: &[u8], key: u64) -> Option<(u8, &[u8])> {
    let (major, pairs, mut at) = head(cbor, 0)?;
    if major != 5 {
        return None;
    }
    for _ in 0..pairs {
        let (kmajor, k, _) = head(cbor, at)?;
        let value = skip(cbor, at, 1)?;
        let end = skip(cbor, value, 1)?;
        if kmajor == 0 && k == key {
            let (vmajor, len, data) = head(cbor, value)?;
            if vmajor != 2 && vmajor != 3 {
                return None;
            }
            return Some((vmajor, cbor.get(data..data.checked_add(usize::try_from(len).ok()?)?)?));
        }
        at = end;
    }
    None
}

fn text(cbor: &[u8], key: u64) -> Option<&str> {
    match field(cbor, key)? {
        (3, bytes) => core::str::from_utf8(bytes).ok(),
        _ => None,
    }
}

/// A resident credential's ID: the byte string under key 0.
pub fn credential_id(cbor: &[u8]) -> Option<&[u8]> {
    match field(cbor, CREDENTIAL_ID)? {
        (2, bytes) => Some(bytes),
        _ => None,
    }
}

/// What the owner sees of a passkey: the site it's for, and whose it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary<'a> {
    pub rp_id: &'a str,
    /// the user's name, or else their display name, if the site gave either
    pub user: Option<&'a str>,
}

pub fn summary(cbor: &[u8]) -> Option<Summary<'_>> {
    Some(Summary {
        rp_id: text(cbor, RP_ID)?,
        user: text(cbor, USER_NAME).or_else(|| text(cbor, USER_DISPLAY_NAME)).filter(|u| !u.is_empty()),
    })
}
