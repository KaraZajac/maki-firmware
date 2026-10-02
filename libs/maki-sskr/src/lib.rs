//! SSKR, for maki's Shamir backup: Blockchain Commons' Sharded Secret Key Reconstruction
//! (BCR-2020-011), which splits a recovery phrase's entropy itself into shares, any k of n of which
//! put it back. The same entropy is the same 12 or 24 words, so the shares restore the same
//! wallets everywhere the phrase works. (SLIP-39, Trezor's, makes a new seed from its shares
//! instead, so they don't give the phrase back.) maki writes each share as ByteWords
//! (BCR-2020-012): 29 words for a 12-word phrase, 46 for a 24-word one. They carry everything
//! needed to put the secret back: what they are, which split they're from, how many it takes,
//! which share each is, and a checksum. (Not how many shares were made.)
//!
//! This does what Blockchain Commons' own code does, and its tests check it against that code byte
//! for byte: their Rust `sskr` 0.12.0 and `bc-shamir` 0.13.0 (the same random bytes make the same
//! shares), their C `bc-sskr` 0.3.2 and `bc-shamir` 0.4.0, which seedtool-cli's C++ releases use
//! (the same, but for the order of the identifier's two random bytes), bc-ur 0.19.2's ByteWords,
//! the spec's examples, the shares seedtool-cli's manuals show (Rust's 0.4.0 and C++'s 0.11.0),
//! shares seedtool-cli 0.4.0 printed, and shares in maki's words that it read back.
//! - `split` makes shares (one group, k of n), with randomness the caller passes in (maki's TRNG);
//!   `split_groups` makes the several-group splits seedtool can.
//! - `combine` puts shares back together, in any order and from any layout the spec allows, checking them as
//!   it goes and saying why it won't.
//! - `Share::words` writes a share as ByteWords, and `Share::from_words`, `from_word_bytes` and `parse` read
//!   one back; `expected_words` says how many words a share is from its first four or five.
//!
//! Secrets, shares, and what's computed between them are wiped when they're dropped (all but
//! SHA-256's own state, in the digest's HMAC).

#![no_std]
extern crate alloc;

pub mod bytewords;
mod gf256;
mod shamir;
mod share;

use alloc::vec::Vec;

pub use share::{METADATA, Share, Words, expected_words, word_count};
use zeroize::Zeroizing;

/// The shortest secret SSKR splits: 16 bytes, a 12-word phrase's entropy.
pub const MIN_SECRET: usize = 16;
/// The longest: 32 bytes, a 24-word phrase's. Lengths between must be even.
pub const MAX_SECRET: usize = 32;
/// The most shares a group can have, and the most groups a split can (four bits each).
pub const MAX_SHARES: usize = 16;

/// Why a share can't be read, a secret can't be split, or shares can't be put back together.
/// Shares are counted from 0, as they were given; `Display` counts them from 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Word `i` isn't one of ByteWords' words, nor a word's first and last letters.
    UnknownWord(usize),
    /// Not as many words as a share has (`word_count`): one left out, or one too many.
    WordCount(usize),
    /// The last four words aren't the others' checksum: a word is wrong, or two are swapped.
    Checksum,
    /// Words, or a UR, that aren't an SSKR share: something else in ByteWords, or words no share
    /// begins with.
    NotAShare,
    /// An SSKR share whose fields can't be: more groups needed than there are, a group that isn't
    /// one of them, reserved bits set, or a value that isn't 16 to 32 bytes, an even number.
    Malformed,
    /// A secret to split that isn't 16 to 32 bytes, an even number.
    SecretLength(usize),
    /// A split that isn't 1 to 16 groups of 1 to 16 shares, each needing 1 to all of its own.
    Layout,
    /// No shares at all.
    NoShares,
    /// Share `share` is from another split: its identifier (`Share::identifier_words`) isn't the
    /// first share's (`set`).
    OtherSet { share: usize, identifier: u16, set: u16 },
    /// Share `share` has the first share's identifier but not its split's layout, its secret's
    /// length, or its group's threshold: from another split that drew the same identifier (1 in
    /// 65,536), or not made by SSKR.
    Mismatch { share: usize },
    /// Shares `first` and `share` are the same share: the same group, the same number.
    Duplicate { first: usize, share: usize },
    /// Too few shares for a one-group split: it takes `need`, and these are `have`.
    TooFew { need: usize, have: usize },
    /// Too few groups: the split takes shares from `need` groups, and `have` groups have enough.
    TooFewGroups { need: usize, have: usize },
    /// The shares don't fit together: the secret they give and the digest they give disagree, so
    /// one is damaged or from another split. `group` says whose, in a split of several groups.
    DontFit { group: Option<usize> },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Error::UnknownWord(i) => write!(f, "word {} isn't one of ByteWords' words", i + 1),
            Error::WordCount(n) => write!(
                f,
                "a share is 29 words (of a 12-word phrase) or 46 (of a 24-word one), and this is {n}"
            ),
            Error::Checksum => f.write_str("the words don't add up: one is wrong, or two are swapped"),
            Error::NotAShare => f.write_str("not an SSKR share"),
            Error::Malformed => {
                f.write_str("not a share SSKR makes: its groups, thresholds or length can't be")
            }
            Error::SecretLength(n) => {
                write!(f, "a secret to split is 16 to 32 bytes, an even number, and this is {n}")
            }
            Error::Layout => {
                f.write_str("a split is 1 to 16 groups of 1 to 16 shares, each needing 1 to all")
            }
            Error::NoShares => f.write_str("no shares"),
            Error::OtherSet { share, identifier, set } => {
                let words = |id: u16| {
                    let [a, b] = id.to_be_bytes();
                    (bytewords::word(a), bytewords::word(b))
                };
                let ((a, b), (c, d)) = (words(identifier), words(set));
                write!(
                    f,
                    "share {} is from another split (\"{a} {b}\", not \"{c} {d}\"): leave it out",
                    share + 1
                )
            }
            Error::Mismatch { share } => {
                write!(f, "share {} doesn't match the others: it's damaged, or from another split", share + 1)
            }
            Error::Duplicate { first, share } => {
                write!(f, "shares {} and {} are the same share: leave one out", first + 1, share + 1)
            }
            Error::TooFew { need, have } => {
                write!(
                    f,
                    "it takes {need} shares, and these are {have}: add {} more",
                    need.saturating_sub(have)
                )
            }
            Error::TooFewGroups { need, have } => {
                write!(f, "it takes shares from {need} groups, and {have} have enough")
            }
            Error::DontFit { group: None } => {
                f.write_str("the shares don't fit together: one is damaged, or from another split")
            }
            Error::DontFit { group: Some(g) } => write!(
                f,
                "group {}'s shares don't fit together: one is damaged, or from another split",
                g + 1
            ),
        }
    }
}

/// A secret put back together: for maki, a recovery phrase's entropy. It's wiped when dropped.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8] { &self.0 }

    /// How long it is: 16 to 32 bytes.
    pub fn len(&self) -> usize { self.0.len() }

    /// Never: a secret is at least 16 bytes.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

/// Not the bytes.
impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// `count` shares of `secret` (16 to 32 bytes, an even number), any `threshold` of which put it
/// back: one group, as maki splits a phrase. `random` fills what it's given with random bytes
/// (maki's TRNG); it's asked as Blockchain Commons' `sskr_generate_using` asks its random number
/// generator, so the same bytes make the same shares (`split_groups` says in what order).
///
/// A threshold of 1 makes `count` copies of the secret, each share holding it whole, as SSKR
/// does: anyone with one share has the phrase. (Blockchain Commons' C library refuses 1 of more
/// than 1; their Rust library, and seedtool's Rust releases, make it.)
pub fn split(
    secret: &[u8],
    threshold: usize,
    count: usize,
    random: impl FnMut(&mut [u8]),
) -> Result<Vec<Share>, Error> {
    split_groups(secret, 1, &[(threshold, count)], random)?.into_iter().next().ok_or(Error::Layout)
}

/// Shares of `secret` in groups, as seedtool makes them (`-g 2-of-3 3-of-5 -t 2`): `groups` are
/// each group's (threshold, count), and shares from `group_threshold` of the groups put the
/// secret back, each group's own threshold of them. The result has each group's shares in turn.
///
/// `random` is asked, as `sskr_generate_using` asks, for: the identifier's two bytes (big-endian);
/// then the split of the secret among the groups; then each group's split of its part among its
/// shares, in turn. A split of threshold t asks for t − 2 shares' worth of bytes, one share at a
/// time, then all but four bytes of one more (the digest's), and nothing when t is 1.
pub fn split_groups(
    secret: &[u8],
    group_threshold: usize,
    groups: &[(usize, usize)],
    mut random: impl FnMut(&mut [u8]),
) -> Result<Vec<Vec<Share>>, Error> {
    if !(MIN_SECRET..=MAX_SECRET).contains(&secret.len()) || !secret.len().is_multiple_of(2) {
        return Err(Error::SecretLength(secret.len()));
    }
    if groups.is_empty()
        || groups.len() > MAX_SHARES
        || !(1..=groups.len()).contains(&group_threshold)
        || groups.iter().any(|&(threshold, count)| {
            !(1..=MAX_SHARES).contains(&count) || !(1..=count).contains(&threshold)
        })
    {
        return Err(Error::Layout);
    }
    let mut identifier = [0u8; 2];
    random(&mut identifier);
    let identifier = u16::from_be_bytes(identifier);
    let parts = shamir::split(group_threshold, groups.len(), secret, &mut random);
    let mut shares = Vec::with_capacity(groups.len());
    for (group_index, (&(threshold, count), part)) in groups.iter().zip(parts.iter()).enumerate() {
        let values = shamir::split(threshold, count, part, &mut random);
        shares.push(
            values
                .into_iter()
                .enumerate()
                .map(|(member_index, value)| Share {
                    identifier,
                    group_threshold: group_threshold as u8,
                    group_count: groups.len() as u8,
                    group_index: group_index as u8,
                    member_threshold: threshold as u8,
                    member_index: member_index as u8,
                    value,
                })
                .collect(),
        );
    }
    Ok(shares)
}

/// The secret, from shares in any order: enough of one split, from any layout of groups. It
/// refuses, saying why: shares from another split, or that don't match the first one's; the same
/// share twice; too few; and shares that don't fit together, which the digest catches (all but 1
/// in 2^32 of them). Then each group with enough shares puts its part back from all of them, not
/// only its threshold's worth as Blockchain Commons' libraries do (they use the first ones), so a
/// share given beyond the threshold must fit too; a group without enough is left out, as their
/// Rust library leaves it (if the other groups are enough). The secret comes from every group
/// that had enough, the same way.
///
/// For a screen that asks for shares one at a time: after each, `TooFew` or `TooFewGroups` means
/// they're good so far, and more are needed; any other error is about the last one, or a share
/// it names.
///
/// What a threshold of 1 doesn't have is a digest: its shares are the secret, and nothing but each
/// share's own checksum says it's right.
pub fn combine(shares: &[Share]) -> Result<Secret, Error> {
    let first = shares.first().ok_or(Error::NoShares)?;
    for (i, share) in shares.iter().enumerate().skip(1) {
        if share.identifier != first.identifier {
            return Err(Error::OtherSet { share: i, identifier: share.identifier, set: first.identifier });
        }
        if share.group_threshold != first.group_threshold
            || share.group_count != first.group_count
            || share.value.len() != first.value.len()
        {
            return Err(Error::Mismatch { share: i });
        }
    }
    for (i, share) in shares.iter().enumerate() {
        for (j, other) in shares[..i].iter().enumerate() {
            if share.group_index == other.group_index {
                if share.member_threshold != other.member_threshold {
                    return Err(Error::Mismatch { share: i });
                }
                if share.member_index == other.member_index {
                    return Err(Error::Duplicate { first: j, share: i });
                }
            }
        }
    }

    let in_group = |g: u8| shares.iter().filter(move |s| s.group_index == g);
    let complete: Vec<u8> = (0..first.group_count)
        .filter(|&g| in_group(g).next().is_some_and(|s| in_group(g).count() >= s.member_threshold as usize))
        .collect();
    let group_threshold = first.group_threshold as usize;
    if complete.len() < group_threshold {
        return Err(if first.group_count == 1 {
            Error::TooFew { need: first.member_threshold as usize, have: shares.len() }
        } else {
            Error::TooFewGroups { need: group_threshold, have: complete.len() }
        });
    }

    let several = first.group_count > 1;
    let mut parts: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(complete.len());
    for &g in &complete {
        let xs: Vec<u8> = in_group(g).map(|s| s.member_index).collect();
        let ys: Vec<&[u8]> = in_group(g).map(|s| &s.value[..]).collect();
        let threshold = in_group(g).next().map_or(1, |s| s.member_threshold as usize);
        let part = shamir::recover(threshold, &xs, &ys)
            .ok_or(Error::DontFit { group: several.then_some(g as usize) })?;
        parts.push(part);
    }
    let ys: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
    let secret = shamir::recover(group_threshold, &complete, &ys).ok_or(Error::DontFit { group: None })?;
    Ok(Secret(secret))
}
