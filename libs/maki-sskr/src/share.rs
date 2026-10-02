//! One share, and the ways it's written: its five bytes of metadata and its value (BCR-2020-011),
//! that as a CBOR byte string tagged `sskr`, and that as ByteWords.
//!
//! The metadata, packed as the spec and both of Blockchain Commons' libraries pack it:
//!
//! ```text
//! byte 0, 1   identifier, big-endian: the same in every share of a split, random
//! byte 2      group threshold − 1 (high four bits), group count − 1 (low four)
//! byte 3      group index (high four bits), member threshold − 1 (low four)
//! byte 4      0000 (reserved, high four bits), member index (low four)
//! byte 5…     the share's value: as long as the secret, 16 to 32 bytes, an even number
//! ```
//!
//! As CBOR: tag 40309 (`d9 9d75`, BCR-2020-011's `sskr`, version 2), then the bytes as a byte
//! string (`55` and 21 bytes for a 16-byte secret, `58 25` and 37 for a 32-byte one). Version 1
//! tagged it 309 (`d9 0135`, `crypto-sskr`): seedtool-cli's C++ releases write and read only that,
//! its Rust releases write and read 40309, and Blockchain Commons' `bc-components` reads both, as
//! this does; it writes 40309.
//!
//! As ByteWords, those bytes and their CRC-32: 29 words for a 16-byte secret, beginning `tuna next
//! keep gyro`, and 46 for a 32-byte one, beginning `tuna next keep hard data` (version 1's begin
//! `tuna acid epic`). As a UR (`ur:sskr/…`), the byte string untagged, in minimal ByteWords: what
//! seedtool prints with `-s ur`.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::bytewords::{self, Form};
use crate::{Error, MAX_SECRET, MIN_SECRET};

/// The metadata's length, before the value.
pub const METADATA: usize = 5;

/// Tag 40309, `sskr`, in CBOR: what maki writes.
const TAG: [u8; 3] = [0xd9, 0x9d, 0x75];
/// Tag 309, `crypto-sskr`: version 1's, still read.
const TAG_V1: [u8; 3] = [0xd9, 0x01, 0x35];

/// How a share's CBOR may be tagged where it's read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tagged {
    /// ByteWords: tagged, 40309 or 309, since nothing else says what the words are.
    Yes,
    /// `ur:sskr/`: untagged, the UR's type saying what it is.
    No,
    /// `ur:crypto-sskr/`: untagged, or tagged 309 as seedtool's C++ releases wrote it (Blockchain
    /// Commons' Rust seedtool takes both).
    MaybeV1,
}

/// One share of a split: which split it's from, how its split was made, which share it is, and
/// its value. Its value is wiped when it's dropped.
#[derive(Clone)]
pub struct Share {
    pub(crate) identifier: u16,
    pub(crate) group_threshold: u8,
    pub(crate) group_count: u8,
    pub(crate) group_index: u8,
    pub(crate) member_threshold: u8,
    pub(crate) member_index: u8,
    pub(crate) value: Zeroizing<Vec<u8>>,
}

/// A share's words, as maki shows them: its CBOR tagged `sskr` (40309) and its checksum, a word
/// for each byte. They're wiped when dropped (the words themselves are only places in the list).
pub struct Words(Zeroizing<Vec<u8>>);

impl Words {
    /// How many words: 29 for a 16-byte secret, 46 for a 32-byte one (`word_count`).
    pub fn len(&self) -> usize { self.0.len() }

    /// Never: a share has at least 29 words.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Word `i`, counting from 0.
    pub fn get(&self, i: usize) -> Option<&'static str> { self.0.get(i).map(|&b| bytewords::word(b)) }

    /// The words in order.
    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().map(|&b| bytewords::word(b))
    }

    /// The bytes the words stand for, checksum and all: what `Share::from_word_bytes` takes back.
    pub fn bytes(&self) -> &[u8] { &self.0 }
}

/// How many words a share of a `secret_len`-byte secret is: its tag (3), its byte string's header
/// (1, or 2 from 24 bytes), its metadata (5), its value and its checksum (4). 29 for 16 bytes (a
/// 12-word phrase's entropy), 46 for 32 (a 24-word phrase's); 31, 34, 36, 38, 40, 42 and 44 for
/// the even lengths between.
pub const fn word_count(secret_len: usize) -> usize {
    let bytes = METADATA + secret_len;
    3 + if bytes < 24 { 1 } else { 2 } + bytes + 4
}

/// How many words a share is, from what its first words stand for, as soon as they say: at its
/// fourth word (`tuna next keep gyro`: 29) or its fifth (`tuna next keep hard data`: 46). `None`
/// until then, and an error as soon as they can't begin a share: for a screen that takes a share's
/// words one at a time.
pub fn expected_words(start: &[u8]) -> Result<Option<usize>, Error> {
    let tag = &start[..start.len().min(TAG.len())];
    if !TAG.starts_with(tag) && !TAG_V1.starts_with(tag) {
        return Err(Error::NotAShare);
    }
    let bytes = match start.get(TAG.len()..) {
        None | Some([]) | Some([0x58]) => return Ok(None),
        Some(&[header, ..]) if header & 0xe0 == 0x40 && header & 0x1f < 24 => (header & 0x1f) as usize,
        Some(&[0x58, len, ..]) if len >= 24 => len as usize,
        _ => return Err(Error::NotAShare),
    };
    match bytes.checked_sub(METADATA) {
        Some(len) if (MIN_SECRET..=MAX_SECRET).contains(&len) && len.is_multiple_of(2) => {
            Ok(Some(word_count(len)))
        }
        _ => Err(Error::Malformed),
    }
}

impl Share {
    /// The split's identifier: the same in every one of its shares, random, so shares of two
    /// splits (even of the same secret) aren't mixed up. It's the two words after the share's first
    /// four (`tuna next keep gyro`), or first five for a 24-word phrase's (`tuna next keep hard
    /// data`): `identifier_words`.
    pub fn identifier(&self) -> u16 { self.identifier }

    /// The identifier as the two words a share shows it with: a name for the set.
    pub fn identifier_words(&self) -> [&'static str; 2] {
        let [a, b] = self.identifier.to_be_bytes();
        [bytewords::word(a), bytewords::word(b)]
    }

    /// How many groups it takes to put the secret back (1 for maki's own splits).
    pub fn group_threshold(&self) -> usize { self.group_threshold as usize }

    /// How many groups the secret was split into (1 for maki's own splits).
    pub fn group_count(&self) -> usize { self.group_count as usize }

    /// Which group this share is in, counting from 0.
    pub fn group_index(&self) -> usize { self.group_index as usize }

    /// How many of its group's shares it takes to put the group's part back: maki's k.
    pub fn member_threshold(&self) -> usize { self.member_threshold as usize }

    /// Which share of its group this is, counting from 0. How many shares its group has isn't
    /// written anywhere.
    pub fn member_index(&self) -> usize { self.member_index as usize }

    /// How long the secret is: 16 bytes for a 12-word phrase's entropy, 32 for a 24-word one's.
    pub fn secret_len(&self) -> usize { self.value.len() }

    /// The share as the words maki shows: `word_count(secret_len)` of them.
    pub fn words(&self) -> Words { Words(bytewords::with_checksum(&self.to_cbor())) }

    /// A share from its words, each whole or as its first and last letters (`bytewords::byte`),
    /// in either case: they must be as many as a share has, and their checksum right.
    pub fn from_words(words: &[&str]) -> Result<Share, Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(words.len()));
        for (i, w) in words.iter().enumerate() {
            bytes.push(bytewords::byte(w).ok_or(Error::UnknownWord(i))?);
        }
        Share::from_word_bytes(&bytes)
    }

    /// A share from the bytes its words stand for (each word's place in the list), checksum and
    /// all: for a screen that has the owner pick each word from the list.
    pub fn from_word_bytes(bytes: &[u8]) -> Result<Share, Error> {
        if !(MIN_SECRET..=MAX_SECRET).step_by(2).any(|len| word_count(len) == bytes.len()) {
            return Err(Error::WordCount(bytes.len()));
        }
        Share::read_cbor(bytewords::checked(bytes)?, Tagged::Yes)
    }

    /// A share from text as Blockchain Commons' tools print it, in any of the forms seedtool
    /// writes (`seedtool -o sskr -s btw`, `btwu`, `btwm` or `ur`): ByteWords separated by spaces
    /// (or any whitespace), by hyphens, or run together as each word's first and last letters;
    /// or a UR, `ur:sskr/…` (or version 1's `ur:crypto-sskr/…`). Case doesn't matter.
    pub fn parse(text: &str) -> Result<Share, Error> {
        let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if text.as_bytes().get(..3).is_some_and(|start| start.eq_ignore_ascii_case(b"ur:")) {
            return Share::parse_ur(&text[3..]);
        }
        let (bytes, _) = bytewords::spelled(text)?;
        Share::from_word_bytes(&bytes)
    }

    /// `type/payload`, after `ur:`: a single-part UR of type `sskr` or `crypto-sskr`.
    fn parse_ur(rest: &str) -> Result<Share, Error> {
        let (kind, payload) = rest.split_once('/').ok_or(Error::NotAShare)?;
        let tagged = if kind.eq_ignore_ascii_case("sskr") {
            Tagged::No
        } else if kind.eq_ignore_ascii_case("crypto-sskr") {
            Tagged::MaybeV1
        } else {
            return Err(Error::NotAShare);
        };
        // a part of a multi-part UR ("1-3/…"): a share is always one part
        if payload.contains(|c: char| c == '/' || c == '-' || c.is_ascii_whitespace()) {
            return Err(Error::NotAShare);
        }
        let (bytes, form) = bytewords::spelled(payload)?;
        if form != Form::Minimal {
            return Err(Error::NotAShare);
        }
        Share::read_cbor(bytewords::checked(&bytes)?, tagged)
    }

    /// The share's CBOR, tagged 40309.
    pub fn to_cbor(&self) -> Zeroizing<Vec<u8>> {
        let bytes = self.to_bytes();
        let mut out = Zeroizing::new(Vec::with_capacity(TAG.len() + 2 + bytes.len()));
        out.extend_from_slice(&TAG);
        // a byte string's header in its shortest form, as deterministic CBOR has it
        match u8::try_from(bytes.len()) {
            Ok(len) if len < 24 => out.push(0x40 | len),
            Ok(len) => out.extend_from_slice(&[0x58, len]),
            // never: a share is 21 to 37 bytes
            Err(_) => {}
        }
        out.extend_from_slice(&bytes);
        out
    }

    /// A share from its CBOR, tagged 40309 or 309: a byte string with its header in the shortest
    /// form (as Blockchain Commons' deterministic CBOR insists), and nothing after it.
    pub fn from_cbor(cbor: &[u8]) -> Result<Share, Error> { Share::read_cbor(cbor, Tagged::Yes) }

    fn read_cbor(cbor: &[u8], tagged: Tagged) -> Result<Share, Error> {
        let tag = cbor.get(..3);
        let rest = match tagged {
            Tagged::Yes if tag == Some(&TAG[..]) || tag == Some(&TAG_V1[..]) => &cbor[3..],
            Tagged::MaybeV1 if tag == Some(&TAG_V1[..]) => &cbor[3..],
            Tagged::No | Tagged::MaybeV1 => cbor,
            Tagged::Yes => return Err(Error::NotAShare),
        };
        let (len, body) = match *rest {
            [header, ref body @ ..] if header & 0xe0 == 0x40 && header & 0x1f < 24 => {
                ((header & 0x1f) as usize, body)
            }
            [0x58, len, ref body @ ..] if len >= 24 => (len as usize, body),
            // another item, or a byte string's length not in its shortest form
            _ => return Err(Error::NotAShare),
        };
        if body.len() != len {
            return Err(Error::Malformed);
        }
        Share::from_bytes(body)
    }

    /// The share as Blockchain Commons' libraries keep it (what `sskr_generate` returns): its
    /// metadata, then its value.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(METADATA + self.value.len()));
        out.extend_from_slice(&self.identifier.to_be_bytes());
        out.push((self.group_threshold - 1) << 4 | (self.group_count - 1));
        out.push(self.group_index << 4 | (self.member_threshold - 1));
        out.push(self.member_index);
        out.extend_from_slice(&self.value);
        out
    }

    /// A share from its metadata and value, if they can be a share: the reserved bits clear, no
    /// more groups needed than there are, its group one of them (both Blockchain Commons'
    /// libraries check the first two; a share their split makes passes all three), and a value of
    /// 16 to 32 bytes, an even number.
    pub fn from_bytes(bytes: &[u8]) -> Result<Share, Error> {
        let (&[id0, id1, groups, group, member], value) =
            bytes.split_first_chunk::<METADATA>().ok_or(Error::Malformed)?;
        let group_threshold = (groups >> 4) + 1;
        let group_count = (groups & 0xf) + 1;
        let group_index = group >> 4;
        if !(MIN_SECRET..=MAX_SECRET).contains(&value.len())
            || !value.len().is_multiple_of(2)
            || member >> 4 != 0
            || group_threshold > group_count
            || group_index >= group_count
        {
            return Err(Error::Malformed);
        }
        Ok(Share {
            identifier: u16::from_be_bytes([id0, id1]),
            group_threshold,
            group_count,
            group_index,
            member_threshold: (group & 0xf) + 1,
            member_index: member & 0xf,
            value: Zeroizing::new(value.to_vec()),
        })
    }
}

impl PartialEq for Share {
    fn eq(&self, other: &Share) -> bool { self.to_bytes() == other.to_bytes() }
}

impl Eq for Share {}

/// Everything but the value.
impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("identifier", &self.identifier)
            .field("group", &(self.group_index, self.group_threshold, self.group_count))
            .field("member", &(self.member_index, self.member_threshold))
            .field("secret_len", &self.value.len())
            .finish()
    }
}
