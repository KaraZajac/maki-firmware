//! ByteWords (BCR-2020-012): bytes as English words, a word for each byte, from a list of 256
//! four-letter words chosen so that a word's first and last letters tell it from every other, as
//! do its first three or its last three. The "standard" form, the one maki shows, is the words of
//! some CBOR and then four words of its CRC-32 (big-endian), separated by spaces; the "URI" form
//! separates them by hyphens, and the "minimal" form keeps only each word's first and last letters,
//! run together. A share's CBOR says what it is, so the words do too: every share begins with the
//! same few words (`tuna next keep …`).

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;

/// The 256 words, each standing for its place in the list: BCR-2020-012's list, as revised on
/// October 4, 2020 (which put it in alphabetical order), from Blockchain Commons' Research
/// repository (github.com/BlockchainCommons/Research, `papers/bcr-2020-012-bytewords.md`), under
/// the BSD-2-Clause-Patent License, Copyright © 2019 Blockchain Commons, LLC: the license's text
/// is `LICENSE-bytewords`, beside this crate's Cargo.toml. The tests check it against the paper's
/// table and against bc-ur 0.19.2's `BYTEWORDS`.
#[rustfmt::skip]
pub const WORDS: [&str; 256] = [
    "able", "acid", "also", "apex", "aqua", "arch", "atom", "aunt", // 0x00
    "away", "axis", "back", "bald", "barn", "belt", "beta", "bias", // 0x08
    "blue", "body", "brag", "brew", "bulb", "buzz", "calm", "cash", // 0x10
    "cats", "chef", "city", "claw", "code", "cola", "cook", "cost", // 0x18
    "crux", "curl", "cusp", "cyan", "dark", "data", "days", "deli", // 0x20
    "dice", "diet", "door", "down", "draw", "drop", "drum", "dull", // 0x28
    "duty", "each", "easy", "echo", "edge", "epic", "even", "exam", // 0x30
    "exit", "eyes", "fact", "fair", "fern", "figs", "film", "fish", // 0x38
    "fizz", "flap", "flew", "flux", "foxy", "free", "frog", "fuel", // 0x40
    "fund", "gala", "game", "gear", "gems", "gift", "girl", "glow", // 0x48
    "good", "gray", "grim", "guru", "gush", "gyro", "half", "hang", // 0x50
    "hard", "hawk", "heat", "help", "high", "hill", "holy", "hope", // 0x58
    "horn", "huts", "iced", "idea", "idle", "inch", "inky", "into", // 0x60
    "iris", "iron", "item", "jade", "jazz", "join", "jolt", "jowl", // 0x68
    "judo", "jugs", "jump", "junk", "jury", "keep", "keno", "kept", // 0x70
    "keys", "kick", "kiln", "king", "kite", "kiwi", "knob", "lamb", // 0x78
    "lava", "lazy", "leaf", "legs", "liar", "limp", "lion", "list", // 0x80
    "logo", "loud", "love", "luau", "luck", "lung", "main", "many", // 0x88
    "math", "maze", "memo", "menu", "meow", "mild", "mint", "miss", // 0x90
    "monk", "nail", "navy", "need", "news", "next", "noon", "note", // 0x98
    "numb", "obey", "oboe", "omit", "onyx", "open", "oval", "owls", // 0xa0
    "paid", "part", "peck", "play", "plus", "poem", "pool", "pose", // 0xa8
    "puff", "puma", "purr", "quad", "quiz", "race", "ramp", "real", // 0xb0
    "redo", "rich", "road", "rock", "roof", "ruby", "ruin", "runs", // 0xb8
    "rust", "safe", "saga", "scar", "sets", "silk", "skew", "slot", // 0xc0
    "soap", "solo", "song", "stub", "surf", "swan", "taco", "task", // 0xc8
    "taxi", "tent", "tied", "time", "tiny", "toil", "tomb", "toys", // 0xd0
    "trip", "tuna", "twin", "ugly", "undo", "unit", "urge", "user", // 0xd8
    "vast", "very", "veto", "vial", "vibe", "view", "visa", "void", // 0xe0
    "vows", "wall", "wand", "warm", "wasp", "wave", "waxy", "webs", // 0xe8
    "what", "when", "whiz", "wolf", "work", "yank", "yawn", "yell", // 0xf0
    "yoga", "yurt", "zaps", "zero", "zest", "zinc", "zone", "zoom", // 0xf8
];

/// The word for `byte`.
pub fn word(byte: u8) -> &'static str { WORDS[byte as usize] }

/// The byte a word stands for, in either case: the whole word, or just its first and last letters,
/// which BCR-2020-012 makes enough ("only two letters of each word (the first and last) are
/// required to uniquely identify each byte value": its minimal form). Three letters aren't taken,
/// though the paper says a word's first three or its last three identify it too: twelve words'
/// first three are another's last three ("qua", quad and aqua; "tom", tomb and atom), so three
/// letters alone can be either.
pub fn byte(token: &str) -> Option<u8> { byte_of(token.as_bytes()) }

/// Words starting with `prefix`, in either case, with the bytes they stand for: what's left to
/// pick from as letters are chosen. A word's first three letters leave only it.
pub fn starting_with(prefix: &str) -> impl Iterator<Item = (u8, &'static str)> + '_ {
    let prefix = prefix.as_bytes();
    (0..=255u8).map(|b| (b, word(b))).filter(move |(_, w)| {
        w.len() >= prefix.len() && w.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

/// CRC-32 as zlib and Ethernet make it (ISO-HDLC: reflected, polynomial 0x04c11db7, starting from
/// and ending with all ones): ByteWords' checksum, its last four words big-endian.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// What a ByteWords text spells, its checksum checked and taken off: words separated by spaces (or
/// any whitespace) or by hyphens, or run together as each word's first and last letters. Each word
/// may be whole or just its first and last letters, in either case (`byte`).
pub fn decode(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (spelled, _) = spelled(text)?;
    Ok(Zeroizing::new(checked(&spelled)?.to_vec()))
}

pub(crate) fn byte_of(token: &[u8]) -> Option<u8> {
    let found = match *token {
        [a, b, c, d] => WORDS.iter().position(|w| w.as_bytes().eq_ignore_ascii_case(&[a, b, c, d])),
        [first, last] => WORDS.iter().position(|w| {
            let w = w.as_bytes();
            w[0] == first.to_ascii_lowercase() && w[3] == last.to_ascii_lowercase()
        }),
        _ => None,
    };
    found.map(|i| i as u8)
}

/// `body` and its checksum: the bytes a ByteWords text spells.
pub(crate) fn with_checksum(body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    out.extend_from_slice(body);
    out.extend_from_slice(&crc32(body).to_be_bytes());
    out
}

/// What a ByteWords text spells, without its checksum, if the checksum is right.
pub(crate) fn checked(spelled: &[u8]) -> Result<&[u8], Error> {
    let split = spelled.len().checked_sub(4).ok_or(Error::Checksum)?;
    let (body, checksum) = spelled.split_at(split);
    if crc32(body).to_be_bytes() == checksum { Ok(body) } else { Err(Error::Checksum) }
}

/// The ways a ByteWords text is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Form {
    /// Words separated by spaces (or any whitespace: lines of them, as they're written down).
    Standard,
    /// Words separated by hyphens.
    Uri,
    /// Each word's first and last letters, run together.
    Minimal,
}

/// The bytes a ByteWords text spells, checksum and all, and which form it's in. Each word may be
/// written whole or as its first and last letters (`byte`), whatever the form.
pub(crate) fn spelled(text: &str) -> Result<(Zeroizing<Vec<u8>>, Form), Error> {
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
    let form = if text.contains(|c: char| c.is_ascii_whitespace()) {
        Form::Standard
    } else if text.contains('-') {
        Form::Uri
    } else {
        Form::Minimal
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() / 2 + 1));
    let mut push = |i: usize, token: &[u8]| -> Result<(), Error> {
        bytes.push(byte_of(token).ok_or(Error::UnknownWord(i))?);
        Ok(())
    };
    match form {
        Form::Standard => {
            for (i, token) in text.split_ascii_whitespace().enumerate() {
                push(i, token.as_bytes())?;
            }
        }
        Form::Uri => {
            for (i, token) in text.split('-').enumerate() {
                push(i, token.as_bytes())?;
            }
        }
        Form::Minimal => {
            for (i, pair) in text.as_bytes().chunks(2).enumerate() {
                push(i, pair)?;
            }
        }
    }
    Ok((bytes, form))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_the_papers() {
        // the SHA-256 of the words in BCR-2020-012's table, in order, joined by spaces
        use sha2::{Digest, Sha256};
        let joined = WORDS.join(" ");
        let expected = "3a696c0977c83d268850775c5da1df831e7c7e1681d52d6e976ac09005e57497";
        let hash: alloc::string::String =
            Sha256::digest(joined.as_bytes()).iter().map(|b| alloc::format!("{b:02x}")).collect();
        assert_eq!(hash, expected);
    }

    #[test]
    fn words_are_as_the_paper_chose_them() {
        // sorted, four lowercase letters, and each told apart by its first and last letters, by
        // its first three, and by its last three
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]));
        assert!(WORDS.iter().all(|w| w.len() == 4 && w.bytes().all(|c| c.is_ascii_lowercase())));
        for (i, w) in WORDS.iter().enumerate() {
            for v in &WORDS[..i] {
                let (w, v) = (w.as_bytes(), v.as_bytes());
                assert!((w[0], w[3]) != (v[0], v[3]));
                assert!(w[..3] != v[..3] && w[1..] != v[1..]);
            }
        }
        for b in 0..=255u8 {
            let w = word(b);
            assert_eq!(byte(w), Some(b));
            assert_eq!(byte(&w.to_ascii_uppercase()), Some(b));
            let short = [w.as_bytes()[0], w.as_bytes()[3]];
            assert_eq!(byte_of(&short), Some(b));
            assert_eq!(byte(&w[..3]), None);
        }
        assert_eq!(byte("abl"), None);
        assert_eq!(byte("ablee"), None);
        assert_eq!(byte("ab"), None);
        assert_eq!(byte(""), None);
        assert_eq!(byte("é"), None);
        assert_eq!(
            starting_with("ju").map(|(_, w)| w).collect::<Vec<_>>(),
            ["judo", "jugs", "jump", "junk", "jury"]
        );
        assert!(WORDS.iter().all(|w| starting_with(&w[..3]).count() == 1));
    }

    #[test]
    fn crc32_is_zlibs() {
        // the ur crate's tests (which bc-ur uses for ByteWords)
        assert_eq!(crc32(b"Hello, world!"), 0xebe6_c6e6);
        assert_eq!(crc32(b"Wolf"), 0x598c_84dc);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
