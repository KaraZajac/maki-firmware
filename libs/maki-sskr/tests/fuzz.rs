//! Shares are typed in by their owner, from paper that may be smudged, and could come from
//! anywhere: whatever text, words or bytes the readers are given, they answer with a share or a
//! reason, never a panic, and never a share that isn't the one written down. Random input, and
//! mutations of real shares: the ones seedtool printed and the ones in the fixtures.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_sskr::{Error, Share, bytewords, combine, split, split_groups};
use serde_json::Value;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize { (self.next() % n.max(1) as u64) as usize }

    fn fill(&mut self, bytes: &mut [u8]) {
        for b in bytes {
            *b = self.next() as u8;
        }
    }
}

/// Text as it's mistyped: letters changed, dropped, doubled or added, words run together or split,
/// case changed, and characters that have no business there.
fn mutate_text(rng: &mut Rng, base: &str) -> String {
    let mut chars: Vec<char> = base.chars().collect();
    for _ in 0..1 + rng.below(3) {
        let i = rng.below(chars.len() + 1);
        match rng.below(7) {
            0 if i < chars.len() => chars[i] = (b'a' + rng.below(26) as u8) as char,
            1 if i < chars.len() => {
                chars.remove(i);
            }
            2 => chars.insert(i, [' ', '-', '\n', '/', ':', 'é', '₿', '\0'][rng.below(8)]),
            3 => chars.insert(i, (b'a' + rng.below(26) as u8) as char),
            4 if i < chars.len() => chars[i] = chars[i].to_ascii_uppercase(),
            5 => chars.truncate(i),
            _ if i < chars.len() => {
                let c = chars[i];
                chars.insert(i, c);
            }
            _ => {}
        }
    }
    chars.into_iter().collect()
}

fn mutate_bytes(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        match rng.below(5) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 => b.truncate(rng.below(b.len() + 1)),
            2 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            // the bytes CBOR headers and the metadata's fields are made of
            _ if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0x00, 0x01, 0x0f, 0x10, 0x11, 0x40, 0x55, 0x58, 0xd9, 0xff][rng.below(10)];
            }
            _ => {}
        }
    }
    b
}

fn with_crc(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&bytewords::crc32(body).to_be_bytes());
    out
}

/// Every share text in the fixtures: what seedtool printed, the documents' and the sskr crate's.
fn texts() -> Vec<String> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vectors.json")).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let mut out = vec![];
    let mut add = |list: &Value| {
        out.extend(list.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()));
    };
    for run in v["seedtool"].as_array().unwrap() {
        add(&run["shares"]);
    }
    for example in v["documented"].as_array().unwrap() {
        add(&example["shares"]);
    }
    for case in v["restored"].as_array().unwrap() {
        add(&case["words"]);
    }
    for case in v["fake"].as_array().unwrap() {
        for share in case["shares"].as_array().unwrap() {
            for form in ["btw", "btwu", "btwm", "ur"] {
                out.push(share[form].as_str().unwrap().to_string());
            }
        }
    }
    out.retain(|t| !t.bytes().all(|c| c.is_ascii_hexdigit()));
    out
}

#[test]
fn no_text_misreads_or_panics() {
    let texts = texts();
    let mut rng = Rng(0x55c2_f022);
    let (mut read, mut refused) = (0, 0);
    for round in 0..60_000 {
        let (text, original) = if round % 10 == 0 {
            let len = rng.below(400);
            let raw: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            (String::from_utf8_lossy(&raw).into_owned(), None)
        } else if round % 10 == 1 {
            // words, but any words: the right count, mostly
            let n = [29, 46, 31, 1 + rng.below(60)][rng.below(4)];
            let words: Vec<&str> = (0..n).map(|_| bytewords::word(rng.next() as u8)).collect();
            (words.join(" "), None)
        } else {
            let base = &texts[rng.below(texts.len())];
            (mutate_text(&mut rng, base), Share::parse(base).ok())
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = bytewords::decode(&text);
            let words: Vec<&str> = text.split(' ').collect();
            let _ = Share::from_words(&words);
            for w in &words {
                let _ = bytewords::byte(w);
            }
            Share::parse(&text)
        }));
        match outcome.unwrap_or_else(|_| panic!("panicked on {text:?}")) {
            Ok(share) => {
                read += 1;
                // a change the checksum lets through is one that changes nothing: case,
                // whitespace, a word's first and last letters for the word
                if let Some(original) = original {
                    assert_eq!(share, original, "{text:?} misread");
                }
            }
            Err(_) => refused += 1,
        }
    }
    assert!(read > 1_000 && refused > 30_000, "read {read}, refused {refused}");
}

/// Bytes past the checksum: what's inside a share's words must be a share, or it's refused.
#[test]
fn no_bytes_panic() {
    let texts = texts();
    let real: Vec<Vec<u8>> =
        texts.iter().filter_map(|t| Share::parse(t).ok()).map(|s| s.to_cbor().to_vec()).collect();
    let mut rng = Rng(0xb17e_5000);
    let mut kinds = [0usize; 4];
    for round in 0..60_000 {
        let body = if round % 8 == 0 {
            let mut b = vec![0u8; rng.below(60)];
            rng.fill(&mut b);
            b
        } else {
            let base = &real[rng.below(real.len())];
            mutate_bytes(&mut rng, base)
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = Share::from_bytes(&body);
            let _ = Share::from_bytes(body.get(3..).unwrap_or(&[]));
            let _ = Share::from_cbor(&body);
            for p in 0..body.len().min(8) {
                let _ = maki_sskr::expected_words(&body[..p]);
            }
            Share::from_word_bytes(&with_crc(&body))
        }));
        let result = outcome.unwrap_or_else(|_| panic!("panicked on {body:02x?}"));
        kinds[match result {
            Ok(share) => {
                // what's read is what was written
                assert_eq!(&share.to_cbor()[3..], &body[3..]);
                0
            }
            Err(Error::Malformed) => 1,
            Err(Error::NotAShare) => 2,
            Err(_) => 3,
        }] += 1;
    }
    assert!(kinds.iter().all(|&k| k > 100), "{kinds:?}");
}

/// Shares of splits, some damaged (and written down again with a right checksum), some from other
/// splits, given in any number and order: `combine` answers, and never with a wrong secret when
/// the shares' metadata is as their split made it and the split has a digest to check: a group
/// threshold over 1, or every group's over 1. (A share's metadata isn't in the digest: one that
/// says it's 1 of n is taken as the secret, as SSKR takes it.)
#[test]
fn combine_never_panics_or_lies() {
    let mut rng = Rng(0xc0b1_4e00);
    let mut answers = [0usize; 2];
    for _ in 0..3_000 {
        let len = 16 + 2 * rng.below(9);
        let mut secret = vec![0u8; len];
        rng.fill(&mut secret);
        let groups: Vec<(usize, usize)> = (0..1 + rng.below(3))
            .map(|_| {
                let n = 1 + rng.below(5);
                (1 + rng.below(n), n)
            })
            .collect();
        let group_threshold = 1 + rng.below(groups.len());
        let mut pool: Vec<Share> = split_groups(&secret, group_threshold, &groups, |b| rng.fill(b))
            .unwrap()
            .into_iter()
            .flatten()
            .collect();
        let mut digested = group_threshold > 1 || groups.iter().all(|&(k, _)| k > 1);
        // a share or two with a damaged value, or damaged anywhere, and a share of another split
        for _ in 0..rng.below(3) {
            let i = rng.below(pool.len());
            let bytes = pool[i].to_bytes();
            let bent = if rng.below(2) == 0 {
                [&bytes[..5], &mutate_bytes(&mut rng, &bytes[5..])[..]].concat()
            } else {
                digested = false;
                mutate_bytes(&mut rng, &bytes)
            };
            if let Ok(share) = Share::from_bytes(&bent) {
                pool.push(share);
            }
        }
        if rng.below(4) == 0 {
            let other = split(&secret, 2, 3, |b| rng.fill(b)).unwrap();
            pool.push(other[rng.below(3)].clone());
        }
        let mut given = vec![];
        for _ in 0..rng.below(pool.len() + 3) {
            given.push(pool[rng.below(pool.len())].clone());
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| combine(&given)));
        match outcome.unwrap_or_else(|_| panic!("panicked on {given:?}")) {
            Ok(found) => {
                answers[0] += 1;
                if digested {
                    assert_eq!(found.as_bytes(), &secret[..], "{given:?}");
                }
            }
            Err(_) => answers[1] += 1,
        }
    }
    assert!(answers.iter().all(|&a| a > 100), "{answers:?}");
}
