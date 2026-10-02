//! Stellar transactions come to maki from a computer that may lie: anything, however broken, must
//! get an error or a review, never a panic. Random bytes, mutations of real envelopes, and
//! StrKeys made of anything.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_xlm::display::review;
use maki_xlm::{Envelope, Network, strkey};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize { (self.next() % n.max(1) as u64) as usize }
}

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 => b.truncate(rng.below(b.len() + 1)),
            // XDR's units: four bytes in, or out
            2 => {
                let i = rng.below(b.len() / 4 + 1) * 4;
                let word = (rng.next() as u32).to_be_bytes();
                b.splice(i..i, word);
            }
            3 if b.len() >= 4 => {
                let i = rng.below(b.len() / 4) * 4;
                b.drain(i..i + 4);
            }
            // the words lengths, counts and types are made of
            4 if b.len() >= 4 => {
                let i = rng.below(b.len() / 4) * 4;
                let v: u32 = [0, 1, 2, 3, 4, 5, 0x7f, 0x100, 0xffff_ffff, 0x8000_0000][rng.below(10)];
                b[i..i + 4].copy_from_slice(&v.to_be_bytes());
            }
            _ if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            _ => {}
        }
    }
    b
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn nothing_a_computer_sends_panics() {
    let me = strkey::decode_account("GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX").unwrap();
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> =
        json.as_array().unwrap().iter().map(|f| unhex(f["envelope"].as_str().unwrap())).collect();
    let mut rng = Rng(0x5eed_57e1);
    let (mut read, mut reviewed) = (0, 0);
    for round in 0..60_000 {
        let bytes = if round % 8 == 0 {
            (0..rng.below(600)).map(|_| rng.next() as u8).collect()
        } else {
            let base = &real[rng.below(real.len())];
            mutate(&mut rng, base)
        };
        let network = if round % 2 == 0 { Network::Public } else { Network::Test };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = strkey::decode(&String::from_utf8_lossy(&bytes));
            match Envelope::parse(&bytes) {
                Ok(e) => {
                    let _ = e.hash(network);
                    (1, review(&e, &me, network).is_ok() as usize)
                }
                Err(_) => (0, 0),
            }
        }));
        let (r, v) = outcome.unwrap_or_else(|_| panic!("panicked on {bytes:02x?}"));
        read += r;
        reviewed += v;
    }
    // the mutations reach the review, not just the parser
    assert!(read > 3_000 && reviewed > 2_000, "{read} read, {reviewed} reviewed");
}

#[test]
fn strkeys_of_anything_are_refused_or_read_back() {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = Rng(0x57e1_1a12);
    let real = [
        "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX",
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU",
        "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU",
    ];
    let (mut changed, mut read) = (0, 0);
    for round in 0..40_000 {
        let (text, real) = if round % 4 == 0 {
            ((0..rng.below(170)).map(|_| alphabet[rng.below(32)] as char).collect(), None)
        } else {
            let real = real[rng.below(real.len())];
            let mut t = real.as_bytes().to_vec();
            let i = rng.below(t.len());
            match rng.below(3) {
                0 => t[i] = alphabet[rng.below(32)],
                1 => {
                    t.remove(i);
                }
                _ => t.insert(i, alphabet[rng.below(32)]),
            }
            (String::from_utf8(t).unwrap(), Some(real))
        };
        // a StrKey maki reads writes back as itself: one way to write each
        if let Some((kind, payload)) = strkey::decode(&text) {
            assert_eq!(strkey::encode(kind, &payload), text);
            read += 1;
            if real.is_some_and(|r| r != text) {
                changed += 1;
            }
        }
    }
    // a character changed, dropped or added is caught (the checksum, the length): what's read is
    // what was written, and only that (the mutations that changed nothing are read)
    assert_eq!(changed, 0);
    assert!(read > 100, "{read}");
}
