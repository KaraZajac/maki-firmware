//! Sign docs are read on maki from whatever the computer sends: anything, however broken, must get
//! an error or a review, never a panic. Random bytes, and mutations of real ones. And whatever maki
//! reads, written again, is the very bytes it read: there's one way of writing a sign doc.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_atom::chains::Network;
use maki_atom::display::review;
use maki_atom::{SignDoc, bech32, chains, json, parse_address};

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

/// What a sign doc is made of: its punctuation, digits, the escapes it may have, and parts of its
/// names and values, so mutations stay JSON long enough to reach the messages.
const PIECES: &[&[u8]] = &[
    b"\"",
    b"{",
    b"}",
    b"[",
    b"]",
    b",",
    b":",
    b"0",
    b"1",
    b"9",
    b"-",
    b".",
    b" ",
    b"\\",
    b"\\n",
    b"\\u0026",
    b"null",
    b"true",
    b"amount",
    b"denom",
    b"uatom",
    b"ibc/",
    b"cosmos1",
    b"cosmosvaloper1",
    b"osmo1",
    b"type",
    b"value",
    b"cosmos-sdk/MsgSend",
    b"cosmos-sdk/MsgTransfer",
    b"cosmos-sdk/MsgVote",
    b"channel-141",
    b"timeout_height",
    b"\xe2\x80\xa8",
    b"\xff",
];

fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    for _ in 0..1 + rng.below(3) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 => b.truncate(rng.below(b.len() + 1)),
            2 if !b.is_empty() => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            // a piece of what sign docs are made of, put in, or put in place of a byte
            3 | 4 => {
                let i = rng.below(b.len() + 1);
                let piece = PIECES[rng.below(PIECES.len())];
                if rng.below(2) == 0 && i < b.len() {
                    b.remove(i);
                }
                b.splice(i..i, piece.iter().copied());
            }
            // a digit changed: an amount, a height, an address's character
            _ if !b.is_empty() => {
                let i = rng.below(b.len());
                if b[i].is_ascii_alphanumeric() {
                    b[i] = b"0123456789qpzry9x8gf2tvdw0s3jn54khce6mua7l"[rng.below(42)];
                }
            }
            _ => {}
        }
    }
    b
}

#[test]
fn nothing_the_computer_sends_panics() {
    let me =
        parse_address(chains::hub(Network::Main), "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4").unwrap();
    // CosmJS's sign docs, and the chains' own
    let mut real: Vec<Vec<u8>> = Vec::new();
    for file in ["signdocs.json", "onchain.json"] {
        let text =
            std::fs::read_to_string(format!("{}/tests/fixtures/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        real.extend(json.as_array().unwrap().iter().map(|f| f["doc"].as_str().unwrap().as_bytes().to_vec()));
    }
    let mut rng = Rng(0x5eed118);
    let (mut read, mut reviewed) = (0, 0);
    for round in 0..40_000 {
        let bytes = if round % 8 == 0 {
            (0..rng.below(300)).map(|_| rng.next() as u8).collect()
        } else {
            let base = &real[rng.below(real.len())];
            mutate(&mut rng, base)
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let text = String::from_utf8_lossy(&bytes);
            let _ = bech32::decode(&text);
            if let Ok(value) = json::parse(&bytes) {
                // the one way of writing it
                assert_eq!(json::write(&value).as_bytes(), &bytes[..]);
            }
            match SignDoc::parse(&bytes) {
                Ok(doc) => {
                    let network = if round % 2 == 0 { Network::Main } else { doc.chain.network };
                    (1, review(&doc, &me, network).map(|r| assert!(r.summary.len() <= 128)).is_ok() as usize)
                }
                Err(e) => {
                    let _ = e.to_string();
                    (0, 0)
                }
            }
        }));
        let (r, v) = outcome.unwrap_or_else(|_| panic!("panicked on {:?}", String::from_utf8_lossy(&bytes)));
        read += r;
        reviewed += v;
    }
    // the mutations reach the review, not just the parser
    assert!(read > 2_000 && reviewed > 1_000, "{read} read, {reviewed} reviewed");
}
