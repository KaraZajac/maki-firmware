//! Aptos transactions are read on maki from whatever the computer sends: anything, however broken,
//! must get an error or a review, never a panic. Random bytes, and mutations of real ones.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_apt::display::review;
use maki_apt::{Network, Transaction, parse_address};

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
    for _ in 0..1 + rng.below(3) {
        match rng.below(6) {
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
            // the bytes variants, lengths, options and type tags are made of
            4 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0x00, 0x01, 0x02, 0x04, 0x06, 0x07, 0x0b, 0x20, 0x7f, 0x80, 0xff][rng.below(11)];
            }
            // a byte past the sender and sequence number changed: the change reaches the payload
            _ if b.len() > 48 => {
                let i = 40 + rng.below(b.len() - 40);
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
fn nothing_the_computer_sends_panics() {
    let me = parse_address("0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf").unwrap();
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> =
        json["transactions"].as_array().unwrap().iter().map(|f| unhex(f["raw"].as_str().unwrap())).collect();
    let mut rng = Rng(0x5eed637);
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
            let _ = parse_address(&text);
            let _ = parse_address(&format!("0x{}", text.chars().take(64).collect::<String>()));
            match Transaction::parse(&bytes) {
                Ok(tx) => {
                    let network = if round % 2 == 0 { Network::Mainnet } else { Network::Testnet };
                    let now = (round % 3 == 0).then_some(rng.next() >> 30);
                    (1, review(&tx, &me, network, now).is_ok() as usize)
                }
                Err(e) => {
                    let _ = e.to_string();
                    (0, 0)
                }
            }
        }));
        let (r, v) = outcome.unwrap_or_else(|_| panic!("panicked on {bytes:02x?}"));
        read += r;
        reviewed += v;
    }
    // the mutations reach the review, not just the parser
    assert!(read > 2_000 && reviewed > 1_000, "{read} read, {reviewed} reviewed");
}
