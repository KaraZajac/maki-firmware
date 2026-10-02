//! Cardano transactions are read on maki from whatever the computer sends: anything, however
//! broken, must get an error or a review, never a panic. Random bytes, and mutations of real ones
//! (CSL's bodies, and requests made of them).

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_ada::display::{Account, Own, review};
use maki_ada::{Address, Body, Key, Network, Request, address};

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
            // the bytes CBOR's heads are made of: small numbers, lengths, tags, the long forms
            4 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [
                    0x00, 0x01, 0x07, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x40, 0x58, 0x80, 0x82, 0x9f, 0xa0, 0xd8,
                    0xd9, 0xff,
                ][rng.below(17)];
            }
            // a value changed but not its length: the change reaches an address, an amount, a hash
            _ if b.len() > 40 => {
                let i = 20 + rng.below(b.len() - 20);
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
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> =
        json["transactions"].as_array().unwrap().iter().map(|f| unhex(f["body"].as_str().unwrap())).collect();
    // the account the fixtures are this account's for: its stake key's hash, and its change key's
    let stake: [u8; 28] =
        unhex("e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d176").try_into().unwrap();
    let change: [u8; 28] =
        unhex("2d7eb5736483635fda3206fdf2b7e60ab41def32a068033b997823ca").try_into().unwrap();
    let mut rng = Rng(0xada_5eed);
    let (mut read, mut reviewed, mut requests) = (0, 0, 0);
    for round in 0..40_000 {
        let bytes = if round % 8 == 0 {
            (0..rng.below(400)).map(|_| rng.next() as u8).collect()
        } else {
            let base = &real[rng.below(real.len())];
            mutate(&mut rng, base)
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let text = String::from_utf8_lossy(&bytes);
            let _ = Address::parse(&bytes);
            let _ = Address::from_text(&text).map(|a| a.text());
            let _ = address::from_bech32(&text);
            let _ = Request::parse(&bytes);
            // as a request's body: one key to sign with, its last output said to be change
            let request = [&[1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0][..], &bytes].concat();
            let request = Request::parse(&request).is_ok() as usize;
            let (read, reviewed) = match Body::parse(&bytes) {
                Ok(body) => {
                    let network = if round % 2 == 0 { Network::Mainnet } else { Network::Preprod };
                    let own = [Own {
                        output: body.outputs.len().saturating_sub(1),
                        key: Key { role: 1, index: 0 },
                        payment: change,
                    }];
                    let own = if round % 3 == 0 { &own[..] } else { &[] };
                    let now = (round % 5 == 0).then_some(rng.next() >> 30);
                    match review(&body, &Account { network, stake }, own, 1 + round % 3, now) {
                        Ok(r) => {
                            assert!(r.summary.len() <= maki_ada::display::MAX_SUMMARY);
                            (1, 1)
                        }
                        Err(e) => {
                            let _ = e.to_string();
                            (1, 0)
                        }
                    }
                }
                Err(e) => {
                    let _ = e.to_string();
                    (0, 0)
                }
            };
            (read, reviewed, request)
        }));
        let (a, b, c) = outcome.unwrap_or_else(|_| panic!("panicked on {bytes:02x?}"));
        read += a;
        reviewed += b;
        requests += c;
    }
    // the mutations reach the review, not just the parser
    assert!(
        read > 2_000 && reviewed > 1_000 && requests > 1_000,
        "{read} read, {reviewed} reviewed, {requests}"
    );
}
