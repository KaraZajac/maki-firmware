//! NEAR transactions are read on maki from whatever the computer sends: anything, however broken,
//! must get an error or a review, never a panic. Random bytes, and mutations of real ones; and a
//! call's arguments, which maki reads as JSON.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_near::display::review;
use maki_near::{Network, Transaction, account, json};

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
            // the bytes tags, lengths and JSON are made of
            4 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] =
                    [0x00, 0x01, 0x02, 0x03, 0x0a, 0x7f, 0x80, 0xff, b'"', b'{', b'\\', b'.'][rng.below(12)];
            }
            // a byte past the signer and its key changed: the change reaches the actions
            _ if b.len() > 120 => {
                let i = 110 + rng.below(b.len() - 110);
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
    let me: [u8; 32] =
        unhex("5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412").try_into().unwrap();
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> = json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| unhex(f["transaction"].as_str().unwrap()))
        .collect();
    let mut rng = Rng(0x5eed397);
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
            let _ = account::valid(&text);
            let _ = account::kind(&text);
            let _ = json::parse(&bytes).map(|v| v.members().is_some());
            match Transaction::parse(&bytes) {
                Ok(tx) => {
                    let network = if round % 2 == 0 { Network::Mainnet } else { Network::Testnet };
                    (1, review(&tx, &me, network).is_ok() as usize)
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

#[test]
fn no_arguments_panic() {
    // JSON as calls carry it, mutated
    let real: [&[u8]; 4] = [
        br#"{"receiver_id":"bob.near","amount":"5250000","memo":"invoice \u00e9 42"}"#,
        br#"{"actions":[{"pool_id":79,"token_in":"wrap.near","amount_in":"1e24","min_amount_out":"1"}],"x":[true,false,null,-1.5e-3]}"#,
        br#"{"account_id":null,"registration_only":true}"#,
        br#"["\ud83d\ude00",{"a":{"b":[[[]]]}},"\"\\\/\b\f\n\r\t"]"#,
    ];
    let mut rng = Rng(0x15011);
    for _ in 0..40_000 {
        let base = real[rng.below(real.len())];
        let bytes = mutate(&mut rng, base);
        let outcome =
            catch_unwind(AssertUnwindSafe(|| json::parse(&bytes).map(|v| v.members().map(|m| m.len()))));
        outcome.unwrap_or_else(|_| panic!("panicked on {:?}", String::from_utf8_lossy(&bytes)));
    }
}
