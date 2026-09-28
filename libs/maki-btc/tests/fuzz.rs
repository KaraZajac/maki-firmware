//! What the computer sends maki is parsed on maki, where a panic takes the service down: the
//! parsers and the review must answer anything, however broken, with an error, never a panic.
//! Random bytes and mutations of real PSBTs (flipped bits, cut short, bytes inserted and
//! dropped), deterministically.

use std::panic::{catch_unwind, AssertUnwindSafe};

use maki_btc::psbt::Psbt;
use maki_btc::tx::Tx;
use maki_btc::{wallet, Account, Network};
use maki_hd::seed::SeedKeys;

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
            _ if !b.is_empty() => {
                // a length or count byte set large
                let i = rng.below(b.len());
                b[i] = [0xfd, 0xfe, 0xff, 0x00, 0x7f][rng.below(5)];
            }
            _ => {}
        }
    }
    b
}

/// maki's keys for a seed, for as long as the tests run.
fn keys(seed: &[u8]) -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(seed).unwrap())) }

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[test]
fn nothing_the_computer_sends_panics_the_wallet() {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ').collect();
    let account = Account::segwit(keys(&maki_seed::seed(&words, "")), Network::Bitcoin).unwrap();
    let unsigned = std::fs::read(format!("{FIXTURES}/abandon-unsigned.psbt")).unwrap();
    let signed = std::fs::read(format!("{FIXTURES}/abandon-signed.psbt")).unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut parsed, mut reviewed) = (0, 0);
    for i in 0..20_000 {
        let input = match i % 4 {
            0 => (0..rng.below(300)).map(|_| rng.next() as u8).collect(),
            1 => mutate(&mut rng, &signed),
            _ => mutate(&mut rng, &unsigned),
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = Tx::parse(&input);
            if let Ok(mut psbt) = Psbt::parse(&input) {
                parsed += 1;
                let _ = psbt.serialize();
                if wallet::review(&psbt, std::slice::from_ref(&account)).is_ok() {
                    reviewed += 1;
                }
                let _ = wallet::sign(&mut psbt, std::slice::from_ref(&account));
            }
        }));
        assert!(outcome.is_ok(), "panicked on {:02x?}", input);
    }
    // the mutations reach the review, not only the parser's first checks
    assert!(parsed > 1000 && reviewed > 10, "parsed {parsed}, reviewed {reviewed}");
}
