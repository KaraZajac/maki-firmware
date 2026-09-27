//! Ethereum transactions and messages from sites are parsed on maki: anything, however broken,
//! must get an error, never a panic. Random bytes, and mutations of a real transaction.

use std::panic::{catch_unwind, AssertUnwindSafe};

use maki_eth::{display, rlp, Account, Tx};

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
                let i = rng.below(b.len());
                b[i] = [0xb8, 0xbf, 0xf8, 0xff, 0x80, 0xc0][rng.below(6)];
            }
            _ => {}
        }
    }
    b
}

#[test]
fn nothing_a_site_sends_panics_the_account() {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
    let unsigned = std::fs::read(format!("{fixtures}/abandon-tx-unsigned.bin")).unwrap();
    // a token transfer and an approval too: calls the review spells out
    let mut calls = Vec::new();
    for selector in [[0xa9u8, 0x05, 0x9c, 0xbb], [0x09, 0x5e, 0xa7, 0xb3], [0xa2, 0x2c, 0xb4, 0x65]] {
        let mut data = selector.to_vec();
        data.extend([0u8; 12]);
        data.extend([0x11; 20]);
        data.extend([0u8; 31]);
        data.push(1);
        let mut payload = Vec::new();
        for f in [&[1u8][..], &[7], &[1], &[2], &[0x52, 0x08], &[0x22; 20], &[], &data[..]] {
            rlp::encode_bytes(&mut payload, f);
        }
        rlp::encode_list(&mut payload, &[]);
        let mut tx = vec![0x02];
        rlp::encode_list(&mut tx, &payload);
        assert!(Tx::parse(&tx).is_ok());
        calls.push(tx);
    }
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ').collect();
    let account = Account::from_seed(&maki_seed::seed(&words, ""), 0).unwrap();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let (mut parsed, mut reviewed) = (0, 0);
    for i in 0..30_000 {
        let input = match i % 5 {
            0 => (0..rng.below(200)).map(|_| rng.next() as u8).collect(),
            1 => mutate(&mut rng, &unsigned),
            n => mutate(&mut rng, &calls[n - 2]),
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = rlp::decode(&input);
            let _ = display::message(&input);
            if let Ok(tx) = Tx::parse(&input) {
                parsed += 1;
                if display::review(&tx).is_ok() {
                    reviewed += 1;
                }
                let _ = tx.sign(&account);
            }
        }));
        assert!(outcome.is_ok(), "panicked on {:02x?}", input);
    }
    assert!(parsed > 500 && reviewed > 500, "parsed {parsed}, reviewed {reviewed}");
}
