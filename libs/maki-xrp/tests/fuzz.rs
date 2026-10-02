//! XRP Ledger transactions are read on maki: anything, however broken, must get an error or a
//! review, never a panic. Random bytes, and mutations of real ones.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_xrp::display::review;
use maki_xrp::{Network, Transaction, address, codec, sign};

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
            2 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                b.remove(i);
            }
            // a piece of the transaction again, somewhere else: a field twice, or out of order
            4 if b.len() > 2 => {
                let (from, n) = (rng.below(b.len() - 1), 1 + rng.below(24));
                let piece = b[from..(from + n).min(b.len())].to_vec();
                let at = rng.below(b.len() + 1);
                b.splice(at..at, piece);
            }
            // the bytes headers, lengths and amounts are made of
            _ if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0x00, 0x01, 0x0f, 0x10, 0x40, 0x7f, 0x80, 0xc0, 0xe1, 0xf1, 0xff][rng.below(11)];
            }
            _ => {}
        }
    }
    b
}

/// Whether a review fits maki's review screen, as its host takes one: as `tests/xrp.rs` has it.
fn fits(r: &maki_xrp::display::Review) -> Result<(), String> {
    let plain = |t: &str| !t.chars().any(|c| c.is_control());
    let lines = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
    if r.summary.len() > 128 || !plain(&r.summary) || r.pages.len() > 128 {
        return Err(r.summary.clone());
    }
    let mut total = r.summary.len() + 32;
    for p in &r.pages {
        if p.heading.trim().is_empty()
            || p.heading.len() > 32
            || p.value.len() > 128
            || p.mono.len() > 4096
            || p.prose.len() > 4096
            || !plain(&p.heading)
            || !plain(&p.value)
            || !lines(&p.mono)
            || !lines(&p.prose)
        {
            return Err(format!("{p:?}"));
        }
        total += 4 + p.heading.len() + p.value.len() + p.mono.len() + p.prose.len();
    }
    if total > 16 * 1024 { Err(format!("{total} bytes")) } else { Ok(()) }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn nothing_a_computer_sends_panics() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let read_all = |list: &str| -> Vec<Vec<u8>> {
        json[list].as_array().unwrap().iter().map(|t| unhex(t["transaction"].as_str().unwrap())).collect()
    };
    // what maki shows, and what it refuses
    let (shown, refused) = (read_all("transactions"), read_all("refused"));
    let key: [u8; 33] =
        unhex("031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE").try_into().unwrap();
    let mut rng = Rng(0x5eed_0144);
    let (mut read, mut reviewed) = (0, 0);
    for round in 0..40_000 {
        let bytes = match round % 8 {
            0 => (0..rng.below(300)).map(|_| rng.next() as u8).collect(),
            1 => {
                let base = &refused[rng.below(refused.len())];
                mutate(&mut rng, base)
            }
            _ => {
                let base = &shown[rng.below(shown.len())];
                mutate(&mut rng, base)
            }
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = address::decode(&String::from_utf8_lossy(&bytes));
            let _ = sign::with_signature(&bytes, &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
            let _ = codec::read(&bytes);
            match Transaction::parse(&bytes) {
                Ok(tx) => {
                    let network = if round % 2 == 0 { Network::Main } else { Network::Test };
                    match review(&tx, &key, network) {
                        // whatever's shown fits maki's screen
                        Ok(r) => (1, fits(&r).map(|_| 1).unwrap_or_else(|e| panic!("doesn't fit: {e}"))),
                        Err(_) => (1, 0),
                    }
                }
                Err(_) => (0, 0),
            }
        }));
        let (r, v) = outcome.unwrap_or_else(|_| panic!("panicked on {bytes:02x?}"));
        read += r;
        reviewed += v;
    }
    // the mutations reach the review, not just the parser
    assert!(read > 2_000 && reviewed > 1_000, "{read} read, {reviewed} reviewed");
}
