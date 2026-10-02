//! TON requests come to maki from a computer that may lie: anything, however broken, must get an
//! error or a review, never a panic. Random bytes, mutations of real bags of cells (bytes changed,
//! dropped and added; descriptors, counts and references made into others), and addresses made of
//! anything.

use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_ton::display::review;
use maki_ton::{Address, Boc, Network, Request};

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
            // the bytes descriptors, counts and references are made of
            4 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0, 1, 2, 3, 4, 5, 7, 8, 9, 0x10, 0x20, 0x28, 0x7f, 0x80, 0xff][rng.below(15)];
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

/// A BOC's CRC32C made right again, so a mutation reaches past the checksum.
fn recrc(b: &mut [u8]) {
    if b.len() > 8 && b[4] & 0x40 != 0 {
        let n = b.len() - 4;
        let c = maki_ton::cell::crc32c(&b[..n]);
        b[n..].copy_from_slice(&c.to_le_bytes());
    }
}

#[test]
fn nothing_a_computer_sends_panics() {
    let me: [u8; 32] =
        unhex("b8c2336996bd97a7789b6deec787797961856628ee518694152ae056387fc9af").try_into().unwrap();
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> = json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|f| [unhex(f["boc"].as_str().unwrap()), unhex(f["external"].as_str().unwrap())])
        .collect();
    let mut rng = Rng(0x5eed_70e5);
    let (mut read, mut reviewed) = (0, 0);
    for round in 0..60_000 {
        let bytes = if round % 8 == 0 {
            (0..rng.below(600)).map(|_| rng.next() as u8).collect()
        } else {
            let base = &real[rng.below(real.len())];
            let mut b = mutate(&mut rng, base);
            if round % 2 == 1 {
                recrc(&mut b);
            }
            b
        };
        let network = if round % 2 == 0 { Network::Main } else { Network::Test };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let Ok(boc) = Boc::parse(&bytes) else { return (false, false) };
            let Ok(request) = Request::parse(&boc) else { return (true, false) };
            (true, review(&request, &me, network).is_ok())
        }));
        let (r, v) = outcome.unwrap_or_else(|_| {
            panic!("panicked on {}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
        });
        read += r as usize;
        reviewed += v as usize;
    }
    // the mutations reach past the checksum and the header, and some still make sense
    assert!(read > 3_000 && reviewed > 500, "{read} {reviewed}");
}

#[test]
fn no_address_panics() {
    let mut rng = Rng(0x0add_2e55);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/:";
    let real = "UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOpj";
    for round in 0..20_000 {
        let text: String = if round % 2 == 0 {
            (0..rng.below(70)).map(|_| alphabet[rng.below(alphabet.len())] as char).collect()
        } else {
            let mut t: Vec<u8> = real.bytes().collect();
            let i = rng.below(t.len());
            t[i] = alphabet[rng.below(alphabet.len())];
            String::from_utf8(t).unwrap()
        };
        let _ = catch_unwind(|| Address::parse(&text)).unwrap_or_else(|_| panic!("panicked on {text}"));
    }
}
