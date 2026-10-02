//! What the Kaspa app is asked to sign comes from a computer that may lie: anything, however broken,
//! must get an error or a review, never a panic. Random bytes, and mutations of real requests; and
//! addresses, and the claims the app keeps, read back from whatever is there.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use maki_hd::seed::SeedKeys;
use maki_hd::{Error, Keys, Public, Tweak};
use maki_kas::claims::Claims;
use maki_kas::{Account, Network, Request, address, display};

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
            // the bytes counts, flags, chains and versions are made of
            _ if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = [0x00, 0x01, 0x02, 0x7f, 0x80, 0xff][rng.below(6)];
            }
            _ => {}
        }
    }
    b
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The test phrase's keys where the fixtures have them, made once; anywhere else, a key that's no
/// one's (the checks only compare scripts), so the rounds aren't spent on curve arithmetic.
struct Quick {
    seed: SeedKeys,
    known: HashMap<Vec<u32>, Public>,
}

impl Keys for Quick {
    fn fingerprint(&self) -> Result<[u8; 4], Error> { self.seed.fingerprint() }

    fn public(&self, path: &[u32]) -> Result<Public, Error> {
        if let Some(p) = self.known.get(path) {
            return Ok(*p);
        }
        let mut key = [2u8; 33];
        for (i, b) in key[1..].iter_mut().enumerate() {
            *b = path.iter().fold(i as u32 * 131, |a, &n| a.rotate_left(5) ^ n) as u8;
        }
        Ok(Public { key, chain_code: [0; 32], parent_fingerprint: [0; 4] })
    }

    fn uncompressed(&self, path: &[u32]) -> Result<[u8; 65], Error> { self.seed.uncompressed(path) }

    fn taproot_output(&self, path: &[u32]) -> Result<[u8; 32], Error> { self.seed.taproot_output(path) }

    fn sign_ecdsa(&self, path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), Error> {
        self.seed.sign_ecdsa(path, digest)
    }

    fn sign_schnorr(&self, path: &[u32], digest: &[u8; 32], tweak: Tweak) -> Result<[u8; 64], Error> {
        self.seed.sign_schnorr(path, digest, tweak)
    }
}

#[test]
fn nothing_a_computer_sends_panics() {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let seed = SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap();
    let mut known = HashMap::new();
    for chain in 0..2u32 {
        for index in 0..48u32 {
            let path = maki_kas::wallet::ACCOUNT.iter().copied().chain([chain, index]).collect::<Vec<_>>();
            known.insert(path.clone(), seed.public(&path).unwrap());
        }
    }
    known.insert(maki_kas::wallet::ACCOUNT.to_vec(), seed.public(&maki_kas::wallet::ACCOUNT).unwrap());
    let keys = Quick { seed, known };
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let real: Vec<Vec<u8>> = json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| unhex(f["request"].as_str().unwrap()))
        .collect();
    let addresses: Vec<String> =
        json["addresses"].as_array().unwrap().iter().map(|a| a["address"].as_str().unwrap().into()).collect();
    let mut rng = Rng(0x5eed6a5);
    let (mut read, mut reviewed, mut signed) = (0, 0, 0);
    for round in 0..40_000 {
        let bytes = if round % 8 == 0 {
            (0..rng.below(600)).map(|_| rng.next() as u8).collect()
        } else {
            let base = &real[rng.below(real.len())];
            mutate(&mut rng, base)
        };
        let network = if round % 2 == 0 { Network::Mainnet } else { Network::Testnet };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = Claims::read(&bytes);
            let text = String::from_utf8_lossy(&bytes);
            let _ = address::decode(&text);
            let a = &addresses[round % addresses.len()];
            let _ =
                address::decode(&String::from_utf8_lossy(&mutate(&mut Rng(round as u64 + 1), a.as_bytes())));
            let Ok(request) = Request::parse(&bytes) else { return (0, 0, 0) };
            let account = Account::new(&keys, network).unwrap();
            let mut claims = Claims::default();
            claims.add(&request);
            let _ = claims.check(&request);
            match account.check(&request) {
                Ok(checked) => {
                    let review = display::review(&checked);
                    assert!(review.summary.len() <= display::MAX_SUMMARY);
                    let sign = round % 64 == 1;
                    if sign {
                        assert_eq!(account.sign(&checked).unwrap().len(), request.inputs.len());
                    }
                    (1, 1, sign as usize)
                }
                Err(_) => (1, 0, 0),
            }
        }));
        let (r, v, s) = outcome.unwrap_or_else(|_| panic!("panicked on {bytes:02x?}"));
        read += r;
        reviewed += v;
        signed += s;
    }
    // the mutations reach the review and the signatures, not just the parser
    assert!(
        read > 2_000 && reviewed > 1_000 && signed > 10,
        "{read} read, {reviewed} reviewed, {signed} signed"
    );
}
