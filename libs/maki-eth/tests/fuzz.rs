//! Ethereum transactions, messages and typed data from sites are parsed on maki: anything,
//! however broken, must get an error, never a panic. Random bytes, and mutations of real ones.

use std::panic::{catch_unwind, AssertUnwindSafe};

use maki_eth::{display, json, rlp, Account, Tx, TypedData};
use maki_hd::seed::{OneKey, SeedKeys};

/// maki's keys for a seed, for as long as the tests run.
fn keys(seed: &[u8]) -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(seed).unwrap())) }

/// One bare private key, as other software makes them, at every path.
fn one(secret: &[u8; 32]) -> &'static OneKey { Box::leak(Box::new(OneKey::new(secret).unwrap())) }

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
    let account = Account::new(keys(&maki_seed::seed(&words, "")), 0).unwrap();
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

/// Typed data to start from: a permit, Permit2's batch and one with arrays of structs.
const TYPED: [&str; 3] = [
    r#"{"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
      "Permit": [{"name": "owner", "type": "address"}, {"name": "spender", "type": "address"}, {"name": "value", "type": "uint256"},
        {"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}]},
     "primaryType": "Permit", "domain": {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"},
     "message": {"owner": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "spender": "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad",
       "value": "1000", "nonce": 0, "deadline": 1790000000}}"#,
    r#"{"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
      "PermitDetails": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint160"}, {"name": "expiration", "type": "uint48"}, {"name": "nonce", "type": "uint48"}],
      "PermitBatch": [{"name": "details", "type": "PermitDetails[]"}, {"name": "spender", "type": "address"}, {"name": "sigDeadline", "type": "uint256"}]},
     "primaryType": "PermitBatch", "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"},
     "message": {"details": [{"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "amount": "0xffff", "expiration": "1790000000", "nonce": 0}],
       "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", "sigDeadline": "1790001800"}}"#,
    r#"{"types": {"EIP712Domain": [{"name": "name", "type": "string"}],
      "Item": [{"name": "id", "type": "int64"}, {"name": "tags", "type": "string[]"}, {"name": "blob", "type": "bytes"}, {"name": "b4", "type": "bytes4"}],
      "Order": [{"name": "items", "type": "Item[2]"}, {"name": "grid", "type": "uint8[2][]"}, {"name": "ok", "type": "bool"}]},
     "primaryType": "Order", "domain": {"name": "Shop"},
     "message": {"items": [{"id": -5, "tags": ["a", "é"], "blob": "0x00ff", "b4": "0x01020304"}, {"id": "0x10", "tags": [], "blob": "0x", "b4": "0x00000000"}],
       "grid": [[1, 2], [3, 4]], "ok": true}}"#,
];

/// Mutations that keep to JSON's alphabet, so more of them get far into the parser.
fn mutate_json(rng: &mut Rng, base: &str) -> String {
    const PIECES: [&str; 16] = ["{", "}", "[", "]", ",", ":", "\"", "\\u", "-", "0x", "1", "99999999999999999999999999999999999999999999999999999999999999999999999999999", "null", "[]", "\"uint256\"", "\"Item[]\""];
    let mut b = base.as_bytes().to_vec();
    // mostly one change: more of them still parse, and reach the checks on types and values
    for _ in 0..if rng.below(4) == 0 { 2 + rng.below(2) } else { 1 } {
        let i = rng.below(b.len() + 1);
        match rng.below(3) {
            0 => {
                let piece = PIECES[rng.below(PIECES.len())].as_bytes();
                b.splice(i..i, piece.iter().copied());
            }
            1 if i < b.len() => {
                let end = (i + 1 + rng.below(8)).min(b.len());
                b.drain(i..end);
            }
            _ => b = mutate(rng, &b),
        }
    }
    String::from_utf8_lossy(&b).into_owned()
}

#[test]
fn no_typed_data_a_site_sends_panics_the_account() {
    for t in TYPED {
        assert!(TypedData::parse(t).is_ok(), "{}", t);
    }
    let account = Account::new(one(&[9u8; 32]), 0).unwrap();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut parsed, mut reviewed) = (0, 0);
    for i in 0..30_000 {
        let input = match i % 4 {
            0 => String::from_utf8_lossy(&(0..rng.below(120)).map(|_| rng.next() as u8).collect::<Vec<u8>>()).into_owned(),
            n => mutate_json(&mut rng, TYPED[n - 1]),
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = json::parse(&input);
            if let Ok(td) = TypedData::parse(&input) {
                parsed += 1;
                if display::typed_review(&td).is_ok() {
                    reviewed += 1;
                }
                let _ = account.sign_typed(&td);
            }
        }));
        assert!(outcome.is_ok(), "panicked on {}", input);
    }
    assert!(parsed > 300 && reviewed > 300, "parsed {parsed}, reviewed {reviewed}");
}
