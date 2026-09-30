//! Real exchanges with three public servers, captured 2026-09-26 with a draft-19 request.

use roughtime::{Error, REQUEST_LEN, Verified, request, verify};

const SERVERS: [&str; 3] = ["time_txryan_com", "roughtime_se", "roughtime_int08h_com"];

fn vector(name: &str) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/");
    let req = std::fs::read(format!("{dir}{name}.req")).unwrap();
    let resp = std::fs::read(format!("{dir}{name}.resp")).unwrap();
    let key_b64 = std::fs::read_to_string(format!("{dir}{name}.key")).unwrap();
    (req, resp, decode_key(key_b64.trim()))
}

fn decode_key(b64: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in b64.bytes().filter(|&c| c != b'=') {
        bits = (bits << 6) | ALPHABET.iter().position(|&a| a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out.try_into().unwrap()
}

#[test]
fn all_three_servers_verify_and_agree() {
    let times: Vec<Verified> = SERVERS
        .iter()
        .map(|s| {
            let (req, resp, key) = vector(s);
            verify(&req, &resp, &key).unwrap_or_else(|e| panic!("{s}: {e:?}"))
        })
        .collect();
    for t in &times {
        assert_eq!(t.midpoint, 1_790_399_658, "2026-09-26 05:14:18 UTC");
        assert!(t.radius <= 5);
    }
}

#[test]
fn our_encoder_matches_what_the_servers_accepted() {
    for s in SERVERS {
        let (req, _, _) = vector(s);
        assert_eq!(req.len(), REQUEST_LEN);
        let nonce: [u8; 32] = req[12 + 32 + 4..12 + 32 + 36].try_into().unwrap();
        assert_eq!(request(&nonce).as_slice(), req.as_slice(), "{s}");
    }
}

#[test]
fn wrong_server_key_is_rejected() {
    let (req, resp, _) = vector("time_txryan_com");
    let (_, _, other) = vector("roughtime_se");
    assert_eq!(verify(&req, &resp, &other), Err(Error::Delegation));
}

#[test]
fn answer_to_someone_elses_request_is_rejected() {
    let (_, resp, key) = vector("time_txryan_com");
    let mine = request(&[7u8; 32]);
    assert_eq!(verify(&mine, &resp, &key), Err(Error::Nonce));
}

#[test]
fn same_nonce_different_request_bytes_fail_the_proof() {
    // a relay that keeps the nonce but alters the rest of the packet can't reuse the answer
    let (mut req, resp, key) = vector("roughtime_se");
    let last = req.len() - 1;
    req[last] ^= 1;
    assert_eq!(verify(&req, &resp, &key), Err(Error::Proof));
}

#[test]
fn every_single_byte_flip_in_a_response_is_caught() {
    let (req, resp, key) = vector("roughtime_int08h_com");
    for i in 0..resp.len() {
        let mut bad = resp.clone();
        bad[i] ^= 0x01;
        assert!(verify(&req, &bad, &key).is_err(), "flip at byte {i} was accepted");
    }
}

#[test]
fn truncated_and_oversized_responses_are_rejected() {
    let (req, resp, key) = vector("time_txryan_com");
    for cut in [0, 7, 11, 12, resp.len() / 2, resp.len() - 1] {
        assert!(verify(&req, &resp[..cut], &key).is_err(), "truncated to {cut}");
    }
    assert_eq!(verify(&req, &vec![0u8; 4096], &key), Err(Error::Framing));
}
