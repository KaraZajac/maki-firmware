//! The XRP app (sdk/examples/xrp), run as maki runs it: the account shared and compared once its
//! owner says, and transactions xrpl.js made (maki-xrp's fixtures) shown and signed as xrpl.js
//! signs them, or refused with why before anything is shown.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's first account, as xrpl.js derives it and Ripple's Xpring SDK published it.
const ME: &str = "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3";
const KEY: &str = "031D68BC1A142E6766B2BDFB006CCFE135EF2E0E2E94ABB5CF5C9AB6104776FBAE";
/// Its second (account 1, `m/44'/144'/1'/0/0`).
const SECOND: &str = "rNAB7uPziNwZAkdzyeo6xRA9pKTsJxZ6td";

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-xrp/tests/fixtures/transactions.json");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(FIXTURES).unwrap()).unwrap()
}

/// A transaction xrpl.js made, unsigned, and xrpl.js's signature of it for this account (if
/// this account signs it).
fn fixture(name: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let json = fixtures();
    let mut all = json["transactions"].as_array().unwrap().iter().chain(json["refused"].as_array().unwrap());
    let t = all.find(|t| t["name"] == name).unwrap();
    (unhex(t["transaction"].as_str().unwrap()), t["signature"].as_str().map(unhex))
}

/// A message to the app: what it is, the network, the account, and what follows.
fn message(kind: u8, network: u8, account: u32, rest: &[u8]) -> Vec<u8> {
    [&[kind, network][..], &account.to_le_bytes(), rest].concat()
}

/// A string16 at `at` in an answer, and where what follows starts.
fn string16(answer: &[u8], at: usize) -> (String, usize) {
    let n = u16::from_le_bytes([answer[at], answer[at + 1]]) as usize;
    (String::from_utf8(answer[at + 2..at + 2 + n].to_vec()).unwrap(), at + 2 + n)
}

#[test]
fn xrp_shares_its_account_once_asked() {
    let r = run_wallet(
        "xrp",
        vec![message(b'A', 0, 0, &[]), message(b'A', 1, 2, &[]), message(b'A', 0, 0, &[])],
        vec![Answer::Yes, Answer::Yes, Answer::No],
        false,
    );
    // the key as its transactions carry it, then the address
    let a = &r.replies[0];
    assert_eq!((a[0], a[1]), (0, 33));
    assert_eq!(a[2..35], unhex(KEY));
    assert_eq!(string16(a, 35), (ME.to_string(), a.len()));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "xrp, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    assert!(review.pages.is_empty());
    // the test network's account 2: its own key, its own words
    assert_eq!(r.reviews[1].detail, "xrp testnet account #2, view only");
    assert_eq!(r.replies[1][0], 0);
    assert_ne!(r.replies[1][2..35], unhex(KEY));
    // a no shares nothing
    assert_eq!(r.replies[2], [1]);
    // locked: nothing to share, and nothing asked
    let r = run_wallet("xrp", vec![message(b'A', 0, 0, &[])], vec![Answer::Yes], true);
    assert_eq!((r.replies[0].as_slice(), r.reviews.len()), (&[3u8][..], 0));
    // what isn't a message of the app's: another network, an account past the hardened ones, more
    // after it, a kind there isn't, too short, too long
    let bad = vec![
        message(b'A', 2, 0, &[]),
        message(b'A', 0, 0x8000_0000, &[]),
        message(b'A', 0, 0, &[0]),
        message(b'Z', 0, 0, &[]),
        vec![b'A', 0, 0],
        vec![],
        message(b'T', 0, 0, &[0x61; 4091]),
    ];
    let r = run_wallet("xrp", bad, vec![], false);
    assert!(r.replies.iter().all(|a| a == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

#[test]
fn xrp_shows_its_address_to_compare() {
    let r = run_wallet(
        "xrp",
        vec![message(b'D', 0, 0, &[]), message(b'D', 1, 1, &[]), message(b'D', 0, 0, &[])],
        vec![Answer::Yes, Answer::No, Answer::NoAnswer],
        false,
    );
    // the owner's answer, then the address either way
    assert_eq!((r.replies[0][0], string16(&r.replies[0], 1).0), (0, ME.to_string()));
    assert_eq!((r.replies[1][0], string16(&r.replies[1], 1).0), (1, SECOND.to_string()));
    assert_eq!((r.replies[2][0], string16(&r.replies[2], 1).0), (2, ME.to_string()));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Same on computer?", "matches", "doesn't match")
    );
    let page = &review.pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str(), page.mono.as_str()), ("Account #0", "xrp", ME));
    assert_eq!(
        (r.reviews[1].pages[0].heading.as_str(), r.reviews[1].pages[0].value.as_str()),
        ("Account #1", "xrp testnet")
    );
    let r = run_wallet("xrp", vec![message(b'D', 0, 0, &[])], vec![], true);
    assert_eq!(r.replies[0], [3]);
}

#[test]
fn xrp_signs_what_the_owner_read_as_xrpl_js_signs_it() {
    let (tx, signature) = fixture("xrp-tag-memo");
    let signature = signature.unwrap();
    let r = run_wallet("xrp", vec![message(b'T', 0, 0, &tx)], vec![Answer::Yes], false);
    // its signature, DER, after its length: xrpl.js's, byte for byte
    assert_eq!(r.replies[0], [&[0, signature.len() as u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 12.5 XRP; fee 0.000012 XRP")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Send", "12.5 XRP", "rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA"),
            ("Destination tag", "4242", ""),
            ("Invoice", "", "6F1DFD1D0FE8A32E40E1F2C05CF1C15545BAB56B617F9C6C2D63A6B704BEF59B"),
            ("Memo 1", "", "thanks for the coffee"),
            ("Memo 2", "in hex", "FF00"),
            ("Source tag", "7", ""),
            ("Fee", "0.000012 XRP", "")
        ]
    );
    // the pages are maki-xrp's, every word
    let key: [u8; 33] = unhex(KEY).try_into().unwrap();
    let parsed = maki_xrp::Transaction::parse(&tx).unwrap();
    let expected = maki_xrp::display::review(&parsed, &key, maki_xrp::Network::Main).unwrap();
    assert!(review.pages.iter().zip(&expected.pages).all(|(a, b)| a.heading == b.heading
        && a.value == b.value
        && a.mono == b.mono
        && a.prose == b.prose));
    // the answer, put in where xrpl.js puts it, is the transaction xrpl.js signed
    let json = fixtures();
    let signed =
        json["transactions"].as_array().unwrap().iter().find(|t| t["name"] == "xrp-tag-memo").unwrap();
    let blob = maki_xrp::sign::with_signature(&tx, &r.replies[0][2..]).unwrap();
    assert_eq!(blob, unhex(signed["signed"].as_str().unwrap()));
    // every transaction maki shows, signed as xrpl.js signs it
    for t in json["transactions"].as_array().unwrap() {
        let (Some(sig), Some(name)) = (t["signature"].as_str(), t["name"].as_str()) else { continue };
        if name == "other-network" {
            continue;
        }
        let tx = unhex(t["transaction"].as_str().unwrap());
        let r = run_wallet("xrp", vec![message(b'T', 0, 0, &tx)], vec![Answer::Yes], false);
        let sig = unhex(sig);
        assert_eq!(r.replies[0], [&[0, sig.len() as u8][..], &sig].concat(), "{name}");
    }
    // a no, no answer, and a locked maki sign nothing
    let r = run_wallet(
        "xrp",
        vec![message(b'T', 0, 0, &tx), message(b'T', 0, 0, &tx)],
        vec![Answer::No, Answer::NoAnswer],
        false,
    );
    assert_eq!((r.replies[0].as_slice(), r.replies[1].as_slice()), (&[1u8][..], &[2u8][..]));
    let r = run_wallet("xrp", vec![message(b'T', 0, 0, &tx)], vec![Answer::Yes], true);
    assert_eq!((r.replies[0].as_slice(), r.reviews.len()), (&[3u8][..], 0));
}

#[test]
fn xrp_on_the_test_network_says_what_that_means() {
    let (tx, signature) = fixture("xrp");
    let r = run_wallet("xrp", vec![message(b'T', 1, 0, &tx)], vec![Answer::Yes], false);
    // the same signature: a transaction doesn't name its network
    assert_eq!(r.replies[0][2..], signature.unwrap());
    let review = &r.reviews[0];
    assert_eq!(review.detail, "testnet: sends 1.5 XRP; fee 0.000012 XRP");
    assert_eq!(
        (review.pages[0].heading.as_str(), review.pages[0].value.as_str()),
        ("Network", "xrp testnet")
    );
    assert!(review.pages[0].prose.contains("good on the main network too"));
}

#[test]
fn xrp_refuses_what_isnt_its_to_sign_before_showing_anything() {
    let refused = |name: &str, account: u32| {
        let (tx, _) = fixture(name);
        let r = run_wallet("xrp", vec![message(b'T', 0, account, &tx)], vec![Answer::Yes], false);
        assert!(r.reviews.is_empty(), "{name}: shown");
        assert_eq!(r.replies[0][0], 5, "{name}");
        string16(&r.replies[0], 1).0
    };
    assert_eq!(refused("not-mine", 0), "not this account's: it's rLpgximdBvEHy8TxUwyj6mjCRNcJju5qGG's");
    assert_eq!(
        refused("other-network", 0),
        "for another network (network 21337): maki signs for the XRP Ledger and its test network"
    );
    // account 1 asked to sign account 0's
    assert_eq!(refused("xrp", 1), format!("not this account's: it's {ME}'s"));
    assert_eq!(refused("multisig", 0), "for several keys to sign together, which maki doesn't do");
    assert_eq!(
        refused("signed", 0),
        "signed already (TxnSignature): maki takes a transaction without its signatures"
    );
    assert_eq!(
        refused("xrp-partial", 0),
        "XRP sent as XRP, as a partial payment: the XRP Ledger would refuse it"
    );
    // and what isn't a transaction at all
    let (tx, _) = fixture("xrp");
    let r = run_wallet("xrp", vec![message(b'T', 0, 0, &tx[..tx.len() - 1])], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], string16(&r.replies[0], 1).0.as_str()),
        (5, "not an XRP Ledger transaction: cut short")
    );
    assert!(r.reviews.is_empty());
}

#[test]
fn xrp_shows_its_address_as_a_qr_code() {
    let r = run_wallet_with(
        "xrp",
        vec![Event::Right, Event::Left, Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(SECOND), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME));
    assert!(read_qr(&r.frames[3]).is_none(), "as text");
    // locked: no address to show
    let r = run_wallet_with("xrp", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
}
