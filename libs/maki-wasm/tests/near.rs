//! The NEAR example (sdk/examples/near), as `maki build` packed it and maki runs it: its account
//! shared once the owner says so, its name compared on maki's screen and shown as a QR code,
//! near-api-js's transactions (`maki-near/tests/fixtures/make.mjs`) read, shown and signed as
//! near-api-js signs them, and what isn't this account's to sign, can't be read, or is another
//! network's, refused before anything is shown. Rebuild the fixture after changing the app: `maki
//! build sdk/examples/near`, then copy `sdk/target/maki/com.leviathan.maki.near.maki` to
//! `tests/fixtures/near.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's NEAR account, `m/44'/397'/0'`, as MyNearWallet, near-cli and near-api-js
/// make it: its implicit account.
const ME: &str = "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412";
/// Its second, `m/44'/397'/1'`, as near-api-js makes it from that path.
const SECOND: &str = "3b93b03253b9715213ec314eb50ecc99d25602ccb5b059f91f51d24710d54326";
const NEAR_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-near/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, index: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&index.to_le_bytes());
    m
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// near-api-js's transactions: each one's name, network (0 or 1), borsh bytes, and near-api-js's
/// signature for this account.
fn fixtures() -> Vec<(String, u8, Vec<u8>, Option<Vec<u8>>)> {
    let text = std::fs::read_to_string(format!("{NEAR_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                (f["network"] == "testnet") as u8,
                unhex(f["transaction"].as_str().unwrap()),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, _, bytes, signature) = fixtures().into_iter().find(|f| f.0 == name).unwrap();
    (bytes, signature.unwrap_or_default())
}

/// `T` for this account, on NEAR's own network, with this transaction.
fn sign(bytes: &[u8]) -> Vec<u8> { [head(b'T', 0, 0), bytes.to_vec()].concat() }

#[test]
fn near_shares_its_account_once_asked_and_compares_its_name() {
    let r =
        run_wallet("near", vec![head(b'A', 0, 0), head(b'A', 0, 0)], vec![Answer::Yes, Answer::No], false);
    // OK, the key's length, the key as NEAR's transactions carry it (its kind, 0, then the key),
    // then the account's name
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1], answer[2]), (0, 33, 0));
    let key: [u8; 32] = answer[3..35].try_into().unwrap();
    assert_eq!(maki_near::account_id(&key), ME);
    assert_eq!(texts(&answer[34..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "near, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("near", vec![head(b'A', 1, 2)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "near testnet account #2, view only");
    let r = run_wallet("near", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // the name on maki's screen: the owner's answer, and maki's name for it either way
    let r = run_wallet(
        "near",
        vec![head(b'D', 0, 0), head(b'D', 0, 1), head(b'D', 1, 0)],
        vec![Answer::Yes, Answer::No, Answer::NoAnswer],
        false,
    );
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![SECOND.to_string()]));
    assert_eq!((r.replies[2][0], texts(&r.replies[2])), (2, vec![ME.to_string()]));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Same on computer?", "matches", "doesn't match")
    );
    assert_eq!(
        review.pages,
        [Page { heading: "Account".into(), value: "near".into(), mono: ME.into(), prose: String::new() }]
    );
    assert_eq!(r.reviews[1].pages[0].value, "near account #1");
    assert_eq!(r.reviews[2].pages[0].value, "near testnet");
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // the hardened indices, a head with more after it, or cut short
    let r = run_wallet(
        "near",
        vec![
            head(b'M', 0, 0),
            head(b'A', 2, 0),
            head(b'A', 0, 0x8000_0000),
            [head(b'A', 0, 0), vec![0]].concat(),
            vec![b'D', 0, 0],
            vec![],
        ],
        vec![],
        false,
    );
    assert!(r.replies.iter().all(|a| a == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

#[test]
fn near_signs_what_the_owner_reviewed_as_near_api_js_signs() {
    let (usdc, signature) = fixture("usdc");
    let r = run_wallet("near", vec![sign(&usdc)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 5.25 USDC; fee up to 0.062397829000688 NEAR")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Network", "NEAR", ""),
            ("Send", "5.25 USDC", "bob.near"),
            ("Max fee", "0.062397829000688 NEAR", "")
        ]
    );
    // every transaction maki shows, signed as near-api-js signs it: a post-quantum key's 1952 bytes
    // written in base58 among them
    let mut signed = 0;
    for (name, network, bytes, signature) in fixtures() {
        if ["not-mine", "create-account", "delegate"].contains(&name.as_str()) {
            continue;
        }
        let r = run_wallet("near", vec![[head(b'T', network, 0), bytes].concat()], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [&[0u8][..], &signature.unwrap()].concat(), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 37);
    // on the test network, which the transaction can't say
    let (testnet, _) = fixture("testnet-usdc");
    let r = run_wallet("near", vec![[head(b'T', 1, 0), testnet].concat()], vec![Answer::Yes], false);
    assert_eq!(
        (r.reviews[0].pages[0].value.as_str(), r.reviews[0].pages[1].value.as_str()),
        ("NEAR testnet", "1 USDC (testnet)")
    );
    // a key that gives another full control, said so under the question
    let (full, _) = fixture("add-full-key");
    let r = run_wallet("near", vec![sign(&full)], vec![Answer::No], false);
    assert_eq!(r.reviews[0].detail, "gives a key full control!; fee up to 0.0008392985 NEAR");
    assert_eq!(r.reviews[0].pages[1].heading, "Full access!");
    assert_eq!(r.replies[0], [1]);
    // a post-quantum key, by the hash NEAR lists it by, as the generator worked it out
    let (post_quantum, _) = fixture("add-ml-dsa-key");
    let r = run_wallet("near", vec![sign(&post_quantum)], vec![Answer::No], false);
    let text = std::fs::read_to_string(format!("{NEAR_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(r.reviews[0].pages[1].mono, json["keys"]["ml_dsa_listed"].as_str().unwrap());
}

#[test]
fn near_refuses_what_isnt_its_to_sign_before_showing_it() {
    let (usdc, _) = fixture("usdc");
    let (not_mine, _) = fixture("not-mine");
    let (create, _) = fixture("create-account");
    let (delegate, _) = fixture("delegate");
    let (testnet, _) = fixture("testnet-transfer");
    let r = run_wallet(
        "near",
        vec![
            // the owner says no
            sign(&usdc),
            // another account's, and this one's but for another of its accounts
            sign(&not_mine),
            [head(b'T', 0, 1), usdc.clone()].concat(),
            // an account made, which only its parent can; a meta transaction; not a transaction
            sign(&create),
            sign(&delegate),
            sign(&[1, 2, 3]),
            sign(&[usdc.clone(), vec![0]].concat()),
            // NEAR's own USDC, which the computer says is the test network's: real money passed
            // off as play money; and the test network's names, said to be NEAR's own
            [head(b'T', 1, 0), usdc.clone()].concat(),
            sign(&testnet),
        ],
        vec![Answer::No],
        false,
    );
    assert_eq!(r.replies[0], [1]);
    let refused = |a: &Vec<u8>| (a[0], texts(a).join(""));
    let not_this = (5, String::from("another account's transaction, not this one's to sign"));
    assert_eq!(refused(&r.replies[1]), not_this);
    assert_eq!(refused(&r.replies[2]), not_this);
    assert_eq!(
        refused(&r.replies[3]),
        (5, String::from("it makes an account, which only that account's parent can: NEAR would refuse it"))
    );
    assert_eq!(
        refused(&r.replies[4]),
        (
            5,
            String::from(
                "a Delegate action (a meta transaction, for another account): maki doesn't sign those"
            )
        )
    );
    assert_eq!(r.replies[5][0], 5);
    assert_eq!(
        refused(&r.replies[6]),
        (5, String::from("not a NEAR transaction: cut short, or with more after it"))
    );
    assert_eq!(
        refused(&r.replies[7]),
        (
            5,
            String::from(
                "it's for a token's contract on NEAR's own network: it's for that network, not testnet"
            )
        )
    );
    assert_eq!(
        refused(&r.replies[8]),
        (
            5,
            String::from(
                "it names an account of NEAR's test network: it's for testnet, not NEAR's own network"
            )
        )
    );
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: nothing read, nothing shown
    let r = run_wallet("near", vec![sign(&usdc)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet("near", vec![[sign(&usdc), vec![0; 4096]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn near_shows_its_account_to_receive_at() {
    let r = run_wallet_with(
        "near",
        vec![Event::Right, Event::Left, Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(SECOND), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME));
    assert!(read_qr(&r.frames[3]).is_none(), "as text");
    // locked: no account to show
    let r = run_wallet_with("near", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}
