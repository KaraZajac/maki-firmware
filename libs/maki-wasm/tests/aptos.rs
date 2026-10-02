//! The Aptos example (sdk/examples/aptos), as `maki build` packed it and maki runs it: its account
//! shared once the owner says so, its address compared on maki's screen and shown as a QR code, the
//! Aptos TypeScript SDK's transactions (`maki-apt/tests/fixtures/make.mjs`) read, shown and signed as
//! the SDK signs them, and what isn't this account's to sign, is for another network, or can't be
//! read, refused before anything is shown. Rebuild the fixture after changing the app: `maki build
//! sdk/examples/aptos`, then copy `sdk/target/maki/com.leviathan.maki.aptos.maki` to
//! `tests/fixtures/aptos.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's first Aptos account, as Petra, Ledger's Aptos app and the SDK make it.
const ME: &str = "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf";
/// Its second, `m/44'/637'/1'/0'/0'`.
const SECOND: &str = "0xf867372dfec13fb6c0740d4b574363685e10e6f243e9554ffa8f6e698e940efa";
const RECIPIENT: &str = "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd";
const APT_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-apt/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, index: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&index.to_le_bytes());
    m
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The SDK's transactions: each one's name, network, BCS, and the SDK's signature for this account.
fn fixtures() -> Vec<(String, u8, Vec<u8>, Option<Vec<u8>>)> {
    let text = std::fs::read_to_string(format!("{APT_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                f["network"].as_u64().unwrap() as u8,
                unhex(f["raw"].as_str().unwrap()),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, _, raw, signature) = fixtures().into_iter().find(|f| f.0 == name).unwrap();
    (raw, signature.unwrap_or_default())
}

/// `T` for this account, on Aptos's own network, with this transaction.
fn sign(raw: &[u8]) -> Vec<u8> { [head(b'T', 0, 0), raw.to_vec()].concat() }

/// What maki refuses to sign of the fixtures, and why.
const REFUSED: &[(&str, &str)] = &[
    ("not-mine", "another account's transaction, not this one's to sign"),
    ("rotate", "it changes this account's key: maki won't sign that"),
    ("offer-signer", "it lets another act as this account: maki won't sign that"),
    ("abstraction", "it lets another's code sign for this account: maki won't sign that"),
    ("multisig-convert", "it makes this account a multisig account, others' to control: maki won't sign that"),
    (
        "script",
        "a script, code maki can't read that could do anything this account can: maki doesn't sign those",
    ),
    ("multisig", "a multisig account's transaction: maki doesn't sign those"),
];

#[test]
fn aptos_shares_its_account_once_asked_and_compares_its_address() {
    let r = run_wallet("aptos", vec![head(b'A', 0, 0), head(b'A', 0, 0)], vec![Answer::Yes, Answer::No], false);
    // OK, the key's length, the key its address is made from, then the address
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1]), (0, 32));
    let key: [u8; 32] = answer[2..34].try_into().unwrap();
    assert_eq!(maki_apt::address(&maki_apt::address_of(&key)), ME);
    assert_eq!(texts(&answer[33..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "aptos, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("aptos", vec![head(b'A', 1, 2)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "aptos testnet account #2, view only");
    let r = run_wallet("aptos", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // the address on maki's screen: the owner's answer, and maki's address either way
    let r = run_wallet(
        "aptos",
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
        [Page { heading: "Address".into(), value: "aptos".into(), mono: ME.into(), prose: String::new() }]
    );
    assert_eq!(r.reviews[1].pages[0].value, "aptos account #1");
    assert_eq!(r.reviews[2].pages[0].value, "aptos testnet");
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // SLIP-10's, a head with more after it, or cut short
    let r = run_wallet(
        "aptos",
        vec![
            head(b'M', 0, 0),
            head(b'A', 2, 0),
            head(b'A', 0, 0x8000_0000),
            [head(b'A', 0, 0), vec![0]].concat(),
            [head(b'D', 0, 0), vec![0]].concat(),
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
fn aptos_signs_what_the_owner_reviewed_as_the_sdk_signs() {
    let (usdc, signature) = fixture("usdc");
    let r = run_wallet("aptos", vec![sign(&usdc)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 5.25 USDC; fee up to 0.002 APT")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Network", "Aptos", ""),
            ("Send", "5.25 USDC", RECIPIENT),
            ("Valid until", "2026-10-02 04:00:20 UTC", ""),
            ("Max fee", "0.002 APT", "")
        ]
    );
    // every transaction maki shows, on its own network, signed as the SDK signs it
    let mut signed = 0;
    for (name, network, raw, signature) in fixtures() {
        if REFUSED.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let r = run_wallet("aptos", vec![[head(b'T', network, 0), raw].concat()], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [&[0u8][..], &signature.unwrap()].concat(), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 27);
    // on the test network, as the transaction says
    let (testnet, _) = fixture("testnet-usdc");
    let r = run_wallet("aptos", vec![[head(b'T', 1, 0), testnet].concat()], vec![Answer::Yes], false);
    assert_eq!(
        (r.reviews[0].pages[0].value.as_str(), r.reviews[0].pages[1].value.as_str()),
        ("Aptos testnet", "1 USDC (testnet)")
    );
    assert_eq!(r.reviews[0].detail, "sends 1 USDC (testnet); fee up to 0.002 APT");
    // a call maki can't read, flagged, still signed once the owner says yes
    let (swap, signature) = fixture("swap");
    let r = run_wallet("aptos", vec![sign(&swap)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    assert_eq!(r.reviews[0].detail, "maki can't read all of it; fee up to 0.002 APT");
    assert_eq!((r.reviews[0].pages[1].heading.as_str(), r.reviews[0].pages[1].value.as_str()), ("Call", "maki can't read it"));
}

#[test]
fn aptos_refuses_what_isnt_its_to_sign_before_showing_it() {
    let (usdc, _) = fixture("usdc");
    let (testnet, _) = fixture("testnet-apt");
    let mut inbox = vec![
        // the owner says no
        sign(&usdc),
        // this one's, but for another of its accounts
        [head(b'T', 0, 1), usdc.clone()].concat(),
        // another network's: Aptos's own transaction said to be the testnet's, and the other way
        [head(b'T', 1, 0), usdc.clone()].concat(),
        [head(b'T', 0, 0), testnet.clone()].concat(),
        // not a transaction, or one with more after it
        sign(&[1, 2, 3]),
        sign(&[usdc.clone(), vec![0]].concat()),
    ];
    for (name, _) in REFUSED {
        inbox.push(sign(&fixture(name).0));
    }
    let r = run_wallet("aptos", inbox, vec![Answer::No], false);
    assert_eq!(r.replies[0], [1]);
    let refused = |a: &Vec<u8>| (a[0], texts(a).join(""));
    let not_this = (5, String::from("another account's transaction, not this one's to sign"));
    assert_eq!(refused(&r.replies[1]), not_this);
    assert_eq!(
        refused(&r.replies[2]),
        (5, String::from("a transaction for Aptos's own network, not its testnet"))
    );
    assert_eq!(
        refused(&r.replies[3]),
        (5, String::from("a transaction for Aptos's testnet, not its own network"))
    );
    assert_eq!(
        refused(&r.replies[4]),
        (5, String::from("not an Aptos transaction: cut short, or with more after it"))
    );
    assert_eq!(
        refused(&r.replies[5]),
        (5, String::from("not an Aptos transaction: cut short, or with more after it"))
    );
    for (i, (name, why)) in REFUSED.iter().enumerate() {
        assert_eq!(refused(&r.replies[6 + i]), (5, why.to_string()), "{name}");
    }
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: nothing read, nothing shown
    let r = run_wallet("aptos", vec![sign(&usdc)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet("aptos", vec![[sign(&usdc), vec![0; 4096]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn aptos_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "aptos",
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
    let r = run_wallet_with("aptos", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}
