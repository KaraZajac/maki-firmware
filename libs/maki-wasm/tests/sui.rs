//! The Sui example (sdk/examples/sui), as `maki build` packed it and maki runs it: its account
//! shared once the owner says so, its address compared on maki's screen and shown as a QR code,
//! @mysten/sui's transactions (`maki-sui/tests/fixtures/make.mjs`) read, shown and signed as the
//! library signs them, and what isn't this account's to sign, or can't be read, refused before
//! anything is shown. Rebuild the fixture after changing the app: `maki build sdk/examples/sui`,
//! then copy `sdk/target/maki/com.leviathan.maki.sui.maki` to `tests/fixtures/sui.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's first Sui account, as Slush, Ledger's Sui app and @mysten/sui make it.
const ME: &str = "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1";
/// Its second, `m/44'/784'/1'/0'/0'`, as Slush counts accounts.
const SECOND: &str = "0x082d099250999ab8450a9ef3a962edf9e2449e1045be32ba5a0f2c6117ff7167";
const RECIPIENT: &str = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
const SUI_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-sui/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, index: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&index.to_le_bytes());
    m
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// @mysten/sui's transactions: each one's name, its data, and the library's signature for this
/// account.
fn fixtures() -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
    let text = std::fs::read_to_string(format!("{SUI_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                unhex(f["tx"].as_str().unwrap()),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, tx, signature) = fixtures().into_iter().find(|f| f.0 == name).unwrap();
    (tx, signature.unwrap_or_default())
}

/// `T` for this account, on Sui's own network, with this transaction's data.
fn sign(tx: &[u8]) -> Vec<u8> { [head(b'T', 0, 0), tx.to_vec()].concat() }

/// What maki refuses of the fixtures, whichever account asks.
const REFUSED: [&str; 8] = [
    "not-mine",
    "sponsored",
    "sponsor-only",
    "publish",
    "upgrade",
    "alias-add",
    "allowance-new",
    "allowance-spend",
];

#[test]
fn sui_shares_its_account_once_asked_and_compares_its_address() {
    let r = run_wallet("sui", vec![head(b'A', 0, 0), head(b'A', 0, 0)], vec![Answer::Yes, Answer::No], false);
    // OK, the key's length, the Ed25519 key, then the address
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1]), (0, 32));
    let key: [u8; 32] = answer[2..34].try_into().unwrap();
    assert_eq!(maki_sui::address(&maki_sui::address_of(&key)), ME);
    assert_eq!(texts(&answer[33..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "sui, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("sui", vec![head(b'A', 1, 2)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "sui testnet account #2, view only");
    let r = run_wallet("sui", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // the address on maki's screen: the owner's answer, and maki's address either way
    let r = run_wallet(
        "sui",
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
        [Page { heading: "Address".into(), value: "sui".into(), mono: ME.into(), prose: String::new() }]
    );
    assert_eq!(r.reviews[1].pages[0].value, "sui account #1");
    assert_eq!(r.reviews[2].pages[0].value, "sui testnet");
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // BIP32's unhardened ones, a head with more after it, or cut short
    let r = run_wallet(
        "sui",
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
fn sui_signs_what_the_owner_reviewed_as_the_sdk_signs() {
    let (tx, signature) = fixture("ab-sui");
    let r = run_wallet("sui", vec![sign(&tx)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 1.5 SUI; fee up to 0.003 SUI")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(pages, [("Network", "Sui", ""), ("Send", "1.5 SUI", RECIPIENT), ("Max fee", "0.003 SUI", "")]);
    assert_eq!(review.pages[1].prose, "From this account's address balance.");
    // as Sui takes it: the flag, the signature, the key
    let key: [u8; 32] = run_wallet("sui", vec![head(b'A', 0, 0)], vec![Answer::Yes], false).replies[0][2..34]
        .try_into()
        .unwrap();
    let serialized = maki_sui::signature(&r.replies[0][1..].try_into().unwrap(), &key);
    assert_eq!((serialized[0], &serialized[1..65], &serialized[65..]), (0, &signature[..], &key[..]));
    // every transaction maki shows, signed as the library signs it
    let mut signed = 0;
    for (name, tx, signature) in fixtures() {
        if REFUSED.contains(&name.as_str()) {
            continue;
        }
        let network = if name.starts_with("testnet") { 1 } else { 0 };
        let r = run_wallet("sui", vec![[head(b'T', network, 0), tx].concat()], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [&[0u8][..], &signature.unwrap()].concat(), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 33);
    // on the test network, which the transaction names
    let (testnet, _) = fixture("testnet-usdc");
    let r = run_wallet("sui", vec![[head(b'T', 1, 0), testnet].concat()], vec![Answer::Yes], false);
    assert_eq!(
        (r.reviews[0].pages[0].value.as_str(), r.reviews[0].pages[1].value.as_str()),
        ("Sui testnet", "1 USDC (testnet)")
    );
    assert_eq!(r.reviews[0].detail, "sends 1 USDC (testnet); fee up to 0.003 SUI");
    // a call maki can't read, flagged under the question too
    let (call, _) = fixture("move-call");
    let r = run_wallet("sui", vec![sign(&call)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "maki can't read all of it; fee up to 0.003 SUI");
    assert_eq!(r.reviews[0].pages[1].heading, "Move call");
}

#[test]
fn sui_refuses_what_isnt_its_to_sign_before_showing_it() {
    let (sui, _) = fixture("sui");
    let (not_mine, _) = fixture("not-mine");
    let (sponsored, _) = fixture("sponsored");
    let (alias, _) = fixture("alias-add");
    let (publish, _) = fixture("publish");
    let (testnet, _) = fixture("testnet");
    let r = run_wallet(
        "sui",
        vec![
            // the owner says no
            sign(&sui),
            // another account's, and this one's but for another of its accounts
            sign(&not_mine),
            [head(b'T', 0, 1), sui.clone()].concat(),
            // its fee another's to pay; another key let sign for the account; code published
            sign(&sponsored),
            sign(&alias),
            sign(&publish),
            // not a transaction, or one with more after it
            sign(&[1, 2, 3]),
            sign(&[sui.clone(), vec![0]].concat()),
            // the test network's, which the computer says is Sui's own
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
        (
            5,
            String::from(
                "its fee is paid by another account: maki signs only transactions this account pays for"
            )
        )
    );
    assert_eq!(
        refused(&r.replies[4]),
        (5, String::from("it changes which keys can sign for this account: maki won't sign that"))
    );
    assert_eq!(
        refused(&r.replies[5]),
        (5, String::from("it publishes Move code: maki can't show what code does, so it doesn't sign that"))
    );
    assert_eq!(r.replies[6][0], 5);
    assert_eq!(
        refused(&r.replies[7]),
        (
            5,
            String::from(
                "not a Sui transaction as BCS writes one: cut short, with more after it, or written another way"
            )
        )
    );
    assert_eq!(
        refused(&r.replies[8]),
        (5, String::from("a transaction for Sui's test network, not its own"))
    );
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: nothing read, nothing shown
    let r = run_wallet("sui", vec![sign(&sui)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet("sui", vec![[sign(&sui), vec![0; 4096]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn sui_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "sui",
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
    let r = run_wallet_with("sui", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}
