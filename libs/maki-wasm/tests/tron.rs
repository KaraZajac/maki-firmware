//! The Tron example (sdk/examples/tron), as `maki build` packed it and maki runs it: its account
//! shared once the owner says so, its address compared on maki's screen and shown as a QR code,
//! TronWeb's transactions (`maki-trx/tests/fixtures/make.mjs`) read, shown and signed as TronWeb
//! signs them, and what isn't this account's to sign, or can't be read, refused before anything is
//! shown. Rebuild the fixture after changing the app: `maki build sdk/examples/tron`, then copy
//! `sdk/target/maki/com.leviathan.maki.tron.maki` to `tests/fixtures/tron.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's first Tron account, as TronLink, Ledger's Tron app and TronWeb make it.
const ME: &str = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";
/// Its second, `m/44'/195'/0'/0/1`, as Keystone's firmware tests have it.
const SECOND: &str = "TSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK";
const RECIPIENT: &str = "TCNkawTmcQgYSU8nP8cHswT1QPjharxJr7";
const TRX_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-trx/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, index: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&index.to_le_bytes());
    m
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// TronWeb's transactions: each one's name, `raw_data`, and TronWeb's signature for this account.
fn fixtures() -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
    let text = std::fs::read_to_string(format!("{TRX_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                unhex(f["raw"].as_str().unwrap()),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, raw, signature) = fixtures().into_iter().find(|f| f.0 == name).unwrap();
    (raw, signature.unwrap_or_default())
}

/// `T` for this account, on Tron's network, with this `raw_data`.
fn sign(raw: &[u8]) -> Vec<u8> { [head(b'T', 0, 0), raw.to_vec()].concat() }

#[test]
fn tron_shares_its_account_once_asked_and_compares_its_address() {
    let r =
        run_wallet("tron", vec![head(b'A', 0, 0), head(b'A', 0, 0)], vec![Answer::Yes, Answer::No], false);
    // OK, the key's length, the key as its address is made from, then the address
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1], answer[2]), (0, 65, 0x04));
    let key: [u8; 65] = answer[2..67].try_into().unwrap();
    assert_eq!(maki_trx::address(&maki_trx::address_of(&key).unwrap()), ME);
    assert_eq!(texts(&answer[66..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "tron, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("tron", vec![head(b'A', 1, 2)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "tron nile account #2, view only");
    let r = run_wallet("tron", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // the address on maki's screen: the owner's answer, and maki's address either way
    let r = run_wallet(
        "tron",
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
        [Page { heading: "Address".into(), value: "tron".into(), mono: ME.into(), prose: String::new() }]
    );
    assert_eq!(r.reviews[1].pages[0].value, "tron account #1");
    assert_eq!(r.reviews[2].pages[0].value, "tron nile");
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // BIP32's unhardened ones, a head with more after it, or cut short
    let r = run_wallet(
        "tron",
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
fn tron_signs_what_the_owner_reviewed_as_tronweb_signs() {
    let (usdt, signature) = fixture("usdt");
    let r = run_wallet("tron", vec![sign(&usdt)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 5.25 USDT; fee up to 30.345 TRX")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [("Network", "Tron", ""), ("Send", "5.25 USDT", RECIPIENT), ("Max fee", "30.345 TRX", "")]
    );
    // every transaction maki shows, signed as TronWeb signs it
    let mut signed = 0;
    for (name, raw, signature) in fixtures() {
        if ["not-mine", "permission-update", "freeze-v1", "create-account"].contains(&name.as_str()) {
            continue;
        }
        let network = if name.starts_with("nile") { 1 } else { 0 };
        let r = run_wallet("tron", vec![[head(b'T', network, 0), raw].concat()], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [&[0u8][..], &signature.unwrap()].concat(), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 29);
    // on Nile, which the transaction can't say
    let (nile, _) = fixture("nile-usdt");
    let r = run_wallet("tron", vec![[head(b'T', 1, 0), nile].concat()], vec![Answer::Yes], false);
    assert_eq!(
        (r.reviews[0].pages[0].value.as_str(), r.reviews[0].pages[1].value.as_str()),
        ("Nile (test)", "1 USDT (Nile)")
    );
    assert_eq!(r.reviews[0].detail, "sends 1 USDT (Nile); fee up to 30.345 TRX");
}

#[test]
fn tron_refuses_what_isnt_its_to_sign_before_showing_it() {
    let (usdt, _) = fixture("usdt");
    let (not_mine, _) = fixture("not-mine");
    let (permissions, _) = fixture("permission-update");
    let (freeze, _) = fixture("freeze-v1");
    let r = run_wallet(
        "tron",
        vec![
            // the owner says no
            sign(&usdt),
            // another account's, and this one's but for another of its accounts
            sign(&not_mine),
            [head(b'T', 0, 1), usdt.clone()].concat(),
            // a change of who controls the account, a kind maki doesn't sign, and not a transaction
            sign(&permissions),
            sign(&freeze),
            sign(&[1, 2, 3]),
            sign(&[usdt.clone(), vec![0]].concat()),
            // Tron's own USDT, which the computer says is on Nile: real money passed off as play money
            [head(b'T', 1, 0), usdt.clone()].concat(),
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
        (5, String::from("it changes who controls this account: maki won't sign that"))
    );
    assert_eq!(refused(&r.replies[4]), (5, String::from("a FreezeBalanceContract: maki doesn't sign those")));
    assert_eq!(r.replies[5][0], 5);
    assert_eq!(
        refused(&r.replies[6]),
        (5, String::from("not a Tron transaction as Tron writes one: cut short, or written another way"))
    );
    assert_eq!(
        refused(&r.replies[7]),
        (5, String::from("a call to a token of Tron's own network: it's for that network, not Nile"))
    );
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: nothing read, nothing shown
    let r = run_wallet("tron", vec![sign(&usdt)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet("tron", vec![[sign(&usdt), vec![0; 4096]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn tron_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "tron",
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
    let r = run_wallet_with("tron", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}
