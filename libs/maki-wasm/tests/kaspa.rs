//! The Kaspa app (sdk/examples/kaspa), as `maki build` packed it, run as maki runs it: its account
//! shared once the owner says so, its addresses compared on maki's screen, the transactions Kaspa's
//! SDK made (maki-kas's fixtures) signed as the SDK checked maki must sign them, after the owner has
//! gone through them; and what isn't this wallet's, or isn't a transaction, or tells a coin's amount
//! two ways, refused before anything is shown. Rebuild the fixture after changing the app:
//! `maki build sdk/examples/kaspa`, then copy `sdk/target/maki/com.leviathan.maki.kaspa.maki` to
//! `tests/fixtures/kaspa.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

const KAS_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-kas/tests/fixtures");
/// The test phrase's first address, as Kaspium, Kaspa NG and Kastle make it.
const ME: &str = "kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh";
const RECIPIENT: &str = "kaspa:qp8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc6547zhh9u4";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn json() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{KAS_FIXTURES}/transactions.json")).unwrap())
        .unwrap()
}

/// A transaction the SDK made, as maki desktop asks the app to sign it (`T`, the network, the
/// request), and maki's signatures for it as the answer gives them (none if maki mustn't sign).
fn kas_fixture(name: &str) -> (Vec<u8>, Option<Vec<u8>>) {
    let json = json();
    let f = json["transactions"].as_array().unwrap().iter().find(|f| f["name"] == name).unwrap();
    let message =
        [&[b'T', f["network"].as_u64().unwrap() as u8][..], &unhex(f["request"].as_str().unwrap())].concat();
    let signatures = f["signatures"]
        .as_array()
        .map(|s| s.iter().flat_map(|s| unhex(s.as_str().unwrap())).collect::<Vec<u8>>());
    (message, signatures)
}

/// The address the fixtures have for a key of the account's.
fn address(network: u64, chain: u64, index: u64) -> String {
    let json = json();
    let a = json["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["network"] == network && a["chain"] == chain && a["index"] == index)
        .unwrap();
    a["address"].as_str().unwrap().into()
}

fn page(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

#[test]
fn kaspa_shares_its_account_once_asked() {
    let json = json();
    let r = run_wallet(
        "kaspa",
        vec![vec![b'A', 0], vec![b'A', 0], vec![b'A', 1]],
        vec![Answer::Yes, Answer::No, Answer::Yes],
        false,
    );
    // the account's key and chain code, as the SDK has them, and its first address to check them by
    let reply = &r.replies[0];
    assert_eq!(reply[0], 0);
    assert_eq!(reply[1..34], unhex(json["account"]["key"].as_str().unwrap()));
    assert_eq!(reply[34..66], unhex(json["account"]["chainCode"].as_str().unwrap()));
    assert_eq!(texts(&reply[65..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "kaspa, view only", "share", "don't")
    );
    assert!(review.pages.is_empty());
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    // the test network's: the same keys, its own addresses
    assert_eq!(r.replies[2][..66], reply[..66]);
    assert_eq!(texts(&r.replies[2][65..]), [address(1, 0, 0)]);
    assert_eq!(r.reviews[2].detail, "kaspa testnet, view only");
    // locked, there's no account to share
    let r = run_wallet("kaspa", vec![vec![b'A', 0]], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    // a network there isn't, more after the message, a message this app hasn't, nothing
    let r = run_wallet("kaspa", vec![vec![b'A', 2], vec![b'A', 0, 0], vec![b'Z', 0], vec![]], vec![], false);
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

/// `D`: the address at a key of the account's, to compare.
fn compare(network: u8, chain: u8, index: u32) -> Vec<u8> {
    [&[b'D', network, chain][..], &index.to_le_bytes()].concat()
}

#[test]
fn kaspa_compares_addresses_on_its_screen() {
    let r = run_wallet(
        "kaspa",
        vec![compare(0, 0, 0), compare(0, 1, 1), compare(1, 0, 2)],
        vec![Answer::Yes, Answer::No, Answer::NoAnswer],
        false,
    );
    // the owner's say, then maki's address either way
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![address(0, 1, 1)]));
    assert_eq!((r.replies[2][0], texts(&r.replies[2])), (2, vec![address(1, 0, 2)]));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Same on computer?", "matches", "doesn't match")
    );
    assert_eq!(review.pages, [page("Receive #0", "kaspa", ME, "")]);
    assert_eq!(r.reviews[1].pages, [page("Change #1", "kaspa", &address(0, 1, 1), "")]);
    assert_eq!(r.reviews[2].pages[0].value, "kaspa testnet");
    // a chain the account hasn't, a hardened index, a message cut short, a network there isn't
    let r = run_wallet(
        "kaspa",
        vec![compare(0, 2, 0), compare(0, 0, 1 << 31), compare(0, 0, 0)[..6].to_vec(), compare(2, 0, 0)],
        vec![],
        false,
    );
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    let r = run_wallet("kaspa", vec![compare(0, 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
}

#[test]
fn kaspa_signs_what_kaspas_sdk_signs() {
    let json = json();
    let mut signed = 0;
    for f in json["transactions"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let (message, signatures) = kas_fixture(name);
        let Some(signatures) = signatures else { continue };
        let r = run_wallet("kaspa", vec![message], vec![Answer::Yes], false);
        // every input's signature, in order, byte for byte the ones the SDK checked
        assert_eq!(r.replies[0], [&[0u8][..], &signatures].concat(), "{name}");
        // and what each coin was said to hold, kept: 20 bytes an input
        assert_eq!(r.storage["claims"].len(), signatures.len() / 65 * 20, "{name}");
        signed += 1;
    }
    assert_eq!(signed, 12);
    // what the owner went through first
    let (message, _) = kas_fixture("payment");
    let r = run_wallet("kaspa", vec![message], vec![Answer::Yes], false);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.timeout_s),
        ("Sign and send", "sends 1.5 KAS; fee 0.002036 KAS", 300)
    );
    assert_eq!(
        review.pages,
        [
            page("Send", "1.5 KAS", RECIPIENT, ""),
            page("Change", "8.497964 KAS", "back to you", ""),
            page("Fee", "0.002036 KAS", "", "")
        ]
    );
    // on the test network, first, that the signatures would spend real KAS as well
    let (message, _) = kas_fixture("payment-testnet");
    let r = run_wallet("kaspa", vec![message], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "sends 1.5 TKAS; fee 0.002036 TKAS");
    assert_eq!(
        (r.reviews[0].pages[0].heading.as_str(), r.reviews[0].pages[0].value.as_str()),
        ("Test network!", "kaspa testnet")
    );
    // the most a message holds: 41 coins, 41 signatures
    let (message, signatures) = kas_fixture("many-inputs");
    assert!(message.len() <= 4096);
    let r = run_wallet("kaspa", vec![message], vec![Answer::Yes], false);
    assert_eq!(r.replies[0].len(), 1 + 41 * 65);
    assert_eq!(r.replies[0][1..], signatures.unwrap());
    let headings: Vec<&str> = r.reviews[0].pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Change", "Fee"]);
}

#[test]
fn kaspa_refuses_what_it_mustnt_sign() {
    let (payment, _) = kas_fixture("payment");
    let (not_mine, _) = kas_fixture("not-mine");
    let too_long = [&payment[..], &vec![0u8; 4097 - payment.len()]].concat();
    let r = run_wallet(
        "kaspa",
        vec![
            payment.clone(),
            not_mine,
            [&[b'T', 0][..], &[0, 0, 1]].concat(),
            [&[b'T', 2][..], &payment[2..]].concat(),
            too_long,
            vec![b'T'],
        ],
        vec![Answer::No],
        false,
    );
    // a no signs nothing
    assert_eq!(r.replies[0], [1]);
    // a coin that isn't this wallet's, and what isn't a transaction: refused with why
    assert_eq!(
        (r.replies[1][0], texts(&r.replies[1])),
        (
            5,
            vec![
                "input 0 isn't this wallet's (maki signs for Kaspa's standard account, m/44'/111111'/0')"
                    .to_string()
            ]
        )
    );
    assert_eq!(
        (r.replies[2][0], texts(&r.replies[2])),
        (5, vec!["not a transaction maki can read: cut short, or with more after it".to_string()])
    );
    // a network there isn't, a message longer than a message, and one with no network
    assert_eq!(r.replies[3..], [vec![4], vec![4], vec![4]]);
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked, nothing can be checked, so nothing is shown
    let r = run_wallet("kaspa", vec![payment], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
}

#[test]
fn kaspa_catches_a_coin_said_to_hold_two_amounts() {
    // receive #0's coin, said to hold 10 KAS and signed for; then the same coin said to hold 1 KAS
    let (ten, _) = kas_fixture("lock-time");
    let (one, _) = kas_fixture("high-fee");
    let r = run_wallet("kaspa", vec![ten.clone(), one.clone(), ten], vec![Answer::Yes, Answer::Yes], false);
    assert_eq!(r.replies[0][0], 0);
    assert_eq!(
        (r.replies[1][0], texts(&r.replies[1])),
        (
            5,
            vec!["input 0's coin was said to hold another amount when maki signed for it before: one of the two isn't true, so maki won't sign".to_string()]
        )
    );
    assert_eq!(r.reviews.len(), 2, "the second wasn't shown");
    // the first again, the same: signed again
    assert_eq!(r.replies[2][0], 0);
    // a no keeps nothing: the coin's other amount is still a first claim
    let (ten, _) = kas_fixture("lock-time");
    let r = run_wallet("kaspa", vec![ten, one], vec![Answer::No, Answer::Yes], false);
    assert_eq!((r.replies[0].as_slice(), r.replies[1][0]), (&[1u8][..], 0));
}

#[test]
fn kaspa_shows_an_address_to_receive_at() {
    let r = run_wallet_with(
        "kaspa",
        vec![Event::Right, Event::Centre, Event::Centre, Event::Menu(0)],
        vec![],
        vec![],
        false,
    );
    assert_eq!(r.menu, ["Kaspa or testnet"]);
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]), Some(address(0, 0, 1)), "receive #1");
    assert!(read_qr(&r.frames[2]).is_none(), "as text");
    assert_eq!(read_qr(&r.frames[3]), Some(address(0, 0, 1)));
    assert_eq!(read_qr(&r.frames[4]), Some(address(1, 0, 1)), "the test network's");
    // locked, no address to show
    let r = run_wallet_with("kaspa", vec![], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 50);
}
