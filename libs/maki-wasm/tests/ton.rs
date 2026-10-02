//! The TON example app (sdk/examples/ton), as `maki build` packed it, run by the host code maki
//! runs it with: the account it shares once asked and shows to compare, in its v4R2 and W5
//! wallets; the requests @ton/ton made (maki-ton's fixtures) shown on maki's review screen and
//! signed as @ton/crypto signs them; what it refuses and why; and its address as a QR code.
//! Rebuild the fixture after changing the app or maki-ton: `maki build examples/ton`, then copy
//! `sdk/target/maki/com.leviathan.maki.ton.maki` to `tests/fixtures/ton.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

const TON_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-ton/tests/fixtures");

/// The test phrase's account 0 as Ledger's TON app makes it, in its two wallets; account 1's W5;
/// account 0 on the test network.
const ME_V4: &str = "UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOpj";
const ME_W5: &str = "UQCr0pJvwmgWeI7Wu0TaRn77bD0m7JkkbnGRCxRUxhbyvbdS";
const ACCOUNT_1_V4: &str = "UQBhJ5wL0OKcTEbmj4YCSg3Bp9oJMOT-uKzZHH385n2a9awB";
const ACCOUNT_1_W5: &str = "UQCU5iZMUjOC9oaEiilY4YM24f-FPzEqD5BXc5ZIk6ctbDXa";
const TEST_V4: &str = "0QBWxXQsPN_l61TJ64LnPAfUi4ewmVfK1DLkwyY_WARTsT24";
const TEST_W5: &str = "0QDxNqXW0IXweuExwOiUuybRpkO2hzOift66DtiHIobBIn_X";
const KEY: &str = "b8c2336996bd97a7789b6deec787797961856628ee518694152ae056387fc9af";
const RECIPIENT: &str = "UQDvr_S6wiD4iy6Y6x2c_8yjv-O2bs4xp9bFiQ0w39evpYZV";

/// A message: what it is, the network, the account, and what follows.
fn message(kind: u8, network: u8, index: u32, rest: &[u8]) -> Vec<u8> {
    [&[kind, network][..], &index.to_le_bytes(), rest].concat()
}

/// A string, as the messages carry one: a u16 length, then it.
fn string(s: &str) -> Vec<u8> { [&(s.len() as u16).to_le_bytes()[..], s.as_bytes()].concat() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn json() -> serde_json::Value {
    let text = std::fs::read_to_string(format!("{TON_FIXTURES}/transactions.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A request @ton/ton made: the cell its signer was handed, and @ton/crypto's signature of its
/// hash with this account.
fn ton_fixture(name: &str, version: &str, network: u8) -> (Vec<u8>, Vec<u8>) {
    let json = json();
    let f = json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name && f["version"] == version && f["network"] == network)
        .unwrap();
    (unhex(f["boc"].as_str().unwrap()), unhex(f["signature"].as_str().unwrap()))
}

#[test]
fn ton_shares_its_account_and_compares_it_once_asked() {
    let key = unhex(KEY);
    let r = run_wallet(
        "ton",
        vec![
            message(b'A', 0, 0, &[]),
            message(b'A', 1, 0, &[]),
            message(b'A', 0, 0, &string("v5R1")),
            message(b'A', 0, 1, &string("v4R2")),
            message(b'A', 0, 0, &[]),
        ],
        vec![Answer::Yes, Answer::Yes, Answer::Yes, Answer::Yes, Answer::No],
        false,
    );
    // the key as a wallet's data holds it, then the wallet's address
    assert_eq!(r.replies[0][..34], [&[0u8, 32][..], &key].concat());
    assert_eq!(texts(&r.replies[0][33..]), [ME_V4]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "ton, view only", "share", "don't")
    );
    assert!(review.pages.is_empty());
    assert_eq!(review.timeout_s, 60);
    assert_eq!(texts(&r.replies[1][33..]), [TEST_V4]);
    assert_eq!(r.reviews[1].detail, "ton testnet, view only");
    assert_eq!(texts(&r.replies[2][33..]), [ME_W5]);
    assert_eq!(r.replies[2][2..34], key[..]);
    assert_eq!(texts(&r.replies[3][33..]), [ACCOUNT_1_V4]);
    assert_eq!(r.reviews[3].detail, "ton account #1, view only");
    // a no shares nothing
    assert_eq!(r.replies[4], [1]);
    // the address on maki's screen, to compare: the owner's say, and maki's address either way
    let r = run_wallet(
        "ton",
        vec![
            message(b'D', 0, 0, &[]),
            message(b'D', 0, 1, &string("v5R1")),
            message(b'D', 1, 0, &string("v5R1")),
        ],
        vec![Answer::Yes, Answer::No, Answer::Yes],
        false,
    );
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME_V4.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![ACCOUNT_1_W5.to_string()]));
    assert_eq!((r.replies[2][0], texts(&r.replies[2])), (0, vec![TEST_W5.to_string()]));
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.yes.as_str()), ("Same on computer?", "matches"));
    let page = &review.pages[0];
    assert_eq!(
        (page.heading.as_str(), page.value.as_str(), page.mono.as_str()),
        ("Account", "TON, v4R2 wallet", ME_V4)
    );
    let page = &r.reviews[1].pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str()), ("Account #1", "TON, W5 wallet"));
    assert_eq!(r.reviews[2].pages[0].value, "TON testnet, W5 wallet");
    // locked: no keys, nothing asked
    let r = run_wallet("ton", vec![message(b'A', 0, 0, &[]), message(b'D', 0, 0, &[])], vec![], true);
    assert_eq!((r.replies[0].as_slice(), r.replies[1].as_slice()), (&[3u8][..], &[3u8][..]));
    assert!(r.reviews.is_empty());
    // a wallet maki doesn't know: refused, and said why
    let r = run_wallet("ton", vec![message(b'A', 0, 0, &string("v3R2"))], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["a TON wallet maki doesn't know: it knows v4R2 and v5R1".to_string()])
    );
    assert!(r.reviews.is_empty());
    // what isn't a message of this app's: another network, an account past the hardened ones, a
    // wallet's name that isn't one string, nothing
    let r = run_wallet(
        "ton",
        vec![
            message(b'A', 2, 0, &[]),
            message(b'A', 0, 0x8000_0000, &[]),
            message(b'A', 0, 0, &[0]),
            message(b'A', 0, 0, &[&string("v4R2")[..], &[0]].concat()),
            message(b'D', 0, 0, &[4, 0, b'v']),
            message(b'D', 0, 0, &[2, 0, 0xff, 0xfe]),
            vec![b'A', 0],
            vec![b'X', 0, 0, 0, 0, 0],
            vec![],
        ],
        vec![Answer::Yes; 9],
        false,
    );
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

#[test]
fn ton_signs_what_the_owner_went_through_as_ton_signs_it() {
    let (ton, signature) = ton_fixture("ton", "v4R2", 0);
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &ton)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 1.5 TON; plus the network's fee")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Send", "1.5 TON", RECIPIENT),
            ("Comment", "", "thanks for the coffee"),
            ("Valid until", "2027-01-01 00:00:00 UTC", ""),
            ("From", "this account's v4R2 wallet", ME_V4)
        ]
    );
    // W5's, sending USDT; and the test network's, signed with its own key
    let (usdt, signature) = ton_fixture("usdt", "v5R1", 0);
    let (test, test_signature) = ton_fixture("ton", "v5R1", 1);
    let r = run_wallet(
        "ton",
        vec![message(b'T', 0, 0, &usdt), message(b'T', 1, 0, &test)],
        vec![Answer::Yes, Answer::Yes],
        false,
    );
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    assert_eq!(r.reviews[0].detail, "sends 5.25 USDT, 0.05 TON; plus the network's fee");
    assert_eq!(
        (r.reviews[0].pages[0].heading.as_str(), r.reviews[0].pages[0].value.as_str()),
        ("Send", "5.25 USDT")
    );
    assert_eq!(r.replies[1], [&[0u8][..], &test_signature].concat());
    assert_eq!(r.reviews[1].detail, "testnet: sends 1.5 TON; plus the network's fee");
    assert_eq!(r.reviews[1].pages.last().unwrap().mono, TEST_W5);
    // what takes everything, loudly; what maki can't read, flagged; a no signs nothing
    let (send_all, _) = ton_fixture("send-all", "v4R2", 0);
    let (nft, _) = ton_fixture("nft", "v5R1", 0);
    let r = run_wallet(
        "ton",
        vec![message(b'T', 0, 0, &send_all), message(b'T', 0, 0, &nft)],
        vec![Answer::No, Answer::No],
        false,
    );
    assert_eq!(r.replies, [vec![1u8], vec![1u8]], "a no signs nothing");
    assert_eq!(r.reviews[0].detail, "sends all its TON, closes the wallet!; plus the network's fee");
    assert_eq!(r.reviews[0].pages[0].heading, "Sends everything!");
    assert_eq!(r.reviews[1].detail, "maki can't read all of it; plus the network's fee");
    assert_eq!(
        (r.reviews[1].pages[1].heading.as_str(), r.reviews[1].pages[1].value.as_str()),
        ("Message", "maki can't read it")
    );
    // every request of this account's, on both networks, signed as @ton/crypto signs it; what
    // maki refuses, refused before anything's shown
    let refused = [
        "extra-currency",
        "workchain-1",
        "mode-64",
        "mode-16",
        "mode-4",
        "mode-192",
        "more-bits",
        "op-9",
        "subwallet",
        "v3r2",
        "signature-off",
        "internal",
        "too-many",
        "256",
        "no-ignore-errors",
        // more text than maki's review screen takes: refused when maki's asked
        "too-long",
        "most",
    ];
    let json = json();
    let (mut signed, mut said_no) = (0, 0);
    for f in json["transactions"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let network = f["network"].as_u64().unwrap() as u8;
        let index = f["account"].as_u64().unwrap() as u32;
        let (boc, signature) = ton_fixture(name, f["version"].as_str().unwrap(), network);
        let r = run_wallet("ton", vec![message(b'T', network, index, &boc)], vec![Answer::Yes], false);
        if refused.contains(&name) {
            assert_eq!(r.replies[0][0], 5, "{name}");
            assert!(r.reviews.is_empty(), "{name}: refused before it's shown");
            said_no += 1;
        } else {
            assert_eq!(r.replies[0], [&[0u8][..], &signature].concat(), "{name} on network {network}");
            signed += 1;
        }
    }
    assert_eq!((signed, said_no), (63, 19));
}

#[test]
fn ton_refuses_what_it_cant_sign_and_says_why() {
    let (ton, _) = ton_fixture("ton", "v4R2", 0);
    let (test_w5, _) = ton_fixture("ton", "v5R1", 1);
    let (subwallet, _) = ton_fixture("subwallet", "v4R2", 0);
    let (internal, _) = ton_fixture("internal", "v5R1", 0);
    let r = run_wallet(
        "ton",
        vec![
            // another of the key's wallets
            message(b'T', 0, 0, &subwallet),
            // the test network's W5 request, asked of TON
            message(b'T', 0, 0, &test_w5),
            // a request for another to pass on
            message(b'T', 0, 0, &internal),
            // cut short, and with more after it
            message(b'T', 0, 0, &ton[..ton.len() - 1]),
            message(b'T', 0, 0, &[&ton[..], &[0]].concat()),
            // not a bag of cells, nothing
            message(b'T', 0, 0, b"not a bag of cells"),
            message(b'T', 0, 0, &[]),
            // a network maki doesn't know
            message(b'T', 2, 0, &ton),
        ],
        vec![Answer::Yes; 8],
        false,
    );
    let said = |i: usize| (r.replies[i][0], texts(&r.replies[i]).join(""));
    assert_eq!(said(0), (5, "not this account's wallet: another wallet ID".to_string()));
    assert_eq!(said(1), (5, "a request for TON's test network, not TON: its wallet ID says so".to_string()));
    assert_eq!(
        said(2),
        (5, "a request for another contract to pass on (W5's signed internal message): maki doesn't sign those".to_string())
    );
    // the CRC32C the BOC carries no longer matches
    assert_eq!(said(3), (5, "not a TON bag of cells: its checksum is wrong".to_string()));
    assert_eq!(said(4), (5, "not a TON bag of cells: its checksum is wrong".to_string()));
    assert_eq!(said(5), (5, "not a TON bag of cells".to_string()));
    assert_eq!(said(6), (5, "not a TON bag of cells".to_string()));
    assert_eq!(r.replies[7], [4]);
    assert!(r.reviews.is_empty(), "nothing shown for what can't be signed");
    // locked: nothing read, nothing shown
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &ton)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
}

#[test]
fn ton_goes_through_as_much_as_a_message_holds() {
    // 40 messages in one W5 request: a page each, in the memory the app asks for
    let (many, signature) = ton_fixture("many", "v5R1", 0);
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &many)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    assert_eq!(r.reviews[0].pages.len(), 42);
    assert_eq!(r.reviews[0].detail, "sends 0.00000082 TON in 40 messages; plus the network's fee");
    // 150: more pages than the screen goes through, refused before maki's asked
    let (too_many, _) = ton_fixture("too-many", "v5R1", 0);
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &too_many)], vec![], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["too much to go through on maki's screen".to_string()])
    );
    assert!(r.reviews.is_empty());
    // 63, each with a long comment: as many pages as it goes through, but more text than maki's
    // review screen takes, so refused, and said why
    let (too_long, _) = ton_fixture("too-long", "v5R1", 0);
    let key: [u8; 32] = unhex(KEY).try_into().unwrap();
    let boc = maki_ton::Boc::parse(&too_long).unwrap();
    let request = maki_ton::Request::parse(&boc).unwrap();
    let shown = maki_ton::display::review(&request, &key, maki_ton::Network::Main).unwrap();
    assert_eq!(shown.pages.len(), 128);
    let text: usize =
        shown.pages.iter().map(|p| 4 + p.heading.len() + p.value.len() + p.mono.len() + p.prose.len()).sum();
    assert!(text > MAX_REVIEW, "{text}");
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &too_long)], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["too much to show on maki's screen".to_string()])
    );
    // as many cells as a message holds (2036, each two bytes, all but the first unreached): read
    // in the memory the app asks for, and refused
    let n: u16 = 2036;
    let mut boc = vec![0xb5, 0xee, 0x9c, 0x72, 0x02, 2];
    for v in [n, 1, 0, 2 * n, 0] {
        boc.extend_from_slice(&v.to_be_bytes());
    }
    boc.extend(std::iter::repeat_n(0u8, 2 * n as usize));
    assert!(boc.len() + 6 <= 4096, "{}", boc.len());
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &boc)], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["a bag of cells with a cell nothing refers to".to_string()])
    );
    // a chain of 1000 cells, each referring to the next: read whole, and refused as no request
    let n: u16 = 1000;
    let mut deep = vec![0xb5, 0xee, 0x9c, 0x72, 0x02, 2];
    for v in [n, 1, 0, (n - 1) * 4 + 2, 0] {
        deep.extend_from_slice(&v.to_be_bytes());
    }
    for i in 1..n {
        deep.extend_from_slice(&[1, 0]);
        deep.extend_from_slice(&i.to_be_bytes());
    }
    deep.extend_from_slice(&[0, 0]);
    let r = run_wallet("ton", vec![message(b'T', 0, 0, &deep)], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["not as TON writes it: a cell ends too soon".to_string()])
    );
}

#[test]
fn ton_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "ton",
        vec![Event::Right, Event::Left, Event::Menu(0), Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME_V4));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(ACCOUNT_1_V4), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME_V4));
    // the menu's other wallet: W5's, and the menu offers v4R2's back
    assert_eq!(read_qr(&r.frames[3]).as_deref(), Some(ME_W5));
    assert_eq!(r.menu, ["v4R2 wallet"]);
    assert!(read_qr(&r.frames[4]).is_none(), "as text");
    assert!(lit(&r.frames[4]) > 100);
    // locked: no address to show
    let r = run_wallet_with("ton", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
}
