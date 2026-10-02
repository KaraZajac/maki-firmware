//! The Cosmos example (sdk/examples/cosmos), as `maki build` packed it and maki runs it: its account
//! shared once the owner says so, on the Cosmos Hub or another chain maki knows, its address
//! compared on maki's screen and shown as a QR code, CosmJS's sign docs
//! (`maki-atom/tests/fixtures/make.mjs`) read, shown and signed as CosmJS signs them, and what isn't
//! this account's to sign, another network's, or can't be read, refused before anything is shown.
//! Rebuild the fixture after changing the app: `maki build sdk/examples/cosmos`, then copy
//! `sdk/target/maki/com.leviathan.maki.cosmos.maki` to `tests/fixtures/cosmos.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

/// The test phrase's first Cosmos account, as Keplr, Ledger's Cosmos app and CosmJS make it.
const ME: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
/// Its second, `m/44'/118'/0'/0/1`, as CosmJS's `makeCosmoshubPath(1)` has it.
const SECOND: &str = "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz";
/// The first, on Osmosis and on Celestia.
const OSMO_ME: &str = "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8";
const CELESTIA_ME: &str = "celestia19rl4cm2hmr8afy4kldpxz3fka4jguq0ad2ud9c";
const RECIPIENT: &str = "cosmos10xcqpzrky6eff2g52qdye53xkk9jxkvrpq6uqr";
/// Its public key, compressed, as CosmJS has it.
const KEY: &str = "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62";
const ATOM_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-atom/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, index: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&index.to_le_bytes());
    m
}

/// A head, then a chain's ID as a string.
fn on(kind: u8, network: u8, index: u32, chain: &str) -> Vec<u8> {
    [head(kind, network, index), (chain.len() as u16).to_le_bytes().to_vec(), chain.as_bytes().to_vec()]
        .concat()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// CosmJS's sign docs: each one's name, its chain, its bytes, and CosmJS's signature for this
/// account.
fn fixtures() -> Vec<(String, String, Vec<u8>, Option<Vec<u8>>)> {
    let text = std::fs::read_to_string(format!("{ATOM_FIXTURES}/signdocs.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                f["chain"].as_str().unwrap().to_string(),
                f["doc"].as_str().unwrap().as_bytes().to_vec(),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> (Vec<u8>, Vec<u8>) {
    let (_, _, doc, signature) = fixtures().into_iter().find(|f| f.0 == name).unwrap();
    (doc, signature.unwrap_or_default())
}

/// `T` for this account, on a main network, with this sign doc.
fn sign(doc: &[u8]) -> Vec<u8> { [head(b'T', 0, 0), doc.to_vec()].concat() }

#[test]
fn cosmos_shares_its_account_once_asked_and_compares_its_address() {
    let r = run_wallet(
        "cosmos",
        vec![head(b'A', 0, 0), on(b'A', 0, 0, "osmosis-1"), head(b'A', 0, 0)],
        vec![Answer::Yes, Answer::Yes, Answer::No],
        false,
    );
    // OK, the key's length, the key compressed (as a transaction carries it), then the address
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1]), (0, 33));
    assert_eq!(answer[2..35], unhex(KEY));
    assert_eq!(texts(&answer[34..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "cosmos hub, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // the same key, its address on Osmosis
    assert_eq!(r.replies[1][2..35], unhex(KEY));
    assert_eq!(texts(&r.replies[1][34..]), [OSMO_ME]);
    assert_eq!(r.reviews[1].detail, "osmosis, view only");
    // a no shares nothing
    assert_eq!(r.replies[2], [1]);
    // a test network's chain, and its Cosmos Hub when it says none
    let r = run_wallet(
        "cosmos",
        vec![on(b'A', 1, 2, "mocha-5"), head(b'A', 1, 0)],
        vec![Answer::Yes, Answer::Yes],
        false,
    );
    assert_eq!(r.reviews[0].detail, "celestia testnet account #2, view only");
    assert_eq!(r.reviews[1].detail, "cosmos hub testnet, view only");
    assert_eq!(texts(&r.replies[1][34..]), [ME]);
    let r = run_wallet("cosmos", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // the address on maki's screen: the owner's answer, and maki's address either way
    let r = run_wallet(
        "cosmos",
        vec![head(b'D', 0, 0), head(b'D', 0, 1), on(b'D', 0, 0, "celestia")],
        vec![Answer::Yes, Answer::No, Answer::NoAnswer],
        false,
    );
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![SECOND.to_string()]));
    assert_eq!((r.replies[2][0], texts(&r.replies[2])), (2, vec![CELESTIA_ME.to_string()]));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Same on computer?", "matches", "doesn't match")
    );
    assert_eq!(
        review.pages,
        [Page {
            heading: "Address".into(),
            value: "cosmos hub".into(),
            mono: ME.into(),
            prose: String::new()
        }]
    );
    assert_eq!(r.reviews[1].pages[0].value, "cosmos hub account #1");
    assert_eq!(r.reviews[2].pages[0].value, "celestia");
    // a chain maki doesn't know, or on the other kind of network than the message says: refused
    let r = run_wallet(
        "cosmos",
        vec![on(b'A', 0, 0, "secret-4"), on(b'A', 0, 0, "osmo-test-5"), on(b'D', 1, 0, "osmosis-1")],
        vec![],
        false,
    );
    let refused = |a: &Vec<u8>| (a[0], texts(a).join(""));
    assert_eq!(refused(&r.replies[0]), (5, String::from("a chain maki doesn't know (secret-4)")));
    assert_eq!(
        refused(&r.replies[1]),
        (5, String::from("osmo-test-5 is a test network, not a main network"))
    );
    assert_eq!(
        refused(&r.replies[2]),
        (5, String::from("osmosis-1 is a main network, not a test network: its coins are real"))
    );
    assert!(r.reviews.is_empty());
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // BIP32's unhardened ones, a chain's ID cut short or with more after it, or not UTF-8, or a
    // head cut short
    let r = run_wallet(
        "cosmos",
        vec![
            head(b'M', 0, 0),
            head(b'A', 2, 0),
            head(b'A', 0, 0x8000_0000),
            [on(b'A', 0, 0, "osmosis-1"), vec![0]].concat(),
            on(b'A', 0, 0, "osmosis-1")[..12].to_vec(),
            [head(b'D', 0, 0), vec![0]].concat(),
            [head(b'A', 0, 0), vec![2, 0, 0xff, 0xfe]].concat(),
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
fn cosmos_signs_what_the_owner_reviewed_as_cosmjs_signs() {
    let (send, signature) = fixture("send");
    let r = run_wallet("cosmos", vec![sign(&send)], vec![Answer::Yes], false);
    // OK, then r and s, 64 bytes, as the transaction carries them
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    assert_eq!(r.replies[0].len(), 65);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 1.5 ATOM; fee up to 0.005 ATOM")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Network", "Cosmos Hub", "cosmoshub-4"),
            ("Send", "1.5 ATOM", RECIPIENT),
            ("Max fee", "0.005 ATOM", "")
        ]
    );
    // every sign doc maki shows, on its chain's network, signed as CosmJS signs it
    let mut signed = 0;
    for (name, chain, doc, signature) in fixtures() {
        if ["not-mine", "grant", "grant-allowance", "unknown-chain"].contains(&name.as_str()) {
            continue;
        }
        let network = if ["provider", "osmo-test-5", "mocha-5"].contains(&chain.as_str()) { 1 } else { 0 };
        let r = run_wallet("cosmos", vec![[head(b'T', network, 0), doc].concat()], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], [&[0u8][..], &signature.unwrap()].concat(), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 58);
    // IBC to Osmosis, and the longest memo maki's link carries, shown whole
    let (ibc, _) = fixture("ibc");
    let (long, _) = fixture("long-memo");
    let r = run_wallet("cosmos", vec![sign(&ibc), sign(&long)], vec![Answer::Yes, Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "sends 1.5 ATOM to Osmosis; fee up to 0.005 ATOM");
    assert_eq!(
        r.reviews[0].pages[1].prose,
        "To Osmosis, by IBC (channel-141). If it hasn't arrived by 2026-10-02 05:00:00 UTC, it comes back."
    );
    assert_eq!(r.reviews[1].pages[2].mono, "a".repeat(3500));
    assert!(r.replies.iter().all(|a| a[0] == 0 && a.len() == 65));
}

#[test]
fn cosmos_refuses_what_isnt_its_to_sign_before_showing_it() {
    let (send, _) = fixture("send");
    let (not_mine, _) = fixture("not-mine");
    let (grant, _) = fixture("grant");
    let (secret, _) = fixture("unknown-chain");
    let (testnet, _) = fixture("send-osmotest");
    let r = run_wallet(
        "cosmos",
        vec![
            // the owner says no
            sign(&send),
            // another account's, and this one's but for another of its accounts
            sign(&not_mine),
            [head(b'T', 0, 1), send.clone()].concat(),
            // a grant to another account, a chain maki doesn't know, and not a sign doc
            sign(&grant),
            sign(&secret),
            sign(b"{}"),
            sign(&[send.clone(), vec![b' ']].concat()),
            // a test network's sign doc said to be a main network's, and the Hub's said to be a
            // test network's: real coins passed off as play money
            sign(&testnet),
            [head(b'T', 1, 0), send.clone()].concat(),
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
                "an authz grant, which lets another account act for this one until it's revoked: maki won't sign that"
            )
        )
    );
    assert_eq!(
        refused(&r.replies[4]),
        (5, String::from("a chain maki doesn't know (secret-4): it won't sign for it"))
    );
    assert_eq!(
        refused(&r.replies[5]),
        (5, String::from("not a sign doc as Cosmos writes one: no account_number"))
    );
    assert_eq!(r.replies[6][0], 5);
    assert_eq!(
        refused(&r.replies[7]),
        (5, String::from("a test network's transaction (osmo-test-5), sent as a main network's"))
    );
    assert_eq!(
        refused(&r.replies[8]),
        (
            5,
            String::from(
                "a main network's transaction (cosmoshub-4), sent as a test network's: its coins are real"
            )
        )
    );
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: nothing read, nothing shown
    let r = run_wallet("cosmos", vec![sign(&send)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet("cosmos", vec![[sign(&send), vec![b' '; 4096]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn cosmos_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "cosmos",
        vec![Event::Right, Event::Left, Event::Menu(0), Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(r.menu, ["Next chain"]);
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(SECOND), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[3]).as_deref(), Some(OSMO_ME), "the next chain: Osmosis");
    assert!(read_qr(&r.frames[4]).is_none(), "as text");
    // every chain in turn, and round to the Hub again
    let mut events = vec![Event::Menu(0); 13];
    events.push(Event::Exit);
    let r = run_wallet_with("cosmos", events, vec![], vec![], false);
    let shown: Vec<String> = r.frames.iter().map(|f| read_qr(f).unwrap()).collect();
    assert_eq!(shown[2], CELESTIA_ME);
    assert_eq!(shown[13], ME);
    assert!(shown.iter().all(|a| a.contains("19rl4cm2hmr8afy4kldpxz3fka4jguq0a")), "{shown:?}");
    // locked: no address to show
    let r = run_wallet_with("cosmos", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}

#[test]
fn cosmos_reads_the_most_a_message_can_hold() {
    // a message maki can't read, as many values as the link carries, and one nested as deep as maki
    // reads: in the app's memory and stack, read, shown and signed
    let doc = |value: &str| {
        format!(
            r#"{{"account_number":"1","chain_id":"cosmoshub-4","fee":{{"amount":[],"gas":"200000"}},"memo":"","msgs":[{{"type":"x/y","value":{value}}}],"sequence":"0"}}"#
        )
    };
    let empty = doc("[]").len();
    let many = format!("[{}0]", "0,".repeat((4096 - 6 - empty) / 2 - 1));
    let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
    let deeper = format!("{}{}", "[".repeat(18), "]".repeat(18));
    let (many, deep, deeper) = (doc(&many), doc(&deep), doc(&deeper));
    assert!(sign(many.as_bytes()).len() >= 4095);
    let r = run_wallet(
        "cosmos",
        vec![sign(many.as_bytes()), sign(deep.as_bytes()), sign(deeper.as_bytes())],
        vec![Answer::Yes, Answer::Yes],
        false,
    );
    assert_eq!((r.replies[0][0], r.replies[1][0]), (0, 0));
    assert_eq!(r.reviews[0].detail, "maki can't read all of it; no fee");
    assert_eq!(r.reviews[1].pages[1].mono, format!("x/y\n{}{}", "[".repeat(17), "]".repeat(17)));
    // the eighteenth array in the message, twenty deep in all, is one too many
    let at = deeper.find(r#""value":"#).unwrap() + 8 + 17;
    assert_eq!(
        texts(&r.replies[2]),
        [format!("not a sign doc as Cosmos writes one: nested too deep at byte {at}")]
    );
}
