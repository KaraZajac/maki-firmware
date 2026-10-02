//! The Zcash app (sdk/examples/zcash), as `maki build` packed it, run as maki runs it: its account
//! shared once the owner says so, its t-addresses compared on maki's screen, the transactions
//! librustzcash made (maki-zec's fixtures: version 5, transparent, at NU6.3's consensus branch)
//! signed byte for byte as librustzcash signs them, after the owner has gone through them; and what
//! isn't this wallet's, or isn't a transaction maki reads (version 6, shielded parts), refused before
//! anything is shown. Rebuild the fixture after changing the app: `maki build examples/zcash` in
//! sdk/, then copy `sdk/target/maki/com.leviathan.maki.zcash.maki` to `tests/fixtures/zcash.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

const ZEC_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-zec/tests/fixtures");
/// The test phrase's first t-address, as Zcash's wallets make it.
const ME: &str = "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn json() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{ZEC_FIXTURES}/transactions.json")).unwrap())
        .unwrap()
}

fn fixture(name: &str) -> serde_json::Value {
    json()["transactions"].as_array().unwrap().iter().find(|f| f["name"] == name).unwrap().clone()
}

/// A transaction librustzcash made, as maki desktop asks the app to sign it (`T`, the network, the
/// request).
fn sign_message(name: &str) -> Vec<u8> {
    let f = fixture(name);
    [&[b'T', f["network"].as_u64().unwrap() as u8][..], &unhex(f["request"].as_str().unwrap())].concat()
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

/// An answer's signatures: each a u8 length, then the signature.
fn signatures(answer: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(answer[0], 0);
    let (mut out, mut at) = (Vec::new(), 1);
    while at < answer.len() {
        let n = answer[at] as usize;
        out.push(answer[at + 1..at + 1 + n].to_vec());
        at += 1 + n;
    }
    out
}

#[test]
fn zcash_shares_its_account_once_asked() {
    let json = json();
    let r = run_wallet(
        "zcash",
        vec![vec![b'A', 0], vec![b'A', 0], vec![b'A', 1]],
        vec![Answer::Yes, Answer::No, Answer::Yes],
        false,
    );
    // the account's key and chain code, as zcash_transparent has them, and its first address
    let reply = &r.replies[0];
    assert_eq!(reply[0], 0);
    assert_eq!(reply[1..34], unhex(json["account"]["key"].as_str().unwrap()));
    assert_eq!(reply[34..66], unhex(json["account"]["chainCode"].as_str().unwrap()));
    assert_eq!(texts(&reply[65..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "zcash, view only", "share", "don't")
    );
    assert!(review.pages.is_empty());
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    // the test network's: its own keys (coin type 1), its own addresses
    assert_ne!(r.replies[2][1..34], reply[1..34]);
    assert_eq!(texts(&r.replies[2][65..]), [address(1, 0, 0)]);
    assert_eq!(r.reviews[2].detail, "zcash testnet, view only");
    // locked, there's no account to share
    let r = run_wallet("zcash", vec![vec![b'A', 0]], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    // a network there isn't, more after the message, a message this app hasn't, nothing
    let r = run_wallet("zcash", vec![vec![b'A', 2], vec![b'A', 0, 0], vec![b'Z', 0], vec![]], vec![], false);
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

/// `D`: the address at a key of the account's, to compare.
fn compare(network: u8, chain: u8, index: u32) -> Vec<u8> {
    [&[b'D', network, chain][..], &index.to_le_bytes()].concat()
}

#[test]
fn zcash_compares_addresses_on_its_screen() {
    let r = run_wallet(
        "zcash",
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
    assert_eq!(review.pages, [page("Receive #0", "zcash", ME, "")]);
    assert_eq!(r.reviews[1].pages, [page("Change #1", "zcash", &address(0, 1, 1), "")]);
    assert_eq!(r.reviews[2].pages[0].value, "zcash testnet");
    // a chain the account hasn't, a hardened index, a message cut short, a network there isn't
    let r = run_wallet(
        "zcash",
        vec![compare(0, 2, 0), compare(0, 0, 1 << 31), compare(0, 0, 0)[..6].to_vec(), compare(2, 0, 0)],
        vec![],
        false,
    );
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    let r = run_wallet("zcash", vec![compare(0, 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
}

#[test]
fn zcash_signs_what_librustzcash_signs() {
    let json = json();
    let mut signed = 0;
    for f in json["transactions"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let Some(theirs) = f["signatures"].as_array() else { continue };
        let r = run_wallet("zcash", vec![sign_message(name)], vec![Answer::Yes], false);
        // every input's signature, in order, byte for byte librustzcash's
        let ours = signatures(&r.replies[0]);
        let theirs: Vec<Vec<u8>> = theirs.iter().map(|s| unhex(s.as_str().unwrap())).collect();
        assert_eq!(ours, theirs, "{name}");
        // and with each input's key after its signature, the transaction librustzcash wrote, signed
        let request = maki_zec::Request::parse(&unhex(f["request"].as_str().unwrap())).unwrap();
        let network = maki_zec::Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap();
        let keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
        let account = maki_zec::Account::new(&keys, network).unwrap();
        let scripts: Vec<Vec<u8>> = request
            .coins
            .iter()
            .zip(&ours)
            .map(|(coin, sig)| {
                let key = account.key(coin.key).unwrap();
                [&[sig.len() as u8][..], sig, &[33], &key].concat()
            })
            .collect();
        assert_eq!(request.tx.write(&scripts), unhex(f["signed"].as_str().unwrap()), "{name}");
        signed += 1;
    }
    assert_eq!(signed, 11);
    // what the owner went through first
    let payee = json["payees"]["p2pkh"].as_str().unwrap();
    let r = run_wallet("zcash", vec![sign_message("payment")], vec![Answer::Yes], false);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.timeout_s),
        ("Sign and send", "sends 1 ZEC; fee 0.0001 ZEC", 300)
    );
    assert_eq!(
        review.pages,
        [
            page("Send", "1 ZEC", payee, ""),
            page("Change", "0.4999 ZEC", "back to you", ""),
            page("Fee", "0.0001 ZEC", "", "ZIP-317's conventional fee.")
        ]
    );
    // a TEX address as the owner gave it; the test network's in TAZ
    let r =
        run_wallet("zcash", vec![sign_message("tex"), sign_message("testnet")], vec![Answer::Yes; 2], false);
    assert_eq!(r.reviews[0].pages[0].mono, json["payees"]["tex"].as_str().unwrap());
    assert_eq!(r.reviews[1].detail, "sends 1 TAZ; fee 0.0001 TAZ");
    // the most a message holds: 49 coins, 49 signatures
    let message = sign_message("many-inputs");
    assert!(message.len() <= 4096);
    let r = run_wallet("zcash", vec![message], vec![Answer::Yes], false);
    assert_eq!(signatures(&r.replies[0]).len(), 49);
    assert!(r.replies[0].len() <= 4096);
}

#[test]
fn zcash_refuses_what_it_mustnt_sign() {
    let payment = sign_message("payment");
    let too_long = [&payment[..], &vec![0u8; 4097 - payment.len()]].concat();
    // librustzcash's version 6 of the payment, as wallets make by default since NU6.3
    let v6 = unhex(json()["version6"].as_str().unwrap());
    let request = &payment[2..];
    let n = u16::from_le_bytes([request[0], request[1]]) as usize;
    let as_v6 = [&[b'T', 0][..], &(v6.len() as u16).to_le_bytes(), &v6, &request[2 + n..]].concat();
    // the payment with a Sapling spend after its transparent parts
    let mut shielded = payment.clone();
    shielded[4 + n - 3] = 1;
    let r = run_wallet(
        "zcash",
        vec![
            payment.clone(),
            sign_message("not-mine"),
            as_v6,
            shielded,
            [&[b'T', 2][..], &payment[2..]].concat(),
            too_long,
            vec![b'T'],
        ],
        vec![Answer::No],
        false,
    );
    // a no signs nothing
    assert_eq!(r.replies[0], [1]);
    // not this wallet's coin, a transaction maki doesn't read: refused with why
    let why = |reply: &[u8]| -> (u8, Vec<String>) { (reply[0], texts(reply)) };
    assert_eq!(
        why(&r.replies[1]),
        (
            5,
            vec![
                "input 0 isn't this wallet's (maki signs for Zcash's transparent account, m/44'/133'/0')"
                    .into()
            ]
        )
    );
    assert_eq!(
        why(&r.replies[2]),
        (
            5,
            vec![
                "a version 6 transaction (ZIP 229, NU6.3's): maki reads version 5, which Zcash still takes"
                    .into()
            ]
        )
    );
    assert_eq!(
        why(&r.replies[3]),
        (
            5,
            vec!["a transaction with Sapling spends, which are shielded: maki can't see into them, and signs transparent transactions only".into()]
        )
    );
    // a network there isn't, a message longer than a message, and one with no network
    assert_eq!(r.replies[4..], [vec![4], vec![4], vec![4]]);
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // the test network's transaction on the main network's account: other keys
    let testnet = sign_message("testnet");
    let r = run_wallet("zcash", vec![[&[b'T', 0][..], &testnet[2..]].concat()], vec![Answer::Yes], false);
    assert_eq!(r.replies[0][0], 5);
    // locked, nothing can be checked, so nothing is shown
    let r = run_wallet("zcash", vec![payment], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
}

#[test]
fn zcash_shows_an_address_to_receive_at() {
    let r = run_wallet_with(
        "zcash",
        vec![Event::Right, Event::Centre, Event::Centre, Event::Menu(0)],
        vec![],
        vec![],
        false,
    );
    assert_eq!(r.menu, ["Zcash or testnet"]);
    // base58: the address as it is
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]), Some(address(0, 0, 1)), "receive #1");
    assert!(read_qr(&r.frames[2]).is_none(), "as text");
    assert_eq!(read_qr(&r.frames[3]), Some(address(0, 0, 1)));
    assert_eq!(read_qr(&r.frames[4]), Some(address(1, 0, 1)), "the test network's");
    // locked, no address to show
    let r = run_wallet_with("zcash", vec![], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 50);
}
