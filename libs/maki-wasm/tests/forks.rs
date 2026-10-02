//! The Dogecoin and Bitcoin Cash apps (sdk/examples/dogecoin, bitcoincash), as maki runs them:
//! Bitcoin's wallet code before SegWit, the Bitcoin app's messages with its third kind of account
//! (2, pay-to-key-hash). The account shared once asked and its first address as wallets publish it
//! for the test phrase, a payment signed as bitcoinjs-lib (Dogecoin) and libauth (Bitcoin Cash) sign
//! it (maki-btc's fixtures), the review in the coin's own units, and the address on the home screen.

mod harness;

use harness::*;
use maki_wasm::*;

const BTC_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-btc/tests/fixtures");

/// A PSBT sent in pieces as maki desktop sends it, then the signed one fetched.
fn psbt_messages(network: u8, psbt: &[u8], fetches: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (i, piece) in psbt.chunks(4000).enumerate() {
        let mut m = vec![b'P', network];
        m.extend_from_slice(&(psbt.len() as u32).to_le_bytes());
        m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
        m.extend_from_slice(piece);
        out.push(m);
    }
    for i in 0..fetches {
        let mut m = vec![b'G'];
        m.extend_from_slice(&((i * 4000) as u32).to_le_bytes());
        out.push(m);
    }
    out
}

fn fetched(replies: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in replies {
        assert_eq!(r[0], 0);
        let total = u32::from_le_bytes(r[1..5].try_into().unwrap()) as usize;
        out.extend_from_slice(&r[9..]);
        if out.len() == total {
            break;
        }
    }
    out
}

#[test]
fn dogecoin_shares_its_account_and_compares_addresses_once_asked() {
    let r = run_wallet(
        "dogecoin",
        vec![vec![b'A', 0, 2], vec![b'D', 0, 2, 0, 0, 0, 0, 0], vec![b'A', 0, 0]],
        vec![Answer::Yes, Answer::Yes],
        false,
    );
    let [key, descriptor] = <[String; 2]>::try_from(texts(&r.replies[0])).unwrap();
    assert!(key.starts_with("xpub"), "{key}");
    assert!(descriptor.starts_with("pkh([73c5da0a/44h/3h/0h]xpub"), "{descriptor}");
    assert_eq!(r.reviews[0].detail, "dogecoin, view only");
    // BIP44's first, as Dogecoin's wallets publish it for the test phrase
    assert_eq!(texts(&r.replies[1]), ["DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC"]);
    // there's no native SegWit account on Dogecoin: a message for one is one it can't read
    assert_eq!(r.replies[2], [4]);
}

#[test]
fn dogecoin_signs_what_the_owner_reviewed_in_dogecoin() {
    let psbt = std::fs::read(format!("{BTC_FIXTURES}/dogecoin-unsigned.psbt")).unwrap();
    let expected = std::fs::read(format!("{BTC_FIXTURES}/dogecoin-signed.psbt")).unwrap();
    let r = run_wallet("dogecoin", psbt_messages(0, &psbt, 1), vec![Answer::Yes], false);
    assert_eq!(fetched(&r.replies[1..]), expected);
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Sign and spend", "10.01 DOGE"));
    let pages: Vec<(&str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str())).collect();
    assert!(pages.contains(&("Change", "11.49 DOGE")), "{pages:?}");
    assert!(review.pages.iter().any(|p| p.mono.replace('\n', "") == "DL54i6msdfchWaR7NHFA41HxSiYciTwhqW"));
    // a no signs nothing
    let r = run_wallet("dogecoin", psbt_messages(0, &psbt, 1), vec![Answer::No], false);
    assert_eq!(r.replies[0], [1]);
    // on the test network's account it isn't this wallet's
    let r = run_wallet("dogecoin", psbt_messages(1, &psbt, 0), vec![Answer::Yes], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(r.reviews.is_empty());
}

#[test]
fn dogecoin_shows_its_address_with_its_capitals() {
    let r = run_wallet_with("dogecoin", vec![], vec![], vec![], false);
    // base58: a code of the address as it is, not in capitals as bech32's are
    assert_eq!(read_qr(r.frames.last().unwrap()).unwrap(), "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
}

#[test]
fn bitcoin_cash_shares_its_account_and_signs_with_its_fork_id() {
    let r = run_wallet(
        "bitcoincash",
        vec![vec![b'A', 0, 2], vec![b'D', 0, 2, 1, 0, 0, 0, 0]],
        vec![Answer::Yes, Answer::Yes],
        false,
    );
    assert!(texts(&r.replies[0])[1].starts_with("pkh([73c5da0a/44h/145h/0h]xpub"));
    assert_eq!(texts(&r.replies[1]), ["bitcoincash:qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx"]);
    assert_eq!(r.reviews[1].pages[0].heading, "Change #0");

    let psbt = std::fs::read(format!("{BTC_FIXTURES}/bitcoincash-unsigned.psbt")).unwrap();
    let expected = std::fs::read(format!("{BTC_FIXTURES}/bitcoincash-signed.psbt")).unwrap();
    let r = run_wallet("bitcoincash", psbt_messages(0, &psbt, 1), vec![Answer::Yes], false);
    // libauth's signatures, SIGHASH_ALL | SIGHASH_FORKID
    assert_eq!(fetched(&r.replies[1..]), expected);
    let review = &r.reviews[0];
    assert_eq!(review.detail, "0.000705 BCH");
    assert!(
        review
            .pages
            .iter()
            .any(|p| p.mono.replace('\n', "") == "bitcoincash:qz3udv0wffyanu408vuq9968gna6jfqkfgvmw4xv9k")
    );
}

#[test]
fn bitcoin_cash_shows_its_cashaddr_in_capitals() {
    let r = run_wallet_with("bitcoincash", vec![Event::Right], vec![], vec![], false);
    assert_eq!(
        read_qr(r.frames.last().unwrap()).unwrap(),
        "BITCOINCASH:QP8SFDHGJLQ68HLZKA9LCSXTCNVUVND0XQXUGFZZC5"
    );
}
