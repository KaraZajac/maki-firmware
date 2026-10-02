//! The Dash app (sdk/examples/dash), as `maki build` packed it, run as maki runs it: Bitcoin's
//! wallet code before SegWit on Dash's networks, in the Bitcoin app's messages with its third kind
//! of account (2, pay-to-key-hash). The account shared once asked, and its first address as Dash's
//! wallets make it for the test phrase; the payment dashcore-lib signed (maki-btc's fixtures: a
//! plain coin and one a withdrawal from Dash Platform paid) signed byte for byte, its review in
//! DASH; special transactions refused by name before anything is shown; and the address on the
//! home screen. Rebuild the fixture after changing the app: `maki build examples/dash` in sdk/,
//! then copy `sdk/target/maki/com.leviathan.maki.dash.maki` to `tests/fixtures/dash.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

const BTC_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-btc/tests/fixtures");
/// BIP44's first, as Dash's wallets make it for the test phrase.
const ME: &str = "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5";

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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn dash_shares_its_account_and_compares_addresses_once_asked() {
    let r = run_wallet(
        "dash",
        vec![
            vec![b'A', 0, 2],
            vec![b'D', 0, 2, 0, 0, 0, 0, 0],
            vec![b'D', 1, 2, 0, 0, 0, 0, 0],
            vec![b'A', 0, 2],
            vec![b'A', 0, 0],
        ],
        vec![Answer::Yes, Answer::Yes, Answer::No, Answer::No],
        false,
    );
    let [key, descriptor] = <[String; 2]>::try_from(texts(&r.replies[0])).unwrap();
    assert_eq!(
        key,
        "xpub6CYEjsU6zPM3sADS2ubu2aZeGxCm3C5KabkCpo4rkNbXGAH9M7rRUJ4E5CKiyUddmRzrSCopPzisTBrXkfCD4o577XKM9mzyZtP1Xdbizyk"
    );
    assert!(descriptor.starts_with(&format!("pkh([73c5da0a/44h/5h/0h]{key}/<0;1>/*)#")), "{descriptor}");
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "dash, view only", "share", "don't")
    );
    // the owner's say, then maki's address either way
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (0, vec![ME.to_string()]));
    let page = &r.reviews[1].pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str(), page.mono.as_str()), ("Receive #0", "dash", ME));
    assert_eq!(
        (r.replies[2][0], texts(&r.replies[2])),
        (1, vec!["yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt".to_string()])
    );
    assert_eq!(r.reviews[2].pages[0].value, "dash testnet");
    // a no shares nothing; Dash has no native SegWit account: a message for one it can't read
    assert_eq!(r.replies[3], [1]);
    assert_eq!(r.replies[4], [4]);
    // locked, there's no account to share
    let r = run_wallet("dash", vec![vec![b'A', 0, 2]], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
}

#[test]
fn dash_signs_what_the_owner_reviewed_in_dash() {
    let psbt = std::fs::read(format!("{BTC_FIXTURES}/dash-unsigned.psbt")).unwrap();
    let expected = std::fs::read(format!("{BTC_FIXTURES}/dash-signed.psbt")).unwrap();
    let r = run_wallet("dash", psbt_messages(0, &psbt, 1), vec![Answer::Yes], false);
    // dashcore-lib's signatures, maki-btc's fixture
    assert_eq!(fetched(&r.replies[1..]), expected);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.timeout_s),
        ("Sign and spend", "1.0001 DASH", 300)
    );
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Send", "1 DASH", "Xqcp16V8Hxw18Wq6VaZpMmp9PvQ1MDVyJV"),
            ("Change", "0.7499 DASH", "back to you"),
            ("Fee", "0.0001 DASH", "27 duff/B")
        ]
    );
    // a no signs nothing
    let r = run_wallet("dash", psbt_messages(0, &psbt, 1), vec![Answer::No], false);
    assert_eq!(r.replies[0], [1]);
    // on the test network's account it isn't this wallet's
    let r = run_wallet("dash", psbt_messages(1, &psbt, 0), vec![Answer::Yes], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(texts(&r.replies[0])[0].starts_with("input 0 isn't this wallet's"));
    assert!(r.reviews.is_empty());
    // locked, nothing can be checked
    let r = run_wallet("dash", psbt_messages(0, &psbt, 0), vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
}

#[test]
fn dash_refuses_special_transactions_by_name() {
    // an asset lock as dashcore-lib makes it (maki-btc's fixture), in a PSBT of its own
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{BTC_FIXTURES}/dash.json")).unwrap()).unwrap();
    let tx = unhex(json["assetLock"]["unsigned"].as_str().unwrap());
    let mut psbt = b"psbt\xff".to_vec();
    psbt.extend_from_slice(&[0x01, 0x00, tx.len() as u8]);
    psbt.extend_from_slice(&tx);
    // the end of the global map, an input's (empty) and two outputs'
    psbt.extend_from_slice(&[0, 0, 0, 0]);
    let r = run_wallet("dash", psbt_messages(0, &psbt, 0), vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["a Dash asset lock (credit for Dash Platform): maki signs payments only".to_string()])
    );
    assert!(r.reviews.is_empty(), "refused before anything was shown");
    // bytes that aren't a PSBT at all, and the asset lock's PSBT cut short
    let r = run_wallet(
        "dash",
        vec![
            psbt_messages(0, b"not a psbt", 0).remove(0),
            psbt_messages(0, &psbt[..psbt.len() - 2], 0).remove(0),
        ],
        vec![],
        false,
    );
    assert!(r.replies.iter().all(|reply| reply[0] == 5), "{:?}", r.replies);
    assert!(texts(&r.replies[0])[0].starts_with("not a PSBT maki can read"));
    assert!(r.reviews.is_empty());
}

#[test]
fn dash_shows_its_address_with_its_capitals() {
    let r = run_wallet_with("dash", vec![Event::Menu(0)], vec![], vec![], false);
    assert_eq!(r.menu, ["Dash or testnet", "Account key"]);
    // base58: a code of the address as it is, not in capitals as bech32's are
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(r.frames.last().unwrap()).as_deref(), Some("yRd4FhXfVGHXpsuZXPNkMrfD9GVj46pnjt"));
}
