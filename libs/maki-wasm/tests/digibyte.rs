//! The DigiByte app (sdk/examples/digibyte), as `maki build` packed it, run as maki runs it:
//! Bitcoin's wallet code on DigiByte's networks, in the Bitcoin app's messages with all three kinds
//! of account (0 native SegWit, 1 taproot, 2 pay-to-key-hash). Each account shared once asked, its
//! addresses as DigiByte's library makes them for the test phrase, the payment DigiByte's library
//! and bitcoinjs-lib signed (maki-btc's fixtures: a SegWit, a taproot and a legacy coin) signed byte
//! for byte, its review in DGB, and the home screen's address in each kind. Rebuild the fixture after
//! changing the app: `maki build examples/digibyte` in sdk/, then copy
//! `sdk/target/maki/com.leviathan.maki.digibyte.maki` to `tests/fixtures/digibyte.maki`.

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

/// The addresses DigiByte's library (and bitcoinjs-lib, for taproot) made, by path.
fn address(path: &str) -> String {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{BTC_FIXTURES}/digibyte.json")).unwrap())
            .unwrap();
    json["addresses"][path].as_str().unwrap().into()
}

/// `D`: network, kind, change, index.
fn compare(network: u8, kind: u8, change: u8, index: u32) -> Vec<u8> {
    [&[b'D', network, kind, change][..], &index.to_le_bytes()].concat()
}

#[test]
fn digibyte_shares_each_account_once_asked() {
    let r = run_wallet(
        "digibyte",
        vec![vec![b'A', 0, 0], vec![b'A', 0, 1], vec![b'A', 0, 2], vec![b'A', 1, 0], vec![b'A', 0, 3]],
        vec![Answer::Yes, Answer::Yes, Answer::Yes, Answer::No],
        false,
    );
    let segwit = texts(&r.replies[0]);
    assert!(segwit[0].starts_with("zpub"), "{}", segwit[0]);
    assert!(segwit[1].starts_with("wpkh([73c5da0a/84h/20h/0h]xpub6BmjNc3e3DmWgKc5xswF9m4pCrJ8qSw9LcHmLsdymvkuYm9BCRqYvkVbkC8JijGLZDwgG62hysxgAf32EdHVVQjiabWVfJ6xMRe425ph1B2/<0;1>/*)#"));
    assert!(texts(&r.replies[1])[1].starts_with("tr([73c5da0a/86h/20h/0h]xpub"));
    let legacy = texts(&r.replies[2]);
    assert_eq!(
        legacy[0],
        "xpub6Cj2cdNXaWhn9mwjaxofCJujxrALww7kw6WcyCsGnU9twBEsGcaMqR6gCtQ9b3k6awqL2egNaat2btUCVoETYzcmngU9outdn6RA2KxmNEn"
    );
    assert!(legacy[1].starts_with("pkh([73c5da0a/44h/20h/0h]xpub6Cj2cd"));
    let details: Vec<&str> = r.reviews.iter().map(|r| r.detail.as_str()).collect();
    assert_eq!(
        details,
        [
            "digibyte, view only",
            "digibyte taproot, view only",
            "digibyte legacy, view only",
            "digibyte testnet, view only"
        ]
    );
    // a no shares nothing; a kind there isn't is a message it can't read
    assert_eq!((r.replies[3].as_slice(), r.replies[4].as_slice()), (&[1u8][..], &[4u8][..]));
}

#[test]
fn digibyte_compares_addresses_of_each_kind() {
    let r = run_wallet(
        "digibyte",
        vec![
            compare(0, 0, 0, 0),
            compare(0, 2, 1, 0),
            compare(0, 1, 0, 0),
            compare(1, 0, 0, 0),
            compare(1, 2, 0, 0),
        ],
        vec![Answer::Yes; 5],
        false,
    );
    let shown: Vec<String> = r.replies.iter().map(|reply| texts(reply).remove(0)).collect();
    assert_eq!(
        shown,
        [
            address("m/84'/20'/0'/0/0"),
            address("m/44'/20'/0'/1/0"),
            address("m/86'/20'/0'/0/0"),
            address("m/84'/1'/0'/0/0"),
            address("m/44'/1'/0'/0/0")
        ]
    );
    let page = &r.reviews[1].pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str()), ("Change #0", "digibyte"));
    assert_eq!(r.reviews[3].pages[0].value, "digibyte testnet");
}

#[test]
fn digibyte_signs_what_the_owner_reviewed_in_dgb() {
    let psbt = std::fs::read(format!("{BTC_FIXTURES}/digibyte-unsigned.psbt")).unwrap();
    let expected = std::fs::read(format!("{BTC_FIXTURES}/digibyte-signed.psbt")).unwrap();
    let r = run_wallet("digibyte", psbt_messages(0, &psbt, 1), vec![Answer::Yes], false);
    // DigiByte's library's signatures for the SegWit and legacy coins, bitcoinjs-lib's for taproot
    assert_eq!(fetched(&r.replies[1..]), expected);
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.detail.as_str()), ("Sign and spend", "1000.1 DGB"));
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(pages[0], ("Send", "1000 DGB", "dgb1q50rtrmj2f8vl9tem8qpfw36ylw5jg9j2jzs696"));
    assert_eq!(pages[1], ("Change", "249.9 DGB", "back to you"));
    assert_eq!((pages[2].0, pages[2].1), ("Fee", "0.1 DGB"));
    // on the test network's accounts it isn't this wallet's
    let r = run_wallet("digibyte", psbt_messages(1, &psbt, 0), vec![Answer::Yes], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(r.reviews.is_empty());
    // a no signs nothing; what isn't a PSBT is refused with why
    let r = run_wallet("digibyte", psbt_messages(0, &psbt, 0), vec![Answer::No], false);
    assert_eq!(r.replies[0], [1]);
    let r = run_wallet("digibyte", psbt_messages(0, &psbt[..psbt.len() / 2], 0), vec![], false);
    assert_eq!(r.replies[0][0], 5);
    assert!(texts(&r.replies[0])[0].starts_with("not a PSBT maki can read"));
    // locked: no account to share, nothing to sign
    let r =
        run_wallet("digibyte", vec![vec![b'A', 0, 0], psbt_messages(0, &psbt, 0).remove(0)], vec![], true);
    assert_eq!(r.replies, [vec![3], vec![3]]);
    assert!(r.reviews.is_empty());
}

#[test]
fn digibyte_shows_each_kinds_address() {
    let r = run_wallet_with(
        "digibyte",
        vec![Event::Menu(0), Event::Menu(0), Event::Menu(0)],
        vec![],
        vec![],
        false,
    );
    assert_eq!(r.menu, ["SegWit, taproot, legacy", "DigiByte or testnet", "Account key"]);
    // bech32's in capitals, which make a smaller code; the legacy address as it is
    let codes: Vec<String> = r.frames.iter().map(|f| read_qr(f).unwrap()).collect();
    assert_eq!(
        codes,
        [
            address("m/84'/20'/0'/0/0").to_uppercase(),
            address("m/86'/20'/0'/0/0").to_uppercase(),
            "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i".to_string(),
            address("m/84'/20'/0'/0/0").to_uppercase(),
        ]
    );
}
