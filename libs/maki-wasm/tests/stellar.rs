//! The Stellar example app (sdk/examples/stellar), as `maki build` packed it, run by the host code
//! maki runs it with: the account it shares once asked and shows to compare, the transactions
//! @stellar/stellar-sdk made (maki-xlm's fixtures) shown on maki's review screen and signed as
//! stellar-sdk signs them, what it refuses and why, and its address as a QR code. Rebuild the
//! fixture after changing the app or maki-xlm: `maki build examples/stellar`, then copy
//! `sdk/target/maki/com.leviathan.maki.stellar.maki` to `tests/fixtures/stellar.maki`.

mod harness;

use harness::*;
use maki_wasm::*;

const XLM_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-xlm/tests/fixtures");

/// SEP-5's first two accounts for the test phrase, and its fourth.
const ME: &str = "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX";
const ACCOUNT_1: &str = "GDVSYYTUAJ3ACHTPQNSTQBDQ4LDHQCMNY4FCEQH5TJUMSSLWQSTG42MV";
const ACCOUNT_3: &str = "GCCCOWAKYVFY5M6SYHOW33TSNC7Z5IBRUEU2XQVVT34CIZU7CXZ4OQ4O";
const RECIPIENT: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";

/// A message: what it is, the network, the account, and what follows.
fn message(kind: u8, network: u8, index: u32, rest: &[u8]) -> Vec<u8> {
    [&[kind, network][..], &index.to_le_bytes(), rest].concat()
}

/// A transaction stellar-sdk made: its envelope and stellar-sdk's signature with this account.
fn xlm_fixture(name: &str, network: u8) -> (Vec<u8>, Vec<u8>) {
    let text = std::fs::read_to_string(format!("{XLM_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let f = json.as_array().unwrap().iter().find(|f| f["name"] == name && f["network"] == network).unwrap();
    let unhex = |s: &str| {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect::<Vec<u8>>()
    };
    (unhex(f["envelope"].as_str().unwrap()), unhex(f["signature"].as_str().unwrap()))
}

#[test]
fn stellar_shares_its_account_and_compares_it_once_asked() {
    let me = maki_xlm::strkey::decode_account(ME).unwrap();
    let r = run_wallet(
        "stellar",
        vec![message(b'A', 0, 0, &[]), message(b'A', 1, 3, &[]), message(b'A', 0, 0, &[])],
        vec![Answer::Yes, Answer::Yes, Answer::No],
        false,
    );
    // the key as transactions carry it, then the address
    assert_eq!(r.replies[0][..34], [&[0u8, 32][..], &me].concat());
    assert_eq!(texts(&r.replies[0][33..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "stellar, view only", "share", "don't")
    );
    assert!(review.pages.is_empty());
    assert_eq!(review.timeout_s, 60);
    assert_eq!(texts(&r.replies[1][33..]), [ACCOUNT_3]);
    assert_eq!(r.reviews[1].detail, "stellar testnet account #3, view only");
    // a no shares nothing
    assert_eq!(r.replies[2], [1]);
    // the address on maki's screen, to compare: the owner's say, and maki's address either way
    let r = run_wallet(
        "stellar",
        vec![message(b'D', 0, 0, &[]), message(b'D', 1, 1, &[])],
        vec![Answer::Yes, Answer::No],
        false,
    );
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![ACCOUNT_1.to_string()]));
    let review = &r.reviews[0];
    assert_eq!((review.question.as_str(), review.yes.as_str()), ("Same on computer?", "matches"));
    let page = &review.pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str(), page.mono.as_str()), ("Account", "Stellar", ME));
    let page = &r.reviews[1].pages[0];
    assert_eq!((page.heading.as_str(), page.value.as_str()), ("Account #1", "Stellar testnet"));
    // locked: no keys, nothing asked
    let r = run_wallet("stellar", vec![message(b'A', 0, 0, &[]), message(b'D', 0, 0, &[])], vec![], true);
    assert_eq!((r.replies[0].as_slice(), r.replies[1].as_slice()), (&[3u8][..], &[3u8][..]));
    assert!(r.reviews.is_empty());
    // what isn't a message of this app's: another network, an account past the hardened ones,
    // more than it takes, nothing
    let r = run_wallet(
        "stellar",
        vec![
            message(b'A', 2, 0, &[]),
            message(b'A', 0, 0x8000_0000, &[]),
            message(b'A', 0, 0, &[0]),
            message(b'D', 0, 0, &[0]),
            vec![b'A', 0],
            vec![b'X', 0, 0, 0, 0, 0],
            vec![],
        ],
        vec![Answer::Yes; 7],
        false,
    );
    assert!(r.replies.iter().all(|reply| reply == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

#[test]
fn stellar_signs_what_the_owner_went_through_as_stellar_sdk_signs_it() {
    let (usdc, signature) = xlm_fixture("usdc", 0);
    let r = run_wallet("stellar", vec![message(b'T', 0, 0, &usdc)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 5.25 USDC; fee up to 0.00001 XLM")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Send", "5.25 USDC", RECIPIENT),
            ("Memo", "ID 1234567890", ""),
            ("Valid until", "2027-01-01 00:00:00 UTC", ""),
            ("Max fee", "0.00001 XLM", ""),
            ("From", "this account", ME)
        ]
    );
    // the same transaction for the test network: another hash, and a review that says so
    let (usdc_test, signature) = xlm_fixture("usdc", 1);
    let r = run_wallet("stellar", vec![message(b'T', 1, 0, &usdc_test)], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], [&[0u8][..], &signature].concat());
    assert_eq!(r.reviews[0].detail, "testnet: sends 5.25 USDC (another issuer's); fee up to 0.00001 XLM");
    // what changes who controls the account, loudly, and what maki can't read, flagged
    let (lockout, _) = xlm_fixture("lockout", 0);
    let (contract, _) = xlm_fixture("contract", 0);
    let r = run_wallet(
        "stellar",
        vec![message(b'T', 0, 0, &lockout), message(b'T', 0, 0, &contract)],
        vec![Answer::No, Answer::No],
        false,
    );
    assert_eq!(r.replies, [vec![1u8], vec![1u8]], "a no signs nothing");
    assert_eq!(r.reviews[0].detail, "locks out this account's key, adds a signer!; fee up to 0.00001 XLM");
    assert_eq!(r.reviews[0].pages[0].heading, "Locks out its key!");
    assert_eq!(r.reviews[1].detail, "maki can't read all of it; fee up to 0.50001 XLM");
    assert_eq!(
        (r.reviews[1].pages[0].heading.as_str(), r.reviews[1].pages[0].value.as_str()),
        ("Contract call", "maki can't read it")
    );
    // every transaction of this account's, on both networks, signed as stellar-sdk signs it
    let text = std::fs::read_to_string(format!("{XLM_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let refused = ["inflation", "revoke-pool", "not-mine", "fee-bump-theirs"];
    let mut signed = 0;
    for f in json.as_array().unwrap() {
        let (name, network) = (f["name"].as_str().unwrap(), f["network"].as_u64().unwrap() as u8);
        let (envelope, signature) = xlm_fixture(name, network);
        let r = run_wallet("stellar", vec![message(b'T', network, 0, &envelope)], vec![Answer::Yes], false);
        if refused.contains(&name) {
            assert_eq!(r.replies[0][0], 5, "{name}");
            assert!(r.reviews.is_empty(), "{name}: refused before it's shown");
        } else {
            assert_eq!(r.replies[0], [&[0u8][..], &signature].concat(), "{name} on network {network}");
            signed += 1;
        }
    }
    let kinds = json.as_array().unwrap().len() / 2;
    assert_eq!(signed, 2 * (kinds - refused.len()));
}

#[test]
fn stellar_refuses_what_it_cant_sign_and_says_why() {
    let (payment, _) = xlm_fixture("payment", 0);
    let (not_mine, _) = xlm_fixture("not-mine", 0);
    let (inflation, _) = xlm_fixture("inflation", 0);
    let r = run_wallet(
        "stellar",
        vec![
            // another's transaction, not this account's to sign
            message(b'T', 0, 0, &not_mine),
            // this account's, asked of another account
            message(b'T', 0, 1, &payment),
            // what Stellar would refuse
            message(b'T', 0, 0, &inflation),
            // cut short, and with more after it
            message(b'T', 0, 0, &payment[..payment.len() - 1]),
            message(b'T', 0, 0, &[&payment[..], &[0, 0, 0, 0]].concat()),
            // nothing
            message(b'T', 0, 0, &[]),
            // a network maki doesn't know
            message(b'T', 2, 0, &payment),
        ],
        vec![Answer::Yes; 7],
        false,
    );
    let said = |i: usize| (r.replies[i][0], texts(&r.replies[i]).join(""));
    let not_this = "not this account's to sign: it doesn't act as this account".to_string();
    assert_eq!(said(0), (5, not_this.clone()));
    assert_eq!(said(1), (5, not_this));
    assert_eq!(said(2), (5, "inflation, which Stellar no longer runs: it would refuse it".to_string()));
    let cut = "not a Stellar transaction: cut short, or with more after it".to_string();
    assert_eq!(said(3), (5, cut.clone()));
    assert_eq!(said(4), (5, cut.clone()));
    assert_eq!(said(5), (5, cut));
    assert_eq!(r.replies[6], [4]);
    assert!(r.reviews.is_empty(), "nothing shown for what can't be signed");
    // locked: nothing read, nothing shown
    let r = run_wallet("stellar", vec![message(b'T', 0, 0, &payment)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
}

/// XDR written out by hand, for transactions as big as a message holds.
fn u32b(n: u32) -> Vec<u8> { n.to_be_bytes().to_vec() }

/// A version 1 envelope from this account with these operations, each written whole.
fn envelope(ops: &[Vec<u8>]) -> Vec<u8> { envelope_with(ops, u32b(0)) }

/// The same, with this extension: a contract's resources.
fn envelope_with(ops: &[Vec<u8>], ext: Vec<u8>) -> Vec<u8> {
    let me = maki_xlm::strkey::decode_account(ME).unwrap();
    let mut out =
        [u32b(2), u32b(0), me.to_vec(), u32b(100), 1i64.to_be_bytes().to_vec(), u32b(0), u32b(0)].concat();
    out.extend(u32b(ops.len() as u32));
    for op in ops {
        out.extend_from_slice(op);
    }
    [out, ext, u32b(0)].concat()
}

#[test]
fn stellar_goes_through_as_much_as_a_message_holds() {
    let issuer = [5u8; 32];
    // 35 payments of an asset maki doesn't know, each to an account with an ID: a page each, and
    // one for the asset, in the memory the app asks for
    let payment = [
        u32b(0),
        u32b(1),
        u32b(0x100),
        42u64.to_be_bytes().to_vec(),
        vec![1; 32],
        u32b(2),
        b"LONGNAME123\0".to_vec(),
        u32b(0),
        issuer.to_vec(),
        1i64.to_be_bytes().to_vec(),
    ]
    .concat();
    let big = envelope(&vec![payment; 35]);
    assert!(big.len() + 6 <= 4096, "{}", big.len());
    let r = run_wallet("stellar", vec![message(b'T', 0, 0, &big)], vec![Answer::Yes], false);
    assert_eq!((r.replies[0][0], r.replies[0].len()), (0, 65));
    assert_eq!(r.reviews[0].pages.len(), 35 + 1 + 3);
    assert_eq!(r.reviews[0].detail, "sends 0.0000001 LONGNAME123; fee up to 0.00001 XLM");
    // 31 changes to who signs, four pages each: 127 pages, as many as fit, signed once gone through
    let control = |home: bool| {
        let mut op = [u32b(0), u32b(5), u32b(0), u32b(0), u32b(0)].concat();
        for weight in [1, 1, 2, 3] {
            op.extend([u32b(1), u32b(weight)].concat());
        }
        if home {
            op.extend(
                [u32b(1), u32b(11), b"example.com\0".to_vec(), u32b(1), u32b(0), vec![2; 32], u32b(1)]
                    .concat(),
            );
        } else {
            op.extend([u32b(0), u32b(0)].concat());
        }
        op
    };
    let big = envelope(&vec![control(true); 31]);
    assert!(big.len() + 6 <= 4096, "{}", big.len());
    let r = run_wallet("stellar", vec![message(b'T', 0, 0, &big)], vec![Answer::Yes], false);
    assert_eq!((r.replies[0][0], r.replies[0].len()), (0, 65));
    assert_eq!(r.reviews[0].pages.len(), 127);
    assert!(r.reviews[0].detail.starts_with("changes who can sign for this account, adds a signer!"));
    // 62 of its key's weight and thresholds, two pages each: more text than maki's review screen
    // takes, so refused, and said why
    let big = envelope(&vec![control(false); 62]);
    assert!(big.len() + 6 <= 4096, "{}", big.len());
    let shown = maki_xlm::display::review(
        &maki_xlm::Envelope::parse(&big).unwrap(),
        &maki_xlm::strkey::decode_account(ME).unwrap(),
        maki_xlm::Network::Public,
    )
    .unwrap();
    let text: usize =
        shown.pages.iter().map(|p| 4 + p.heading.len() + p.value.len() + p.mono.len() + p.prose.len()).sum();
    assert!(text > MAX_REVIEW, "{text}");
    let r = run_wallet("stellar", vec![message(b'T', 0, 0, &big)], vec![Answer::Yes], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["too much to show on maki's screen".to_string()])
    );
    // and 33 of the first, more pages than the screen goes through: refused before maki's asked
    let r =
        run_wallet("stellar", vec![message(b'T', 0, 0, &envelope(&vec![control(true); 33]))], vec![], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0])),
        (5, vec!["too much to go through on maki's screen".to_string()])
    );
    assert!(r.reviews.is_empty());
}

#[test]
fn stellar_reads_a_contracts_arguments_as_deep_as_it_says_in_its_own_stack() {
    // a call of a contract's function with one argument, lists in lists `depth` deep, and the
    // resources a contract's transaction carries
    let call = |depth: usize| {
        let mut value = u32b(1);
        for _ in 1..depth {
            value = [u32b(16), u32b(1), u32b(1), value].concat();
        }
        let op = [
            u32b(0),
            u32b(24),
            u32b(0),
            u32b(1),
            vec![0x11; 32],
            u32b(1),
            b"f\0\0\0".to_vec(),
            u32b(1),
            value,
            u32b(0),
        ]
        .concat();
        let resources =
            [u32b(1), u32b(0), u32b(0), u32b(0), u32b(0), u32b(0), u32b(0), 50i64.to_be_bytes().to_vec()]
                .concat();
        envelope_with(&[op], resources)
    };
    let r = run_wallet(
        "stellar",
        vec![
            message(b'T', 0, 0, &call(maki_xlm::soroban::MAX_DEPTH)),
            message(b'T', 0, 0, &call(maki_xlm::soroban::MAX_DEPTH + 1)),
        ],
        vec![Answer::Yes],
        false,
    );
    assert_eq!((r.replies[0][0], r.replies[0].len()), (0, 65));
    assert_eq!(r.reviews[0].detail, "maki can't read all of it; fee up to 0.00001 XLM");
    assert_eq!(
        (r.replies[1][0], texts(&r.replies[1])),
        (5, vec!["a contract's data nested deeper than maki reads".to_string()])
    );
}

#[test]
fn stellar_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "stellar",
        vec![Event::Right, Event::Left, Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(ACCOUNT_1), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME));
    assert!(read_qr(&r.frames[3]).is_none(), "as text");
    assert!(lit(&r.frames[3]) > 100);
    // locked: no address to show
    let r = run_wallet_with("stellar", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
}
