//! The Cardano example (sdk/examples/cardano), as `maki build` packed it and maki runs it: its
//! account shared once the owner says so, its addresses compared on maki's screen and its first shown
//! as a QR code, CSL's transactions (`maki-ada/tests/fixtures/make.mjs`) read, shown and signed as
//! CSL signs them (one bigger than a message, in pieces), and what isn't this account's to sign, or
//! can't be read, refused before anything is shown. Rebuild the fixture after changing the app:
//! `maki build sdk/examples/cardano`, then copy `sdk/target/maki/com.leviathan.maki.cardano.maki` to
//! `tests/fixtures/cardano.maki`.

mod harness;

use harness::*;
use maki_ada::request::{Change, Key, Request};
use maki_wasm::*;

/// The test phrase's first Cardano address, as Eternl, Lace, Yoroi and CSL make it.
const ME: &str =
    "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv";
const ME_TEST: &str = "addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn";
/// Its first change address, and its reward address.
const CHANGE: &str =
    "addr1qykhadtnvjpkxh76xgr0mu4huc9tg800x2sxsqemn9uz8jh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq28kufu";
const REWARDS: &str = "stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l";
/// The account's public key and chain code, as CSL makes it (maki-hd's vectors).
const ACCOUNT_KEY: &str = "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16";
const RECIPIENT: &str =
    "addr1qxttdu6d96klw8xvme7ctwuv0jg7xns0vm35ksv4l722aupyayzk39uascqj78hynwh3ax5w8ch5n9062k0vpnj3dlps3a8a9a";
const ADA_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../maki-ada/tests/fixtures");

/// A message's head: what it is, the network, the account.
fn head(kind: u8, network: u8, account: u32) -> Vec<u8> {
    let mut m = vec![kind, network];
    m.extend_from_slice(&account.to_le_bytes());
    m
}

/// `D` for this role and index.
fn compare(network: u8, account: u32, role: u8, index: u32) -> Vec<u8> {
    [head(b'D', network, account), vec![role], index.to_le_bytes().to_vec()].concat()
}

/// A piece of a `T`: the request's total, this piece's offset, the piece.
fn piece(network: u8, account: u32, total: usize, offset: usize, bytes: &[u8]) -> Vec<u8> {
    [
        head(b'T', network, account),
        (total as u32).to_le_bytes().to_vec(),
        (offset as u32).to_le_bytes().to_vec(),
        bytes.to_vec(),
    ]
    .concat()
}

/// A whole request in one `T`.
fn sign(network: u8, request: &[u8]) -> Vec<u8> { piece(network, 0, request.len(), 0, request) }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Fixture {
    name: String,
    network: u8,
    body: Vec<u8>,
    /// The keys that witness it, and each one's witness as CSL makes it: the key, its signature.
    witnesses: Vec<(Key, Vec<u8>)>,
    change: Vec<Change>,
}

impl Fixture {
    /// The request the computer sends for it: its keys, its change, its body.
    fn request(&self) -> Vec<u8> {
        Request {
            witnesses: self.witnesses.iter().map(|w| w.0).collect(),
            change: self.change.clone(),
            body: &self.body,
        }
        .write()
    }

    /// OK, then each witness: what maki answers.
    fn answer(&self) -> Vec<u8> {
        let mut out = vec![0];
        for (_, w) in &self.witnesses {
            out.extend_from_slice(w);
        }
        out
    }
}

/// CSL's transactions.
fn fixtures() -> Vec<Fixture> {
    let text = std::fs::read_to_string(format!("{ADA_FIXTURES}/transactions.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: (f["network"] != "mainnet") as u8,
            body: unhex(f["body"].as_str().unwrap()),
            witnesses: f["witnesses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| {
                    let key = Key {
                        role: w["role"].as_u64().unwrap() as u8,
                        index: w["index"].as_u64().unwrap() as u32,
                    };
                    (
                        key,
                        [unhex(w["key"].as_str().unwrap()), unhex(w["signature"].as_str().unwrap())].concat(),
                    )
                })
                .collect(),
            change: f["change"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| Change {
                    output: c["output"].as_u64().unwrap() as usize,
                    key: Key {
                        role: c["role"].as_u64().unwrap() as u8,
                        index: c["index"].as_u64().unwrap() as u32,
                    },
                })
                .collect(),
        })
        .collect()
}

fn fixture(name: &str) -> Fixture { fixtures().into_iter().find(|f| f.name == name).unwrap() }

/// What maki-ada refuses of them.
const REFUSED: &[&str] = &[
    "collateral",
    "required-signer",
    "reference-input",
    "pool-retirement",
    "drep-registration",
    "voting",
    "proposal",
    "their-delegation",
    "their-withdrawal",
];

/// Account `account`'s first address, as maki makes it.
fn first(account: u32) -> String {
    let mut keys = maki_hd::seed::SeedKeys::from_seed(&test_seed()).unwrap();
    keys.with_cardano(&[0; 16]);
    let hash =
        |path: &[u32]| maki_ada::key_hash(&keys.cardano_public(path).unwrap()[..32].try_into().unwrap());
    maki_ada::Address::base(
        maki_ada::Network::Mainnet,
        &hash(&maki_ada::key_path(account, 0, 0)),
        &hash(&maki_ada::stake_path(account)),
    )
    .text()
}

#[test]
fn cardano_shares_its_account_once_asked_and_compares_its_addresses() {
    let r =
        run_wallet("cardano", vec![head(b'A', 0, 0), head(b'A', 0, 0)], vec![Answer::Yes, Answer::No], false);
    // OK, the length, the account's key and chain code, then its first address
    let answer = &r.replies[0];
    assert_eq!((answer[0], answer[1]), (0, 64));
    assert_eq!(answer[2..66], unhex(ACCOUNT_KEY)[..]);
    assert_eq!(texts(&answer[65..]), [ME]);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Share account?", "cardano, view only", "share", "don't")
    );
    assert_eq!(review.timeout_s, 60);
    // a no shares nothing
    assert_eq!(r.replies[1], [1]);
    let r = run_wallet("cardano", vec![head(b'A', 1, 2)], vec![Answer::Yes], false);
    assert_eq!(r.reviews[0].detail, "cardano preprod account #2, view only");
    let r = run_wallet("cardano", vec![head(b'A', 0, 0)], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3], "locked");
    assert!(r.reviews.is_empty());
    // addresses on maki's screen: the owner's answer, and maki's address either way
    let r = run_wallet(
        "cardano",
        vec![
            compare(0, 0, 0, 0),
            compare(0, 0, 1, 0),
            compare(0, 0, 2, 0),
            compare(1, 0, 0, 0),
            compare(0, 1, 0, 0),
        ],
        vec![Answer::Yes, Answer::No, Answer::Yes, Answer::NoAnswer, Answer::Yes],
        false,
    );
    assert_eq!((r.replies[0][0], texts(&r.replies[0])), (0, vec![ME.to_string()]));
    assert_eq!((r.replies[1][0], texts(&r.replies[1])), (1, vec![CHANGE.to_string()]));
    assert_eq!((r.replies[2][0], texts(&r.replies[2])), (0, vec![REWARDS.to_string()]));
    assert_eq!((r.replies[3][0], texts(&r.replies[3])), (2, vec![ME_TEST.to_string()]));
    assert_eq!((r.replies[4][0], texts(&r.replies[4])), (0, vec![first(1)]));
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.yes.as_str(), review.no.as_str()),
        ("Same on computer?", "matches", "doesn't match")
    );
    assert_eq!(
        review.pages,
        [Page {
            heading: "Receive #0".into(),
            value: "cardano".into(),
            mono: ME.into(),
            prose: String::new()
        }]
    );
    let pages: Vec<(&str, &str)> =
        r.reviews[1..].iter().map(|r| (r.pages[0].heading.as_str(), r.pages[0].value.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Change #0", "cardano"),
            ("Stake address", "cardano"),
            ("Receive #0", "cardano preprod"),
            ("Receive #0", "cardano account #1")
        ]
    );
    // what isn't a message of the protocol: another kind, a network there isn't, an account past
    // BIP32's unhardened ones, a head with more after it or cut short; a key that isn't a payment
    // key or the stake key, an index past 2^31
    let r = run_wallet(
        "cardano",
        vec![
            head(b'M', 0, 0),
            head(b'A', 2, 0),
            head(b'A', 0, 0x8000_0000),
            [head(b'A', 0, 0), vec![0]].concat(),
            vec![b'A', 0, 0],
            compare(0, 0, 3, 0),
            compare(0, 0, 2, 1),
            compare(0, 0, 0, 0x8000_0000),
            compare(0, 0, 0, 0)[..10].to_vec(),
            vec![],
        ],
        vec![],
        false,
    );
    assert!(r.replies.iter().all(|a| a == &[4]), "{:?}", r.replies);
    assert!(r.reviews.is_empty());
}

#[test]
fn cardano_signs_what_the_owner_reviewed_as_csl_signs() {
    let f = fixture("payment");
    let r = run_wallet("cardano", vec![sign(0, &f.request())], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], f.answer());
    assert_eq!(r.replies[0].len(), 1 + 32 + 64);
    let review = &r.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Sign and send", "sends 1.5 ADA; fee 0.168581 ADA")
    );
    assert_eq!(review.timeout_s, 300);
    let pages: Vec<(&str, &str, &str)> =
        review.pages.iter().map(|p| (p.heading.as_str(), p.value.as_str(), p.mono.as_str())).collect();
    assert_eq!(
        pages,
        [
            ("Network", "Cardano", ""),
            ("Send", "1.5 ADA", RECIPIENT),
            ("Change", "8.331419 ADA", ""),
            ("Valid until", "2026-10-02 06:01:50 UTC", ""),
            ("Fee", "0.168581 ADA", "")
        ]
    );
    // every transaction maki shows, signed as CSL signs it, each witness in the order asked for
    let mut signed = 0;
    for f in fixtures() {
        if REFUSED.contains(&f.name.as_str()) || f.name == "seventy" {
            continue;
        }
        let r = run_wallet("cardano", vec![sign(f.network, &f.request())], vec![Answer::Yes], false);
        assert_eq!(r.replies[0], f.answer(), "{}", f.name);
        signed += f.witnesses.len();
    }
    assert_eq!(signed, 42);
    // two witnesses, the stake key's second: a delegation
    let f = fixture("delegation");
    let r = run_wallet("cardano", vec![sign(0, &f.request())], vec![Answer::Yes], false);
    assert_eq!(r.replies[0].len(), 1 + 2 * 96);
    assert_eq!(r.reviews[0].detail, "registers its stake key, delegates to a pool; fee 0.174917 ADA");
    // on Preprod
    let f = fixture("preprod");
    let r = run_wallet("cardano", vec![sign(1, &f.request())], vec![Answer::Yes], false);
    assert_eq!(r.replies[0], f.answer());
    assert_eq!(
        (r.reviews[0].pages[0].value.as_str(), r.reviews[0].detail.as_str()),
        ("Preprod (test)", "sends 1.5 tADA; fee 0.168581 tADA")
    );
}

#[test]
fn cardano_takes_a_big_transaction_in_pieces() {
    let f = fixture("seventy");
    let request = f.request();
    assert!(request.len() > 4096);
    let pieces: Vec<&[u8]> = request.chunks(4000).collect();
    let total = request.len();
    let r = run_wallet(
        "cardano",
        vec![piece(0, 0, total, 0, pieces[0]), piece(0, 0, total, 4000, pieces[1])],
        vec![Answer::Yes],
        false,
    );
    assert_eq!(r.replies[0], [6], "more");
    assert_eq!(r.replies[1], f.answer());
    assert_eq!(r.replies[1].len(), 1 + 3 * 96);
    assert_eq!(r.reviews[0].pages.len(), 74);
    assert_eq!(r.reviews[0].detail, "sends 70.002485 ADA in 70 payments; fee 0.378021 ADA");
    // pieces out of order, another account's or network's than the first's, a total that changes,
    // more than the total: each refused as not the protocol, and what came before forgotten
    let r = run_wallet(
        "cardano",
        vec![
            piece(0, 0, total, 4000, pieces[1]),
            piece(0, 0, total, 0, pieces[0]),
            piece(0, 1, total, 4000, pieces[1]),
            piece(0, 0, total, 4000, pieces[1]),
            piece(0, 0, total, 0, pieces[0]),
            piece(1, 0, total, 4000, pieces[1]),
            piece(0, 0, total, 0, pieces[0]),
            piece(0, 0, total + 1, 4000, pieces[1]),
            piece(0, 0, 10, 0, &request[..11]),
            piece(0, 0, 0, 0, &[]),
            // and one taken whole after all that
            piece(0, 0, total, 0, pieces[0]),
            piece(0, 0, total, 4000, pieces[1]),
        ],
        vec![Answer::Yes],
        false,
    );
    let statuses: Vec<u8> = r.replies.iter().map(|a| a[0]).collect();
    assert_eq!(statuses, [4, 6, 4, 4, 6, 4, 6, 4, 4, 4, 6, 0]);
    assert_eq!(r.replies[11], f.answer());
    // bigger than any transaction: refused at once
    let r = run_wallet("cardano", vec![piece(0, 0, 20_000, 0, &request[..100])], vec![], false);
    assert_eq!(
        (r.replies[0][0], texts(&r.replies[0]).join("")),
        (5, String::from("bigger than a Cardano transaction can be"))
    );
}

#[test]
fn cardano_refuses_what_isnt_its_to_sign_before_showing_it() {
    let payment = fixture("payment");
    let refused = |a: &Vec<u8>| (a[0], texts(a).join(""));
    let mut false_change = fixture("payment");
    false_change.change[0].key.index = 1;
    let r = run_wallet(
        "cardano",
        vec![
            // the owner says no
            sign(0, &payment.request()),
            // another account's stake; a test network's said to be Cardano's own, and the other way
            sign(0, &fixture("their-delegation").request()),
            sign(0, &fixture("preprod").request()),
            sign(1, &payment.request()),
            // what maki doesn't sign; change that isn't
            sign(0, &fixture("voting").request()),
            sign(0, &false_change.request()),
            // not a request, not a body, a body with more after it
            sign(0, &[1, 2, 3]),
            sign(0, &[&payment.request()[..], &[0]].concat()),
        ],
        vec![Answer::No],
        false,
    );
    assert_eq!(r.replies[0], [1]);
    assert_eq!(
        refused(&r.replies[1]),
        (5, String::from("a certificate for another stake key than this account's"))
    );
    assert_eq!(refused(&r.replies[2]), (5, String::from("for a test network, not Cardano's own")));
    assert_eq!(refused(&r.replies[3]), (5, String::from("for Cardano's own network, not a test network")));
    assert_eq!(
        refused(&r.replies[4]),
        (5, String::from("votes on Cardano's governance: maki doesn't sign those"))
    );
    assert_eq!(
        refused(&r.replies[5]),
        (5, String::from("an output said to be change that doesn't pay this account's address for that key"))
    );
    assert_eq!(r.replies[6][0], 5);
    assert_eq!(
        refused(&r.replies[7]),
        (
            5,
            String::from(
                "not written as Cardano's hardware wallets take a transaction (CIP-21's canonical CBOR): cut short, or written another way"
            )
        )
    );
    assert_eq!(r.reviews.len(), 1, "only the first was shown");
    // locked: refused at the first piece, nothing shown
    let r = run_wallet("cardano", vec![sign(0, &payment.request())], vec![Answer::Yes], true);
    assert_eq!(r.replies[0], [3]);
    assert!(r.reviews.is_empty());
    // longer than maki's link carries: not read at all
    let r = run_wallet(
        "cardano",
        vec![[sign(0, &payment.request()), vec![0; 4096]].concat()],
        vec![Answer::Yes],
        false,
    );
    assert_eq!(r.replies[0], [4]);
    assert!(r.reviews.is_empty());
}

#[test]
fn cardano_shows_its_address_to_receive_at() {
    let r = run_wallet_with(
        "cardano",
        vec![Event::Right, Event::Left, Event::Centre, Event::Exit],
        vec![],
        vec![],
        false,
    );
    assert_eq!(read_qr(&r.frames[0]).as_deref(), Some(ME));
    assert_eq!(read_qr(&r.frames[1]).as_deref(), Some(first(1).as_str()), "account #1");
    assert_eq!(read_qr(&r.frames[2]).as_deref(), Some(ME));
    assert!(read_qr(&r.frames[3]).is_none(), "as text");
    assert!(lit(&r.frames[3]) > 0);
    // locked: no address to show
    let r = run_wallet_with("cardano", vec![Event::Exit], vec![], vec![], true);
    assert!(read_qr(&r.frames[0]).is_none());
    assert!(lit(&r.frames[0]) > 0);
}
