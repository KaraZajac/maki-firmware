//! maki-sol against Solana's own libraries: transactions @solana/web3.js and @solana/spl-token
//! made (`fixtures/make.mjs`), read as they are and shown as they should be, and signed by maki's
//! keys as web3.js signs them with the same account (the test phrase's first, as Phantom has it).

use maki_hd::seed::SeedKeys;
use maki_sol::display::{self, Error, Page, decimals, message_pages, review};
use maki_sol::message::{self, Message};
use maki_sol::{Key, address, base58, program};

const ME: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const RECIPIENT: &str = "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9";
const DELEGATE: &str = "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const PAYER: &str = "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse";
const CREATED: &str = "EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1";
const NONCE: &str = "8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe";
const PROGRAM: &str = "AKkzLhjhyFtM9j7WAhbaqYpFe49cXeJBg2kzLRC2PnNa";
const TABLE: &str = "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB";
const MINT: &str = "J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WSOL: &str = "So11111111111111111111111111111111111111112";

fn key(text: &str) -> Key { base58::decode_key(text).unwrap() }

fn me() -> Key { key(ME) }

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The transactions web3.js made: name, message, and web3.js's signature for this account.
fn fixtures() -> Vec<(String, Vec<u8>, Option<Vec<u8>>)> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().into(),
                unhex(f["message"].as_str().unwrap()),
                f["signature"].as_str().map(unhex),
            )
        })
        .collect()
}

fn fixture(name: &str) -> Vec<u8> { fixtures().into_iter().find(|f| f.0 == name).unwrap().1 }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn shown(name: &str) -> display::Review { review(&Message::parse(&fixture(name)).unwrap(), &me()).unwrap() }

/// The associated token account of `owner` for `mint`, as spl-token has it.
fn ata(owner: &str, mint: &str) -> String {
    address(&program::associated_token_account(&key(owner), &program::TOKEN, &key(mint)).unwrap())
}

const RENT: &str = "For its owner's tokens. If it's new, this account pays its rent: about 0.002 SOL, back when it's closed.";

#[test]
fn addresses_and_amounts() {
    assert_eq!(address(&me()), ME);
    assert_eq!(base58::encode(&[0, 0, 1]), "112");
    assert_eq!(base58::decode("112"), Some(vec![0, 0, 1]));
    assert_eq!(base58::decode("0OIl"), None);
    assert_eq!(base58::decode_key("112"), None);
    assert_eq!(program::SYSTEM, [0; 32]);
    assert_eq!(address(&program::TOKEN), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    // spl-token's associated token account for this account's USDC
    assert_eq!(ata(ME, USDC), "5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt");
    assert!(program::on_curve(&me()));
    assert!(!program::on_curve(&key("5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt")));
    assert_eq!(decimals(0, 9), "0");
    assert_eq!(decimals(1, 9), "0.000000001");
    assert_eq!(decimals(1_500_000_000, 9), "1.5");
    assert_eq!(decimals(42, 0), "42");
    assert_eq!(decimals(u64::MAX as u128, 200).len(), 202);
    assert_eq!(display::sol(5060), "0.00000506 SOL");
}

#[test]
fn maki_signs_what_web3js_signs() {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    let keys = SeedKeys::from_seed(&seed).unwrap();
    let account = maki_hd::parse_path("m/44'/501'/0'/0'").unwrap();
    assert_eq!(keys.ed25519_public(&account).unwrap(), me());
    for (name, message, signature) in fixtures() {
        let parsed = Message::parse(&message).unwrap_or_else(|e| panic!("{name}: {e}"));
        if let Some(signature) = signature {
            assert!(review(&parsed, &me()).is_ok(), "{name}");
            assert_eq!(keys.sign_ed25519(&account, &message).unwrap().to_vec(), signature, "{name}");
        } else {
            assert_eq!(review(&parsed, &me()), Err(Error::NotSigner), "{name}");
        }
    }
}

#[test]
fn sol_sent_and_the_fee() {
    for name in ["sol", "sol-v0"] {
        let r = shown(name);
        assert_eq!(
            r.pages,
            [
                p("Send", "1.5 SOL", RECIPIENT, ""),
                p(
                    "Max fee",
                    "0.00000506 SOL",
                    "",
                    "0.000005 SOL for 1 signature, up to 0.00000006 SOL for priority."
                )
            ],
            "{name}"
        );
        assert_eq!(r.summary, "sends 1.5 SOL; fee up to 0.00000506 SOL");
    }
    let r = shown("memo");
    assert_eq!(
        r.pages[..2],
        [
            p("Send", "0.02 SOL", RECIPIENT, ""),
            p("Memo", "", "thanks for the coffee", "Everyone can read it, on chain.")
        ]
    );
    let r = shown("nonce");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "No time limit",
                "a durable nonce",
                NONCE,
                "It stays valid until it's sent or its nonce moves on; others last a minute or two."
            ),
            p("Send", "0.1 SOL", RECIPIENT, "")
        ]
    );
    assert_eq!(r.summary, "sends 0.1 SOL; fee up to 0.000005 SOL");
    let r = shown("create-account");
    assert_eq!(
        r.pages,
        [
            p(
                "New account",
                "0.00228288 SOL",
                CREATED,
                "200 bytes, owned by the Stake program; this account pays for it."
            ),
            p("Signed by others", "1 more", CREATED, "It needs their signatures as well as this account's."),
            p("Max fee", "0.00001 SOL", "", "0.00001 SOL for 2 signatures, up to 0 SOL for priority.")
        ]
    );
    // another pays the fee, and signs
    let r = shown("others-pay");
    assert_eq!(
        r.pages,
        [
            p("Send", "1 SOL", PAYER, ""),
            p("Signed by others", "1 more", PAYER, "It needs their signatures as well as this account's."),
            p(
                "Fee paid by",
                "someone else",
                PAYER,
                "Up to 0.00001 SOL, not this account's. 0.00001 SOL for 2 signatures, up to 0 SOL for priority."
            )
        ]
    );
    assert_eq!(r.summary, "sends 1 SOL; another pays the fee");
}

#[test]
fn tokens_sent_to_their_owners() {
    let r = shown("usdc");
    assert_eq!(
        r.pages[..2],
        [
            p("New token account", "USDC", RECIPIENT, RENT),
            p("Send", "5.25 USDC", RECIPIENT, "To their USDC account.")
        ]
    );
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.00000506 SOL");
    let r = shown("pyusd-2022");
    assert_eq!(
        r.pages[..2],
        [
            p("New token account", "PYUSD", RECIPIENT, RENT),
            p("Send", "10 PYUSD", RECIPIENT, "To their PYUSD account.")
        ]
    );
    assert_eq!(r.summary, "sends 10 PYUSD; fee up to 0.000005 SOL");
    // a token maki doesn't know, to a token account nothing here says is anyone's
    let r = shown("unknown-token");
    assert_eq!(
        r.pages[..2],
        [
            p("Send", "42 tokens", &ata(RECIPIENT, MINT), "To a token account: maki can't see whose."),
            p("Token", "one maki doesn't know", MINT, "Check its mint's address.")
        ]
    );
    assert_eq!(r.summary, "sends 42 tokens; fee up to 0.000005 SOL");
    // a transfer that doesn't say which token
    let r = shown("plain-token");
    assert_eq!(
        r.pages[0],
        p(
            "Send",
            "1000000 units",
            &ata(RECIPIENT, USDC),
            "To a token account: maki can't see whose. The transfer doesn't say which token: maki can't tell."
        )
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.000005 SOL");
    let r = shown("wrap-unwrap");
    assert_eq!(
        r.pages[..3],
        [
            p("Wrapped SOL", "brought up to date", &ata(ME, WSOL), ""),
            p("Burn", "1 USDC", &ata(ME, USDC), "Destroyed, from this token account: no one gets them."),
            p(
                "Close",
                "a token account",
                &ata(ME, WSOL),
                "The SOL it holds goes to this account: its rent, or all of it if it's wrapped SOL."
            )
        ]
    );
    assert_eq!(r.summary, "burns 1 USDC; fee up to 0.000005 SOL");
}

#[test]
fn what_hands_control_over_says_so() {
    let r = shown("approve");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Approve!",
                "up to 100 USDC",
                DELEGATE,
                &format!("That address may spend them from token account {}, without asking.", ata(ME, USDC))
            ),
            p(
                "Approve!",
                "up to 7 units",
                DELEGATE,
                &format!("That address may spend them from token account {}, without asking.", ata(ME, MINT))
            )
        ]
    );
    // the second is of a token maki can't tell: that it can't read it too
    assert_eq!(r.summary, "lets another spend tokens! And maki can't read all of it; fee up to 0.000005 SOL");
    let r = shown("set-authority");
    assert_eq!(
        r.pages[0],
        p(
            "Hands over!",
            "the account",
            &format!("of {}\nto {DELEGATE}", ata(ME, USDC)),
            "Whoever it goes to decides, from then on."
        )
    );
    assert_eq!(r.summary, "hands control over!; fee up to 0.000005 SOL");
    let r = shown("assign");
    assert_eq!(
        r.pages[0],
        p(
            "Hands over!",
            "this account",
            PROGRAM,
            "That program would own this account, and everything in it."
        )
    );
    assert_eq!(r.summary, "hands this account over!; fee up to 0.000005 SOL");
}

#[test]
fn what_maki_cant_read_is_flagged() {
    let r = shown("swap-v0");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Program",
                "maki can't read it",
                &format!("{PROGRAM}\n3 accounts, 5 bytes"),
                "It's given this account's signature: it can do anything this account can."
            ),
            p(
                "Send",
                "0.003 SOL",
                &format!("an address maki can't see: entry 2 of lookup table {TABLE}"),
                ""
            )
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.00000506 SOL");
    let r = shown("not-given");
    assert_eq!(
        r.pages[1],
        p(
            "Program",
            "maki can't read it",
            &format!("{PROGRAM}\n1 account, 1 byte"),
            "It isn't given this account's signature: it can't act as this account."
        )
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.000005 SOL");
}

/// A legacy message, written out: the header, keys, a blockhash of 7s, instructions.
fn legacy(header: [u8; 3], keys: &[Key], instructions: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
    let mut out = header.to_vec();
    out.push(keys.len() as u8);
    for k in keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&[7; 32]);
    out.push(instructions.len() as u8);
    for (program, accounts, data) in instructions {
        out.push(*program);
        out.push(accounts.len() as u8);
        out.extend_from_slice(accounts);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn messages_solana_would_refuse_maki_refuses() {
    let transfer: &[u8] = &[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    let keys = [me(), key(RECIPIENT), program::SYSTEM];
    let good = legacy([1, 0, 1], &keys, &[(2, &[0, 1], transfer)]);
    assert!(Message::parse(&good).is_ok());
    let bad = |bytes: Vec<u8>, e: message::Error| assert_eq!(Message::parse(&bytes), Err(e));
    // cut short, or with more after it
    bad(good[..good.len() - 1].to_vec(), message::Error::Length);
    bad([&good[..], &[0]].concat(), message::Error::Length);
    // a count written longer than it need be
    let mut long = good[..3].to_vec();
    long.extend_from_slice(&[0x83, 0x00]);
    long.extend_from_slice(&good[4..]);
    bad(long, message::Error::Encoding);
    // version 1, which there isn't
    bad([&[0x81][..], &good[..]].concat(), message::Error::Version);
    // no signer that writes, to pay the fee; more read-only than there are keys
    bad(legacy([1, 1, 0], &keys, &[]), message::Error::Header);
    bad(legacy([1, 0, 3], &keys, &[]), message::Error::Header);
    // the fee payer as a program, a program past the keys, an account past them
    bad(legacy([1, 0, 1], &keys, &[(0, &[0, 1], transfer)]), message::Error::Index);
    bad(legacy([1, 0, 1], &keys, &[(3, &[0, 1], transfer)]), message::Error::Index);
    bad(legacy([1, 0, 1], &keys, &[(2, &[0, 3], transfer)]), message::Error::Index);
    // a key twice
    bad(legacy([1, 0, 1], &[me(), me(), program::SYSTEM], &[]), message::Error::Duplicate);
    bad(vec![1; message::MAX_MESSAGE + 1], message::Error::TooBig);
    // compute budget instructions: once each, and ones Solana knows
    let budget = [me(), key(RECIPIENT), program::SYSTEM, program::COMPUTE_BUDGET];
    let limit: &[u8] = &[2, 0x40, 0x0d, 0x03, 0x00];
    let twice = Message::parse(&legacy([1, 0, 2], &budget, &[(3, &[], limit), (3, &[], limit)])).unwrap();
    assert!(matches!(review(&twice, &me()), Err(Error::Invalid(_))));
    let odd = Message::parse(&legacy([1, 0, 2], &budget, &[(3, &[], &[0, 1, 2, 3, 4, 5, 6, 7, 8])])).unwrap();
    assert!(matches!(review(&odd, &me()), Err(Error::Invalid(_))));
    // a transfer without its accounts
    let short = Message::parse(&legacy([1, 0, 1], &keys, &[(2, &[0], transfer)])).unwrap();
    assert!(matches!(review(&short, &me()), Err(Error::Invalid(_))));
    // a token account that isn't the owner's
    let ata_program = program::ASSOCIATED_TOKEN;
    let lie = [me(), key(DELEGATE), key(RECIPIENT), key(USDC), program::SYSTEM, program::TOKEN, ata_program];
    let lying = Message::parse(&legacy([1, 0, 5], &lie, &[(6, &[0, 1, 2, 3, 4, 5], &[1])])).unwrap();
    assert!(matches!(review(&lying, &me()), Err(Error::Invalid(_))));
}

#[test]
fn closing_a_token_account_to_another_is_flagged() {
    // this account's token account closed, its SOL (all of it, if it's wrapped SOL) to another
    let keys = [me(), key(&ata(ME, WSOL)), key(RECIPIENT), program::TOKEN];
    let close = Message::parse(&legacy([1, 0, 1], &keys, &[(3, &[1, 2, 0], &[9])])).unwrap();
    let r = review(&close, &me()).unwrap();
    assert_eq!(
        r.pages[0].prose,
        format!("The SOL it holds goes to {RECIPIENT}: its rent, or all of it if it's wrapped SOL.")
    );
    assert_eq!(r.summary, "sends a token account's SOL to another!; fee up to 0.000005 SOL");
    // and the line under the question, however much there is to warn of, fits maki's screen
    let most: &[u8] = &[2, 0xff, 0xff, 0xff, 0xff];
    let price: &[u8] = &[3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let assign: &[u8] = &[[1, 0, 0, 0].as_slice(), &[6; 32]].concat();
    let keys = [
        me(),
        key(&ata(ME, WSOL)),
        key(RECIPIENT),
        program::TOKEN,
        program::COMPUTE_BUDGET,
        program::SYSTEM,
        [8; 32],
    ];
    let everything = Message::parse(&legacy(
        [1, 0, 4],
        &keys,
        &[(4, &[], most), (4, &[], price), (3, &[1, 2, 0], &[9]), (5, &[0], assign), (6, &[0], &[1])],
    ))
    .unwrap();
    let r = review(&everything, &me()).unwrap();
    assert_eq!(r.summary.len(), display::MAX_SUMMARY);
    assert!(
        r.summary.starts_with(
            "sends a token account's SOL to another, hands this account over! And maki can't read"
        ),
        "{}",
        r.summary
    );
    assert!(r.summary.ends_with('…'));
}

#[test]
fn a_compute_limit_the_price_and_their_fee() {
    let budget = [me(), key(RECIPIENT), program::SYSTEM, program::COMPUTE_BUDGET];
    let transfer: &[u8] = &[2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    // no limit: 200,000 units for each instruction; at 1 microlamport a unit, 0.2 lamports, rounded up
    let price: &[u8] = &[3, 1, 0, 0, 0, 0, 0, 0, 0];
    let r = review(
        &Message::parse(&legacy([1, 0, 2], &budget, &[(3, &[], price), (2, &[0, 1], transfer)])).unwrap(),
        &me(),
    )
    .unwrap();
    assert_eq!(r.pages.last().unwrap().value, "0.000005001 SOL");
    // no more than 1.4 million units, whatever's asked
    let most: &[u8] = &[2, 0xff, 0xff, 0xff, 0xff];
    let price: &[u8] = &[3, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0];
    let r = review(
        &Message::parse(&legacy(
            [1, 0, 2],
            &budget,
            &[(3, &[], most), (3, &[], price), (2, &[0, 1], transfer)],
        ))
        .unwrap(),
        &me(),
    )
    .unwrap();
    assert_eq!(r.pages.last().unwrap().value, "0.001405 SOL");
}

#[test]
fn messages_to_sign_and_sign_ins() {
    let sign_in = format!(
        "example.com wants you to sign in with your Solana account:\n{ME}\n\nSign in to Example\n\nURI: https://example.com\nVersion: 1\nNonce: 32891756"
    );
    let pages = message_pages("example.com", &me(), sign_in.as_bytes()).unwrap();
    assert_eq!(pages, [p("Message", "", &sign_in, "")]);
    let pages = message_pages("example.org", &me(), sign_in.as_bytes()).unwrap();
    assert_eq!(
        pages[0],
        p(
            "Wrong site!",
            "a sign-in for",
            "example.com",
            "Not the site asking: it may be copying that site's sign-in."
        )
    );
    let theirs = sign_in.replace(ME, RECIPIENT);
    let pages = message_pages("example.com", &me(), theirs.as_bytes()).unwrap();
    assert_eq!(pages[0], p("Wrong account!", "a sign-in for", RECIPIENT, "Not this account."));
    assert_eq!(
        message_pages("example.com", &me(), &[0xff, 0, 1]).unwrap(),
        [p("Message", "in hex", "ff0001", "")]
    );
    // a transaction isn't a message
    assert!(matches!(message_pages("example.com", &me(), &fixture("sol")), Err(Error::Invalid(_))));
}
