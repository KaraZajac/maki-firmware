//! maki-ton against TON's own libraries: requests @ton/ton made for its wallets
//! (`fixtures/make.mjs`), read as the wallets read them, hashed as @ton/core hashes cells, shown as
//! they should be, and signed by maki's keys as @ton/crypto signs them with the same account (the
//! test phrase's, at the path Ledger's TON app has); addresses as @ton/core writes them, and
//! TEP-2's own; the jetton wallets maki works out, as their masters said on chain they are; and
//! what TON (or maki) refuses, refused, bags of cells written by hand among them.

use maki_hd::seed::SeedKeys;
use maki_ton::address::{Parsed, crc16};
use maki_ton::cell::{Boc, Builder, MAX_BOC, crc32c};
use maki_ton::display::{self, Page, Review, review};
use maki_ton::wallet::{Action, Request, V4R2_SUBWALLET, Wallet};
use maki_ton::{Address, Error, Network, jettons, path};

/// The test phrase's first account's wallets, as @ton/ton makes them from Ledger's key for it.
const ME_V4: &str = "UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOpj";
const ME_W5: &str = "UQCr0pJvwmgWeI7Wu0TaRn77bD0m7JkkbnGRCxRUxhbyvbdS";
const ME_V4_TEST: &str = "0QBWxXQsPN_l61TJ64LnPAfUi4ewmVfK1DLkwyY_WARTsT24";
/// The fixtures' others: a wallet (v4R2 of the key whose seed is 32 ones), contracts of 32 0x22s,
/// 0x44s (a stranger) and 0x55s (a plugin), one on the masterchain.
const RECIPIENT: &str = "UQDvr_S6wiD4iy6Y6x2c_8yjv-O2bs4xp9bFiQ0w39evpYZV";
const RECIPIENT_TEST: &str = "0QDvr_S6wiD4iy6Y6x2c_8yjv-O2bs4xp9bFiQ0w39evpT3f";
const CONTRACT: &str = "EQAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIp3C";
const STRANGER: &str = "UQBERERERERERERERERERERERERERERERERERERERERERDel";
const PLUGIN: &str = "EQBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUMv";
const MASTERCHAIN: &str = "Ef8zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM0vF";
const DEPLOYED: &str = "UQA3jCfhaMmZC12CTs5tts9HWC5efqeAnNhnzrWEgHb4BEeg";

const VALID: (&str, &str, &str, &str) =
    ("Valid until", "2027-01-01 00:00:00 UTC", "", "After that, the wallet refuses it.");
const FEE: &str = "The network's fee comes from its balance as well, at TON's prices when it runs.";
const NOT_BOUNCEABLE: &str = "Not bounceable: it stays, even if nothing's at the address yet.";
const BOUNCEABLE: &str = "Bounceable: if nothing at the address takes it, it comes back.";
const ON_TOP: &str = "The network's fee for sending it comes from this wallet.";
const OUT_OF_IT: &str = "The network's fee for sending it comes out of it.";
const READ: &str = "Everyone can read it, on chain.";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn keys() -> SeedKeys {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    SeedKeys::from_seed(&seed).unwrap()
}

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A request @ton/ton made: the cell its signer was handed (a BOC), the hash it signs, its
/// signature with this account's key, and the external message that carries them.
struct Fixture {
    name: String,
    network: Network,
    wallet: Wallet,
    account: u32,
    boc: Vec<u8>,
    hash: Vec<u8>,
    signature: Vec<u8>,
    external: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap(),
            wallet: Wallet::from_id(f["version"].as_str().unwrap()).unwrap(),
            account: f["account"].as_u64().unwrap() as u32,
            boc: unhex(f["boc"].as_str().unwrap()),
            hash: unhex(f["hash"].as_str().unwrap()),
            signature: unhex(f["signature"].as_str().unwrap()),
            external: unhex(f["external"].as_str().unwrap()),
        })
        .collect()
}

fn fixture_on(name: &str, wallet: Wallet, network: Network) -> Vec<u8> {
    fixtures().into_iter().find(|f| f.name == name && f.wallet == wallet && f.network == network).unwrap().boc
}

fn fixture(name: &str, wallet: Wallet) -> Vec<u8> { fixture_on(name, wallet, Network::Main) }

fn me(network: Network, account: u32) -> [u8; 32] { keys().ed25519_public(&path(network, account)).unwrap() }

fn shown_on(name: &str, wallet: Wallet, network: Network) -> Review {
    let bytes = fixture_on(name, wallet, network);
    let boc = Boc::parse(&bytes).unwrap();
    let r = review(&Request::parse(&boc).unwrap(), &me(network, 0), network).unwrap();
    fits_the_screen(&r);
    r
}

fn shown(name: &str, wallet: Wallet) -> Review { shown_on(name, wallet, Network::Main) }

/// Why a fixture is refused: reading it, or showing it.
fn refused(name: &str, wallet: Wallet) -> String {
    let bytes = fixture(name, wallet);
    let boc = Boc::parse(&bytes).unwrap();
    match Request::parse(&boc) {
        Err(e) => e.to_string(),
        Ok(r) => review(&r, &me(Network::Main, 0), Network::Main).unwrap_err().to_string(),
    }
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn valid() -> Page { p(VALID.0, VALID.1, VALID.2, VALID.3) }

fn from(wallet: Wallet, address: &str, seqno: &str) -> Page {
    p(
        "From",
        &format!("this account's {} wallet", wallet.name()),
        address,
        &format!("On TON; its seqno is {seqno}. {FEE}"),
    )
}

/// What maki's review screen takes (maki-wasm's limits): a heading of 32 bytes, a value of 128, no
/// control characters but newlines in the fixed-width text and the prose, 4096 bytes of each.
fn fits_the_screen(r: &Review) {
    assert!(r.summary.len() <= display::MAX_SUMMARY, "{}", r.summary);
    assert!(r.pages.len() <= display::MAX_PAGES);
    for page in &r.pages {
        let plain = |t: &str| !t.chars().any(|c| c.is_control());
        let lines = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
        assert!(!page.heading.trim().is_empty() && page.heading.len() <= 32, "{page:?}");
        assert!(page.value.len() <= 128 && page.mono.len() <= 4096 && page.prose.len() <= 4096, "{page:?}");
        assert!(
            plain(&page.heading) && plain(&page.value) && lines(&page.mono) && lines(&page.prose),
            "{page:?}"
        );
    }
}

#[test]
fn accounts_are_ledgers_and_their_wallets_tons() {
    let keys = keys();
    let accounts = json()["accounts"].as_array().unwrap().clone();
    assert_eq!(accounts.len(), 4);
    for a in &accounts {
        let network = Network::from_byte(a["network"].as_u64().unwrap() as u8).unwrap();
        let account = a["account"].as_u64().unwrap() as u32;
        // Ledger's path, as ton-ledger-ts writes it: m/44'/607'/network'/0'/account'/0'
        assert_eq!(maki_hd::format_path(&path(network, account)), a["path"].as_str().unwrap());
        let key = keys.ed25519_public(&path(network, account)).unwrap();
        assert_eq!(hex(&key), a["public_key"].as_str().unwrap(), "{}", a["path"]);
        let testnet = network == Network::Test;
        for wallet in Wallet::ALL {
            let forms = &a[wallet.id()];
            let address = wallet.address(&key, network);
            assert_eq!(address.raw(), forms["raw"].as_str().unwrap(), "{} {}", a["path"], wallet.id());
            assert_eq!(address.friendly(true, testnet), forms["bounceable"].as_str().unwrap());
            assert_eq!(address.friendly(false, testnet), forms["non_bounceable"].as_str().unwrap());
        }
    }
    assert_eq!(Wallet::V4R2.address(&me(Network::Main, 0), Network::Main).friendly(false, false), ME_V4);
    assert_eq!(Wallet::V5R1.address(&me(Network::Main, 0), Network::Main).friendly(false, false), ME_W5);
    // W5's address is another on the test network (its wallet ID is), v4R2's isn't
    let key = me(Network::Main, 0);
    assert_ne!(Wallet::V5R1.address(&key, Network::Main), Wallet::V5R1.address(&key, Network::Test));
    assert_eq!(Wallet::V4R2.address(&key, Network::Main), Wallet::V4R2.address(&key, Network::Test));
    // the names maki's messages use
    assert_eq!((Wallet::from_id("v4R2"), Wallet::from_id("v5R1")), (Some(Wallet::V4R2), Some(Wallet::V5R1)));
    assert_eq!((Wallet::from_id("v4r2"), Wallet::from_id("W5"), Wallet::from_id("")), (None, None, None));
}

#[test]
fn wallet_ids_are_as_ton_ton_writes_them() {
    // v4R2's first subwallet; W5's for each network (@ton/ton's walletId, 2147483409 on TON)
    assert_eq!(Wallet::V4R2.wallet_id(Network::Main), V4R2_SUBWALLET);
    assert_eq!(Wallet::V4R2.wallet_id(Network::Test), 698_983_191);
    assert_eq!(Wallet::V5R1.wallet_id(Network::Main), 2_147_483_409);
    assert_eq!(Wallet::V5R1.wallet_id(Network::Test), 2_147_483_645);
    for (wallet, network) in [
        (Wallet::V4R2, Network::Main),
        (Wallet::V4R2, Network::Test),
        (Wallet::V5R1, Network::Main),
        (Wallet::V5R1, Network::Test),
    ] {
        let bytes = fixture_on("ton", wallet, network);
        let boc = Boc::parse(&bytes).unwrap();
        let request = Request::parse(&boc).unwrap();
        assert_eq!((request.wallet, request.wallet_id), (wallet, wallet.wallet_id(network)));
        assert_eq!((request.valid_until, request.seqno), (1_798_761_600, 7));
    }
}

#[test]
fn addresses_read_and_write_as_tep2_and_ton_core_have_them() {
    let json = json();
    for a in json["addresses"].as_array().unwrap() {
        let raw = Address::parse(a["raw"].as_str().unwrap()).unwrap();
        assert_eq!((raw.bounceable, raw.testnet), (None, None));
        let address = raw.address;
        assert_eq!(address.raw(), a["raw"].as_str().unwrap());
        assert_eq!(address.friendly(true, false), a["bounceable"].as_str().unwrap());
        assert_eq!(address.friendly(false, false), a["non_bounceable"].as_str().unwrap());
        for (text, bounceable) in [(&a["bounceable"], true), (&a["non_bounceable"], false)] {
            let parsed = Address::parse(text.as_str().unwrap()).unwrap();
            assert_eq!(parsed, Parsed { address, bounceable: Some(bounceable), testnet: Some(false) });
        }
        if let Some(test) = a.get("test") {
            assert_eq!(address.friendly(false, true), test["non_bounceable"].as_str().unwrap());
            let parsed = Address::parse(test["bounceable"].as_str().unwrap()).unwrap();
            assert_eq!(parsed, Parsed { address, bounceable: Some(true), testnet: Some(true) });
        }
    }
    // TEP-2's own example: the root DNS contract, on the masterchain
    let dns = Address::parse("-1:E56754F83426F69B09267BD876AC97C44821345B7E266BD956A7BFBFB98DF35C").unwrap();
    assert_eq!(dns.address.friendly(true, false), "Ef_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXDvq");
    assert_eq!(dns.address.friendly(false, false), "Uf_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXGYv");
    // base64's other two letters, as some software writes them
    assert_eq!(
        Address::parse("Ef/lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7+/uY3zXDvq").unwrap().address,
        dns.address
    );
    // the CRC16 TEP-2 checks with (XModem's), and Ledger's TON app's own test of it
    assert_eq!(crc16(&(0..16).collect::<Vec<u8>>()), 20797);
    assert_eq!(crc16(b"123456789"), 0x31c3);
    let refused = |text: &str| Address::parse(text).unwrap_err().to_string();
    let not = "not a TON address";
    // mistyped: a letter changed, so its checksum doesn't hold
    assert_eq!(
        refused("UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOpk"),
        "a TON address whose checksum is wrong: mistyped?"
    );
    assert_eq!(refused("UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOp"), not);
    assert_eq!(refused("UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l-8mOpjj"), not);
    assert_eq!(refused("UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l+8mO_j"), not);
    assert_eq!(refused("UQAhEnZmOZ4XCJ1BKsvvt4D1DobiFgIf8nbZdTiT0l 8mOpj"), not);
    assert_eq!(refused(""), not);
    assert_eq!(refused("0:21127666399e17089d412acbefb780f50e86e216021ff276d9753893d25fbc9"), not);
    assert_eq!(refused("0:21127666399e17089d412acbefb780f50e86e216021ff276d9753893d25fbcxx"), not);
    assert_eq!(refused("+0:21127666399e17089d412acbefb780f50e86e216021ff276d9753893d25fbc98"), not);
    assert_eq!(
        refused("1:21127666399e17089d412acbefb780f50e86e216021ff276d9753893d25fbc98"),
        "an address on a workchain TON doesn't have"
    );
    assert_eq!(refused("x:21127666399e17089d412acbefb780f50e86e216021ff276d9753893d25fbc98"), not);
    // a tag that isn't one: bounceable on another network, say
    let mut b = [0u8; 36];
    b[0] = 0x12;
    b[2..34].copy_from_slice(&[7; 32]);
    let crc = crc16(&b[..34]).to_be_bytes();
    b[34..].copy_from_slice(&crc);
    let text = Address { workchain: 0, hash: [7; 32] }.friendly(true, false);
    assert_eq!(Address::parse(&text).unwrap().address.hash, [7; 32]);
    let other: String = base64url(&b);
    assert_eq!(refused(&other), not);
    // workchain 1 in a user-friendly address
    b[0] = 0x11;
    b[1] = 1;
    let crc = crc16(&b[..34]).to_be_bytes();
    b[34..].copy_from_slice(&crc);
    assert_eq!(refused(&base64url(&b)), "an address on a workchain TON doesn't have");
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    b.chunks(3)
        .flat_map(|c| {
            let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
            [18, 12, 6, 0].map(|s| A[(n >> s & 63) as usize] as char)
        })
        .collect()
}

#[test]
fn jetton_wallets_are_the_ones_their_masters_say() {
    let json = json();
    let theirs = &json["accounts"][0]["jettons"];
    let key = me(Network::Main, 0);
    for j in jettons::KNOWN {
        for wallet in Wallet::ALL {
            let owner = wallet.address(&key, Network::Main);
            // as the master's own get_wallet_address said, on chain
            assert_eq!(
                j.wallet(&owner).raw(),
                theirs[j.symbol][wallet.id()].as_str().unwrap(),
                "{}",
                j.symbol
            );
            assert_eq!(jettons::known(&j.wallet(&owner), &owner), Some(&j));
            // not anyone else's
            let other = Wallet::ALL.into_iter().find(|w| *w != wallet).unwrap().address(&key, Network::Main);
            assert_eq!(jettons::known(&j.wallet(&owner), &other), None);
        }
    }
    // the masters, and their wallets' code: the library cell's hash is the one Ledger's TON app has
    // for it, and toncenter's jetton_wallet_code_hash
    assert_eq!(
        jettons::USDT.master().friendly(true, false),
        "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
    );
    assert_eq!(
        jettons::NOT.master().friendly(true, false),
        "EQAvlWFDxGF2lXm67y4yzC17wYKD9A0guwPkMs1gOsM__NOT"
    );
    assert_eq!(
        jettons::DOGS.master().friendly(true, false),
        "EQCvxJy4eG8hyHBFsZ7eePxrRsUQSFE_jpptRAYBmcG_DOGS"
    );
    assert_eq!(
        hex(&jettons::USDT.code_cell()),
        "89468f02c78e570802e39979c8516fc38df07ea76a48357e0536f2ba7b3ee37b"
    );
    assert_eq!(
        hex(&jettons::NOT.code_cell()),
        "8d28ea421b77e805fea52acf335296499f03aec8e9fd21ddb5f2564aa65c48de"
    );
    assert_eq!(jettons::NOT.code_cell(), jettons::DOGS.code_cell());
    assert_eq!((jettons::USDT.decimals, jettons::NOT.decimals, jettons::DOGS.decimals), (6, 9, 9));
}

/// The requests maki refuses, and why: what TON would refuse, what maki can't show, and what isn't
/// this account's.
const REFUSED: &[(&str, &str)] = &[
    ("extra-currency", "extra currencies, which maki doesn't read"),
    ("workchain-1", "a message to a workchain TON doesn't have: it would refuse it"),
    ("mode-64", "a send mode for contracts (+16 or +64), which wallets don't use"),
    ("mode-16", "a send mode for contracts (+16 or +64), which wallets don't use"),
    ("mode-4", "a send mode TON refuses"),
    ("mode-192", "a send mode TON refuses"),
    ("more-bits", "not as TON writes it: more in a cell after what it holds"),
    ("op-9", "a wallet operation v4R2 doesn't have: it would do nothing but count it"),
    ("subwallet", "not this account's wallet: another wallet ID"),
    // a v3R2 wallet's request (the same subwallet, no op): never read as v4R2's
    ("v3r2", "not as TON writes it: a cell ends too soon"),
    (
        "signature-off",
        "turning its key's signatures off or on, which only an extension may: W5 would refuse it",
    ),
    (
        "internal",
        "a request for another contract to pass on (W5's signed internal message): maki doesn't sign those",
    ),
    ("too-many", "too much to go through on maki's screen"),
    ("256", "more messages than W5 sends at once: it would refuse them"),
    (
        "no-ignore-errors",
        "a message without +2 (ignore errors) in a request from outside: W5 would refuse it",
    ),
];

#[test]
fn every_request_is_hashed_and_signed_as_ton_signs_it() {
    let keys = keys();
    let (mut signed, mut refused_n) = (0, 0);
    for f in fixtures() {
        let boc = Boc::parse(&f.boc).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        // the cell's hash, as @ton/core's Cell.hash(): what the wallet checks the signature against
        assert_eq!(boc.hash().to_vec(), f.hash, "{}", f.name);
        // signed by maki's key for the account as @ton/crypto signs it, byte for byte
        let at = path(f.network, f.account);
        assert_eq!(keys.sign_ed25519(&at, &boc.hash()).unwrap().to_vec(), f.signature, "{}", f.name);
        let key = keys.ed25519_public(&at).unwrap();
        let shown = Request::parse(&boc)
            .map_err(|e| e.to_string())
            .and_then(|r| review(&r, &key, f.network).map_err(|e| e.to_string()));
        match REFUSED.iter().find(|(n, _)| *n == f.name) {
            Some((_, why)) => {
                assert_eq!(shown.unwrap_err(), *why, "{}", f.name);
                refused_n += 1;
            }
            // the other network's W5 request, asked of this one, says whose it is
            None if f.name == "testnet-id" => {
                let r = Request::parse(&boc).unwrap();
                assert_eq!(
                    review(&r, &key, Network::Main).unwrap_err().to_string(),
                    "a request for TON's test network, not TON: its wallet ID says so"
                );
                assert!(shown.is_ok());
                signed += 1;
            }
            None => {
                fits_the_screen(&shown.unwrap_or_else(|e| panic!("{}: {e}", f.name)));
                signed += 1;
            }
        }
    }
    // 82 requests: 15 kinds refused, two of them made for both wallets
    assert_eq!((signed, refused_n), (65, REFUSED.len() + 2));
}

/// A slice's bits, as booleans.
fn bits(s: &mut maki_ton::cell::Slice<'_>) -> Vec<bool> {
    let mut out = Vec::new();
    while s.bits_left() > 0 {
        out.push(s.bit().unwrap());
    }
    out
}

#[test]
fn the_external_message_carries_the_signature_where_the_wallet_reads_it() {
    // what maki desktop sends: the request with the signature (v4R2: first; W5: last), in an
    // external message to the wallet, with its first state if its seqno is 0, as @ton/ton makes it
    for f in fixtures() {
        let ext = Boc::parse(&f.external).unwrap();
        let mut s = ext.root().unwrap();
        // ext_in_msg_info$10 src:addr_none dest:MsgAddressInt import_fee:Grams
        assert_eq!(s.uint(2).unwrap(), 0b10, "{}", f.name);
        assert_eq!(s.address().unwrap(), None);
        let key = me(f.network, f.account);
        assert_eq!(s.address().unwrap(), Some(f.wallet.address(&key, f.network)), "{}", f.name);
        assert_eq!(s.coins().unwrap(), 0);
        // init: the wallet's first state, only for its first request
        let deploys = s.bit().unwrap();
        assert_eq!(deploys, f.name == "first", "{}", f.name);
        if deploys {
            let init = if s.bit().unwrap() {
                s.reference().unwrap().rest_hash().0
            } else {
                // inline: its five bits and two references, taken out as a cell of their own
                let mut b = Builder::new();
                for _ in 0..5 {
                    b.bit(s.bit().unwrap());
                }
                for _ in 0..2 {
                    let c = s.reference_cell().unwrap();
                    b.reference(s.cell_hash(c));
                }
                b.finish().0
            };
            assert_eq!(init, f.wallet.init(&key, f.network).hash());
        }
        let mut body = s.either().unwrap();
        let request = Boc::parse(&f.boc).unwrap();
        let mut signing = request.root().unwrap();
        let (sig, rest) = match f.wallet {
            Wallet::V4R2 => {
                let sig: Vec<bool> = (0..512).map(|_| body.bit().unwrap()).collect();
                (sig, bits(&mut body))
            }
            Wallet::V5R1 => {
                let all = bits(&mut body);
                (all[all.len() - 512..].to_vec(), all[..all.len() - 512].to_vec())
            }
        };
        let expected: Vec<bool> =
            f.signature.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 != 0)).collect();
        assert_eq!(sig, expected, "{}", f.name);
        assert_eq!(rest, bits(&mut signing), "{}", f.name);
        // and the same references
        assert_eq!(body.refs_left(), signing.refs_left());
        while body.refs_left() > 0 {
            let (a, b) = (body.reference_cell().unwrap(), signing.reference_cell().unwrap());
            assert_eq!(body.cell_hash(a), signing.cell_hash(b), "{}", f.name);
        }
    }
}

#[test]
fn ton_sent_is_shown_with_its_comment_and_how_its_sent() {
    for wallet in Wallet::ALL {
        let me = if wallet == Wallet::V4R2 { ME_V4 } else { ME_W5 };
        let r = shown("ton", wallet);
        assert_eq!(r.summary, "sends 1.5 TON; plus the network's fee");
        assert_eq!(
            r.pages,
            [
                p("Send", "1.5 TON", RECIPIENT, &format!("{NOT_BOUNCEABLE} {ON_TOP}")),
                p("Comment", "", "thanks for the coffee", READ),
                valid(),
                from(wallet, me, "7"),
            ]
        );
        let r = shown("bounceable", wallet);
        assert_eq!(r.pages[0], p("Send", "0.25 TON", CONTRACT, &format!("{BOUNCEABLE} {ON_TOP}")));
        // the masterchain's, bounceable
        assert_eq!(shown("masterchain", wallet).pages[0].mono, MASTERCHAIN);
        // a long comment, over three cells; one that isn't UTF-8, and one with a bell in it, in hex
        let long = "A comment longer than a cell holds, so it goes on into the next cell, and the one after that, as TON writes long text: ".repeat(3);
        assert_eq!(shown("long-comment", wallet).pages[1], p("Comment", "", &long, READ));
        assert_eq!(shown("comment-bytes", wallet).pages[1], p("Comment", "in hex", "c32841", READ));
        assert_eq!(shown("comment-control", wallet).pages[1], p("Comment", "in hex", "72696e6707", READ));
        // to itself, and setting up its other wallet
        let r = shown("to-self", wallet);
        assert_eq!(
            r.pages[0],
            p("Send", "0.000000001 TON", &format!("this account's {} wallet", wallet.name()), ON_TOP)
        );
        let other = Wallet::ALL.into_iter().find(|w| *w != wallet).unwrap();
        let r = shown("deploy-other-wallet", wallet);
        assert_eq!(
            r.summary,
            format!("sets up its {} wallet, sends 0.1 TON; plus the network's fee", other.name())
        );
        assert_eq!(r.pages[0].mono, format!("this account's {} wallet", other.name()));
        assert_eq!(
            r.pages[1],
            p(
                "Sets up",
                &format!("this account's {} wallet", other.name()),
                "",
                &format!("With {}'s code and this account's key: the wallet starts working.", other.name())
            )
        );
        // its first request, which sets the wallet up, and one with no time limit
        assert_eq!(
            *shown("first", wallet).pages.last().unwrap(),
            from(wallet, me, "0: its first, which sets the wallet up")
        );
        let r = shown("no-time-limit", wallet);
        assert_eq!(
            r.pages[2],
            p("No time limit", "", "", "It stays good until it's sent, or the wallet's seqno moves past it.")
        );
        // another account's: its own address
        let account_7 = if wallet == Wallet::V4R2 {
            "UQDxqNeR3QsANcdf5SxbzC4yKvHfazWrhRV2aDrnJYgt7m1d"
        } else {
            "UQAS4KGFE27MqUphjEGabs-LprTPYxAugKRWRe8gSnZlR5fN"
        };
        let bytes = fixture("account-7", wallet);
        let boc = Boc::parse(&bytes).unwrap();
        let r = review(&Request::parse(&boc).unwrap(), &me_7(), Network::Main).unwrap();
        assert_eq!(*r.pages.last().unwrap(), from(wallet, account_7, "7"));
    }
    // the test network's: its addresses say so, and so does the summary
    let r = shown_on("ton", Wallet::V4R2, Network::Test);
    assert_eq!(r.summary, "testnet: sends 1.5 TON; plus the network's fee");
    assert_eq!(r.pages[0].mono, RECIPIENT_TEST);
    assert_eq!(
        r.pages[3],
        p(
            "From",
            "this account's v4R2 wallet",
            ME_V4_TEST,
            &format!("On TON's test network, where TON is worth nothing; its seqno is 7. {FEE}")
        )
    );
    // four messages, each with its own mode: the fee on top (+1) or out of it
    let r = shown("modes", Wallet::V4R2);
    assert_eq!(r.summary, "sends 1.500000009 TON in 4 messages; plus the network's fee");
    let fees: Vec<&str> = r
        .pages
        .iter()
        .filter(|p| p.heading == "Send")
        .map(|p| p.prose.rsplit(". ").next().unwrap())
        .collect();
    assert_eq!(fees, [OUT_OF_IT, ON_TOP, OUT_OF_IT, ON_TOP]);
    let r = shown("many", Wallet::V5R1);
    assert_eq!(r.summary, "sends 0.00000082 TON in 40 messages; plus the network's fee");
    assert_eq!(r.pages.len(), 42);
    // in the order W5 sends them: the first of its list's cells is the last
    assert_eq!(r.pages[0].value, "0.000000001 TON");
    assert_eq!(r.pages[39].value, "0.00000004 TON");
}

fn me_7() -> [u8; 32] { me(Network::Main, 7) }

#[test]
fn jettons_maki_knows_are_shown_as_theirs_and_the_rest_flagged() {
    for wallet in Wallet::ALL {
        let me = if wallet == Wallet::V4R2 { ME_V4 } else { ME_W5 };
        let r = shown("usdt", wallet);
        assert_eq!(r.summary, "sends 5.25 USDT, 0.05 TON; plus the network's fee");
        assert_eq!(
            r.pages,
            [
                p(
                    "Send",
                    "5.25 USDT",
                    RECIPIENT,
                    "From this account's USDT, with 0.05 TON to its jetton wallet for the fees; what's left comes back to this wallet. 0.000000001 TON goes on to them with it."
                ),
                p("Comment", "", "invoice 42", READ),
                valid(),
                from(wallet, me, "7"),
            ]
        );
        let r = shown("not-inline", wallet);
        assert_eq!(r.summary, "sends 1000 NOT, 0.05 TON; plus the network's fee");
        assert_eq!(r.pages.len(), 3);
        assert_eq!(
            shown("usdt-no-response", wallet).pages[0].prose,
            "From this account's USDT, with 0.05 TON to its jetton wallet for the fees; what's left isn't sent back."
        );
        assert_eq!(
            shown("usdt-binary", wallet).pages[1],
            p(
                "Comment",
                "binary, in hex",
                "6f726465722031323334",
                "For software, not people: everyone can read it, on chain."
            )
        );
        // what's left to another, a payload for the jetton wallet, and one for them maki can't read
        let r = shown("usdt-elsewhere", wallet);
        assert_eq!(r.summary, "maki can't read all of it; plus the network's fee");
        assert_eq!(
            r.pages[..4],
            [
                p(
                    "Send",
                    "0.000001 USDT",
                    STRANGER,
                    "From this account's USDT, with 0.05 TON to its jetton wallet for the fees; what's left goes to another address. 0.01 TON goes on to them with it."
                ),
                p(
                    "What's left to",
                    "another address",
                    STRANGER,
                    "What's left of the TON sent with it goes there, not to this wallet."
                ),
                p(
                    "Jetton payload",
                    "maki can't read it",
                    "",
                    "A payload for the jetton wallet itself: what it asks, maki can't tell."
                ),
                p(
                    "For them",
                    "maki can't read it",
                    "op 0x25938561\n12 bytes, 1 cell",
                    "It goes to them with the jettons: what it asks of them, maki can't tell."
                ),
            ]
        );
        // a jetton wallet that isn't this account's for a jetton maki knows
        let r = shown("jetton-unknown", wallet);
        assert_eq!(r.summary, "maki can't read all of it; plus the network's fee");
        assert_eq!(
            r.pages[..2],
            [
                p(
                    "Send",
                    "77 units",
                    RECIPIENT,
                    "Of a jetton maki doesn't know, with 0.05 TON to its jetton wallet for the fees; what's left comes back to this wallet."
                ),
                p(
                    "Jetton",
                    "one maki doesn't know",
                    "EQBERERERERERERERERERERERERERERERERERERERERERGpg",
                    "Its jetton wallet: maki can't tell which jetton it holds, or whose it is."
                ),
            ]
        );
        // on the test network, no jetton is one maki knows
        let r = shown_on("usdt", wallet, Network::Test);
        assert_eq!(r.summary, "testnet: maki can't read all of it; plus the network's fee");
        assert_eq!((r.pages[0].value.as_str(), r.pages[1].heading.as_str()), ("5250000 units", "Jetton"));
    }
}

#[test]
fn what_takes_everything_or_gives_control_is_said_loudly() {
    for wallet in Wallet::ALL {
        let r = shown("send-all", wallet);
        assert_eq!(r.summary, "sends all its TON, closes the wallet!; plus the network's fee");
        assert_eq!(
            r.pages[..2],
            [
                p(
                    "Sends everything!",
                    "all its TON",
                    RECIPIENT,
                    &format!("Everything this wallet holds, less the network's fee. {NOT_BOUNCEABLE}")
                ),
                p(
                    "Closes it!",
                    "deletes this wallet",
                    "",
                    "If this leaves it with no TON, TON deletes this wallet. Set up again, its seqno starts over, and requests signed before could go through again."
                ),
            ]
        );
        assert_eq!(shown("send-all-keep", wallet).summary, "sends all its TON!; plus the network's fee");
        // a contract set up, whose code maki can't read
        let r = shown("deploy", wallet);
        assert_eq!(r.summary, "maki can't read all of it; plus the network's fee");
        assert_eq!(r.pages[0].mono, DEPLOYED);
        assert_eq!(
            r.pages[1],
            p(
                "Sets up!",
                "a contract maki can't read",
                "",
                "At the address it's sent to. Its code and data come from the computer: what it does, maki can't tell."
            )
        );
        // a body maki can't read (an NFT's transfer), and an encrypted comment
        let r = shown("nft", wallet);
        assert_eq!(
            r.pages[1],
            p(
                "Message",
                "maki can't read it",
                "op 0x5fcc3d14\n48 bytes, 1 cell",
                "Its body is for the contract it goes to: what it asks, maki can't tell."
            )
        );
        let r = shown("encrypted", wallet);
        assert_eq!(r.summary, "maki can't read all of it; plus the network's fee");
        assert_eq!(
            r.pages[1],
            p("Comment", "encrypted", "", "Only the recipient's key opens it: maki can't read it.")
        );
        assert_eq!(shown("multi", wallet).summary, "maki can't read all of it; plus the network's fee");
        let r = shown("nothing", wallet);
        assert_eq!(r.summary, "sends nothing; plus the network's fee");
        assert_eq!(
            r.pages[0],
            p(
                "Nothing",
                "no messages",
                "",
                "It sends nothing: the wallet only counts it, and its seqno moves on."
            )
        );
    }
    // v4R2's plugins: one may take TON from the wallet
    let r = shown("plugin-install", Wallet::V4R2);
    assert_eq!(r.summary, "lets a plugin take its TON!; plus the network's fee");
    assert_eq!(
        r.pages[0],
        p(
            "Plugin!",
            "may take its TON",
            PLUGIN,
            "That contract may take TON from this wallet whenever it asks, until it's removed. It's sent 0.1 TON to say so."
        )
    );
    let r = shown("plugin-deploy", Wallet::V4R2);
    assert_eq!(
        r.summary,
        "lets a plugin take its TON! And maki can't read all of it; plus the network's fee"
    );
    assert_eq!(r.pages[0].mono, "EQA3jCfhaMmZC12CTs5tts9HWC5efqeAnNhnzrWEgHb4BBpl");
    let r = shown("plugin-remove", Wallet::V4R2);
    assert_eq!(r.summary, "removes a plugin, sends 0.05 TON; plus the network's fee");
    assert_eq!((r.pages[0].heading.as_str(), r.pages[0].mono.as_str()), ("Remove plugin", PLUGIN));
    // W5's extensions: one may do anything the key can
    let r = shown("extension-add", Wallet::V5R1);
    assert_eq!(r.summary, "lets another control the wallet!; plus the network's fee");
    assert_eq!(
        r.pages[0],
        p(
            "Extension!",
            "may do anything",
            PLUGIN,
            "That contract may send anything from this wallet, and change who controls it, without its key."
        )
    );
    assert_eq!(
        shown("extension-remove", Wallet::V5R1).summary,
        "removes an extension; plus the network's fee"
    );
    let r = shown("extensions-and-send", Wallet::V5R1);
    let headings: Vec<&str> = r.pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Comment", "Extension!", "Remove extension", "Valid until", "From"]);
    assert_eq!(r.pages[3].mono, "EQBERERERERERERERERERERERERERERERERERERERERERGpg");
}

#[test]
fn what_isnt_this_accounts_or_this_networks_is_refused_and_said_why() {
    for (name, why) in REFUSED {
        let w5 = ["signature-off", "internal", "too-many", "256", "no-ignore-errors"];
        let wallet = if w5.contains(name) { Wallet::V5R1 } else { Wallet::V4R2 };
        assert_eq!(refused(name, wallet), *why, "{name}");
    }
    for wallet in Wallet::ALL {
        for name in ["extra-currency", "workchain-1"] {
            assert_eq!(refused(name, wallet), REFUSED.iter().find(|r| r.0 == name).unwrap().1);
        }
    }
    // the test network's W5 request on TON, and TON's on the test network
    let test = fixture_on("ton", Wallet::V5R1, Network::Test);
    let boc = Boc::parse(&test).unwrap();
    let request = Request::parse(&boc).unwrap();
    assert_eq!(
        review(&request, &me(Network::Main, 0), Network::Main).unwrap_err().to_string(),
        "a request for TON's test network, not TON: its wallet ID says so"
    );
    let main = fixture("ton", Wallet::V5R1);
    let boc = Boc::parse(&main).unwrap();
    let request = Request::parse(&boc).unwrap();
    assert_eq!(
        review(&request, &me(Network::Test, 0), Network::Test).unwrap_err().to_string(),
        "a request for TON, not its test network: its wallet ID says so"
    );
    // v4R2's request is the same on both networks: the key, from another path, is what differs
    let main = fixture("ton", Wallet::V4R2);
    let boc = Boc::parse(&main).unwrap();
    assert!(review(&Request::parse(&boc).unwrap(), &me(Network::Test, 0), Network::Test).is_ok());
}

/// A bag of cells written by hand: each cell its two descriptor bytes, its data and its references
/// (one byte each); the root first; a CRC32C if asked.
fn boc(cells: &[(u8, u8, &[u8], &[u8])], crc: bool) -> Vec<u8> {
    let data: Vec<u8> = cells.iter().flat_map(|(d1, d2, d, r)| [&[*d1, *d2][..], d, r].concat()).collect();
    let mut out = vec![0xb5, 0xee, 0x9c, 0x72, if crc { 0x41 } else { 0x01 }, 2, cells.len() as u8, 1, 0];
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.push(0);
    out.extend(data);
    if crc {
        let c = crc32c(&out);
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

#[test]
fn bags_of_cells_are_read_as_ton_reads_them() {
    let refused = |b: &[u8]| Boc::parse(b).unwrap_err();
    // a cell of 8 bits with one reference to an empty one, and the same without a CRC
    let good = boc(&[(1, 2, &[0xab], &[1]), (0, 0, &[], &[])], true);
    let plain = boc(&[(1, 2, &[0xab], &[1]), (0, 0, &[], &[])], false);
    assert_eq!(Boc::parse(&good).unwrap().hash(), Boc::parse(&plain).unwrap().hash());
    assert_eq!(Boc::parse(&good).unwrap().len(), 2);
    // as @ton/core hashes it
    let mut b = Builder::new();
    b.uint(0xab, 8).reference(Builder::new().finish());
    assert_eq!(Boc::parse(&good).unwrap().hash(), b.finish().0);
    // seven bits: an end mark after them
    let seven = boc(&[(0, 1, &[0b1010_1011], &[])], true);
    let mut b = Builder::new();
    b.uint(0b101_0101, 7);
    assert_eq!(Boc::parse(&seven).unwrap().hash(), b.finish().0);
    // not a bag of cells, or more than maki reads
    assert_eq!(refused(&[]), Error::NotBoc);
    assert_eq!(refused(&[0xb5, 0xee, 0x9c, 0x73, 0]), Error::NotBoc);
    // the old forms, with an index always
    assert_eq!(refused(&[&[0x68, 0xff, 0x65, 0xf3][..], &good[4..]].concat()), Error::NotBoc);
    assert_eq!(refused(&vec![0; MAX_BOC + 1]), Error::TooBig);
    let with = |at: usize, f: &dyn Fn(u8) -> u8| {
        let mut b = plain.clone();
        b[at] = f(b[at]);
        b
    };
    // an index, cache bits, flags that must be 0, a size or offset size TON doesn't have
    assert_eq!(refused(&with(4, &|b| b | 0x80)), Error::Index);
    assert_eq!(refused(&with(4, &|b| b | 0x20)), Error::Index);
    assert_eq!(refused(&with(4, &|b| b | 0x10)), Error::Header);
    assert_eq!(refused(&with(4, &|b| b | 0x08)), Error::Header);
    assert_eq!(refused(&with(4, &|b| b & 0xf8)), Error::Header);
    assert_eq!(refused(&with(4, &|b| b & 0xf8 | 5)), Error::Header);
    assert_eq!(refused(&with(5, &|_| 0)), Error::Header);
    assert_eq!(refused(&with(5, &|_| 9)), Error::Header);
    // two roots, an absent cell, no cells, the root not first or not there
    assert_eq!(refused(&with(7, &|_| 2)), Error::Roots);
    assert_eq!(refused(&with(8, &|_| 1)), Error::Header);
    assert_eq!(refused(&with(6, &|_| 0)), Error::Header);
    assert_eq!(refused(&with(11, &|_| 1)), Error::Unreached);
    assert_eq!(refused(&with(11, &|_| 2)), Error::Header);
    // the data's size not what it is: cut short, more after it
    assert_eq!(refused(&with(10, &|b| b + 1)), Error::Header);
    assert_eq!(refused(&with(10, &|b| b - 1)), Error::Header);
    assert_eq!(refused(&plain[..plain.len() - 1]), Error::Header);
    assert_eq!(refused(&[&plain[..], &[0]].concat()), Error::Header);
    // a CRC that isn't its own
    let mut bad = good.clone();
    bad[13] ^= 1;
    assert_eq!(refused(&bad), Error::Checksum);
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert_eq!(refused(&bad), Error::Checksum);
    // references back, to itself, to a cell that isn't there
    assert_eq!(refused(&boc(&[(1, 0, &[], &[0]), (0, 0, &[], &[])], false)), Error::Order);
    assert_eq!(refused(&boc(&[(1, 0, &[], &[2]), (0, 0, &[], &[])], false)), Error::Order);
    assert_eq!(refused(&boc(&[(1, 0, &[], &[2]), (1, 0, &[], &[1]), (0, 0, &[], &[])], false)), Error::Order);
    // a cell nothing refers to
    assert_eq!(
        refused(&boc(&[(1, 0, &[], &[2]), (0, 0, &[], &[]), (0, 0, &[], &[])], false)),
        Error::Unreached
    );
    // five references, an absent cell, its hashes stored with it, a level, data with no end mark
    // (or one with no data before it)
    assert_eq!(refused(&boc(&[(5, 0, &[], &[1, 1, 1, 1, 1]), (0, 0, &[], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(7, 0, &[], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(0x10, 0, &[], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(0x20, 0, &[], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(0, 1, &[0x00], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(0, 1, &[0x80], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(0, 3, &[0xff, 0x80], &[])], false)), Error::Encoding);
    // pruned branches and Merkle proofs: cells standing for others maki can't see
    let pruned = [&[1u8, 1][..], &[0; 32], &[0, 0]].concat();
    assert_eq!(refused(&boc(&[(0x28, 72, &pruned, &[])], false)), Error::Special);
    let proof = [&[3u8][..], &[0; 32], &[0, 0]].concat();
    assert_eq!(refused(&boc(&[(9, 70, &proof, &[1]), (0, 0, &[], &[])], false)), Error::Special);
    // an exotic cell of no kind TON has, or too short to say its kind
    assert_eq!(refused(&boc(&[(8, 2, &[9], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(8, 1, &[0x18], &[])], false)), Error::Encoding);
    // a library cell: its hash, as @ton/core's; but not where data should be
    let library = [&[2u8][..], &[0x11; 32]].concat();
    let lib = boc(&[(8, 66, &library, &[])], false);
    let parsed = Boc::parse(&lib).unwrap();
    assert_eq!(parsed.hash(), Builder::library(&[0x11; 32]).finish().0);
    assert!(parsed.root_cell().is_library());
    assert_eq!(
        Request::parse(&parsed).unwrap_err().to_string(),
        "a library cell where data should be: maki can't see what it stands for"
    );
    // a library cell with references, or the wrong size
    assert_eq!(refused(&boc(&[(9, 66, &library, &[1]), (0, 0, &[], &[])], false)), Error::Encoding);
    assert_eq!(refused(&boc(&[(8, 64, &library[..32], &[])], false)), Error::Encoding);
    // cells as deep as a BOC maki reads holds: a chain of 1000, each referring to the next
    let mut deep = vec![0xb5, 0xee, 0x9c, 0x72, 0x02, 2];
    let n = 1000u16;
    let size = (n as usize - 1) * 4 + 2;
    for v in [n, 1, 0] {
        deep.extend_from_slice(&v.to_be_bytes());
    }
    deep.extend_from_slice(&(size as u16).to_be_bytes());
    deep.extend_from_slice(&0u16.to_be_bytes());
    for i in 1..n {
        deep.extend_from_slice(&[1, 0]);
        deep.extend_from_slice(&i.to_be_bytes());
    }
    deep.extend_from_slice(&[0, 0]);
    let parsed = Boc::parse(&deep).unwrap();
    assert_eq!((parsed.len(), parsed.root_cell().depth()), (1000, 999));
    // and none of it a request: refused, not misread
    assert_eq!(Request::parse(&Boc::parse(&good).unwrap()).unwrap_err(), Error::Short);
}

#[test]
fn requests_are_read_as_the_wallets_read_them() {
    // v4R2's: subwallet, valid until, seqno, op 0, then a mode for each message
    let bytes = fixture("modes", Wallet::V4R2);
    let boc = Boc::parse(&bytes).unwrap();
    let request = Request::parse(&boc).unwrap();
    let modes: Vec<u8> = request
        .actions
        .iter()
        .map(|a| match a {
            Action::Send { mode, .. } => *mode,
            _ => panic!("{a:?}"),
        })
        .collect();
    assert_eq!(modes, [0, 1, 2, 3]);
    // W5's: messages in the order they're sent, every one with +2
    let bytes = fixture("multi", Wallet::V5R1);
    let boc = Boc::parse(&bytes).unwrap();
    let request = Request::parse(&boc).unwrap();
    assert_eq!(request.actions.len(), 7);
    assert!(request.actions.iter().all(|a| matches!(a, Action::Send { mode: 3, .. })));
    let bytes = fixture("extensions-and-send", Wallet::V5R1);
    let boc = Boc::parse(&bytes).unwrap();
    let request = Request::parse(&boc).unwrap();
    let plugin = Address::parse(PLUGIN).unwrap().address;
    let stranger = Address::parse(STRANGER).unwrap().address;
    assert!(
        matches!(request.actions[..], [Action::Send { .. }, Action::AddExtension(a), Action::RemoveExtension(b)] if a == plugin && b == stranger)
    );
}

/// A cell written by hand, for what TON's libraries won't make: its bits and its references.
#[derive(Clone, Default)]
struct C {
    bits: Vec<bool>,
    refs: Vec<C>,
}

impl C {
    fn uint(mut self, v: u64, n: usize) -> C {
        self.bits.extend((0..n).rev().map(|i| v >> i & 1 != 0));
        self
    }

    fn bit(self, b: bool) -> C { self.uint(b as u64, 1) }

    fn bytes(self, b: &[u8]) -> C { b.iter().fold(self, |c, &x| c.uint(x as u64, 8)) }

    /// Coins, in as few bytes as they take.
    fn coins(self, v: u128) -> C {
        let n = (128 - v.leading_zeros() as usize).div_ceil(8);
        let c = self.uint(n as u64, 4);
        (0..n).rev().fold(c, |c, i| c.uint((v >> (8 * i)) as u64 & 0xff, 8))
    }

    fn addr(self, a: Address) -> C { self.uint(0b100, 3).uint(a.workchain as u8 as u64, 8).bytes(&a.hash) }

    fn none(self) -> C { self.uint(0, 2) }

    fn r(mut self, c: C) -> C {
        self.refs.push(c);
        self
    }

    /// The cells under it, the root first, each before those it refers to.
    fn order<'a>(&'a self, out: &mut Vec<&'a C>) {
        out.push(self);
        for r in &self.refs {
            r.order(out);
        }
    }

    /// In a bag of cells, without a CRC: one-byte references, two-byte sizes.
    fn boc(&self) -> Vec<u8> {
        let mut cells = Vec::new();
        self.order(&mut cells);
        let index = |c: &C| cells.iter().position(|x| std::ptr::eq(*x, c)).unwrap() as u8;
        let mut data = Vec::new();
        for c in &cells {
            let n = c.bits.len();
            data.push(c.refs.len() as u8);
            data.push((n / 8 * 2 + usize::from(n % 8 != 0)) as u8);
            let mut bits = c.bits.clone();
            if n % 8 != 0 {
                bits.push(true);
                while bits.len() % 8 != 0 {
                    bits.push(false);
                }
            }
            data.extend(bits.chunks(8).map(|b| b.iter().fold(0u8, |v, &x| v << 1 | x as u8)));
            data.extend(c.refs.iter().map(index));
        }
        let mut out = vec![0xb5, 0xee, 0x9c, 0x72, 0x01, 2, cells.len() as u8, 1, 0];
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.push(0);
        out.extend(data);
        out
    }
}

fn recipient() -> Address { Address::parse(RECIPIENT).unwrap().address }

/// An internal message's head as wallets write it, to `dest`, with `value` (bounceable), then no
/// first state and the body in the cell.
fn message(dest: Address, value: u128) -> C {
    C::default()
        .uint(0b0110, 4)
        .none()
        .addr(dest)
        .coins(value)
        .bit(false)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
}

/// A v4R2 request for these messages, each with its mode.
fn v4(messages: Vec<(u8, C)>) -> C {
    let c = C::default().uint(V4R2_SUBWALLET as u64, 32).uint(1_798_761_600, 32).uint(7, 32).uint(0, 8);
    messages.into_iter().fold(c, |c, (mode, m)| c.uint(mode as u64, 8).r(m))
}

/// A W5 request for these messages, each with its mode, then `rest` (whether other actions follow,
/// and them).
fn w5(messages: Vec<(u8, C)>, rest: C) -> C {
    let c = C::default().uint(0x7369_676e, 32).uint(2_147_483_409, 32).uint(1_798_761_600, 32).uint(7, 32);
    let c = if messages.is_empty() {
        c.bit(false)
    } else {
        let list = messages.into_iter().fold(C::default(), |prev, (mode, m)| {
            C::default().r(prev).uint(0x0ec3_c86d, 32).uint(mode as u64, 8).r(m)
        });
        c.bit(true).r(list)
    };
    C { bits: [c.bits, rest.bits].concat(), refs: [c.refs, rest.refs].concat() }
}

/// What maki says of a request written by hand: its summary, or why it's refused.
fn says(c: &C) -> String {
    let bytes = c.boc();
    let boc = Boc::parse(&bytes).unwrap();
    match Request::parse(&boc) {
        Ok(r) => match review(&r, &me(Network::Main, 0), Network::Main) {
            Ok(r) => r.summary,
            Err(e) => e.to_string(),
        },
        Err(e) => e.to_string(),
    }
}

#[test]
fn messages_not_as_wallets_write_them_are_refused() {
    let plain = || message(recipient(), 1_000_000_000).bit(false).bit(false);
    // as written by hand, it's as @ton/core writes it: shown
    assert_eq!(says(&v4(vec![(3, plain())])), "sends 1 TON; plus the network's fee");
    assert_eq!(says(&w5(vec![(3, plain())], C::default().bit(false))), "sends 1 TON; plus the network's fee");
    let head = |bits: u64| {
        C::default()
            .uint(bits, 4)
            .none()
            .addr(recipient())
            .coins(1)
            .bit(false)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
    };
    let refused = |m: C| says(&v4(vec![(3, m)]));
    // the fields TON fills in or ignores: not as wallets write them
    let not = "a message not as wallets write it";
    assert_eq!(refused(head(0b0010).bit(false).bit(false)), not, "IHR not disabled");
    assert_eq!(refused(head(0b0111).bit(false).bit(false)), not, "bounced");
    let with = |extra: u128, fee: u128, lt: u64, at: u64| {
        C::default()
            .uint(0b0110, 4)
            .none()
            .addr(recipient())
            .coins(1)
            .bit(false)
            .coins(extra)
            .coins(fee)
            .uint(lt, 64)
            .uint(at, 32)
            .bit(false)
            .bit(false)
    };
    assert_eq!(refused(with(1, 0, 0, 0)), not);
    assert_eq!(refused(with(0, 1, 0, 0)), not);
    assert_eq!(refused(with(0, 0, 1, 0)), not);
    assert_eq!(refused(with(0, 0, 0, 1)), not);
    assert_eq!(refused(with(4, 0, 0, 0)), "a message with flags TON doesn't know: it would refuse it");
    // a sender named, no address, one outside TON, an anycast one, the variable form
    let src = C::default()
        .uint(0b0110, 4)
        .addr(recipient())
        .addr(recipient())
        .coins(1)
        .bit(false)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(0, 32)
        .bit(false)
        .bit(false);
    assert_eq!(refused(src), "a message that names who sends it: wallets leave that to TON");
    let to = |a: C| C {
        bits: [
            C::default().uint(0b0110, 4).none().bits,
            a.bits,
            C::default()
                .coins(1)
                .bit(false)
                .coins(0)
                .coins(0)
                .uint(0, 64)
                .uint(0, 32)
                .bit(false)
                .bit(false)
                .bits,
        ]
        .concat(),
        refs: vec![],
    };
    assert_eq!(refused(to(C::default().none())), "a message to no address: TON would refuse it");
    assert_eq!(
        refused(to(C::default().uint(0b01, 2).uint(8, 9).uint(0xff, 8))),
        "an address outside TON, where an account's should be"
    );
    assert_eq!(
        refused(to(C::default().uint(0b101, 3).uint(1, 5).bit(true).uint(0, 8).bytes(&[1; 32]))),
        "an anycast address, which TON refuses"
    );
    assert_eq!(
        refused(to(C::default().uint(0b110, 3).uint(256, 9).uint(0, 32).bytes(&[1; 32]))),
        "an address in a form wallets don't write (addr_var)"
    );
    // an external message out, not an internal one
    let out = C::default().uint(0b11, 2).none().none().uint(0, 64).uint(0, 32).bit(false).bit(false);
    assert_eq!(refused(out), "a message out of TON, to no account: wallets don't send those");
    // a body in a reference, and more after it
    let body = message(recipient(), 1).bit(false).bit(true).bit(true).r(C::default());
    assert_eq!(refused(body), "not as TON writes it: more in a cell after what it holds");
    // a contract's first state: one not for the address it goes to, with what wallets don't deploy
    let code = C::default().uint(0xdead, 16);
    let init = |bits: u64, refs: Vec<C>| C { bits: C::default().uint(bits, 5).bits, refs };
    let deploy = |dest: Address, i: C| {
        let m = message(dest, 1).bit(true).bit(true);
        C { bits: [m.bits, vec![false]].concat(), refs: vec![i] }
    };
    let state = Builder::new()
        .uint(0b00110, 5)
        .reference((code_hash(&code), 0))
        .reference((code_hash(&C::default()), 0))
        .finish()
        .0;
    let there = Address { workchain: 0, hash: state };
    assert_eq!(
        says(&v4(vec![(3, deploy(there, init(0b00110, vec![code.clone(), C::default()])))])),
        "maki can't read all of it; plus the network's fee"
    );
    assert_eq!(
        refused(deploy(recipient(), init(0b00110, vec![code.clone(), C::default()]))),
        "a contract's first state that isn't for the address it's sent to"
    );
    for bits in [0b10110, 0b01110, 0b00111] {
        assert_eq!(
            refused(deploy(there, init(bits, vec![code.clone(), C::default(), C::default()]))),
            "a contract's first state with what wallets don't deploy: a fixed prefix, tick-tock, or libraries"
        );
    }
    assert_eq!(
        refused(deploy(there, init(0b00100, vec![code.clone()]))),
        "a contract's first state without its code or its data"
    );
    // a comment not in whole bytes, or branching
    assert_eq!(
        refused(message(recipient(), 1).bit(false).bit(false).uint(0, 32).uint(1, 7)),
        "a comment not as TON writes text: not whole bytes, or branching"
    );
    assert_eq!(
        refused(
            message(recipient(), 1)
                .bit(false)
                .bit(false)
                .uint(0, 32)
                .bytes(b"a")
                .r(C::default())
                .r(C::default())
        ),
        "a comment not as TON writes text: not whole bytes, or branching"
    );
    // a body too short for an op: something maki can't read
    assert_eq!(
        says(&v4(vec![(3, message(recipient(), 1).bit(false).bit(false).uint(5, 8))])),
        "maki can't read all of it; plus the network's fee"
    );
}

/// A cell's hash, as maki works it out.
fn code_hash(c: &C) -> [u8; 32] {
    let bytes = c.boc();
    Boc::parse(&bytes).unwrap().hash()
}

#[test]
fn jetton_transfers_their_wallets_would_refuse_are_refused() {
    let key = me(Network::Main, 0);
    let mine = Wallet::V4R2.address(&key, Network::Main);
    let usdt = jettons::USDT.wallet(&mine);
    let transfer = |to: C, response: C, forward: C| {
        let body = C::default().uint(0x0f8a_7ea5, 32).uint(0, 64).coins(5_250_000);
        let body = C { bits: [body.bits, to.bits, response.bits].concat(), refs: vec![] }.bit(false).coins(0);
        let body = C { bits: [body.bits, forward.bits].concat(), refs: forward.refs };
        let m = message(usdt, 50_000_000).bit(false).bit(true).r(body);
        says(&v4(vec![(3, m)]))
    };
    let them = C::default().addr(recipient());
    let back = C::default().addr(mine);
    assert_eq!(
        transfer(them.clone(), back.clone(), C::default().bit(false)),
        "sends 5.25 USDT, 0.05 TON; plus the network's fee"
    );
    // to no one, to the masterchain, what's left to a workchain TON doesn't have
    assert_eq!(
        transfer(C::default().none(), back.clone(), C::default().bit(false)),
        "a jetton transfer to no one: the jetton's wallet would refuse it"
    );
    let master = C::default().addr(Address { workchain: -1, hash: [3; 32] });
    assert_eq!(
        transfer(master, back.clone(), C::default().bit(false)),
        "jettons to an account off the basechain: the jetton's wallet would refuse it"
    );
    let nowhere = C::default().addr(Address { workchain: 5, hash: [3; 32] });
    assert_eq!(
        transfer(them.clone(), nowhere, C::default().bit(false)),
        "what's left of a jetton transfer to a workchain TON doesn't have"
    );
    // a forward payload in a reference, and more after it (USDT's wallet checks there's nothing)
    let more = C::default().bit(true).uint(1, 1).r(C::default());
    assert_eq!(
        transfer(them.clone(), back.clone(), more),
        "not as TON writes it: more in a cell after what it holds"
    );
    // no forward payload at all: its Either bit missing
    assert_eq!(transfer(them, back, C::default()), "not as TON writes it: a cell ends too soon");
}

#[test]
fn wallet_requests_not_as_the_wallets_take_them_are_refused() {
    let m = || message(recipient(), 1).bit(false).bit(false);
    let refused = |c: C| says(&c);
    // W5: an action other than sending (setting its code), a list's cell with more in it
    let set_code = C::default()
        .uint(0x7369_676e, 32)
        .uint(2_147_483_409, 32)
        .uint(1_798_761_600, 32)
        .uint(7, 32)
        .bit(true);
    let list = C::default().r(C::default()).uint(0xad4d_e08e, 32).r(C::default());
    assert_eq!(
        refused(set_code.clone().r(list).bit(false)),
        "an action W5 refuses: it sends messages, nothing else"
    );
    let list = C::default().r(C::default()).uint(0x0ec3_c86d, 32).uint(3, 8).r(m()).bit(true);
    assert_eq!(
        refused(set_code.r(list).bit(false)),
        "not as TON writes it: more in a cell after what it holds"
    );
    // W5's other actions: one it doesn't have, one at no address, one on the masterchain, one with
    // more after it, two in a row as @ton/ton writes them
    let other = |actions: C| w5(vec![], C { bits: [vec![true], actions.bits].concat(), refs: actions.refs });
    assert_eq!(refused(other(C::default().uint(9, 8))), "an action W5 doesn't have: it would refuse it");
    assert_eq!(
        refused(other(C::default().uint(2, 8).none())),
        "an extension at no address: W5 would refuse it"
    );
    let master = Address { workchain: -1, hash: [5; 32] };
    assert_eq!(
        refused(other(C::default().uint(2, 8).addr(master))),
        "an extension on another workchain: W5 would refuse it"
    );
    let plugin = Address::parse(PLUGIN).unwrap().address;
    assert_eq!(
        refused(other(C::default().uint(2, 8).addr(plugin).bit(false))),
        "not as TON writes it: more in a cell after what it holds"
    );
    let next = C::default().uint(3, 8).addr(recipient());
    assert_eq!(
        refused(other(C::default().uint(2, 8).addr(plugin).r(next))),
        "lets another control the wallet!; plus the network's fee"
    );
    // and nothing after its last bit
    assert_eq!(
        refused(w5(vec![(3, m())], C::default().bit(false).bit(false))),
        "not as TON writes it: more in a cell after what it holds"
    );
    // v4R2: a message without its mode, a plugin on a workchain TON doesn't have, its first state
    // with more in it
    let no_mode =
        C::default().uint(V4R2_SUBWALLET as u64, 32).uint(1_798_761_600, 32).uint(7, 32).uint(0, 8).r(m());
    assert_eq!(refused(no_mode), "not as TON writes it: a cell ends too soon");
    let plugin_on = |wc: i8| {
        C::default()
            .uint(V4R2_SUBWALLET as u64, 32)
            .uint(1_798_761_600, 32)
            .uint(7, 32)
            .uint(2, 8)
            .uint(wc as u8 as u64, 8)
            .bytes(&[5; 32])
            .coins(1)
            .uint(0, 64)
    };
    assert_eq!(refused(plugin_on(0)), "lets a plugin take its TON!; plus the network's fee");
    assert_eq!(refused(plugin_on(7)), "an address on a workchain TON doesn't have");
    let deploy = C::default()
        .uint(V4R2_SUBWALLET as u64, 32)
        .uint(1_798_761_600, 32)
        .uint(7, 32)
        .uint(1, 8)
        .uint(0, 8)
        .coins(1);
    let state = C::default().uint(0b00110, 5).r(C::default().uint(1, 8)).r(C::default());
    assert_eq!(
        refused(deploy.clone().r(state.clone()).r(C::default())),
        "lets a plugin take its TON! And maki can't read all of it; plus the network's fee"
    );
    assert_eq!(
        refused(deploy.r(state.bit(true)).r(C::default())),
        "not as TON writes it: more in a cell after what it holds"
    );
    // what an extension asks, which no key signs
    assert_eq!(
        refused(C::default().uint(0x6578_746e, 32).uint(0, 64)),
        "an extension's request, which no key signs"
    );
}
