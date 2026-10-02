//! maki-near against NEAR's own library: transactions near-api-js made (`fixtures/make.mjs`), read
//! as they are and shown as they should be, and signed by maki's keys as near-api-js signs them with
//! the same account (the test phrase's, at `m/44'/397'/0'`, as MyNearWallet and near-cli have it).
//! What near-api-js wouldn't make, written by hand and refused as nearcore refuses it; the fee held
//! to what NEAR's own network burnt.

use maki_hd::seed::SeedKeys;
use maki_near::display::{self, Error, Page, Review, review};
use maki_near::tx::{self, Action, Code, Permission, PublicKey, Transaction};
use maki_near::{Network, account, account_id, base58, fees, hash, json, path, public_key, tokens};

/// The test phrase's account, as near-seed-phrase (MyNearWallet's, near-api-js's) makes it.
const ME: &str = "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412";
const ME_KEY: &str = "ed25519:6j4b6zUaty6fD1awqcGCCU9JYGCWYUgdJhQrzfZhqE25";
/// Keys the fixtures add, delete and stake with: Ed25519's of 32 twos, threes, fours and fives.
const KEY_2: &str = "ed25519:9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu";
const KEY_3: &str = "ed25519:GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse";
const KEY_4: &str = "ed25519:EdmxWPmx2WH6WgFfTdu9xfkYf3k1g5wD1zccTVySEEh1";
const KEY_5: &str = "ed25519:8SFqwqnq4whPhs8icwHA2hQg3hUoN1qrCLK1SBx3WKwe";
/// The implicit account of Ed25519's key of 32 ones.
const IMPLICIT: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const ETH: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
const USDC: &str = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
const TESTNET_USDC: &str = "3e2210e1184b45b64c8a434c0a7e7b23cc04ea7eb7a6c3c32520d03d4afcb8af";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn me() -> [u8; 32] { unhex(ME).try_into().unwrap() }

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

struct Fixture {
    name: String,
    network: Network,
    bytes: Vec<u8>,
    /// Its hash in base58, as near-api-js gives it: the transaction's ID.
    hash: String,
    /// near-api-js's signature for this account, if it's this account's, and the signed
    /// transaction it made of it.
    signature: Option<Vec<u8>>,
    signed: Option<Vec<u8>>,
}

/// The transactions near-api-js made.
fn fixtures() -> Vec<Fixture> {
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: if f["network"] == "testnet" { Network::Testnet } else { Network::Mainnet },
            bytes: unhex(f["transaction"].as_str().unwrap()),
            hash: f["hash"].as_str().unwrap().into(),
            signature: f["signature"].as_str().map(unhex),
            signed: f["signed"].as_str().map(unhex),
        })
        .collect()
}

fn fixture(name: &str) -> Vec<u8> { fixtures().into_iter().find(|f| f.name == name).unwrap().bytes }

fn parsed(name: &str) -> Transaction { Transaction::parse(&fixture(name)).unwrap() }

fn shown_on(name: &str, network: Network) -> Review { review(&parsed(name), &me(), network).unwrap() }

fn shown(name: &str) -> Review { shown_on(name, Network::Mainnet) }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "NEAR", "", "") }

fn keys() -> SeedKeys {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    SeedKeys::from_seed(&seed).unwrap()
}

/// The fee page for gas `g` (as nearcore charges it) at NEAR's highest price, and what it is at
/// its lowest.
fn fee(max: &str, gas: &str, low: &str, rest: &str) -> Page {
    p(
        "Max fee",
        max,
        "",
        &format!(
            "For up to {gas} Tgas of gas, at the most NEAR's gas price can be: 0.002 NEAR a Tgas. It's usually at its lowest, 0.0001 NEAR a Tgas: {low} NEAR.{rest}"
        ),
    )
}

const BACK: &str = " Gas a call doesn't use comes back.";
const YOCTO: &str = "To the contract, with the call: the least there is, which contracts ask for to know the account's own key signed.";
const CALL: &str = "maki can't tell what it does: that's the contract's to decide, with what it's given. It can't act as this account anywhere else.";

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
fn accounts_as_near_wallets_make_them() {
    let keys = keys();
    // the test phrase's accounts, as near-api-js and near-seed-phrase make them
    let accounts = json()["accounts"].as_array().unwrap().clone();
    assert_eq!(accounts.len(), 3);
    for (i, a) in accounts.iter().enumerate() {
        let key = keys.ed25519_public(&path(i as u32)).unwrap();
        assert_eq!(maki_hd::format_path(&path(i as u32)), a["path"].as_str().unwrap());
        assert_eq!(account_id(&key), a["account_id"].as_str().unwrap(), "account {i}");
        assert_eq!(public_key(&key), a["public_key"].as_str().unwrap(), "account {i}");
    }
    assert_eq!(account_id(&me()), ME);
    assert_eq!(public_key(&me()), ME_KEY);
    // Trust Wallet's wallet-core publishes another phrase's key at the same path (HDWalletTests)
    let seed = maki_seed::seed(
        &"owner erupt swamp room swift final allow unaware hint identify figure cotton"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    let published = SeedKeys::from_seed(&seed).unwrap().ed25519_public(&path(0)).unwrap();
    assert_eq!(account_id(&published), "b8d5df25047841365008f30fb6b30dd820e9a84d869f05623d114e96831f2fbf");
    // base58 as NEAR writes keys and hashes
    assert_eq!(base58::encode(&[0, 0, 1]), "112");
    assert_eq!(base58::encode(&[]), "");
    assert_eq!(base58::encode(&[0; 32]), "11111111111111111111111111111111");
}

#[test]
fn account_names_as_nearcore_takes_them() {
    // near-account-id's own lists of names it takes and names it doesn't
    let good = [
        "aa",
        "a-a",
        "a-aa",
        "100",
        "0o",
        "com",
        "near",
        "bowen",
        "b-o_w_e-n",
        "b.owen",
        "bro.wen",
        "a.ha",
        "a.b-a.ra",
        "system",
        "over.9000",
        "google.com",
        "illia.cheapaccounts.near",
        "0o0ooo00oo00o",
        "alex-skidanov",
        "10-4.8-2",
        "b-o_w_e-n",
        "no_lols",
        "0123456789012345678901234567890123456789012345678901234567890123",
        "near.a",
    ];
    let bad = [
        "a",
        "A",
        "Abc",
        "-near",
        "near-",
        "-near-",
        "near.",
        ".near",
        "near@",
        "@near",
        "неар",
        "@@@@@",
        "0__0",
        "0_-_0",
        "0_-_0",
        "..",
        "a..near",
        "nEar",
        "_bowen",
        "hello world",
        "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
        "01234567890123456789012345678901234567890123456789012345678901234",
        "some-complex-address@gmail.com",
        "sub.buy_d1gitz@atata@b0-rg.c_0_m",
    ];
    for id in good {
        assert!(account::valid(id), "{id}");
    }
    for id in bad {
        assert!(!account::valid(id), "{id}");
    }
    use account::Kind;
    assert_eq!(account::kind(ME), Kind::Implicit);
    assert_eq!(account::kind(&ME.to_uppercase()), Kind::Named, "not a name at all");
    assert_eq!(account::kind(&ME[1..]), Kind::Named);
    assert_eq!(account::kind(ETH), Kind::Ethereum);
    assert_eq!(account::kind("0s5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), Kind::Code);
    // a universal account: 52 digits of base32, the last with four bits of nothing (0 or g)
    let universal = |last: char| format!("0u0123456789abcdefghjkmnpqrstvwxyz0123456789abcdefghj{last}");
    assert_eq!(account::kind(&universal('0')), Kind::Code);
    assert_eq!(account::kind(&universal('g')), Kind::Code);
    assert_eq!(account::kind(&universal('1')), Kind::Named);
    assert_eq!(account::kind(&universal('i')), Kind::Named, "not Crockford's");
    assert_eq!(account::kind("bob.near"), Kind::Named);
    assert!(account::is_sub_account_of("alice.near", "near"));
    assert!(account::is_sub_account_of("a.alice.near", "alice.near"));
    assert!(!account::is_sub_account_of("near", "near"));
    assert!(!account::is_sub_account_of("xnear", "near"));
    assert!(!account::is_sub_account_of(".near", "near"));
    assert!(account::is_testnet("bob.testnet") && account::is_testnet("testnet"));
    assert!(!account::is_testnet("mytestnet") && !account::is_testnet("bob.near"));
    // every token maki knows, by a name NEAR takes, on one network
    for t in tokens::TOKENS {
        assert!(account::valid(t.contract), "{}", t.contract);
        assert_eq!(tokens::network_of(t.contract), Some(t.network));
    }
    let usdc = tokens::known(Network::Mainnet, USDC).unwrap();
    assert_eq!((usdc.symbol, usdc.decimals), ("USDC", 6));
    assert!(tokens::known(Network::Testnet, USDC).is_none(), "mainnet's USDC isn't testnet's");
}

#[test]
fn amounts_gas_and_hashes() {
    assert_eq!(display::decimals(0, 24), "0");
    assert_eq!(display::decimals(1, 6), "0.000001");
    assert_eq!(display::decimals(1_500_000, 6), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::near(1), "0.000000000000000000000001 NEAR");
    assert_eq!(display::near(1_500_000_000_000_000_000_000_000), "1.5 NEAR");
    assert_eq!(display::near(u128::MAX), "340282366920938.463463374607431768211455 NEAR");
    assert_eq!(display::tgas(30_000_000_000_000), "30 Tgas");
    assert_eq!(display::tgas(446_365_125_000), "0.446365125 Tgas");
    // what's signed is the transaction's hash, which near-api-js gives as its ID
    for f in fixtures() {
        assert_eq!(base58::encode(&hash(&f.bytes)), f.hash, "{}", f.name);
    }
}

#[test]
fn maki_signs_what_near_api_js_signs() {
    let keys = keys();
    let mut signed = 0;
    for f in fixtures() {
        let Some(expected) = f.signature else { continue };
        let signature = keys.sign_ed25519(&path(0), &hash(&f.bytes)).unwrap();
        assert_eq!(signature.to_vec(), expected, "{}", f.name);
        // and the signed transaction NEAR's nodes take: the transaction, Ed25519's kind, the signature
        assert_eq!([&f.bytes[..], &[0], &signature].concat(), f.signed.unwrap(), "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 39);
}

#[test]
fn every_transaction_near_api_js_made_reads_as_it_should() {
    for f in fixtures() {
        let result = Transaction::parse(&f.bytes)
            .map_err(|e| e.to_string())
            .and_then(|tx| review(&tx, &me(), f.network).map_err(|e| e.to_string()));
        match f.name.as_str() {
            "not-mine" => {
                assert_eq!(result, Err(String::from("another account's transaction, not this one's to sign")))
            }
            "create-account" => assert_eq!(
                result,
                Err(String::from(
                    "it makes an account, which only that account's parent can: NEAR would refuse it"
                ))
            ),
            "delegate" => assert_eq!(
                result,
                Err(String::from(
                    "a Delegate action (a meta transaction, for another account): maki doesn't sign those"
                ))
            ),
            name => fits_the_screen(&result.unwrap_or_else(|e| panic!("{name}: {e}"))),
        }
    }
}

#[test]
fn near_sent() {
    let r = shown("transfer");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "1.5 NEAR", "bob.near", ""),
            fee("0.00089273025 NEAR", "0.446365125", "0.0000446365125", "")
        ]
    );
    assert_eq!(r.summary, "sends 1.5 NEAR; fee up to 0.00089273025 NEAR");
    let tx = parsed("transfer");
    assert_eq!(
        (tx.signer.as_str(), tx.receiver.as_str(), tx.nonce, tx.key.to_string()),
        (ME, "bob.near", 218_152_378_000_001, String::from(ME_KEY))
    );
    assert_eq!(base58::encode(&tx.block_hash), "Cf8GRmjFKSM3jnE7BPENs5LNQdhhMbpmJWTaEzg6gfCw");
    assert_eq!(tx.actions, [Action::Transfer { deposit: 1_500_000_000_000_000_000_000_000 }]);
    // to an account sending makes: it costs what making one does, and more if it's new
    let made = " If the account it's sent to is new, making it costs 0.00628 NEAR more.";
    let r = shown("transfer-implicit");
    assert_eq!(
        r.pages[1..],
        [
            p(
                "Send",
                "0.1 NEAR",
                IMPLICIT,
                "To an account named by its key: if it's new, sending makes it, held by that key."
            ),
            fee("0.01669979075 NEAR", "8.349895375", "0.0008349895375", made)
        ]
    );
    let r = shown("transfer-eth");
    assert_eq!(
        r.pages[1..],
        [
            p(
                "Send",
                "0.25 NEAR",
                ETH,
                "To an Ethereum address's account: if it's new, sending makes it, held by that address's key."
            ),
            fee("0.01629273025 NEAR", "8.146365125", "0.0008146365125", made)
        ]
    );
    // to itself, an implicit account: NEAR charges as it does any sent to one
    let r = shown("transfer-self");
    assert_eq!(
        r.pages[1..],
        [
            p("Send", "1 NEAR", "this account", "To this account itself: only the fee is spent."),
            fee("0.01669979075 NEAR", "8.349895375", "0.0008349895375", "")
        ]
    );
    assert_eq!(
        shown("transfer-yocto").pages[1],
        p("Send", "0.000000000000000000000001 NEAR", "bob.near", "")
    );
    let r = shown("batch");
    assert_eq!(
        r.pages[1..],
        [
            p("Send", "1 NEAR", "bob.near", ""),
            p("Contract call", "maki can't read it", "bob.near\nmethod hello", CALL),
            p("Arguments", "in JSON", "{\"name\":\"maki\"}", ""),
            fee("0.02285472703596 NEAR", "11.42736351798", "0.001142736351798", BACK)
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.02285472703596 NEAR");
    let r = shown("nothing");
    assert_eq!(r.pages[1], p("Nothing", "no actions", "", "It does nothing but pay the fee."));
    assert_eq!(r.summary, "does nothing; fee up to 0.000432238 NEAR");
}

#[test]
fn tokens_sent_and_registered() {
    let usdc = "With 1 yoctoNEAR to USDC's contract, as NEAR's token transfers need.";
    let r = shown("usdc");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "5.25 USDC", "bob.near", usdc),
            fee("0.062397829000688 NEAR", "31.198914500344", "0.0031198914500344", BACK)
        ]
    );
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.062397829000688 NEAR");
    let r = shown("usdt-memo");
    assert_eq!(
        r.pages[1..3],
        [
            p(
                "Send",
                "10 USDT",
                "bob.near",
                "With 1 yoctoNEAR to USDT's contract, as NEAR's token transfers need."
            ),
            p("Memo", "", "invoice 42", "Everyone can read it, on chain.")
        ]
    );
    // to a contract, which is called with them
    let r = shown("usdc-call");
    assert_eq!(
        r.pages[1],
        p(
            "Send",
            "100 USDC",
            "v2.ref-finance.near",
            &format!(
                "Then the token's contract calls that account's contract, which decides what's done with them, and may send some back. {usdc}"
            )
        )
    );
    assert_eq!(r.summary, "sends 100 USDC; fee up to 0.102400524661734 NEAR");
    // 24 decimals; a bridged token, to an implicit account
    assert_eq!(shown("wnear").pages[1].value, "2 wNEAR");
    assert_eq!(shown("usdc-bridged").pages[1].value, "1 USDC.e");
    assert_eq!(shown("usdc-bridged").pages[1].mono, IMPLICIT);
    // storage paid for another account, and for this one
    let storage = "So bob.near can hold USDC: its contract keeps the NEAR for that account's storage, and gives it back when the account leaves. Anything more than registering takes comes back.";
    let r = shown("storage-deposit");
    assert_eq!(r.pages[1], p("Storage deposit", "0.00125 NEAR", USDC, storage));
    assert_eq!(r.summary, "deposits 0.00125 NEAR for storage; fee up to 0.06239872755437 NEAR");
    assert_eq!(
        shown("storage-deposit-self").pages[1],
        p(
            "Storage deposit",
            "0.00125 NEAR",
            "usdt.tether-token.near",
            "So this account can hold USDT: its contract keeps the NEAR for that account's storage, and gives it back when the account leaves."
        )
    );
    let r = shown("usdc-register-and-send");
    assert_eq!(
        r.pages[1..3],
        [p("Storage deposit", "0.00125 NEAR", USDC, storage), p("Send", "5.25 USDC", "bob.near", usdc)]
    );
    assert_eq!(
        r.summary,
        "deposits 0.00125 NEAR for storage, sends 5.25 USDC; fee up to 0.124364318555058 NEAR"
    );
    // a token maki doesn't know
    let r = shown("unknown-token");
    assert_eq!(
        r.pages[1..4],
        [
            p(
                "Send",
                "42 units",
                "bob.near",
                "Of a token maki doesn't know, if that's what the contract is: maki can't tell what it does."
            ),
            p(
                "Token",
                "one maki doesn't know",
                "token.example.near",
                "Check its contract's account: maki can't tell what the contract does."
            ),
            p("Send", "0.000000000000000000000001 NEAR", "token.example.near", YOCTO)
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.062397329804198 NEAR");
}

#[test]
fn calls_maki_cant_read_are_flagged() {
    let r = shown("call");
    assert_eq!(
        r.pages[1],
        p("Contract call", "maki can't read it", "v2.ref-finance.near\nmethod swap", CALL)
    );
    assert_eq!(
        r.pages[2],
        p(
            "Arguments",
            "in JSON",
            &format!(
                "{{\"actions\":[{{\"pool_id\":79,\"token_in\":\"wrap.near\",\"token_out\":\"{USDC}\",\"amount_in\":\"1000000000000000000000000\",\"min_amount_out\":\"1\"}}]}}"
            ),
            ""
        )
    );
    assert_eq!(r.pages[3], p("Send", "0.000000000000000000000001 NEAR", "v2.ref-finance.near", YOCTO));
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.20241170666311 NEAR");
    let r = shown("call-binary");
    assert_eq!(
        r.pages[1..],
        [
            p("Contract call", "maki can't read it", "aurora\nmethod submit", CALL),
            p("Arguments", "in hex", "f86c01843b9aca00ff", ""),
            fee("0.60239373558947 NEAR", "301.196867794735", "0.0301196867794735", BACK)
        ]
    );
    let r = shown("stake-pool");
    assert_eq!(
        r.pages[1..4],
        [
            p(
                "Contract call",
                "maki can't read it",
                "astro-stakers.poolv1.near\nmethod deposit_and_stake",
                CALL
            ),
            p("Arguments", "in JSON", "{}", ""),
            p("Send", "10 NEAR", "astro-stakers.poolv1.near", "To the contract, with the call.")
        ]
    );
    // a call to a token maki knows, that isn't a transfer
    let r = shown("wrap");
    assert_eq!(
        r.pages[1],
        p(
            "Contract call",
            "maki can't read it",
            "wrap.near\nmethod near_deposit",
            "A call to wNEAR's contract that maki can't spell out: it may move this account's wNEAR."
        )
    );
}

#[test]
fn keys_code_stake_and_the_account_itself() {
    let full = "Whoever holds that key can do anything this account can, as maki can: send all it holds, add keys, delete it.";
    let r = shown("add-full-key");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Full access!", "a new key", KEY_2, full),
            fee("0.0008392985 NEAR", "0.41964925", "0.000041964925", "")
        ]
    );
    assert_eq!(r.summary, "gives a key full control!; fee up to 0.0008392985 NEAR");
    let tx = parsed("add-full-key");
    assert!(matches!(&tx.actions[..], [Action::AddKey { permission: Permission::FullAccess, .. }]));
    // a key for calls, to some methods, with an allowance; to any, without
    let r = shown("add-call-key");
    assert_eq!(
        r.pages[1],
        p(
            "Key for calls!",
            "a new key",
            KEY_3,
            "It can sign calls to v2.ref-finance.near as this account, without asking: only swap, withdraw. It can't attach NEAR to them, but it pays their gas from this account's NEAR, up to 0.25 NEAR in all."
        )
    );
    assert_eq!(r.summary, "lets a key make calls as this account!; fee up to 0.000841216318536 NEAR");
    assert_eq!(
        shown("add-call-key-any").pages[1],
        p(
            "Key for calls!",
            "a new key",
            KEY_4,
            "It can sign calls to app.example.near as this account, without asking: any of its methods. It can't attach NEAR to them, but it pays their gas from this account's NEAR, with no limit."
        )
    );
    // keys of NEAR's other kinds, as NEAR writes them
    let keys = json()["keys"].clone();
    assert_eq!(
        shown("add-secp256k1-key").pages[1],
        p("Full access!", "a new key", keys["secp256k1"].as_str().unwrap(), full)
    );
    // a post-quantum key, by the hash NEAR keeps and lists it by (2,676 characters as it's written)
    let r = shown("add-ml-dsa-key");
    assert_eq!(
        r.pages[1],
        p(
            "Full access!",
            "a new key",
            keys["ml_dsa_listed"].as_str().unwrap(),
            &format!("{full} It's a post-quantum key, which NEAR lists by its hash, as here.")
        )
    );
    assert_eq!(r.summary, "gives a key full control!; fee up to 0.0008392985 NEAR");
    // deleting a key, and maki's own: the test phrase's own account on NEAR has had its key
    // deleted and eight others added, by whoever else has the phrase
    let r = shown("delete-key");
    assert_eq!(r.pages[1], p("Delete key", "", KEY_2, "That key can't sign for this account any more."));
    assert_eq!(r.summary, "deletes a key; fee up to 0.0008120245 NEAR");
    let r = shown("delete-own-key");
    assert_eq!(
        r.pages[1],
        p(
            "Delete key!",
            "maki's own",
            ME_KEY,
            "maki can't sign for this account after this. Unless it has another full-access key, no one can use it again, and all it holds stays there for good."
        )
    );
    assert_eq!(r.summary, "deletes maki's own key!; fee up to 0.0008120245 NEAR");
    let r = shown("delete-account");
    assert_eq!(
        r.pages[1],
        p(
            "Delete account!",
            "all its NEAR to",
            "bob.near",
            "This account is deleted, and all its NEAR goes to that account (burnt, if it doesn't exist). Tokens it holds aren't moved: they stay with their contracts, under this account's name."
        )
    );
    assert_eq!(r.summary, "deletes this account!; fee up to 0.001022194 NEAR");
    // code: deployed, published, and used by its hash and by another's name
    let code = "Code maki can't read, run as this account in place of any it had: whoever calls it can have it do anything this account can.";
    let r = shown("deploy");
    assert_eq!(
        r.pages[1],
        p("Deploy!", "a contract", "34 bytes, code hash\nGSTYS6tpNRW4jwkP7M2U97GaEUmyqqmFf8SXv4dAEtz1", code)
    );
    assert_eq!(r.summary, "puts code on this account!; fee up to 0.001176155244124 NEAR");
    let r = shown("deploy-global");
    assert_eq!(
        r.pages[1],
        p(
            "Publish",
            "burns 0.0008 NEAR",
            "8 bytes, code hash\nAwLEfgaHQguPVVLGUV9Sf5QKGrMMMr2N6MVSjBj9dJAh",
            "For any account to use by its hash. NEAR burns that much of this account's NEAR to keep it, for good."
        )
    );
    assert_eq!(r.summary, "publishes a contract, burning 0.0008 NEAR; fee up to 0.001172530007984 NEAR");
    assert!(shown("deploy-global-account").pages[1].prose.starts_with("Under this account's name: accounts that use it run whatever this account publishes there, now and later."));
    assert!(matches!(
        &parsed("deploy-global-account").actions[..],
        [Action::DeployGlobalContract { by_account: true, .. }]
    ));
    let r = shown("use-global-hash");
    assert_eq!(
        r.pages[1],
        p(
            "Deploy!",
            "published code",
            "code hash\nGSTYS6tpNRW4jwkP7M2U97GaEUmyqqmFf8SXv4dAEtz1",
            "Code published on NEAR that maki can't read, run as this account in place of any it had: whoever calls it can have it do anything this account can."
        )
    );
    let r = shown("use-global-account");
    assert_eq!(
        r.pages[1],
        p(
            "Deploy!",
            "another's code",
            "contracts.example.near",
            "Whatever code that account publishes, now and later, runs as this account: that account decides what this one does, and can change it any time."
        )
    );
    assert_eq!(
        r.summary,
        "lets another account change this account's code!; fee up to 0.001174441981492 NEAR"
    );
    assert_eq!(
        parsed("use-global-account").actions,
        [Action::UseGlobalContract(Code::Account("contracts.example.near".into()))]
    );
    // staking as a validator, and unstaking
    let r = shown("stake");
    assert_eq!(
        r.pages[1],
        p(
            "Stake",
            "100 NEAR",
            KEY_5,
            "As a validator, with that key: NEAR locks this much of this account's NEAR in all, not this much more. Most stake through a pool's contract instead."
        )
    );
    assert_eq!(r.summary, "stakes 100 NEAR; fee up to 0.000920104625 NEAR");
    assert_eq!(
        shown("unstake").pages[1],
        p(
            "Unstake",
            "all of it",
            KEY_5,
            "As a validator: what this account has locked for it unlocks a few epochs later."
        )
    );
}

#[test]
fn the_networks() {
    let r = shown_on("testnet-transfer", Network::Testnet);
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Network",
                "NEAR testnet",
                "",
                "NEAR's test network, whose NEAR is worth nothing. A transaction doesn't name its network: made for NEAR's own, it would work there."
            ),
            p("Send", "2 NEAR", "bob.testnet", "")
        ]
    );
    let r = shown_on("testnet-usdc", Network::Testnet);
    assert_eq!(parsed("testnet-usdc").receiver, TESTNET_USDC);
    assert_eq!(r.pages[1].value, "1 USDC (testnet)");
    assert_eq!(r.summary, "sends 1 USDC (testnet); fee up to 0.062398128518582 NEAR");
    // the test network's names, and its tokens, given away; and NEAR's own tokens, said to be the
    // test network's (real money passed off as play money)
    let testnet = Error::Invalid(
        "it names an account of NEAR's test network: it's for testnet, not NEAR's own network",
    );
    assert_eq!(review(&parsed("testnet-transfer"), &me(), Network::Mainnet), Err(testnet));
    assert_eq!(
        review(&parsed("testnet-usdc"), &me(), Network::Mainnet),
        Err(Error::Invalid(
            "it's for a token's contract on NEAR's test network: it's for testnet, not NEAR's own network"
        ))
    );
    assert_eq!(
        review(&parsed("usdc"), &me(), Network::Testnet),
        Err(Error::Invalid(
            "it's for a token's contract on NEAR's own network: it's for that network, not testnet"
        ))
    );
    // a named account on the test network can be anything there: NEAR's own names are there too
    assert!(review(&parsed("transfer"), &me(), Network::Testnet).is_ok());
}

/// Borsh written by hand, for what near-api-js wouldn't make.
#[derive(Clone, Default)]
struct B(Vec<u8>);

impl B {
    fn u8(mut self, n: u8) -> B {
        self.0.push(n);
        self
    }

    fn u32(mut self, n: u32) -> B {
        self.0.extend(n.to_le_bytes());
        self
    }

    fn u64(mut self, n: u64) -> B {
        self.0.extend(n.to_le_bytes());
        self
    }

    fn u128(mut self, n: u128) -> B {
        self.0.extend(n.to_le_bytes());
        self
    }

    fn raw(mut self, b: &[u8]) -> B {
        self.0.extend_from_slice(b);
        self
    }

    fn bytes(self, b: &[u8]) -> B { self.u32(b.len() as u32).raw(b) }

    fn string(self, s: &str) -> B { self.bytes(s.as_bytes()) }

    fn key(self, k: &[u8; 32]) -> B { self.u8(0).raw(k) }
}

/// A transaction from `signer` with `key`, to `receiver`, naming the fixtures' block and nonce.
fn tx_from(signer: &str, key: &[u8; 32], receiver: &str, actions: &[B]) -> Vec<u8> {
    let block = parsed("transfer").block_hash;
    let mut b = B::default().string(signer).key(key).u64(218_152_378_000_001).string(receiver).raw(&block);
    b = b.u32(actions.len() as u32);
    for a in actions {
        b = b.raw(&a.0);
    }
    b.0
}

fn tx(receiver: &str, actions: &[B]) -> Vec<u8> { tx_from(ME, &me(), receiver, actions) }

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const TGAS: u64 = 1_000_000_000_000;

fn transfer(deposit: u128) -> B { B::default().u8(3).u128(deposit) }

fn call(method: &str, args: &[u8], gas: u64, deposit: u128) -> B {
    B::default().u8(2).string(method).bytes(args).u64(gas).u128(deposit)
}

fn add_full(key: &[u8; 32]) -> B { B::default().u8(5).key(key).u64(0).u8(1) }

fn delete_account(beneficiary: &str) -> B { B::default().u8(7).string(beneficiary) }

fn refused(bytes: &[u8]) -> tx::Error { Transaction::parse(bytes).unwrap_err() }

fn reviewed(bytes: &[u8]) -> Result<Review, Error> {
    review(&Transaction::parse(bytes).unwrap(), &me(), Network::Mainnet)
}

#[test]
fn transactions_nearcore_would_refuse_maki_refuses() {
    use tx::Error::*;
    let good = tx("bob.near", &[transfer(3 * NEAR / 2)]);
    // written as near-api-js writes it
    assert_eq!(good, fixture("transfer"));
    // cut short, or with more after it; longer than maki reads
    assert_eq!(refused(&good[..good.len() - 1]), Length);
    assert_eq!(refused(&[&good[..], &[0]].concat()), Length);
    assert_eq!(refused(&[]), Length);
    assert_eq!(refused(&[0xff; tx::MAX_TRANSACTION + 1]), TooBig);
    // NEAR's newer kind of transaction (a 1, then the signer's length), and what's neither
    assert_eq!(refused(&[&[1][..], &good[..]].concat()), Version);
    assert_eq!(refused(&[&[2][..], &good[..]].concat()), Encoding);
    // names NEAR doesn't take: the signer's, the receiver's, a beneficiary's, a key's contract's
    assert_eq!(refused(&tx_from("Bob.near", &me(), "bob.near", &[transfer(1)])), Account);
    assert_eq!(refused(&tx("bob..near", &[transfer(1)])), Account);
    assert_eq!(refused(&tx("a", &[transfer(1)])), Account);
    assert_eq!(refused(&tx(ME, &[delete_account("-bob")])), Account);
    let to = |contract: &str| B::default().u8(5).key(&[2; 32]).u64(0).u8(0).u8(0).string(contract).u32(0);
    assert_eq!(refused(&tx(ME, &[to("A.near")])), Account);
    assert!(Transaction::parse(&tx(ME, &[to("app.near")])).is_ok());
    // a string that isn't UTF-8, an option or an enum's tag there isn't
    let not_utf8 = B::default().u8(2).bytes(&[b'h', 0xff]).bytes(b"").u64(TGAS).u128(0);
    assert_eq!(refused(&tx("bob.near", &[not_utf8])), Encoding);
    assert_eq!(refused(&tx(ME, &[B::default().u8(5).key(&[2; 32]).u64(0).u8(0).u8(2)])), Encoding);
    assert_eq!(refused(&tx(ME, &[B::default().u8(5).key(&[2; 32]).u64(0).u8(4)])), Encoding);
    assert_eq!(refused(&tx(ME, &[B::default().u8(6).u8(3).raw(&[2; 32])])), Encoding);
    assert_eq!(refused(&tx(ME, &[B::default().u8(9).bytes(&[0]).u8(2)])), Encoding);
    assert_eq!(refused(&tx(ME, &[B::default().u8(10).u8(2)])), Encoding);
    // a list's count past what's there
    let mut long = good.clone();
    let at = good.len() - 21;
    long[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(refused(&long), Length);
    // actions maki doesn't sign, by name: near-api-js doesn't make them
    for (tag, name) in [
        (11, "a DeterministicStateInit action: maki doesn't sign those"),
        (12, "a TransferToGasKey action: maki doesn't sign those"),
        (13, "a WithdrawFromGasKey action: maki doesn't sign those"),
        (14, "a DelegateV2 action: maki doesn't sign those"),
        (15, "a UniversalStateInit action: maki doesn't sign those"),
        (16, "an action of a kind NEAR doesn't have: maki doesn't sign those"),
    ] {
        assert_eq!(refused(&tx(ME, &[B::default().u8(tag)])).to_string(), name);
    }
    // a gas key, with NEAR of its own to pay gas from
    let gas_key = B::default().u8(5).key(&[2; 32]).u64(0).u8(3).u128(0).u32(1);
    assert_eq!(refused(&tx(ME, &[gas_key])).to_string(), "a gas key: maki doesn't sign those");
    // what nearcore checks: a call with no gas, to no method, to a method longer than it takes
    let invalid = |bytes: &[u8]| match refused(bytes) {
        Invalid(why) => why,
        e => panic!("{e:?}"),
    };
    assert_eq!(
        invalid(&tx("bob.near", &[call("hello", b"", 0, 0)])),
        "a call with no gas: NEAR would refuse it"
    );
    assert_eq!(
        invalid(&tx("bob.near", &[call("", b"", TGAS, 0)])),
        "a call to no method: NEAR would refuse it"
    );
    assert_eq!(
        invalid(&tx("bob.near", &[call(&"m".repeat(257), b"", TGAS, 0)])),
        "a method name longer than NEAR takes"
    );
    assert!(Transaction::parse(&tx("bob.near", &[call(&"m".repeat(256), b"", TGAS, 0)])).is_ok());
    // more gas than a transaction gets, or than adds up
    let pgas = 1_000 * TGAS;
    assert!(
        Transaction::parse(&tx("bob.near", &[call("a", b"", pgas / 2, 0), call("b", b"", pgas / 2, 0)]))
            .is_ok()
    );
    assert_eq!(
        invalid(&tx("bob.near", &[call("a", b"", pgas / 2, 0), call("b", b"", pgas / 2 + 1, 0)])),
        "more gas for its calls than NEAR gives a transaction (1 PGas)"
    );
    assert!(matches!(
        refused(&tx("bob.near", &[call("a", b"", u64::MAX, 0), call("b", b"", u64::MAX, 0)])),
        Invalid(_)
    ));
    // more than 100 actions; the account deleted before its last; more than 10 contracts deployed
    assert!(Transaction::parse(&tx("bob.near", &vec![transfer(1); 100])).is_ok());
    assert_eq!(
        invalid(&tx("bob.near", &vec![transfer(1); 101])),
        "more than 100 actions: NEAR would refuse it"
    );
    assert_eq!(
        invalid(&tx(ME, &[delete_account("bob.near"), transfer(1)])),
        "an action after the account's deleted: NEAR would refuse it"
    );
    let deploy = B::default().u8(1).bytes(b"\0asm\x01\0\0\0");
    assert!(Transaction::parse(&tx(ME, &vec![deploy.clone(); 10])).is_ok());
    assert_eq!(
        invalid(&tx(ME, &vec![deploy; 11])),
        "more than 10 contracts deployed at once: NEAR would refuse it"
    );
    // a key's method names: none empty, each at most 256 bytes, 2000 in all with their ends
    let methods = |names: &[String]| {
        let mut b =
            B::default().u8(5).key(&[2; 32]).u64(0).u8(0).u8(0).string("app.near").u32(names.len() as u32);
        for n in names {
            b = b.string(n);
        }
        b
    };
    assert!(Transaction::parse(&tx(ME, &[methods(&vec!["m".repeat(199); 10])])).is_ok());
    assert_eq!(
        invalid(&tx(ME, &[methods(&vec!["m".repeat(200); 10])])),
        "more method names than NEAR takes for a key"
    );
    assert_eq!(invalid(&tx(ME, &[methods(&["m".repeat(257)])])), "a method name longer than NEAR takes");
    assert_eq!(invalid(&tx(ME, &[methods(&[String::new()])])), "a key for a method with no name");
    // a new key's nonce, which NEAR sets itself
    assert_eq!(
        invalid(&tx(ME, &[B::default().u8(5).key(&[2; 32]).u64(1).u8(1)])),
        "a new key with a nonce, which NEAR sets itself: its libraries write 0"
    );
    // a validator's key that isn't of the curve's prime-order group: the point of order 2 (y is
    // -1), a y that's no point at all (2), and a key of another kind
    let stake = |key: B| B::default().u8(4).u128(NEAR).raw(&key.0);
    let mut order_2 = [0xff; 32];
    (order_2[0], order_2[31]) = (0xec, 0x7f);
    let mut no_point = [0; 32];
    no_point[0] = 2;
    for key in [B::default().key(&order_2), B::default().key(&no_point), B::default().u8(1).raw(&[9; 64])] {
        assert_eq!(
            invalid(&tx(ME, &[stake(key)])),
            "a validator key NEAR can't stake with: NEAR would refuse it"
        );
    }
    assert!(Transaction::parse(&tx(ME, &[stake(B::default().key(&me()))])).is_ok());
    // nearcore's check passes the curve's identity (y is 1), whose order is 1: so does maki's
    let mut identity = [0; 32];
    identity[0] = 1;
    assert!(Transaction::parse(&tx(ME, &[stake(B::default().key(&identity))])).is_ok());
    // as Trust Wallet's wallet-core writes them (its SerializationTests): read as near-api-js's are
    for (hex_tx, action) in [
        (
            "09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e6561720fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef6010000000301000000000000000000000000000000",
            Action::Transfer { deposit: 1 },
        ),
        (
            "09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e6561720fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef601000000020300000071717103000000010203e80300000000000001000000000000000000000000000000",
            Action::FunctionCall { method: "qqq".into(), args: vec![1, 2, 3], gas: 1000, deposit: 1 },
        ),
        (
            "09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00000077686174657665722e6e6561720fa473fd26901df296be6adc4cc4df34d040efa2435224b6986910e630c2fef6010000000703000000313233",
            Action::DeleteAccount { beneficiary: "123".into() },
        ),
    ] {
        let tx = Transaction::parse(&unhex(hex_tx)).unwrap();
        assert_eq!((tx.signer.as_str(), tx.receiver.as_str(), tx.nonce), ("test.near", "whatever.near", 1));
        assert_eq!(tx.actions, [action]);
    }
}

#[test]
fn what_maki_wont_sign() {
    // another account's, and this one's for another of its keys
    assert_eq!(review(&parsed("not-mine"), &me(), Network::Mainnet), Err(Error::NotMine));
    let other_key = Transaction::parse(&tx_from(ME, &[2; 32], "bob.near", &[transfer(1)])).unwrap();
    assert_eq!(review(&other_key, &me(), Network::Mainnet), Err(Error::NotMaki));
    assert_eq!(Error::NotMaki.to_string(), "for another of this account's keys, not maki's");
    // what only the receiver can do to itself, done to another account
    let another = "it acts on another account as only that account can: NEAR would refuse it";
    for action in [add_full(&[2; 32]), delete_account("bob.near"), B::default().u8(6).key(&[2; 32])] {
        assert_eq!(reviewed(&tx("bob.near", &[action])), Err(Error::Invalid(another)));
    }
    // an account made: only its parent can
    assert_eq!(
        reviewed(&tx("sub.bob.near", &[B::default().u8(0)])),
        Err(Error::Invalid(
            "it makes an account, which only that account's parent can: NEAR would refuse it"
        ))
    );
    // maki's own key added, which the account has; the account deleted to itself
    assert_eq!(
        reviewed(&tx(ME, &[add_full(&me())])),
        Err(Error::Invalid("it adds maki's own key, which this account already has: NEAR would refuse it"))
    );
    assert_eq!(
        reviewed(&tx(ME, &[delete_account(ME)])),
        Err(Error::Invalid(
            "it deletes this account and gives what it holds to itself: NEAR would burn it all"
        ))
    );
    // a token transfer its contract would refuse: without exactly 1 yoctoNEAR, of nothing, to itself
    let ft =
        |args: &str, deposit: u128| tx(USDC, &[call("ft_transfer", args.as_bytes(), 30 * TGAS, deposit)]);
    let bob = r#"{"receiver_id":"bob.near","amount":"5250000"}"#;
    assert!(reviewed(&ft(bob, 1)).is_ok());
    assert_eq!(
        reviewed(&ft(bob, 2)),
        Err(Error::Invalid(
            "a token transfer without exactly 1 yoctoNEAR attached: its contract would refuse it"
        ))
    );
    assert_eq!(
        reviewed(&ft(r#"{"receiver_id":"bob.near","amount":"0"}"#, 1)),
        Err(Error::Invalid("a token transfer of nothing: its contract would refuse it"))
    );
    assert_eq!(
        reviewed(&ft(&format!(r#"{{"receiver_id":"{ME}","amount":"1"}}"#), 1)),
        Err(Error::Invalid("tokens sent to the account they're from: its contract would refuse it"))
    );
    // tokens sent to a test network's account, on NEAR's own
    assert_eq!(
        reviewed(&ft(r#"{"receiver_id":"bob.testnet","amount":"1"}"#, 1)),
        Err(Error::Invalid(
            "it names an account of NEAR's test network: it's for testnet, not NEAR's own network"
        ))
    );
    // arguments too long to show, a method name maki can't show, more than maki's screen shows
    assert_eq!(
        reviewed(&tx("bob.near", &[call("hello", &[0xff; 2049], TGAS, 0)])),
        Err(Error::Invalid("a call's arguments too long to show on maki's screen"))
    );
    assert!(reviewed(&tx("bob.near", &[call("hello", &[0xff; 2048], TGAS, 0)])).is_ok());
    assert_eq!(
        reviewed(&tx("bob.near", &[call("hel\nlo", b"", TGAS, 0)])),
        Err(Error::Invalid("a method name maki can't show"))
    );
    // two pages a call (the call, its arguments), the network's and the fee's
    assert!(reviewed(&tx("bob.near", &vec![call("a", b"{}", TGAS, 0); 63])).is_ok());
    assert_eq!(
        reviewed(&tx("bob.near", &vec![call("a", b"{}", TGAS, 0); 64])),
        Err(Error::Invalid("more than maki's screen can show"))
    );
}

#[test]
fn token_transfers_spelled_out_only_as_nep_141_writes_them() {
    let ft = |method: &str, args: &str| {
        reviewed(&tx(USDC, &[call(method, args.as_bytes(), 30 * TGAS, 1)])).unwrap().pages[1].clone()
    };
    let sent = |args: &str| ft("ft_transfer", args).value;
    // any order, a memo or null, whitespace between JSON's tokens
    assert_eq!(sent(r#"{"amount":"1","receiver_id":"bob.near"}"#), "0.000001 USDC");
    assert_eq!(sent(r#"{"receiver_id":"bob.near","amount":"1","memo":null}"#), "0.000001 USDC");
    assert_eq!(sent(" {\t\"receiver_id\" : \"bob.near\",\r\n\"amount\":\"1\" } "), "0.000001 USDC");
    // escapes in a string are what they stand for
    assert_eq!(ft("ft_transfer", r#"{"receiver_id":"b\u006fb.near","amount":"1"}"#).mono, "bob.near");
    // anything else isn't spelled out: a call maki can't read, with its arguments as they are
    for args in [
        r#"{"receiver_id":"bob.near","amount":"1","amount":"2"}"#,
        r#"{"receiver_id":"bob.near","amount":"01"}"#,
        r#"{"receiver_id":"bob.near","amount":"+1"}"#,
        r#"{"receiver_id":"bob.near","amount":1}"#,
        r#"{"receiver_id":"bob.near","amount":"340282366920938463463374607431768211456"}"#,
        r#"{"receiver_id":"Bob.near","amount":"1"}"#,
        r#"{"receiver_id":"bob.near","amount":"1","msg":""}"#,
        r#"{"receiver_id":"bob.near","amount":"1","extra":true}"#,
        r#"{"receiver_id":"bob.near","amount":"1","memo":7}"#,
        r#"{"receiver_id":"bob.near"}"#,
        r#"{"receiver_id":"bob.near","amount":"1"} x"#,
        r#"["bob.near","1"]"#,
    ] {
        assert_eq!(ft("ft_transfer", args).heading, "Contract call", "{args}");
    }
    // a transfer and call needs its message
    assert_eq!(ft("ft_transfer_call", r#"{"receiver_id":"bob.near","amount":"1"}"#).heading, "Contract call");
    let r = reviewed(&tx(
        USDC,
        &[call("ft_transfer_call", br#"{"receiver_id":"bob.near","amount":"1","msg":"swap"}"#, 30 * TGAS, 1)],
    ))
    .unwrap();
    assert_eq!(
        r.pages[2],
        p("Message", "", "swap", "For the receiving contract: everyone can read it, on chain.")
    );
    assert!(r.pages[1].prose.starts_with(
        "Then the token's contract calls that account's contract with the message that follows"
    ));
    // a memo that isn't text to show as it is, in hex
    let r = reviewed(&tx(
        USDC,
        &[call("ft_transfer", br#"{"receiver_id":"bob.near","amount":"1","memo":"a\u0007b"}"#, 30 * TGAS, 1)],
    ))
    .unwrap();
    assert_eq!(r.pages[2], p("Memo", "in hex", "610762", "Everyone can read it, on chain."));
    // storage: for whom, and whether registering is all; anything else, a call maki can't read
    let storage = |args: &str| {
        reviewed(&tx(USDC, &[call("storage_deposit", args.as_bytes(), 30 * TGAS, 1)])).unwrap().pages[1]
            .clone()
    };
    assert!(storage("{}").prose.starts_with("So this account can hold USDC"));
    assert!(
        storage(r#"{"account_id":null,"registration_only":false}"#)
            .prose
            .ends_with("when the account leaves.")
    );
    assert_eq!(storage(r#"{"account_id":"bob.near","registration_only":"yes"}"#).heading, "Contract call");
    assert_eq!(storage(r#"{"account":"bob.near"}"#).heading, "Contract call");
    // a storage deposit to a contract maki doesn't know
    let r = reviewed(&tx("token.example.near", &[call("storage_deposit", b"{}", 30 * TGAS, NEAR / 800)]))
        .unwrap();
    assert_eq!(
        r.pages[1],
        p(
            "Storage deposit",
            "0.00125 NEAR",
            "token.example.near",
            "For this account's storage in that contract, if that's what it does with it: maki doesn't know the contract."
        )
    );
    assert!(r.summary.starts_with("maki can't read all of it"));
}

#[test]
fn json_as_contracts_read_it() {
    use json::Value;
    let s = |t: &str| Value::String(t.into());
    assert_eq!(json::parse(b" null "), Some(Value::Null));
    assert_eq!(json::parse(b"[true,false]"), Some(Value::Array(vec![Value::Bool(true), Value::Bool(false)])));
    assert_eq!(json::parse(br#""\"\\\/\b\f\n\r\t""#), Some(s("\"\\/\u{8}\u{c}\n\r\t")));
    // a surrogate pair is the one character it stands for; half of one isn't JSON to maki
    assert_eq!(json::parse(br#""\ud83d\ude00""#), Some(s("\u{1f600}")));
    assert_eq!(json::parse(br#""\ud83d""#), None);
    assert_eq!(json::parse(br#""\ude00""#), None);
    assert_eq!(json::parse(br#""\ud83dx""#), None);
    for n in ["0", "-0", "12", "1.5", "-1.5e10", "1E+2", "1e-2"] {
        assert_eq!(json::parse(n.as_bytes()), Some(Value::Number(n.into())), "{n}");
    }
    for bad in [
        "",
        "01",
        "1.",
        ".5",
        "+1",
        "1e",
        "- 1",
        "tru",
        "nul",
        "[1,]",
        "{\"a\":1,}",
        "{a:1}",
        "'a'",
        "\"a",
        "\"\t\"",
        "[1] [2]",
        "\u{1}",
        "\"\\x\"",
        "\"\\u12\"",
        "NaN",
    ] {
        assert_eq!(json::parse(bad.as_bytes()), None, "{bad:?}");
    }
    assert_eq!(json::parse(&[b'"', 0xff, b'"']), None, "not UTF-8");
    // as deep as maki follows, and no deeper
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(json::parse(deep(json::MAX_DEPTH).as_bytes()).is_some());
    assert!(json::parse(deep(json::MAX_DEPTH + 1).as_bytes()).is_none());
    // an object with a name twice is JSON, but maki spells nothing out of it
    let twice = json::parse(br#"{"a":1,"a":2}"#).unwrap();
    assert!(matches!(twice, Value::Object(ref m) if m.len() == 2));
    assert!(twice.members().is_none());
    assert_eq!(json::parse(br#"{"a":1}"#).unwrap().members().map(|m| m.len()), Some(1));
}

#[test]
fn fees_as_nearcore_charges_them() {
    // a transaction on NEAR's own network, as it was recorded (survivalisnear.near's EEa2t2bD… of
    // 2026-10-02): a storage deposit and a USDT transfer, whose taking burnt 519,265,173,025 gas,
    // and whose receipt then burnt 3,562,934,202,005 of what it was given
    let to = "19cf707874a66514a13a76dcf59532950c008b17c237babc3703fe44cfd92dad";
    let real = Transaction::parse(&tx_from(
        "survivalisnear.near",
        &[3; 32],
        "usdt.tether-token.near",
        &[
            call(
                "storage_deposit",
                format!(r#"{{"account_id":"{to}","registration_only":true}}"#).as_bytes(),
                30 * TGAS,
                1_250_000_000_000_000_000_000,
            ),
            call(
                "ft_transfer",
                format!(r#"{{"receiver_id":"{to}","amount":"167956823"}}"#).as_bytes(),
                50 * TGAS,
                1,
            ),
        ],
    ))
    .unwrap();
    assert_eq!(fees::conversion(&real), 519_265_173_025);
    assert!(fees::gas(&real) - fees::conversion(&real) >= 3_562_934_202_005);
    // NEAR sent to an implicit account (the test phrase's own, to which people keep sending NEAR,
    // 9c484fa5…'s BiuXnScW… among them): 824,947,687,500 gas to take, 7,524,947,687,500 to run
    let sent = Transaction::parse(&tx_from(
        "9c484fa5d2d069569ba063fc555c34e621ccd88fdbb0295fc79bad232621c5c1",
        &[3; 32],
        ME,
        &[transfer(847_680_490_000_000_000_000_000)],
    ))
    .unwrap();
    assert_eq!(fees::conversion(&sent), 824_947_687_500);
    assert_eq!(fees::gas(&sent), 824_947_687_500 + 7_524_947_687_500);
    // to a named account: 223,182,562,500 each, as a refund's receipt burns it
    let named = Transaction::parse(&tx("bob.near", &[transfer(1)])).unwrap();
    assert_eq!((fees::conversion(&named), fees::gas(&named)), (223_182_562_500, 446_365_125_000));
    // making an account costs 0.007 NEAR in all; its gas at the least price is 0.00072 NEAR of it
    assert_eq!(display::near(fees::creation_surcharge()), "0.00628 NEAR");
    assert_eq!(fees::MAX_GAS_PRICE, 2_000_000_000);
    // publishing burns 0.0001 NEAR a byte
    assert_eq!(display::near(10_000 * fees::PUBLISH_PER_BYTE), "1 NEAR");
}

#[test]
fn keys_as_near_writes_them() {
    assert_eq!(PublicKey::Ed25519(me()).to_string(), ME_KEY);
    assert_eq!(PublicKey::Ed25519(me()).kind(), "ed25519");
    let keys = json()["keys"].clone();
    let tx = parsed("add-ml-dsa-key");
    let Action::AddKey { key, .. } = &tx.actions[0] else { panic!() };
    assert_eq!((key.kind(), key.data().len()), ("ml-dsa-65", tx::ML_DSA_65_KEY));
    // as near-api-js writes it, and as NEAR lists it (nearcore's hash, by @noble/hashes' SHA3)
    assert_eq!(key.to_string(), keys["ml_dsa"].as_str().unwrap());
    assert_eq!(key.listed(), keys["ml_dsa_listed"].as_str().unwrap());
    assert!(!key.can_stake());
    // any other key is listed as it's written
    let secp = parsed("add-secp256k1-key");
    let Action::AddKey { key, .. } = &secp.actions[0] else { panic!() };
    assert_eq!(
        (key.listed(), key.to_string()),
        (keys["secp256k1"].as_str().unwrap().into(), keys["secp256k1"].as_str().unwrap().into())
    );
    assert!(PublicKey::Ed25519(me()).can_stake());
    assert_eq!(hex(&hash(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
