//! maki-atom against Cosmos's own software: sign docs CosmJS made (`fixtures/make.mjs`), read as they
//! are and shown as they should be, and signed by maki's keys as CosmJS signs them with the same
//! account (the test phrase's first, as Keplr, Cosmostation and Ledger's Cosmos app have it), with the
//! transactions CosmJS made of some, which carry maki's signature; sign docs of transactions the
//! chains themselves took (`fixtures/onchain.mjs`), read as they are; and what a chain would refuse,
//! written by hand, refused.

use maki_atom::chains::{self, Network};
use maki_atom::display::{self, Error, Page, Review, review};
use maki_atom::doc::{self, Coin, Msg, SignDoc, Vote};
use maki_atom::{account, address, bech32, digest, json, parse_address, path};
use maki_hd::Keys;
use maki_hd::seed::SeedKeys;

const ME: &str = "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4";
const OSMO_ME: &str = "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8";
const RECIPIENT: &str = "cosmos10xcqpzrky6eff2g52qdye53xkk9jxkvrpq6uqr";
const SECOND: &str = "cosmos1a0qwuze2h85zw7nqpsj3ga0z9geyrgwphl8j6w";
const STRANGER: &str = "cosmos1g975h6gdx5mryeac72h6lj2nzygugxhy2xgtga";
const GRANTEE: &str = "cosmos13zxmh4ue370cp48c9d8eeek43qhnzzhv7fwl2v";
const VALIDATOR: &str = "cosmosvaloper1n454ga9rqwkx6ax309knw5hs0z2erz7j3ahchn";
const VALIDATOR2: &str = "cosmosvaloper16jlzchtg6pl8sstn4m42uaz7xmnkhv36kj8mk0";
const OSMO_ON_HUB: &str = "ibc/14F9BC3E44B8A9C1BE1FB08980FAB87034C9905EF17CF2F5008FC085218811CC";
const ATOM_ON_OSMOSIS: &str = "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2";
const USDC_ON_OSMOSIS: &str = "ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4";
const USDC_ON_DYDX: &str = "ibc/8E27BA2D5493AF5636760E354E46004562C46AB7EC0CC4C1CA14E9E20E2545B5";

fn me() -> [u8; 20] { parse_address(hub(), ME).unwrap() }

fn hub() -> &'static chains::Chain { chains::hub(Network::Main) }

fn chain(id: &str) -> &'static chains::Chain { chains::by_id(id).unwrap() }

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

struct Fixture {
    name: String,
    chain: String,
    doc: String,
    /// CosmJS's signature for this account, if it's this account's
    signature: Option<Vec<u8>>,
    /// CosmJS's whole transaction (TxRaw), for some
    tx: Option<Vec<u8>>,
}

/// The sign docs CosmJS made.
fn fixtures() -> Vec<Fixture> {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/signdocs.json"))
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    json.as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            chain: f["chain"].as_str().unwrap().into(),
            doc: f["doc"].as_str().unwrap().into(),
            signature: f["signature"].as_str().map(unhex),
            tx: f["tx"].as_str().map(unhex),
        })
        .collect()
}

fn fixture(name: &str) -> String { fixtures().into_iter().find(|f| f.name == name).unwrap().doc }

fn parsed(name: &str) -> SignDoc { SignDoc::parse(fixture(name).as_bytes()).unwrap() }

fn shown(name: &str) -> Review {
    let doc = parsed(name);
    review(&doc, &me(), doc.chain.network).unwrap()
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "Cosmos Hub", "cosmoshub-4", "") }

const GAS: &str = "For up to 200000 gas.";

fn fee() -> Page { p("Max fee", "0.005 ATOM", "", GAS) }

fn keys() -> SeedKeys {
    let seed = maki_seed::seed(
        &"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect::<Vec<_>>(),
        "",
    );
    SeedKeys::from_seed(&seed).unwrap()
}

/// What maki's review screen takes (maki-wasm's limits): a heading of 32 bytes, a value of 128, no
/// control characters but newlines in the fixed-width text and the prose, 4096 bytes of each.
fn fits_the_screen(r: &Review) {
    assert!(r.summary.len() <= display::MAX_SUMMARY, "{}", r.summary);
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
fn addresses_as_cosmos_wallets_make_them() {
    let keys = keys();
    // the test phrase's accounts, as CosmJS makes them (makeCosmoshubPath); the first as Ledger's
    // ledgerjs (abandonseed.ts) and Keystone's firmware tests publish it
    for (index, expected) in [
        (0, ME),
        (1, "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz"),
        (2, "cosmos1kng7tv83qesgvv2ze7hxlw4urfrjk8vqqnpqdt"),
    ] {
        let key = keys.public(&path(index)).unwrap().key;
        assert_eq!(address(hub(), &account(&key)), expected, "account {index}");
    }
    let key = keys.public(&path(0)).unwrap().key;
    assert_eq!(hex(&key), "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62");
    assert_eq!(maki_hd::format_path(&path(0)), "m/44'/118'/0'/0/0");
    // the same account on every chain, under its prefix: as Keystone's tests have it on Osmosis and
    // Akash, and as CosmJS signed a payment from it on each chain maki knows
    assert_eq!(address(chain("osmosis-1"), &account(&key)), OSMO_ME);
    assert_eq!(address(chain("akashnet-2"), &account(&key)), "akash19rl4cm2hmr8afy4kldpxz3fka4jguq0a3mq6x0");
    for c in chains::CHAINS {
        let f = fixtures().into_iter().find(|f| f.name.starts_with("send-") && f.chain == c.id).unwrap();
        let doc = SignDoc::parse(f.doc.as_bytes()).unwrap();
        let Msg::Send { from, .. } = &doc.msgs[0] else { panic!("{}", f.name) };
        assert_eq!(*from, address(c, &account(&key)), "{}", c.id);
        assert_eq!(parse_address(c, from), Some(account(&key)));
    }
    // another chain's address, a validator's, one mistyped, one in capitals, one of 32 bytes
    assert_eq!(parse_address(hub(), OSMO_ME), None);
    assert_eq!(parse_address(hub(), VALIDATOR), None);
    assert_eq!(parse_address(hub(), "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5"), None);
    assert_eq!(parse_address(hub(), &ME.to_uppercase()), None);
    assert_eq!(parse_address(hub(), &bech32::encode("cosmos", &[7; 32])), None);
}

#[test]
fn bech32_as_bip173_has_it() {
    // BIP-173's valid strings (those in lower case), and their bytes where they're whole
    for (text, prefix, len) in [
        ("a12uel5l", "a", 0),
        (
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
            0,
        ),
        ("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", "abcdef", 20),
        ("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "split", 30),
        ("?1ezyfcl", "?", 0),
    ] {
        let (p, bytes) = bech32::decode(text).unwrap_or_else(|| panic!("{text}"));
        assert_eq!((p, bytes.len()), (prefix, len), "{text}");
        assert_eq!(bech32::encode(p, &bytes), text);
    }
    // BIP-173's invalid ones: a character out of range, too long, no separator, no prefix, a
    // character bech32 doesn't have, a checksum too short, the wrong checksum
    for text in [
        "\x201nwldj5",
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "pzry9x0s0muk",
        "1pzry9x0s0muk",
        "x1b4n0q5v",
        "li1dgmt3",
        "de1lg7wt\u{ff}",
        "10a06t8",
        "1qzzfhee",
        "a12uel5m",
    ] {
        assert_eq!(bech32::decode(text), None, "{text:?}");
    }
    // in capitals, or mixed, or bech32m's checksum (BIP-350's vector): not as Cosmos writes them
    assert_eq!(bech32::decode("A12UEL5L"), None);
    assert_eq!(bech32::decode("a12UEL5L"), None);
    assert_eq!(bech32::decode("a1lqfn3a"), None);
    // their checksums good, but the bits left over at the end not zero, or five of them: not whole
    // bytes
    assert_eq!(bech32::encode("a", &[0xff]), "a1lu9cgf6y");
    assert_eq!(bech32::decode("a1lu9cgf6y"), Some(("a", vec![0xff])));
    assert_eq!(bech32::decode("a1lacwuu8k"), None);
    assert_eq!(bech32::decode("a1q3g6mn3"), None);
    assert_eq!(bech32::decode("a1qqqqqqqqughnlu"), Some(("a", vec![0; 5])));
}

#[test]
fn amounts_times_and_spans() {
    assert_eq!(display::decimals(0, 6), "0");
    assert_eq!(display::decimals(1, 6), "0.000001");
    assert_eq!(display::decimals(1_500_000, 6), "1.5");
    assert_eq!(display::decimals(1_500_000_000_000_000_000, 18), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::decimals(u128::MAX, 18), "340282366920938463463.374607431768211455");
    let coin = |amount, denom: &str| Coin { amount, denom: denom.into() };
    assert_eq!(display::amount(hub(), &coin(5_000, "uatom")), "0.005 ATOM");
    assert_eq!(display::amount(hub(), &coin(42, "uosmo")), "42 units");
    assert_eq!(display::amount(hub(), &coin(2_500_000, OSMO_ON_HUB)), "2.5 OSMO");
    assert_eq!(display::amount(chain("osmosis-1"), &coin(1, ATOM_ON_OSMOSIS)), "0.000001 ATOM");
    // the same denom on another chain is another coin
    assert_eq!(display::amount(hub(), &coin(1, ATOM_ON_OSMOSIS)), "1 units");
    assert_eq!(display::utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(display::utc(1_790_917_200_000_000_000), "2026-10-02 05:00:00 UTC");
    assert_eq!(display::utc(951_782_400_000_000_000), "2000-02-29 00:00:00 UTC");
    assert_eq!(display::utc(u64::MAX), "2554-07-21 23:34:33 UTC");
    assert_eq!(display::span(21 * 86_400), "21 days");
    assert_eq!(display::span(14 * 86_400 + 3_600), "14 days 1 hour");
    assert_eq!(display::span(5_400), "1 hour 30 minutes");
    assert_eq!(display::span(90), "1 minute 30 seconds");
}

#[test]
fn every_chain_maki_knows_is_as_the_registry_has_it() {
    // each chain once, its validators' prefix its own and `valoper`, the Hub on each network
    for (i, c) in chains::CHAINS.iter().enumerate() {
        assert!(chains::CHAINS[..i].iter().all(|o| o.id != c.id), "{}", c.id);
        assert_eq!(chains::by_id(c.id), Some(c));
        assert_eq!(c.valoper(), format!("{}valoper", c.prefix));
        assert!(c.name.len() <= 128 && c.coin.symbol.len() <= 16, "{}", c.id);
    }
    assert_eq!(chains::CHAINS.len(), 13);
    assert_eq!(chains::hub(Network::Main).id, "cosmoshub-4");
    assert_eq!(chains::hub(Network::Test).id, "provider");
    assert_eq!(chains::by_id("cosmoshub-3"), None);
    assert_eq!(Network::from_byte(0), Some(Network::Main));
    assert_eq!(Network::from_byte(1), Some(Network::Test));
    assert_eq!(Network::from_byte(2), None);
    // every channel between two main networks maki knows, once each way
    for &(a, a_channel, b, b_channel) in chains::CHANNELS {
        let (a, b) = (chain(a), chain(b));
        assert!(a.network == Network::Main && b.network == Network::Main && a != b);
        assert_eq!(chains::route(a, a_channel), Some(b));
        assert_eq!(chains::route(b, b_channel), Some(a));
    }
    // IBC denoms, as the registry's assetlists name them: ICS-20's hash of the path a coin came by
    assert_eq!(chains::ibc_denom("channel-0", "uatom"), ATOM_ON_OSMOSIS);
    assert_eq!(chains::ibc_denom("channel-750", "uusdc"), USDC_ON_OSMOSIS);
    assert_eq!(chains::ibc_denom("channel-141", "uosmo"), OSMO_ON_HUB);
    assert_eq!(chains::ibc_denom("channel-0", "uusdc"), USDC_ON_DYDX);
    let usdc = chains::token(chain("dydx-mainnet-1"), USDC_ON_DYDX).unwrap();
    assert_eq!((usdc.token.symbol, usdc.token.decimals), ("USDC", 6));
    assert_eq!(usdc.from.map(|(c, channel)| (c.id, channel)), Some(("noble-1", "channel-0")));
    assert_eq!(chains::token(hub(), "uatom").map(|k| k.from), Some(None));
    // a denom in lower case isn't the coin's: the bank keys balances by the very string
    assert_eq!(chains::token(chain("osmosis-1"), &ATOM_ON_OSMOSIS.to_lowercase()), None);
    assert_eq!(chains::token(chain("osmo-test-5"), ATOM_ON_OSMOSIS), None);
}

#[test]
fn maki_signs_what_cosmjs_signs() {
    let keys = keys();
    let mut signed = 0;
    for f in fixtures() {
        let Some(expected) = f.signature else { continue };
        let (rs, _) = keys.sign_ecdsa(&path(0), &digest(f.doc.as_bytes())).unwrap();
        assert_eq!(rs.to_vec(), expected, "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 61);
}

#[test]
fn every_sign_doc_cosmjs_made_reads_as_it_should() {
    for f in fixtures() {
        let result = SignDoc::parse(f.doc.as_bytes()).map_err(|e| e.to_string()).and_then(|doc| {
            // what maki read is what it signs: written again, the very bytes
            assert_eq!(f.doc, json::write(&json::parse(f.doc.as_bytes()).unwrap()));
            review(&doc, &me(), doc.chain.network).map_err(|e| e.to_string())
        });
        match f.name.as_str() {
            "not-mine" => {
                assert_eq!(result, Err(String::from("another account's transaction, not this one's to sign")))
            }
            "grant" => assert_eq!(
                result,
                Err(String::from(
                    "an authz grant, which lets another account act for this one until it's revoked: maki won't sign that"
                ))
            ),
            "grant-allowance" => assert_eq!(
                result,
                Err(String::from(
                    "a fee grant, which lets another account spend this one's coins on its fees: maki won't sign that"
                ))
            ),
            "unknown-chain" => {
                assert_eq!(
                    result,
                    Err(String::from("a chain maki doesn't know (secret-4): it won't sign for it"))
                )
            }
            name => fits_the_screen(&result.unwrap_or_else(|e| panic!("{name}: {e}"))),
        }
    }
}

#[test]
fn coins_sent() {
    let r = shown("send");
    assert_eq!(r.pages, [network(), p("Send", "1.5 ATOM", RECIPIENT, ""), fee()]);
    assert_eq!(r.summary, "sends 1.5 ATOM; fee up to 0.005 ATOM");
    let doc = parsed("send");
    assert_eq!(
        (doc.chain.id, doc.account_number, doc.sequence, doc.timeout_height),
        ("cosmoshub-4", 1234567, 42, 0)
    );
    assert_eq!(
        doc.msgs,
        [Msg::Send {
            from: ME.into(),
            to: RECIPIENT.into(),
            amount: vec![Coin { denom: "uatom".into(), amount: 1_500_000 }]
        }]
    );
    let r = shown("send-memo");
    assert_eq!(r.pages[2], p("Memo", "", "thanks for the coffee", "Everyone can read it, on chain."));
    assert_eq!(r.summary, "sends 20 ATOM; fee up to 0.005 ATOM");
    // what Cosmos escapes (<, >, &, quotes, backslashes, line breaks), shown as it is
    assert_eq!(
        shown("send-escapes").pages[2].mono,
        "Tom & Jerry <tj@example.com> said \"hi\" \\o/\nsecond line: café ✓"
    );
    assert!(
        fixture("send-escapes")
            .contains(r#""memo":"Tom \u0026 Jerry \u003ctj@example.com\u003e said \"hi\" \\o/\nsecond"#)
    );
    // two coins at once, one of them OSMO that came from Osmosis by the Hub's channel to it
    let r = shown("send-two-coins");
    assert_eq!(
        r.pages[1..3],
        [
            p("Send", "2.5 OSMO", RECIPIENT, "OSMO from Osmosis, by IBC (channel-141)."),
            p("Send", "1.5 ATOM", RECIPIENT, "")
        ]
    );
    assert_eq!(r.summary, "sends 2.5 OSMO and 1.5 ATOM; fee up to 0.005 ATOM");
    assert_eq!(shown("send-to-itself").pages[1], p("Send", "1 ATOM", ME, "That's this account."));
    // a coin maki doesn't know, in its smallest units
    let r = shown("send-unknown-coin");
    assert_eq!(
        r.pages[1],
        p(
            "Send",
            "42 units",
            RECIPIENT,
            "Of factory/cosmos1xyz/token, in its smallest units: maki doesn't know it."
        )
    );
    assert_eq!(r.summary, "sends 42 units of a coin maki doesn't know; fee up to 0.005 ATOM");
    let r = shown("multi-send");
    assert_eq!(r.pages[1..3], [p("Send", "1 ATOM", RECIPIENT, ""), p("Send", "2 ATOM", SECOND, "")]);
    assert_eq!(r.summary, "sends 3 ATOM in 2 payments; fee up to 0.005 ATOM");
}

#[test]
fn staking_and_rewards() {
    let r = shown("delegate");
    assert_eq!(
        r.pages,
        [
            network(),
            p(
                "Stake",
                "10 ATOM",
                VALIDATOR,
                "With that validator. Staked, it stays this account's and earns rewards, but can't be spent: unstaking takes 21 days. If the validator breaks the chain's rules, part of it can be lost."
            ),
            fee()
        ]
    );
    assert_eq!(r.summary, "stakes 10 ATOM; fee up to 0.005 ATOM");
    let r = shown("undelegate");
    assert_eq!(
        r.pages[1],
        p(
            "Unstake",
            "5 ATOM",
            VALIDATOR,
            "From that validator. It comes back to this account in 21 days; until then it earns nothing and can't be spent."
        )
    );
    assert_eq!(r.summary, "unstakes 5 ATOM; fee up to 0.005 ATOM");
    let r = shown("redelegate");
    assert_eq!(
        r.pages[1],
        p(
            "Restake",
            "5 ATOM",
            &format!("from {VALIDATOR}\nto {VALIDATOR2}"),
            "Moved from the first validator to the second at once, staked all the while. It can't be moved on again for 21 days."
        )
    );
    assert_eq!(r.summary, "restakes 5 ATOM; fee up to 0.005 ATOM");
    let r = shown("cancel-unstaking");
    assert_eq!(
        r.pages[1],
        p(
            "Cancel unstaking",
            "1 ATOM",
            VALIDATOR,
            "Staked with that validator again: of what began unstaking at block 33218000."
        )
    );
    assert_eq!(r.summary, "stakes 1 ATOM again; fee up to 0.005 ATOM");
    let claim = |v: &str| {
        p(
            "Claim rewards",
            "of staking",
            v,
            "What this account has earned staking with that validator is paid out: to this account, or to the address its rewards are set to go to.",
        )
    };
    assert_eq!(shown("claim-rewards").pages[1], claim(VALIDATOR));
    assert_eq!(shown("claim-rewards").summary, "claims rewards; fee up to 0.005 ATOM");
    // claimed from two validators and staked again
    let r = shown("compound");
    assert_eq!(r.pages[1..3], [claim(VALIDATOR), claim(VALIDATOR2)]);
    assert_eq!(r.pages[3].heading, "Stake");
    assert_eq!(r.summary, "claims rewards from 2 validators, stakes 2 ATOM; fee up to 0.005 ATOM");
    // rewards sent elsewhere: said loudly
    let r = shown("rewards-elsewhere");
    assert_eq!(
        r.pages[1],
        p(
            "Rewards to!",
            "another address",
            STRANGER,
            "Every staking reward this account earns would be paid to that address, until it's set back."
        )
    );
    assert_eq!(r.summary, "sends its staking rewards elsewhere!; fee up to 0.005 ATOM");
    let r = shown("rewards-to-itself");
    assert_eq!(
        r.pages[1],
        p(
            "Rewards to",
            "this account",
            ME,
            "Its staking rewards are paid to this account itself, from now on."
        )
    );
    assert_eq!(r.summary, "has its rewards paid to it; fee up to 0.005 ATOM");
    let r = shown("donate");
    assert_eq!(
        r.pages[1],
        p(
            "Donate",
            "1 ATOM",
            "",
            "To the Cosmos Hub's community pool, which its governance spends: it doesn't come back."
        )
    );
    assert_eq!(r.summary, "donates 1 ATOM; fee up to 0.005 ATOM");
    // unstaking takes each chain's own time
    let mut doc = parsed("delegate");
    doc.chain = chain("juno-1");
    let r = review(&doc, &me(), Network::Main);
    assert_eq!(r, Err(Error::NotMine), "the Hub's address isn't Juno's");
    let juno = fixture("delegate").replace("cosmoshub-4", "juno-1").replace("uatom", "ujuno");
    let juno = juno.replace(ME, &address(chain("juno-1"), &me()));
    let juno = juno.replace(VALIDATOR, &bech32::encode("junovaloper", &bech32::decode(VALIDATOR).unwrap().1));
    let doc = SignDoc::parse(juno.as_bytes()).unwrap();
    assert!(review(&doc, &me(), Network::Main).unwrap().pages[1].prose.contains("unstaking takes 28 days"));
}

#[test]
fn governance() {
    let vote =
        |value: &str| p("Vote", value, "", "On proposal 1000. Until voting ends, another vote replaces it.");
    assert_eq!(shown("vote-yes").pages, [network(), vote("Yes"), fee()]);
    assert_eq!(shown("vote-yes").summary, "votes yes on proposal 1000; fee up to 0.005 ATOM");
    assert_eq!(shown("vote-abstain").pages[1], vote("Abstain"));
    assert_eq!(shown("vote-no").pages[1], vote("No"));
    assert_eq!(shown("vote-veto").pages[1], vote("No with veto"));
    assert_eq!(shown("vote-veto").summary, "votes no with veto on proposal 1000; fee up to 0.005 ATOM");
    // governance v1's vote, with its note
    let r = shown("vote-v1");
    assert_eq!(r.pages[1].mono, "for the community");
    assert_eq!(
        parsed("vote-v1").msgs,
        [Msg::Vote { voter: ME.into(), proposal: 1000, vote: Vote::Yes, note: "for the community".into() }]
    );
    let r = shown("vote-split");
    assert_eq!(
        r.pages[1],
        p(
            "Vote",
            "split",
            "Yes 70%\nNo 30%",
            "On proposal 1000: this account's vote, split as it says. Until voting ends, another vote replaces it."
        )
    );
    assert_eq!(r.summary, "splits its vote on proposal 1000; fee up to 0.005 ATOM");
    let r = shown("deposit");
    assert_eq!(
        r.pages[1],
        p(
            "Deposit",
            "10 ATOM",
            "",
            "On proposal 1000. Whether it comes back depends on how the proposal fares: it can be burnt."
        )
    );
    assert_eq!(r.summary, "deposits 10 ATOM on proposal 1000; fee up to 0.005 ATOM");
}

#[test]
fn ibc_transfers() {
    let osmosis = "To Osmosis, by IBC (channel-141).";
    let by_then = "If it hasn't arrived by 2026-10-02 05:00:00 UTC, it comes back.";
    let r = shown("ibc");
    assert_eq!(
        r.pages,
        [network(), p("Send over IBC", "1.5 ATOM", OSMO_ME, &format!("{osmosis} {by_then}")), fee()]
    );
    assert_eq!(r.summary, "sends 1.5 ATOM to Osmosis; fee up to 0.005 ATOM");
    let Msg::Transfer { timeout, timeout_height, channel, .. } = &parsed("ibc").msgs[0] else { panic!() };
    assert_eq!(
        (*timeout, *timeout_height, channel.as_str()),
        (1_790_917_200_000_000_000, (0, 0), "channel-141")
    );
    assert_eq!(
        shown("ibc-height").pages[1].prose,
        format!("{osmosis} If it hasn't arrived by block 72000000 there, it comes back.")
    );
    assert_eq!(
        shown("ibc-both").pages[1].prose,
        format!(
            "{osmosis} If it hasn't arrived by 2026-10-02 05:00:00 UTC or by block 72000000 there, it comes back."
        )
    );
    // a memo of instructions for the other chain: maki can't read what they do
    let r = shown("ibc-instructions");
    assert_eq!(
        r.pages[2],
        p(
            "IBC memo",
            "maki can't read it",
            r#"{"forward":{"receiver":"neutron1g975h6gdx5mryeac72h6lj2nzygugxhywepfj6","port":"transfer","channel":"channel-874"}}"#,
            "Instructions the chain at the other end may follow: to send the coins on, to someone else, or swap them."
        )
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.005 ATOM");
    let r = shown("ibc-memo");
    assert_eq!(
        r.pages[2],
        p("IBC memo", "", "deposit 1234", "For the chain at the other end. Everyone can read it.")
    );
    assert_eq!(r.summary, "sends 1.5 ATOM to Osmosis; fee up to 0.005 ATOM");
    let r = shown("ibc-unknown-channel");
    assert_eq!(
        r.pages[1].prose,
        format!("By IBC (channel-9999), to a chain maki doesn't know: check the channel. {by_then}")
    );
    assert_eq!(r.summary, "sends 1.5 ATOM over IBC; fee up to 0.005 ATOM");
    assert_eq!(
        shown("ibc-wrong-receiver").pages[1],
        p(
            "Send over IBC",
            "1.5 ATOM",
            RECIPIENT,
            &format!(
                "{osmosis} The receiver isn't an address of Osmosis's: it would send it back. {by_then}"
            )
        )
    );
    // ATOM on Osmosis, going home the way it came
    let r = shown("osmosis-ibc-home");
    assert_eq!(
        r.pages[1],
        p(
            "Send over IBC",
            "1.5 ATOM",
            ME,
            &format!("ATOM back to the Cosmos Hub, by IBC (channel-0). {by_then}")
        )
    );
    assert_eq!(r.summary, "sends 1.5 ATOM to the Cosmos Hub; fee up to 0.02 OSMO");
}

#[test]
fn coins_from_other_chains_and_messages_maki_cant_read() {
    let osmosis = p("Network", "Osmosis", "osmosis-1", "");
    let fee = p("Max fee", "0.02 OSMO", "", GAS);
    let to = "osmo10xcqpzrky6eff2g52qdye53xkk9jxkvrfmfvk3";
    let r = shown("osmosis-atom");
    assert_eq!(
        r.pages,
        [osmosis.clone(), p("Send", "1.5 ATOM", to, "ATOM from the Cosmos Hub, by IBC (channel-0)."), fee]
    );
    assert_eq!(r.summary, "sends 1.5 ATOM; fee up to 0.02 OSMO");
    assert_eq!(
        shown("osmosis-usdc").pages[1],
        p("Send", "25 USDC", to, "USDC from Noble, by IBC (channel-750).")
    );
    // ATOM that came some other way isn't the ATOM a wallet means: in units, by its denom
    let r = shown("osmosis-stray-atom");
    assert_eq!(r.pages[1].value, "1500000 units");
    assert!(r.pages[1].prose.starts_with("Of ibc/0000"));
    // a swap and a contract's call: as they're written, flagged
    let r = shown("osmosis-swap");
    assert_eq!(r.pages[1].heading, "Message");
    assert_eq!(r.pages[1].value, "maki can't read it");
    assert!(
        r.pages[1]
            .mono
            .starts_with("osmosis/poolmanager/swap-exact-amount-in\n{\"routes\":[{\"pool_id\":\"1\"")
    );
    assert_eq!(
        r.pages[1].prose,
        "As it's written. If it's this account's to sign, it can do anything this account can."
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.02 OSMO");
    let r = shown("osmosis-contract");
    assert!(r.pages[1].mono.contains(r#""msg":{"swap":{"min_out":"100","route":[1,2]}}"#));
    // dYdX's 18 decimals, and its fee in USDC from Noble
    let r = shown("dydx-usdc-fee");
    assert_eq!(r.pages[1], p("Send", "1.5 DYDX", "dydx10xcqpzrky6eff2g52qdye53xkk9jxkvrge5cq5", ""));
    assert_eq!(
        r.pages[2],
        p("Max fee", "0.005 USDC", "", "For up to 200000 gas. USDC from Noble, by IBC (channel-0).")
    );
    assert_eq!(r.summary, "sends 1.5 DYDX; fee up to 0.005 USDC");
    // each chain's own coin, and its test networks said to be
    for (name, network, value, fee) in [
        ("send-celestia", p("Network", "Celestia", "celestia", ""), "1.5 TIA", "0.004 TIA"),
        ("send-dydx", p("Network", "dYdX", "dydx-mainnet-1", ""), "1.5 DYDX", "0.0025 DYDX"),
        ("send-neutron", p("Network", "Neutron", "neutron-1", ""), "1.5 NTRN", "0.00106 NTRN"),
        ("send-noble", p("Network", "Noble", "noble-1", ""), "1.5 USDC", "0.02 USDC"),
        ("send-akash", p("Network", "Akash", "akashnet-2", ""), "1.5 AKT", "0.005 AKT"),
        ("send-axelar", p("Network", "Axelar", "axelar-dojo-1", ""), "1.5 AXL", "0.0014 AXL"),
        ("send-babylon", p("Network", "Babylon", "bbn-1", ""), "1.5 BABY", "0.0014 BABY"),
        ("send-juno", p("Network", "Juno", "juno-1", ""), "1.5 JUNO", "0.02 JUNO"),
        (
            "send-hubtest",
            p("Network", "Cosmos Hub testnet", "provider", "A test network: its ATOM is worth nothing."),
            "1.5 ATOM",
            "0.004 ATOM",
        ),
        (
            "send-osmotest",
            p("Network", "Osmosis testnet", "osmo-test-5", "A test network: its OSMO is worth nothing."),
            "1.5 OSMO",
            "0.005 OSMO",
        ),
        (
            "send-celestiatest",
            p("Network", "Celestia testnet", "mocha-5", "A test network: its TIA is worth nothing."),
            "1.5 TIA",
            "0.004 TIA",
        ),
    ] {
        let r = shown(name);
        assert_eq!(r.pages[0], network, "{name}");
        assert_eq!((r.pages[1].value.as_str(), r.pages[2].value.as_str()), (value, fee), "{name}");
    }
}

#[test]
fn revokes_fees_and_limits() {
    let r = shown("revoke");
    assert_eq!(
        r.pages[1],
        p(
            "Revoke",
            "a permission",
            &format!("{GRANTEE}\n/cosmos.staking.v1beta1.MsgDelegate"),
            "That address may no longer send this kind of message for this account."
        )
    );
    assert_eq!(r.summary, "revokes a permission; fee up to 0.005 ATOM");
    let r = shown("revoke-allowance");
    assert_eq!(
        r.pages[1],
        p("Revoke", "a fee allowance", GRANTEE, "That address may no longer pay its fees from this account.")
    );
    let r = shown("fee-granter");
    assert_eq!(
        r.pages[2],
        p(
            "Max fee",
            "0.005 ATOM",
            "",
            &format!("{GAS} Paid from the fee allowance {GRANTEE} gave this account.")
        )
    );
    assert_eq!(r.summary, "sends 1.5 ATOM; another pays the fee");
    let r = shown("fee-payer");
    assert_eq!(
        r.pages[2],
        p("Max fee", "0.005 ATOM", "", &format!("{GAS} Paid by {GRANTEE}, which signs it too."))
    );
    assert_eq!(r.summary, "sends 1.5 ATOM; another pays the fee");
    let r = shown("no-fee");
    assert_eq!(r.pages[2], p("Max fee", "nothing", "", GAS));
    assert_eq!(r.summary, "sends 1.5 ATOM; no fee");
    // a fee of nothing, as CosmJS's calculateFee writes one at a gas price of nothing: the chain
    // takes it, and charges nothing
    let r = shown("fee-of-nothing");
    assert_eq!(r.pages[2], p("Max fee", "0 OSMO", "", GAS));
    assert_eq!(r.summary, "sends 1.5 OSMO; no fee");
    let r = shown("valid-until");
    assert_eq!(
        r.pages[2],
        p("Valid until", "block 33300000", "", "The chain won't take it in a block after that.")
    );
    assert_eq!(parsed("valid-until").timeout_height, 33_300_000);
    // a memo as long as a message to maki lets it be, shown whole
    assert_eq!(shown("long-memo").pages[2].mono, "a".repeat(3500));
}

#[test]
fn what_maki_wont_sign() {
    // another account's
    assert_eq!(review(&parsed("not-mine"), &me(), Network::Main), Err(Error::NotMine));
    assert_eq!(Error::NotMine.to_string(), "another account's transaction, not this one's to sign");
    // a test network's sign doc said to be the main network's, and a main network's said to be a
    // test network's (real coins passed off as play money)
    let test = parsed("send-osmotest");
    assert_eq!(review(&test, &me(), Network::Main), Err(Error::Network(chain("osmo-test-5"))));
    assert_eq!(
        Error::Network(chain("osmo-test-5")).to_string(),
        "a test network's transaction (osmo-test-5), sent as a main network's"
    );
    assert_eq!(review(&parsed("send"), &me(), Network::Test), Err(Error::Network(hub())));
    assert_eq!(
        Error::Network(hub()).to_string(),
        "a main network's transaction (cosmoshub-4), sent as a test network's: its coins are real"
    );
    // grants that let another account act for this one, and a chain maki doesn't know
    assert!(matches!(SignDoc::parse(fixture("grant").as_bytes()), Err(doc::Error::Refused(_))));
    assert!(matches!(SignDoc::parse(fixture("grant-allowance").as_bytes()), Err(doc::Error::Refused(_))));
    assert_eq!(
        SignDoc::parse(fixture("unknown-chain").as_bytes()),
        Err(doc::Error::Chain("secret-4".into()))
    );
}

/// A sign doc for the Hub with these messages, as the chain writes one.
fn hub_doc(msgs: &str) -> String {
    format!(
        r#"{{"account_number":"1","chain_id":"cosmoshub-4","fee":{{"amount":[{{"amount":"5000","denom":"uatom"}}],"gas":"200000"}},"memo":"","msgs":[{msgs}],"sequence":"0"}}"#
    )
}

fn send_msg(amount: &str) -> String {
    format!(
        r#"{{"type":"cosmos-sdk/MsgSend","value":{{"amount":{amount},"from_address":"{ME}","to_address":"{RECIPIENT}"}}}}"#
    )
}

fn refused(text: &str) -> doc::Error { SignDoc::parse(text.as_bytes()).unwrap_err() }

fn invalid(text: &str) -> String {
    match refused(text) {
        doc::Error::Invalid(why) => why.into(),
        e => panic!("{e:?}: {text}"),
    }
}

#[test]
fn json_as_cosmos_writes_it() {
    let good = fixture("send");
    assert!(SignDoc::parse(good.as_bytes()).is_ok());
    let json_error = |text: &str| match refused(text) {
        doc::Error::Json(e) => e.what,
        e => panic!("{e:?}: {text}"),
    };
    // a space or line break anywhere but in a string
    assert_eq!(json_error(&good.replacen(',', ", ", 1)), "a space or line break, which Cosmos doesn't write");
    assert_eq!(json_error(&good.replacen(':', ": ", 1)), "a space or line break, which Cosmos doesn't write");
    assert_eq!(json_error(&format!(" {good}")), "a space or line break, which Cosmos doesn't write");
    assert_eq!(json_error(&format!("{good}\n")), "more after the end");
    // names out of order, or twice
    let swapped = good.replace(
        r#""account_number":"1234567","chain_id":"cosmoshub-4""#,
        r#""chain_id":"cosmoshub-4","account_number":"1234567""#,
    );
    assert_eq!(json_error(&swapped), "names out of order");
    assert_eq!(json_error(&good.replace(r#""memo":"""#, r#""memo":"","memo":"""#)), "a name given twice");
    // <, > and & as Go writes them, and only those escapes
    let memo = |m: &str| good.replace(r#""memo":"""#, &format!(r#""memo":"{m}""#));
    assert!(SignDoc::parse(memo(r#"\u003cb\u003e \u0026 \"q\" \\ \n"#).as_bytes()).is_ok());
    assert_eq!(json_error(&memo("<b>")), "<, > or & as Cosmos doesn't write them: it escapes them");
    assert_eq!(json_error(&memo("&")), "<, > or & as Cosmos doesn't write them: it escapes them");
    assert_eq!(json_error(&memo(r"\u003C")), "an escape Cosmos doesn't write");
    assert_eq!(json_error(&memo(r"\u0041")), "an escape Cosmos doesn't write");
    assert_eq!(json_error(&memo(r"a\/b")), "an escape Cosmos doesn't write");
    assert_eq!(json_error(&memo(r"\t")), "an escape Cosmos doesn't write");
    assert_eq!(json_error(&memo("\t")), "a control character in a string");
    assert_eq!(json_error(&memo("\u{7f}")), "a control character maki can't show");
    assert_eq!(json_error(&memo("\u{85}")), "a control character maki can't show");
    assert_eq!(json_error(&memo("\u{2028}")), "U+2028 or U+2029, which Go and JavaScript write differently");
    assert_eq!(json_error(&memo(r"\u2028")), "an escape Cosmos doesn't write");
    assert_eq!(json::parse(br#""abc"#).unwrap_err().what, "a string that doesn't end");
    assert_eq!(json::parse(br#""abc\"#).unwrap_err().what, "an escape Cosmos doesn't write");
    let mut bytes = memo("ab").into_bytes();
    let at = bytes.windows(4).position(|w| w == b"\"ab\"").unwrap() + 1;
    bytes[at] = 0xff;
    assert_eq!(SignDoc::parse(&bytes), Err(doc::Error::Json(json::Error { at, what: "not UTF-8" })));
    // whole numbers, as a double holds them and both Go and JavaScript write them
    for (n, what) in [
        ("1.5", "a number that isn't whole, which Go and JavaScript may write differently"),
        ("1e5", "a number that isn't whole, which Go and JavaScript may write differently"),
        ("01", "a number with a leading zero"),
        ("-0", "-0, which Go and JavaScript write differently"),
        ("9007199254740992", "a number too big for a double to hold"),
        ("-", "not a number"),
    ] {
        assert_eq!(json::parse(n.as_bytes()).unwrap_err().what, what, "{n}");
    }
    assert_eq!(json::parse(b"9007199254740991"), Ok(json::Value::Number(9_007_199_254_740_991)));
    assert_eq!(json::parse(b"-9007199254740991"), Ok(json::Value::Number(-9_007_199_254_740_991)));
    assert_eq!(
        json::parse(b"[true,false,null]").map(|v| json::write(&v)),
        Ok(String::from("[true,false,null]"))
    );
    assert_eq!(json::parse(b"tru").unwrap_err().what, "not a value");
    assert_eq!(json::parse(b"").unwrap_err().what, "cut short");
    assert_eq!(json::parse(b"{\"a\":1").unwrap_err().what, "cut short");
    // twenty deep at most
    let deep = |n| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(json::parse(deep(20).as_bytes()).is_ok());
    assert_eq!(json::parse(deep(21).as_bytes()).unwrap_err().what, "nested too deep");
    // the longest sign doc maki reads
    assert_eq!(refused(&format!("{good}{}", " ".repeat(doc::MAX_DOC))), doc::Error::TooBig);
}

#[test]
fn sign_docs_the_chain_would_refuse_maki_refuses() {
    use doc::Error::*;
    let good = hub_doc(&send_msg(r#"[{"amount":"1","denom":"uatom"}]"#));
    assert!(SignDoc::parse(good.as_bytes()).is_ok());
    // the doc's own fields: one maki doesn't know (an unordered transaction's, a tip), one missing,
    // one of the wrong kind, a number not as Go writes it, a block of 0 written out
    assert_eq!(
        refused(&good.replace(r#""sequence":"0""#, r#""sequence":"0","unordered":true"#)),
        Unknown("unordered".into())
    );
    assert_eq!(
        refused(
            &good
                .replace(r#""sequence":"0""#, r#""sequence":"0","timeout_timestamp":"2026-10-02T05:00:00Z""#)
        ),
        Unknown("timeout_timestamp".into())
    );
    assert_eq!(
        refused(&good.replace(r#""sequence":"0""#, r#""sequence":"0","tip":null"#)),
        Unknown("tip".into())
    );
    assert_eq!(refused(&good.replace(r#""memo":"","#, "")), Missing("memo"));
    assert_eq!(
        refused(&good.replace(r#""account_number":"1""#, r#""account_number":1"#)),
        Field("account_number")
    );
    assert_eq!(refused(&good.replace(r#""sequence":"0""#, r#""sequence":"00""#)), Field("sequence"));
    assert_eq!(
        refused(&good.replace(r#""sequence":"0""#, r#""sequence":"18446744073709551616""#)),
        Field("sequence")
    );
    assert_eq!(
        refused(&good.replace(r#""sequence":"0""#, r#""sequence":"0","timeout_height":"0""#)),
        Field("timeout_height")
    );
    assert_eq!(refused(&good.replace("cosmoshub-4", "cosmoshub-3")), Chain("cosmoshub-3".into()));
    assert_eq!(invalid(&hub_doc("")), "a transaction of no messages: the chain would refuse it");
    // a fee: more gas than can be, an address that isn't one, coins out of order
    assert_eq!(
        invalid(&good.replace(r#""gas":"200000""#, r#""gas":"9223372036854775808""#)),
        "more gas than a transaction can have: the chain would refuse it"
    );
    assert_eq!(
        refused(&good.replace(r#""gas":"200000""#, r#""gas":"200000","payer":"me""#)),
        Address("fee's payer")
    );
    let fee = |coins: &str| {
        good.replace(
            r#""fee":{"amount":[{"amount":"5000","denom":"uatom"}]"#,
            &format!(r#""fee":{{"amount":{coins}"#),
        )
    };
    assert!(SignDoc::parse(fee(r#"[{"amount":"0","denom":"uatom"}]"#).as_bytes()).is_ok());
    assert_eq!(
        invalid(&fee(r#"[{"amount":"0","denom":"ibc/AB"},{"amount":"1","denom":"uatom"}]"#)),
        "a fee of nothing beside a fee of something: the chain would refuse it"
    );
    let two = r#"[{"amount":"1","denom":"uatom"},{"amount":"1","denom":"uatom"}]"#;
    assert_eq!(
        invalid(&good.replace(
            r#""fee":{"amount":[{"amount":"5000","denom":"uatom"}]"#,
            &format!(r#""fee":{{"amount":{two}"#)
        )),
        "coins out of order, or one twice: the chain would refuse them"
    );
    // coins: none, nothing, out of order, a denom the chain wouldn't take, an amount not as Go
    // writes it, one bigger than maki reads
    let send = |amount: &str| hub_doc(&send_msg(amount));
    assert_eq!(invalid(&send("[]")), "no coins: the chain would refuse it");
    assert_eq!(
        invalid(&send(r#"[{"amount":"0","denom":"uatom"}]"#)),
        "an amount of nothing: the chain would refuse it"
    );
    assert_eq!(
        invalid(&send(r#"[{"amount":"1","denom":"uatom"},{"amount":"1","denom":"ibc/AB"}]"#)),
        "coins out of order, or one twice: the chain would refuse them"
    );
    for denom in ["u", "1atom", "u atom", "uatom!", &"u".repeat(129)] {
        assert_eq!(
            invalid(&send(&format!(r#"[{{"amount":"1","denom":"{denom}"}}]"#))),
            "a coin's denom the chain wouldn't take",
            "{denom}"
        );
    }
    for amount in ["01", "-1", "1.0", ""] {
        assert_eq!(
            refused(&send(&format!(r#"[{{"amount":"{amount}","denom":"uatom"}}]"#))),
            Field("amount"),
            "{amount}"
        );
    }
    assert_eq!(refused(&send(r#"[{"amount":1,"denom":"uatom"}]"#)), Field("amount"));
    assert_eq!(
        invalid(&send(r#"[{"amount":"340282366920938463463374607431768211456","denom":"uatom"}]"#)),
        "an amount bigger than maki reads"
    );
    assert!(
        SignDoc::parse(
            send(r#"[{"amount":"340282366920938463463374607431768211455","denom":"uatom"}]"#).as_bytes()
        )
        .is_ok()
    );
    // addresses: another chain's, a validator's, mistyped, in capitals; a field the message doesn't
    // have, one it must
    let coins = r#"[{"amount":"1","denom":"uatom"}]"#;
    let with = |to: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/MsgSend","value":{{"amount":{coins},"from_address":"{ME}","to_address":"{to}"}}}}"#
        ))
    };
    for to in
        [OSMO_ME, VALIDATOR, "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal5", &RECIPIENT.to_uppercase(), ""]
    {
        assert_eq!(refused(&with(to)), Address("to_address"), "{to}");
    }
    assert!(
        SignDoc::parse(with(&bech32::encode("cosmos", &[7; 32])).as_bytes()).is_ok(),
        "a contract's address"
    );
    assert_eq!(refused(&with(&bech32::encode("cosmos", &[7; 21]))), Address("to_address"));
    let extra = format!(
        r#"{{"type":"cosmos-sdk/MsgSend","value":{{"amount":{coins},"from_address":"{ME}","to_address":"{RECIPIENT}","x":1}}}}"#
    );
    assert_eq!(refused(&hub_doc(&extra)), Unknown("x".into()));
    let short =
        format!(r#"{{"type":"cosmos-sdk/MsgSend","value":{{"amount":{coins},"from_address":"{ME}"}}}}"#);
    assert_eq!(refused(&hub_doc(&short)), Missing("to_address"));
    assert_eq!(refused(&hub_doc(r#"{"type":"cosmos-sdk/MsgSend"}"#)), Missing("value"));
    assert_eq!(refused(&hub_doc(r#"{"type":"cosmos-sdk/MsgSend","value":[]}"#)), Field("message's value"));
    assert_eq!(refused(&hub_doc(r#"{"type":1,"value":{}}"#)), Field("message's type"));
    assert_eq!(invalid(&hub_doc(r#"{"type":"a b","value":{}}"#)), "a message whose type maki can't show");
    // staking: another coin than the chain stakes, a validator that's an account, restaked where it
    // is, unstaking that began at no block
    let stake = |kind: &str, denom: &str, validator: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/{kind}","value":{{"amount":{{"amount":"1","denom":"{denom}"}},"delegator_address":"{ME}","validator_address":"{validator}"}}}}"#
        ))
    };
    assert!(SignDoc::parse(stake("MsgDelegate", "uatom", VALIDATOR).as_bytes()).is_ok());
    assert_eq!(
        invalid(&stake("MsgDelegate", "uosmo", VALIDATOR)),
        "a coin other than the one this chain stakes: the chain would refuse it"
    );
    assert_eq!(refused(&stake("MsgUndelegate", "uatom", RECIPIENT)), Address("validator_address"));
    let redelegate = format!(
        r#"{{"type":"cosmos-sdk/MsgBeginRedelegate","value":{{"amount":{{"amount":"1","denom":"uatom"}},"delegator_address":"{ME}","validator_dst_address":"{VALIDATOR}","validator_src_address":"{VALIDATOR}"}}}}"#
    );
    assert_eq!(
        invalid(&hub_doc(&redelegate)),
        "restaked with the validator it's staked with: the chain would refuse it"
    );
    let cancel = |height: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/MsgCancelUnbondingDelegation","value":{{"amount":{{"amount":"1","denom":"uatom"}},{height}"delegator_address":"{ME}","validator_address":"{VALIDATOR}"}}}}"#
        ))
    };
    assert!(SignDoc::parse(cancel(r#""creation_height":"5","#).as_bytes()).is_ok());
    assert_eq!(invalid(&cancel("")), "unstaking that began at no block: the chain would refuse it");
    assert_eq!(refused(&cancel(r#""creation_height":"-5","#)), Field("creation_height"));
    assert_eq!(
        invalid(&cancel(r#""creation_height":"9223372036854775808","#)),
        "unstaking that began at no block: the chain would refuse it"
    );
    // votes: an option there isn't, one written as a string, proposal 0, governance v1's empty note
    let vote = |option: &str, proposal: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/MsgVote","value":{{"option":{option},"proposal_id":"{proposal}","voter":"{ME}"}}}}"#
        ))
    };
    assert!(SignDoc::parse(vote("4", "7").as_bytes()).is_ok());
    assert_eq!(
        invalid(&vote("5", "7")),
        "a vote that isn't yes, no, abstain or veto: the chain would refuse it"
    );
    assert_eq!(
        invalid(&vote("0", "7")),
        "a vote that isn't yes, no, abstain or veto: the chain would refuse it"
    );
    assert_eq!(refused(&vote(r#""1""#, "7")), Field("option"));
    assert_eq!(invalid(&vote("1", "0")), "proposal 0, which there isn't: the chain would refuse it");
    let v1 = format!(
        r#"{{"type":"cosmos-sdk/v1/MsgVote","value":{{"metadata":"","option":1,"proposal_id":"7","voter":"{ME}"}}}}"#
    );
    assert_eq!(refused(&hub_doc(&v1)), Field("metadata"));
    // split votes: weights that aren't a whole, an option twice, a weight not as the chain writes it
    let split = |options: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/MsgVoteWeighted","value":{{"options":[{options}],"proposal_id":"7","voter":"{ME}"}}}}"#
        ))
    };
    let option = |o: u8, w: &str| format!(r#"{{"option":{o},"weight":"{w}"}}"#);
    let whole = option(1, "1.000000000000000000");
    assert!(SignDoc::parse(split(&whole).as_bytes()).is_ok());
    let halves = format!("{},{}", option(1, "0.500000000000000000"), option(3, "0.400000000000000000"));
    assert_eq!(
        invalid(&split(&halves)),
        "a split vote whose weights aren't a whole: the chain would refuse it"
    );
    let twice = format!("{},{}", option(1, "0.500000000000000000"), option(1, "0.500000000000000000"));
    assert_eq!(invalid(&split(&twice)), "a vote's option given twice: the chain would refuse it");
    assert_eq!(refused(&split(&option(1, "1.0"))), Field("weight"));
    assert_eq!(refused(&split(&option(1, "10000000000000000000"))), Field("weight"));
    assert_eq!(
        invalid(&split(&option(1, "1.000000000000000001"))),
        "a vote's weight that isn't above nothing and a whole at most"
    );
    assert_eq!(
        invalid(&split(&option(1, "0.000000000000000000"))),
        "a vote's weight that isn't above nothing and a whole at most"
    );
    assert_eq!(invalid(&split("")), "a split vote whose weights aren't a whole: the chain would refuse it");
    // multi-sends: from two accounts, to no one, paying out what it doesn't take in
    let multi = |inputs: &str, outputs: &str| {
        hub_doc(&format!(
            r#"{{"type":"cosmos-sdk/MsgMultiSend","value":{{"inputs":[{inputs}],"outputs":[{outputs}]}}}}"#
        ))
    };
    let io = |who: &str, amount: &str| {
        format!(r#"{{"address":"{who}","coins":[{{"amount":"{amount}","denom":"uatom"}}]}}"#)
    };
    assert!(
        SignDoc::parse(
            multi(&io(ME, "3"), &format!("{},{}", io(RECIPIENT, "1"), io(SECOND, "2"))).as_bytes()
        )
        .is_ok()
    );
    assert_eq!(
        invalid(&multi(&format!("{},{}", io(ME, "1"), io(SECOND, "1")), &io(RECIPIENT, "2"))),
        "a multi-send from other than one account: the chain would refuse it"
    );
    assert_eq!(invalid(&multi(&io(ME, "1"), "")), "a multi-send to no one: the chain would refuse it");
    assert_eq!(
        invalid(&multi(&io(ME, "3"), &format!("{},{}", io(RECIPIENT, "1"), io(SECOND, "1")))),
        "a multi-send whose outputs aren't what it sends: the chain would refuse it"
    );
    // IBC: another port, a channel that can't be, a receiver with a space, no timeout, a timeout
    // at block 0, a memo written out empty, ibc-go v10's encoding (which maki doesn't read)
    let transfer =
        |fields: &str| hub_doc(&format!(r#"{{"type":"cosmos-sdk/MsgTransfer","value":{{{fields}}}}}"#));
    let base = |memo: &str, receiver: &str, channel: &str, port: &str, height: &str, timeout: &str| {
        transfer(&format!(
            r#"{memo}"receiver":"{receiver}","sender":"{ME}","source_channel":"{channel}","source_port":"{port}","timeout_height":{{{height}}},{timeout}"token":{{"amount":"1","denom":"uatom"}}"#
        ))
    };
    let at = r#""timeout_timestamp":"1790917200000000000","#;
    assert!(SignDoc::parse(base("", OSMO_ME, "channel-141", "transfer", "", at).as_bytes()).is_ok());
    assert_eq!(
        invalid(&base("", OSMO_ME, "channel-141", "wasm.x", "", at)),
        "an IBC transfer from a port other than transfer's"
    );
    for channel in ["channel 141", "chan-1", &"c".repeat(65)] {
        assert_eq!(
            invalid(&base("", OSMO_ME, channel, "transfer", "", at)),
            "an IBC channel that can't be: the chain would refuse it",
            "{channel}"
        );
    }
    assert_eq!(refused(&base("", OSMO_ME, "", "transfer", "", at)), Field("source_channel"));
    assert_eq!(
        invalid(&base("", "osmo1 x", "channel-141", "transfer", "", at)),
        "an IBC receiver maki can't show: too long, or with spaces in it"
    );
    assert_eq!(
        invalid(&base("", &"o".repeat(2049), "channel-141", "transfer", "", at)),
        "an IBC receiver maki can't show: too long, or with spaces in it"
    );
    assert_eq!(
        invalid(&base("", OSMO_ME, "channel-141", "transfer", "", "")),
        "an IBC transfer that never times out: the chain would refuse it"
    );
    assert_eq!(
        invalid(&base("", OSMO_ME, "channel-141", "transfer", r#""revision_number":"1""#, "")),
        "an IBC transfer that times out at block 0"
    );
    assert_eq!(
        refused(&base("", OSMO_ME, "channel-141", "transfer", r#""revision_height":"0""#, at)),
        Field("revision_height")
    );
    assert_eq!(refused(&base(r#""memo":"","#, OSMO_ME, "channel-141", "transfer", "", at)), Field("memo"));
    assert_eq!(
        refused(&base(r#""encoding":"application/json","#, OSMO_ME, "channel-141", "transfer", "", at)),
        Unknown("encoding".into())
    );
    // a permission taken back that isn't a kind of message
    let revoke = format!(
        r#"{{"type":"cosmos-sdk/MsgRevoke","value":{{"grantee":"{GRANTEE}","granter":"{ME}","msg_type_url":"send"}}}}"#
    );
    assert_eq!(invalid(&hub_doc(&revoke)), "a permission that isn't a kind of message");
    // the reasons, as the computer reads them
    assert_eq!(
        Unknown("x".into()).to_string(),
        "a field maki doesn't know (x): it won't sign what it can't show"
    );
    assert_eq!(Missing("memo").to_string(), "not a sign doc as Cosmos writes one: no memo");
    assert_eq!(Field("sequence").to_string(), "not a sign doc as Cosmos writes one: its sequence");
    assert_eq!(Address("to_address").to_string(), "an address that isn't this chain's: its to_address");
    assert_eq!(TooBig.to_string(), "bigger than maki takes a sign doc");
    assert_eq!(
        refused(&format!("{good} ")).to_string(),
        format!("not a sign doc as Cosmos writes one: more after the end at byte {}", good.len())
    );
    // a field's name, cut short in what's said of it
    let long = good.replace(r#""sequence":"0""#, &format!(r#""sequence":"0","{}":1"#, "z".repeat(100)));
    assert_eq!(refused(&long), Unknown("z".repeat(32)));
}

/// A protobuf message's fields: each number, and its value (a varint's, or a length's bytes).
fn proto(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    fn varint(b: &mut &[u8]) -> u64 {
        let mut n = 0;
        for i in 0.. {
            let byte = b[0];
            *b = &b[1..];
            n |= ((byte & 0x7f) as u64) << (7 * i);
            if byte & 0x80 == 0 {
                break;
            }
        }
        n
    }
    let mut out = Vec::new();
    while !b.is_empty() {
        let key = varint(&mut b);
        let value = match key & 7 {
            0 => varint(&mut b).to_le_bytes().to_vec(),
            2 => {
                let n = varint(&mut b) as usize;
                let (v, rest) = b.split_at(n);
                b = rest;
                v.to_vec()
            }
            w => panic!("wire type {w}"),
        };
        out.push((key >> 3, value));
    }
    out
}

fn field(fields: &[(u64, Vec<u8>)], n: u64) -> Vec<Vec<u8>> {
    fields.iter().filter(|(k, _)| *k == n).map(|(_, v)| v.clone()).collect()
}

fn number(v: &[u8]) -> u64 { u64::from_le_bytes(v.try_into().unwrap()) }

#[test]
fn the_transactions_cosmjs_made_carry_makis_signature() {
    let keys = keys();
    let key = keys.public(&path(0)).unwrap().key;
    let mut checked = 0;
    for f in fixtures() {
        let Some(tx) = f.tx else { continue };
        let doc = SignDoc::parse(f.doc.as_bytes()).unwrap();
        let (rs, _) = keys.sign_ecdsa(&path(0), &digest(f.doc.as_bytes())).unwrap();
        // TxRaw: body_bytes (1), auth_info_bytes (2), signatures (3): maki's, as it signs
        let raw = proto(&tx);
        assert_eq!(field(&raw, 3), [rs.to_vec()], "{}", f.name);
        // AuthInfo: signer_infos (1), fee (2)
        let auth = proto(&field(&raw, 2)[0]);
        let [signer] = field(&auth, 1).try_into().unwrap();
        let signer = proto(&signer);
        // SignerInfo: public_key (1, an Any: type_url 1, value 2), mode_info (2), sequence (3)
        let public = proto(&field(&signer, 1)[0]);
        assert_eq!(field(&public, 1), [b"/cosmos.crypto.secp256k1.PubKey".to_vec()]);
        // PubKey: key (1), compressed
        assert_eq!(field(&public, 2), [[&[0x0a, 33][..], &key].concat()]);
        // ModeInfo: single (1), whose mode (1) is SIGN_MODE_LEGACY_AMINO_JSON, 127
        let single = proto(&field(&proto(&field(&signer, 2)[0]), 1)[0]);
        assert_eq!(number(&field(&single, 1)[0]), 127);
        assert_eq!(number(&field(&signer, 3)[0]), doc.sequence);
        // Fee: amount (1), gas_limit (2), payer (3), granter (4), as the sign doc has them
        let fee = proto(&field(&auth, 2)[0]);
        assert_eq!(field(&fee, 1).len(), doc.fee.amount.len());
        assert_eq!(number(&field(&fee, 2)[0]), doc.fee.gas);
        assert_eq!(field(&fee, 3), doc.fee.payer.iter().map(|p| p.as_bytes().to_vec()).collect::<Vec<_>>());
        assert_eq!(field(&fee, 4), doc.fee.granter.iter().map(|g| g.as_bytes().to_vec()).collect::<Vec<_>>());
        // TxBody: messages (1), memo (2), timeout_height (3)
        let body = proto(&field(&raw, 1)[0]);
        assert_eq!(field(&body, 1).len(), doc.msgs.len());
        assert_eq!(
            field(&body, 2),
            if doc.memo.is_empty() { vec![] } else { vec![doc.memo.as_bytes().to_vec()] }
        );
        assert_eq!(field(&body, 3).first().map(|v| number(v)).unwrap_or(0), doc.timeout_height);
        checked += 1;
    }
    assert_eq!(checked, 11);
}

/// What kind of message maki read, by name.
fn kind(m: &Msg) -> &'static str {
    match m {
        Msg::Send { .. } => "send",
        Msg::MultiSend { .. } => "multi-send",
        Msg::Delegate { .. } => "stake",
        Msg::Undelegate { .. } => "unstake",
        Msg::Redelegate { .. } => "restake",
        Msg::CancelUnstake { .. } => "cancel unstaking",
        Msg::ClaimRewards { .. } => "claim rewards",
        Msg::RewardsTo { .. } => "rewards to",
        Msg::Donate { .. } => "donate",
        Msg::Vote { .. } => "vote",
        Msg::SplitVote { .. } => "split vote",
        Msg::Deposit { .. } => "deposit",
        Msg::Transfer { .. } => "IBC",
        Msg::Revoke { .. } => "revoke",
        Msg::RevokeAllowance { .. } => "revoke allowance",
        Msg::Other { .. } => "other",
    }
}

/// Sign docs of transactions the chains took (`fixtures/onchain.mjs`): made again from the
/// transactions, and kept where the transactions' own signatures check out over them, so each chain
/// made these very bytes to check its signature. maki reads every one as it is, and shows it to the
/// account that signed it; and its signature checks out over what maki would sign, the SHA-256 of
/// the bytes. Governance v1's votes and an authz permission taken back among them are of the kinds
/// CosmJS can't write: maki reads them as the chains write them.
#[test]
fn sign_docs_the_chains_made_read_as_they_are() {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{Signature, VerifyingKey};

    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/onchain.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();
    for tx in json.as_array().unwrap() {
        let doc = tx["doc"].as_str().unwrap();
        let hash = tx["hash"].as_str().unwrap();
        let key: [u8; 33] = unhex(tx["key"].as_str().unwrap()).try_into().unwrap();
        let signature = Signature::from_slice(&unhex(tx["signature"].as_str().unwrap())).unwrap();
        VerifyingKey::from_sec1_bytes(&key)
            .unwrap()
            .verify_prehash(&digest(doc.as_bytes()), &signature)
            .unwrap();
        let read = SignDoc::parse(doc.as_bytes()).unwrap_or_else(|e| panic!("{hash}: {e}"));
        assert_eq!(read.chain.id, tx["chain"].as_str().unwrap());
        let r = review(&read, &account(&key), read.chain.network).unwrap_or_else(|e| panic!("{hash}: {e}"));
        fits_the_screen(&r);
        // the ones governance v1 and authz wrote, which CosmJS can't
        let v1 = tx["kinds"].as_array().unwrap().iter().any(|k| k == "/cosmos.gov.v1.MsgVote");
        assert!(!v1 || read.msgs.iter().all(|m| matches!(m, Msg::Vote { .. })), "{hash}");
        seen.insert(read.chain.id);
        kinds.extend(read.msgs.iter().map(kind));
    }
    assert_eq!(seen.len(), chains::CHAINS.iter().filter(|c| c.network == Network::Main).count());
    for k in [
        "send",
        "multi-send",
        "stake",
        "unstake",
        "restake",
        "cancel unstaking",
        "claim rewards",
        "rewards to",
        "vote",
        "IBC",
        "revoke",
    ] {
        assert!(kinds.contains(k), "{k}: {kinds:?}");
    }
    assert!(!kinds.contains("other"));
}
