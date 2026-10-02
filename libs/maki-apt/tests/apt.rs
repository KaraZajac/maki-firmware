//! maki-apt against Aptos's own library: transactions the Aptos TypeScript SDK made
//! (`fixtures/make.mjs`), read as they are and shown as they should be, and signed by maki's keys as
//! the SDK signs them with the same account (the test phrase's first, as Petra and Ledger's Aptos
//! app have it), each signature put in a signed transaction as the SDK puts it. And what Aptos would
//! refuse, written by hand, refused.

use maki_apt::call::{Asset, Call, Payment, Staking};
use maki_apt::display::{self, Error, Page, Review, review};
use maki_apt::tx::{self, Replay, Transaction, TypeTag};
use maki_apt::{
    Address, FRAMEWORK, Network, address, address_of, assets, authenticator, parse_address, path, prefix,
    signing_message,
};
use maki_hd::seed::SeedKeys;
use sha3::{Digest, Sha3_256};

const ME: &str = "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf";
const RECIPIENT: &str = "0x7df415e5b21bdaa8b2946e8f1f4278b39904e51a69627494cd3e6f2996732fbd";
const SECOND: &str = "0x7d9947d5ce9efdd02bb88c44cf2f941c829ed5ac483090a6ba22c12db9251c41";
const POOL: &str = "0xf4f9450e6f0b72ba78becf56a39f8bd322295548fdd52b29bc4aebd58dd0223d";
const OBJECT: &str = "0x7d89318c0cab59e1ba83ac392b747ed2e5ab7222aa8edc425e6b3b42ae8d5199";
const ISSUER: &str = "0xa56b7fd183a77c66ce1e516677c211dda51e394c32080545d49352ff0919340f";
const DEX: &str = "0xcc405722b15c00a19d37e51d9a756de1e61b780ad0935f3363bc7fce64edbdad";
const USDC: &str = "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b";
/// 2026-10-02 04:00:00 UTC, when the fixtures were made; each expires 20 seconds later.
const MADE: u64 = 1_790_913_600;

fn me() -> Address { parse_address(ME).unwrap() }

fn a(text: &str) -> Address { parse_address(text).unwrap() }

fn unhex(text: &str) -> Vec<u8> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

struct Fixture {
    name: String,
    network: Network,
    raw: Vec<u8>,
    message: Vec<u8>,
    /// The SDK's signature for this account, the signed transaction it makes with it and that
    /// transaction's hash, if it's this account's.
    signature: Option<Vec<u8>>,
    signed: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
}

/// The transactions the SDK made.
fn fixtures() -> Vec<Fixture> {
    let bytes = |v: &serde_json::Value| v.as_str().map(unhex);
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap(),
            raw: unhex(f["raw"].as_str().unwrap()),
            message: unhex(f["message"].as_str().unwrap()),
            signature: bytes(&f["signature"]),
            signed: bytes(&f["signed"]),
            hash: bytes(&f["hash"]),
        })
        .collect()
}

fn fixture(name: &str) -> Vec<u8> { fixtures().into_iter().find(|f| f.name == name).unwrap().raw }

fn parsed(name: &str) -> Transaction { Transaction::parse(&fixture(name)).unwrap() }

fn shown_on(name: &str, network: Network) -> Review { review(&parsed(name), &me(), network, None).unwrap() }

fn shown(name: &str) -> Review { shown_on(name, Network::Mainnet) }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "Aptos", "", "") }

const UNTIL: &str = "Whoever has it can send it until then, unless this account sends another first.";

/// The fixtures' expiry: 20 seconds after they were made.
fn valid() -> Page { p("Valid until", "2026-10-02 04:00:20 UTC", "", UNTIL) }

fn fee() -> Page {
    p(
        "Max fee",
        "0.002 APT",
        "",
        "Up to 2000 gas units, at 100 octas each. Aptos charges this account only for the gas it uses.",
    )
}

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
/// control characters but newlines in the fixed-width text and the prose, 4096 bytes of each, 128
/// pages, and 16 KiB of the review's text in all.
fn fits_the_screen(r: &Review) {
    assert!(r.summary.len() <= display::MAX_SUMMARY, "{}", r.summary);
    assert!(r.pages.len() <= 128);
    let mut text = 64 + 128 + 16 + 16 + 3;
    for page in &r.pages {
        let plain = |t: &str| !t.chars().any(|c| c.is_control());
        let lines = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
        assert!(!page.heading.trim().is_empty() && page.heading.len() <= 32, "{page:?}");
        assert!(page.value.len() <= 128 && page.mono.len() <= 4096 && page.prose.len() <= 4096, "{page:?}");
        assert!(
            plain(&page.heading) && plain(&page.value) && lines(&page.mono) && lines(&page.prose),
            "{page:?}"
        );
        text += 4 + page.heading.len() + page.value.len() + page.mono.len() + page.prose.len();
    }
    assert!(text <= 16 * 1024, "{text} bytes");
}

#[test]
fn addresses_as_aptos_wallets_make_them() {
    let keys = keys();
    // the test phrase's accounts, as the SDK makes them (Account.fromDerivationPath), which is
    // Petra's and Ledger's way
    let accounts = json()["accounts"].as_array().unwrap().clone();
    assert_eq!(accounts.len(), 3);
    for account in accounts {
        let index = account["index"].as_u64().unwrap() as u32;
        assert_eq!(maki_hd::format_path(&path(index)), account["path"].as_str().unwrap());
        let key = keys.ed25519_public(&path(index)).unwrap();
        assert_eq!(key.to_vec(), unhex(account["publicKey"].as_str().unwrap()), "account {index}");
        assert_eq!(address(&address_of(&key)), account["address"].as_str().unwrap(), "account {index}");
    }
    assert_eq!(address(&address_of(&keys.ed25519_public(&path(0)).unwrap())), ME);
    // Aptos's own addresses are written short, every other in full, its zeros and all
    assert_eq!(address(&FRAMEWORK), "0x1");
    let mut ten = [0u8; 32];
    ten[31] = 10;
    assert_eq!(address(&ten), "0xa");
    let mut low = [0u8; 32];
    low[31] = 0x10;
    assert_eq!(address(&low), format!("0x{}10", "0".repeat(62)));
    assert_eq!(parse_address(ME), Some(me()));
    assert_eq!(parse_address(&ME.to_uppercase().replace("0X", "0x")), Some(me()));
    assert_eq!(parse_address("0x1"), Some(FRAMEWORK));
    assert_eq!(parse_address(&format!("0x{}1", "0".repeat(63))), Some(FRAMEWORK));
    // anything else isn't an address as AIP-40 writes one: no 0x, padded, short but not Aptos's own,
    // a digit too many or too few, not hex
    for bad in [
        &ME[2..],
        "0x01",
        "0x10",
        "0x",
        &ME[..65],
        &format!("{ME}0"),
        &ME.replace('e', "g"),
        "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3b ",
    ] {
        assert_eq!(parse_address(bad), None, "{bad}");
    }
    // every asset maki knows, on its own network alone
    let usdc = Asset::Fungible(a(USDC));
    assert_eq!(assets::known(Network::Mainnet, &usdc).map(|k| (k.symbol, k.decimals)), Some(("USDC", 6)));
    assert!(assets::known(Network::Testnet, &usdc).is_none(), "mainnet's USDC isn't the testnet's");
    assert_eq!(assets::known(Network::Testnet, &Asset::Apt).map(|k| k.symbol), Some("APT"));
    assert_eq!(assets::KNOWN.len(), 11);
}

/// The SDK's own unit tests' account (aptos-ts-sdk, packages/ts-sdk/tests/unit/helper.ts's `wallet`,
/// at commit 15f4d35): a phrase's key at m/44'/637'/0'/0'/0', and the address it makes. The same
/// key's `SingleKey` account (scheme 2, `Ed25519WalletTestObject` there) is another address, which
/// Petra and Ledger's app don't make: maki's account is the first.
#[test]
fn addresses_as_the_sdk_publishes_them() {
    let words: Vec<&str> = "shoot island position soft burden budget tooth cruel issue economy destroy above"
        .split(' ')
        .collect();
    let keys = SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap();
    let key = keys.ed25519_public(&path(0)).unwrap();
    assert_eq!(hex(&key), "ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c");
    assert_eq!(
        address(&address_of(&key)),
        "0x07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30"
    );
    let single_key = Sha3_256::new().chain_update([0, 32]).chain_update(key).chain_update([2]).finalize();
    assert_eq!(hex(&single_key), "28b829b524d7c24aa7fd8916573c814df766dae542f724e1cf8914536232c346");
}

#[test]
fn amounts_times_and_sizes() {
    assert_eq!(display::decimals(0, 8), "0");
    assert_eq!(display::decimals(1, 8), "0.00000001");
    assert_eq!(display::decimals(150_000_000, 8), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::apt(200_000), "0.002 APT");
    assert_eq!(display::apt(u64::MAX as u128), "184467440737.09551615 APT");
    assert_eq!(display::utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(display::utc(MADE + 20), "2026-10-02 04:00:20 UTC");
    assert_eq!(display::utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(display::utc(4_102_444_800), "2100-01-01 00:00:00 UTC");
    assert_eq!(display::utc(display::NEVER - 1), "9999-12-31 23:59:59 UTC");
    assert_eq!(display::utc(u64::MAX), "584554051223-11-09 07:00:15 UTC");
    assert_eq!(display::span(3 * 86_400), "3 days");
    assert_eq!(display::span(86_400 + 3_600), "1 day 1 hour");
    assert_eq!(display::span(5_400), "1 hour 30 minutes");
    assert_eq!(display::span(90), "1 minute 30 seconds");
    assert_eq!(display::span(20), "20 seconds");
    // what every signing message starts with
    assert_eq!(hex(&prefix()), "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193");
}

/// Keystone's firmware signs a transaction's signing message with the test phrase's key at
/// m/44'/637'/0'/0'/0' in its tests (keystone3-firmware, rust/apps/aptos/src/lib.rs's
/// `test_aptos_sign`, at commit 0c0ae46): maki must sign it the same.
#[test]
fn maki_signs_as_keystone_published() {
    let message = unhex(
        "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b193f007dbb60994463db95b80fad4259ec18767a5bb507f9e048da84b75ea793ef500000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e740e7472616e736665725f636f696e73010700000000000000000000000000000000000000000000000000000000000000010a6170746f735f636f696e094170746f73436f696e000220f007dbb60994463db95b80fad4259ec18767a5bb507f9e048da84b75ea793ef50800000000000000000a00000000000000640000000000000061242e650000000002",
    );
    let signature = keys().sign_ed25519(&path(0), &message).unwrap();
    assert_eq!(
        hex(&signature),
        "ff2c5e05557c30d1cddd505b26836747eaf28f25b2816b1e702bd40236be674eaaef10e4bd940b85317bede537cad22365eb7afca7456b90dcc2807cbbdcaa0a"
    );
    // a signing message: the prefix, then a testnet transaction of another account's
    assert_eq!(message[..32], prefix());
    let tx = Transaction::parse(&message[32..]).unwrap();
    assert_eq!(tx.chain_id, 2);
    assert_eq!(review(&tx, &me(), Network::Testnet, None), Err(Error::NotMine));
}

#[test]
fn maki_signs_what_the_sdk_signs() {
    let keys = keys();
    let key = keys.ed25519_public(&path(0)).unwrap();
    let transaction = Sha3_256::digest(b"APTOS::Transaction");
    let mut signed = 0;
    for f in fixtures() {
        // the signing message: the prefix, then the transaction
        assert_eq!(signing_message(&f.raw), f.message, "{}", f.name);
        let Some(expected) = f.signature else { continue };
        let signature = keys.sign_ed25519(&path(0), &f.message).unwrap();
        assert_eq!(signature.to_vec(), expected, "{}", f.name);
        // the transaction as Aptos's fullnodes take it, and its hash
        let whole = [f.raw.clone(), authenticator(&key, &signature).to_vec()].concat();
        assert_eq!(Some(whole.clone()), f.signed, "{}", f.name);
        let hash =
            Sha3_256::new().chain_update(transaction).chain_update([0]).chain_update(&whole).finalize();
        assert_eq!(Some(hash.to_vec()), f.hash, "{}", f.name);
        signed += 1;
    }
    assert_eq!(signed, 33);
}

#[test]
fn every_transaction_the_sdk_made_reads_as_it_should() {
    for f in fixtures() {
        let result = Transaction::parse(&f.raw)
            .map_err(|e| e.to_string())
            .and_then(|tx| review(&tx, &me(), f.network, None).map_err(|e| e.to_string()));
        let refused = |why: &str| assert_eq!(result, Err(String::from(why)), "{}", f.name);
        match f.name.as_str() {
            "not-mine" => refused("another account's transaction, not this one's to sign"),
            "rotate" => refused("it changes this account's key: maki won't sign that"),
            "offer-signer" => refused("it lets another act as this account: maki won't sign that"),
            "abstraction" => refused("it lets another's code sign for this account: maki won't sign that"),
            "multisig-convert" => {
                refused("it makes this account a multisig account, others' to control: maki won't sign that")
            }
            "script" => refused(
                "a script, code maki can't read that could do anything this account can: maki doesn't sign those",
            ),
            "multisig" => refused("a multisig account's transaction: maki doesn't sign those"),
            name => fits_the_screen(&result.unwrap_or_else(|e| panic!("{name}: {e}"))),
        }
    }
}

#[test]
fn apt_sent_and_the_fee() {
    let r = shown("apt");
    assert_eq!(r.pages, [network(), p("Send", "1.5 APT", RECIPIENT, ""), valid(), fee()]);
    assert_eq!(r.summary, "sends 1.5 APT; fee up to 0.002 APT");
    let tx = parsed("apt");
    assert_eq!((tx.sender, tx.replay, tx.chain_id), (me(), Replay::Sequence(7), 1));
    assert_eq!((tx.max_gas_amount, tx.gas_unit_price, tx.expiration), (2000, 100, MADE + 20));
    assert_eq!(tx.function.to_string(), "0x1::aptos_account::transfer");
    assert_eq!(
        tx.call,
        Call::Send {
            asset: Asset::Apt,
            payments: vec![Payment { to: a(RECIPIENT), amount: 150_000_000 }],
            batch: false
        }
    );
    // APT as a coin, as the SDK's own transfer sends it, as coin::transfer does, and as a fungible
    // asset
    assert_eq!(shown("apt-coins").pages[1], p("Send", "0.25 APT", RECIPIENT, ""));
    assert_eq!(shown("apt-coin-transfer").pages[1], p("Send", "1 APT", RECIPIENT, ""));
    assert_eq!(shown("apt-fa").pages[1], p("Send", "2 APT", RECIPIENT, ""));
    // to itself
    assert_eq!(shown("self").pages[1], p("Send", "1 APT", ME, "To this account itself."));
    // the SDK's most gas when it isn't told, which an account must hold to send it
    let r = shown("default-gas");
    assert_eq!(
        r.pages[3],
        p(
            "Max fee",
            "2 APT",
            "",
            "Up to 2000000 gas units, at 100 octas each. Aptos charges this account only for the gas it uses."
        )
    );
    assert_eq!(r.summary, "sends 1 APT; fee up to 2 APT");
}

#[test]
fn coins_and_fungible_assets_sent() {
    let r = shown("usdc");
    assert_eq!(r.pages, [network(), p("Send", "5.25 USDC", RECIPIENT, ""), valid(), fee()]);
    assert_eq!(r.summary, "sends 5.25 USDC; fee up to 0.002 APT");
    assert_eq!(shown("usdt").pages[1], p("Send", "100 USDT", RECIPIENT, ""));
    assert_eq!(shown("lzusdc").pages[1], p("Send", "5.25 lzUSDC", RECIPIENT, ""));
    // a coin maki doesn't know, in its smallest units, by its type
    let r = shown("coin-unknown");
    assert_eq!(
        r.pages[1..3],
        [
            p("Send", "42 units", RECIPIENT, "In its smallest units: maki doesn't know the coin."),
            p(
                "Coin",
                "one maki doesn't know",
                &format!("{ISSUER}::meme::MEME"),
                "Check its type: anyone can make a coin, and call it anything."
            )
        ]
    );
    assert_eq!(r.summary, "sends 42 units of a coin maki doesn't know; fee up to 0.002 APT");
    // a coin named as APT is, somewhere else: not APT
    let r = shown("coin-lookalike");
    assert_eq!(
        r.pages[1..3],
        [
            p("Send", "100000000 units", RECIPIENT, "In its smallest units: maki doesn't know the coin."),
            p(
                "Another APT!",
                "not the one maki knows",
                &format!("{ISSUER}::aptos_coin::AptosCoin"),
                "Anyone can make a coin and name it as APT is: this one isn't the APT maki knows."
            )
        ]
    );
    assert_eq!(r.summary, "not the APT maki knows!; fee up to 0.002 APT");
    // an asset maki doesn't know, by its metadata's address
    let r = shown("fa-unknown");
    assert_eq!(
        r.pages[1..3],
        [
            p("Send", "42 units", RECIPIENT, "In its smallest units: maki doesn't know the asset."),
            p(
                "Asset",
                "one maki doesn't know",
                ISSUER,
                "Check its address: anyone can make an asset, and call it anything."
            )
        ]
    );
    assert_eq!(r.summary, "sends 42 units of an asset maki doesn't know; fee up to 0.002 APT");
    // several at once
    let r = shown("batch-apt");
    assert_eq!(
        r.pages,
        [network(), p("Send", "1 APT", RECIPIENT, ""), p("Send", "2 APT", SECOND, ""), valid(), fee()]
    );
    assert_eq!(r.summary, "sends 3 APT in 2 payments; fee up to 0.002 APT");
    assert_eq!(shown("batch-usdc").summary, "sends 3.5 USDC in 2 payments; fee up to 0.002 APT");
    assert_eq!(shown("batch-lzusdt").pages[2], p("Send", "3 lzUSDT", SECOND, ""));
    // the test network's USDC, on the test network
    let r = shown_on("testnet-usdc", Network::Testnet);
    assert_eq!(
        r.pages[..2],
        [
            p("Network", "Aptos testnet", "", "Aptos's test network, whose APT is worth nothing."),
            p("Send", "1 USDC (testnet)", RECIPIENT, "")
        ]
    );
    assert_eq!(r.summary, "sends 1 USDC (testnet); fee up to 0.002 APT");
    assert_eq!(shown_on("testnet-apt", Network::Testnet).summary, "sends 1.5 APT; fee up to 0.002 APT");
}

#[test]
fn staking_with_a_delegation_pool() {
    let r = shown("stake");
    assert_eq!(
        r.pages,
        [
            network(),
            p(
                "Stake",
                "100 APT",
                POOL,
                "With that delegation pool: it stays this account's, and earns rewards. Getting it back takes unlocking it, then withdrawing it once the pool's lockup ends, within 14 days. While its validator is active, a fee of about one epoch's rewards is taken, and mostly made back by the epoch's end."
            ),
            valid(),
            fee()
        ]
    );
    assert_eq!(r.summary, "stakes 100 APT; fee up to 0.002 APT");
    let r = shown("unlock");
    assert_eq!(
        r.pages[1],
        p(
            "Unstake",
            "50 APT",
            POOL,
            "Unlocked from that delegation pool: it earns rewards until the pool's lockup ends, within 14 days, and can be withdrawn then. A pool keeps 10 APT at least of a delegator's staked and unlocked, so it may unlock a little more, or all of it."
        )
    );
    assert_eq!(r.summary, "unstakes 50 APT; fee up to 0.002 APT");
    let r = shown("reactivate");
    assert_eq!(
        r.pages[1],
        p(
            "Restake",
            "50 APT",
            POOL,
            "APT unlocked and not yet withdrawn, staked with that delegation pool again: it won't come free when the lockup ends, and goes on earning rewards."
        )
    );
    assert_eq!(r.summary, "restakes 50 APT; fee up to 0.002 APT");
    let r = shown("withdraw");
    assert_eq!(
        r.pages[1],
        p(
            "Withdraw",
            "50 APT",
            POOL,
            "Unlocked APT whose lockup has ended comes back to this account from that delegation pool, to spend."
        )
    );
    assert_eq!(r.summary, "withdraws 50 APT; fee up to 0.002 APT");
    assert_eq!(
        parsed("unlock").call,
        Call::Stake { action: Staking::Unlock, pool: a(POOL), amount: 5_000_000_000 }
    );
}

#[test]
fn objects_handed_over_and_calls_maki_cant_read() {
    let handed = "Whoever it goes to owns it, and everything it holds: maki can't see what that is.";
    let r = shown("nft");
    assert_eq!(r.pages[1], p("Hands over!", "a digital asset", &format!("{OBJECT}\nto {RECIPIENT}"), handed));
    assert_eq!(r.summary, "hands over a digital asset!; fee up to 0.002 APT");
    let r = shown("object");
    assert_eq!(r.pages[1], p("Hands over!", "an object", &format!("{OBJECT}\nto {RECIPIENT}"), handed));
    assert_eq!(r.summary, "hands over an object!; fee up to 0.002 APT");
    // an object of a type the call names, which isn't a digital asset's: the type said too
    let vault = struct_tag(&a(ISSUER), "vault", "Vault", &[]);
    let f = entry(&FRAMEWORK, "object", "transfer", &[vault], &[a(OBJECT).to_vec(), a(RECIPIENT).to_vec()]);
    let tx = Transaction::parse(&transaction(7, &calls(&f))).unwrap();
    assert_eq!(
        review(&tx, &me(), Network::Mainnet, None).unwrap().pages[1].prose,
        format!("{handed} Its type: {ISSUER}::vault::Vault.")
    );
    // a swap on an exchange maki doesn't know: its function, its types, its arguments' bytes
    let r = shown("swap");
    assert_eq!(
        r.pages,
        [
            network(),
            p(
                "Call",
                "maki can't read it",
                &format!(
                    "{DEX}::router::swap_exact_input<0x1::aptos_coin::AptosCoin, {ISSUER}::meme::MEME>\n1: 00e1f50500000000\n2: 40420f0000000000\n3: {}",
                    &RECIPIENT[2..]
                ),
                "maki can't tell what it does, or what its arguments mean. It may act as this account, and move anything this account holds."
            ),
            valid(),
            fee()
        ]
    );
    assert_eq!(r.summary, "maki can't read all of it; fee up to 0.002 APT");
}

#[test]
fn when_it_expires_says_so() {
    // an orderless transaction: a nonce in place of the sequence number
    let tx = parsed("orderless");
    assert_eq!(tx.replay, Replay::Nonce(7_777_777));
    assert_eq!(
        tx.call,
        Call::Send {
            asset: Asset::Apt,
            payments: vec![Payment { to: a(RECIPIENT), amount: 100_000_000 }],
            batch: false
        }
    );
    let orderless = "It's orderless: whoever has it can send it once before then, whatever else this account sends. Aptos takes it only in the 100 seconds before it expires.";
    assert_eq!(shown("orderless").pages[2], p("Valid until", "2026-10-02 04:00:20 UTC", "", orderless));
    // three days, and forever
    assert_eq!(shown("three-days").pages[2], p("Valid until", "2026-10-05 04:00:00 UTC", "", UNTIL));
    assert_eq!(
        shown("forever").pages[2],
        p(
            "No time limit",
            "never expires",
            "",
            "Whoever has it can send it whenever they like, unless this account sends another first."
        )
    );
    // by maki's clock: as made, nothing more to say; three days off; past; and an orderless one too
    // far off for Aptos to take it yet
    let at = |name: &str, now: u64| review(&parsed(name), &me(), Network::Mainnet, Some(now)).unwrap();
    assert_eq!(at("apt", MADE).pages[2], valid());
    let r = at("three-days", MADE);
    assert_eq!(
        r.pages[2],
        p(
            "Valid for",
            "3 days",
            "",
            "Whoever has it can send it until 2026-10-05 04:00:00 UTC, unless this account sends another first."
        )
    );
    assert_eq!(r.summary, "sends 1 APT; fee up to 0.002 APT");
    let r = at("apt", MADE + 20);
    assert_eq!(
        r.pages[2],
        p("Expired!", "2026-10-02 04:00:20 UTC", "", "That's past, by maki's clock: Aptos won't take it.")
    );
    assert_eq!(r.summary, "already expired!; fee up to 0.002 APT");
    assert_eq!(at("orderless", MADE).pages[2].heading, "Valid until");
    let r = at("orderless", MADE - 100);
    assert_eq!(
        r.pages[2],
        p(
            "Expires late!",
            "2026-10-02 04:00:20 UTC",
            "",
            "Aptos takes an orderless transaction only in the 100 seconds before it expires: whoever has this one can send it then, whatever else this account sends, and not before."
        )
    );
    assert_eq!(r.summary, "can only be sent later!; fee up to 0.002 APT");
    assert_eq!(at("forever", MADE).pages[2].heading, "No time limit");
}

/// BCS written by hand, for what the SDK wouldn't make.
#[derive(Clone, Default)]
struct Bcs(Vec<u8>);

impl Bcs {
    fn uleb(mut self, mut n: u64) -> Bcs {
        while n >= 0x80 {
            self.0.push(n as u8 | 0x80);
            n >>= 7;
        }
        self.0.push(n as u8);
        self
    }

    fn raw(mut self, b: &[u8]) -> Bcs {
        self.0.extend_from_slice(b);
        self
    }

    fn u64(self, n: u64) -> Bcs { self.raw(&n.to_le_bytes()) }

    fn bytes(self, b: &[u8]) -> Bcs { self.uleb(b.len() as u64).raw(b) }

    fn str(self, s: &str) -> Bcs { self.bytes(s.as_bytes()) }
}

/// A struct's type, with these type arguments.
fn struct_tag(address: &Address, module: &str, name: &str, args: &[Bcs]) -> Bcs {
    let mut b = Bcs::default().uleb(7).raw(address).str(module).str(name).uleb(args.len() as u64);
    for t in args {
        b = b.raw(&t.0);
    }
    b
}

/// A type that has no type arguments: its variant alone.
fn plain(variant: u64) -> Bcs { Bcs::default().uleb(variant) }

/// An entry function, called with these type arguments and arguments.
fn entry(address: &Address, module: &str, function: &str, types: &[Bcs], args: &[Vec<u8>]) -> Bcs {
    let mut b = Bcs::default().raw(address).str(module).str(function).uleb(types.len() as u64);
    for t in types {
        b = b.raw(&t.0);
    }
    b = b.uleb(args.len() as u64);
    for arg in args {
        b = b.bytes(arg);
    }
    b
}

/// The payload that calls it (`TransactionPayload::EntryFunction`).
fn calls(f: &Bcs) -> Bcs { Bcs::default().uleb(2).raw(&f.0) }

/// A transaction from this account, with this payload and fee, expiring when the fixtures do, on
/// mainnet.
fn transaction_with(sequence: u64, payload: &Bcs, max_gas: u64, price: u64) -> Vec<u8> {
    Bcs::default().raw(&me()).u64(sequence).raw(&payload.0).u64(max_gas).u64(price).u64(MADE + 20).raw(&[1]).0
}

fn transaction(sequence: u64, payload: &Bcs) -> Vec<u8> { transaction_with(sequence, payload, 2000, 100) }

fn u64_arg(n: u64) -> Vec<u8> { n.to_le_bytes().to_vec() }

/// 0x1::aptos_account::transfer, to the recipient.
fn transfer(amount: u64) -> Bcs {
    entry(&FRAMEWORK, "aptos_account", "transfer", &[], &[a(RECIPIENT).to_vec(), u64_arg(amount)])
}

fn refused(bytes: &[u8]) -> tx::Error { Transaction::parse(bytes).unwrap_err() }

#[test]
fn transactions_aptos_would_refuse_maki_refuses() {
    use tx::Error::*;
    let good = transaction(7, &calls(&transfer(150_000_000)));
    // written as the SDK writes it
    assert_eq!(good, fixture("apt"));
    // cut short, or with more after it, or longer than maki reads
    assert_eq!(refused(&good[..good.len() - 1]), Length);
    assert_eq!(refused(&[good.clone(), vec![0]].concat()), Length);
    assert_eq!(refused(&[0; tx::MAX_RAW + 1]), TooBig);
    assert_eq!(refused(&[]), Length);
    // a ULEB128 longer than it need be, or bigger than a u32
    let long = Bcs::default().raw(&[0x82, 0x00]).raw(&transfer(1).0);
    assert_eq!(refused(&transaction(7, &long)), Encoding);
    let mut huge = Bcs::default().raw(&FRAMEWORK).str("aptos_account").str("transfer").uleb(0).0;
    huge.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert_eq!(refused(&transaction(7, &Bcs::default().uleb(2).raw(&huge))), Encoding);
    // payloads maki doesn't sign, and kinds there aren't
    let script =
        "a script, code maki can't read that could do anything this account can: maki doesn't sign those";
    let multisig = "a multisig account's transaction: maki doesn't sign those";
    let encrypted = "an encrypted transaction, which maki can't read: maki doesn't sign those";
    let payload = |variant: u64| transaction(7, &Bcs::default().uleb(variant).raw(&transfer(1).0));
    assert_eq!(refused(&payload(0)), Unsupported(script));
    assert_eq!(refused(&payload(1)), Invalid("a module bundle, which Aptos no longer takes"));
    assert_eq!(refused(&payload(3)), Unsupported(multisig));
    assert_eq!(refused(&payload(5)), Unsupported(encrypted));
    assert_eq!(refused(&payload(6)), Unknown);
    // the newer form: an executable, a multisig account it's for (or none) and a nonce (or none)
    let newer = |inner: u64, executable: u64, config: u64, tail: &[u8]| {
        Bcs::default().uleb(4).uleb(inner).uleb(executable).raw(&transfer(1).0).uleb(config).raw(tail)
    };
    let tx = Transaction::parse(&transaction(7, &newer(0, 1, 0, &[0, 0]))).unwrap();
    assert_eq!(
        (tx.replay, tx.function.to_string()),
        (Replay::Sequence(7), String::from("0x1::aptos_account::transfer"))
    );
    let nonce = [&[0u8, 1][..], &42u64.to_le_bytes()].concat();
    assert_eq!(
        Transaction::parse(&transaction(u64::MAX, &newer(0, 1, 0, &nonce))).unwrap().replay,
        Replay::Nonce(42)
    );
    assert_eq!(
        refused(&transaction(7, &newer(0, 1, 0, &nonce))),
        Invalid("an orderless transaction with a sequence number: not as Aptos writes one")
    );
    let for_multisig = [&[1u8][..], &a(DEX), &[0]].concat();
    assert_eq!(refused(&transaction(7, &newer(0, 1, 0, &for_multisig))), Unsupported(multisig));
    assert_eq!(
        refused(&transaction(7, &newer(0, 1, 1, &[0, 0, 0]))),
        Unsupported("a transaction asking Aptos for higher limits: maki doesn't sign those")
    );
    assert_eq!(refused(&transaction(7, &newer(0, 1, 2, &[0, 0]))), Unknown);
    assert_eq!(refused(&transaction(7, &newer(0, 0, 0, &[0, 0]))), Unsupported(script));
    assert_eq!(
        refused(&transaction(7, &newer(0, 2, 0, &[0, 0]))),
        Unsupported("a transaction that runs nothing: maki doesn't sign those")
    );
    assert_eq!(refused(&transaction(7, &newer(0, 3, 0, &[0, 0]))), Unsupported(encrypted));
    assert_eq!(refused(&transaction(7, &newer(0, 4, 0, &[0, 0]))), Unknown);
    assert_eq!(refused(&transaction(7, &newer(1, 1, 0, &[0, 0]))), Unknown);
    // an option's tag that's neither 0 nor 1
    assert_eq!(refused(&transaction(7, &newer(0, 1, 0, &[2, 0]))), Encoding);
    // a sequence number no account has, and a fee too big to be a number
    assert_eq!(
        refused(&transaction(1 << 63, &calls(&transfer(1)))),
        Invalid("a sequence number too big for any account: Aptos would refuse it")
    );
    assert!(Transaction::parse(&transaction((1 << 63) - 1, &calls(&transfer(1)))).is_ok());
    assert_eq!(
        refused(&transaction_with(7, &calls(&transfer(1)), u64::MAX, 2)),
        Invalid("a fee too big to pay: Aptos would refuse it")
    );
    assert_eq!(
        Transaction::parse(&transaction_with(7, &calls(&transfer(1)), u64::MAX, 1)).unwrap().max_fee(),
        u64::MAX
    );
}

#[test]
fn names_and_types_aptos_would_refuse_maki_refuses() {
    use tx::Error::*;
    let named =
        |module: &str| Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), module, "go", &[], &[]))));
    // what Move's names may be: letters, digits, _ and $, not starting with a digit, and the names
    // scripts' modules have
    for good in ["a", "Z9", "_x", "$x", "a_b$c", "<SELF>", "<SELF>_12"] {
        assert!(named(good).is_ok(), "{good}");
    }
    for bad in ["", "_", "$", "1abc", "a-b", "a b", "é", "<SELF>_", "<SELF>_x", "<self>"] {
        assert_eq!(named(bad), Err(Identifier), "{bad}");
    }
    // types nested eight deep are what Aptos reads, nine aren't
    let nested = |depth: usize, outer: &dyn Fn(Bcs) -> Bcs| {
        let mut t = plain(1);
        for _ in 0..depth {
            t = outer(t);
        }
        Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), "m", "f", &[t], &[]))))
    };
    let vector = |t: Bcs| plain(6).raw(&t.0);
    let wrapped = |t: Bcs| struct_tag(&a(ISSUER), "box", "Box", &[t]);
    assert!(nested(8, &vector).is_ok());
    assert_eq!(nested(9, &vector), Err(Nesting));
    assert!(nested(8, &wrapped).is_ok());
    assert_eq!(nested(9, &wrapped), Err(Nesting));
    // a function's type, a type there isn't, a variant written long
    let typed = |t: Bcs| Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), "m", "f", &[t], &[]))));
    assert_eq!(
        typed(plain(11)),
        Err(Unsupported("a function's type as a type argument: maki can't show those"))
    );
    assert_eq!(typed(plain(18)), Err(Unknown));
    assert_eq!(typed(Bcs::default().raw(&[0x81, 0x00])), Err(Encoding));
    // every type maki shows, as Move writes them, in a call it can't read
    let types: Vec<Bcs> =
        [0, 1, 8, 9, 2, 3, 10, 12, 13, 14, 15, 16, 17, 4, 5].iter().map(|&v| plain(v)).collect();
    let mut all = types.clone();
    all.push(vector(plain(1)));
    all.push(struct_tag(&FRAMEWORK, "string", "String", &[]));
    all.push(struct_tag(
        &a(ISSUER),
        "pair",
        "Pair",
        &[plain(2), struct_tag(&FRAMEWORK, "aptos_coin", "AptosCoin", &[])],
    ));
    let tx =
        Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), "m", "f", &all, &[vec![1]])))).unwrap();
    let shown: Vec<String> = tx.function.type_args.iter().map(TypeTag::to_string).collect();
    assert_eq!(
        shown.join(", "),
        format!(
            "bool, u8, u16, u32, u64, u128, u256, i8, i16, i32, i64, i128, i256, address, signer, vector<u8>, 0x1::string::String, {ISSUER}::pair::Pair<u64, 0x1::aptos_coin::AptosCoin>"
        )
    );
    let r = review(&tx, &me(), Network::Mainnet, None).unwrap();
    assert!(r.pages[1].mono.starts_with(&format!("{DEX}::m::f<bool, u8, u16,")), "{}", r.pages[1].mono);
    assert!(r.pages[1].mono.ends_with(">\n1: 01"), "{}", r.pages[1].mono);
}

#[test]
fn calls_aptos_would_refuse_maki_refuses() {
    let arguments =
        tx::Error::Invalid("arguments that aren't what the function takes: Aptos would refuse it");
    let types =
        tx::Error::Invalid("type arguments that aren't what the function takes: Aptos would refuse it");
    let call = |module: &str, function: &str, t: &[Bcs], args: &[Vec<u8>]| {
        Transaction::parse(&transaction(7, &calls(&entry(&FRAMEWORK, module, function, t, args))))
    };
    let to = a(RECIPIENT).to_vec();
    // too few arguments, too many, an address a byte short, an amount a byte short
    assert_eq!(call("aptos_account", "transfer", &[], std::slice::from_ref(&to)), Err(arguments));
    assert_eq!(call("aptos_account", "transfer", &[], &[to.clone(), u64_arg(1), u64_arg(1)]), Err(arguments));
    assert_eq!(call("aptos_account", "transfer", &[], &[to[..31].to_vec(), u64_arg(1)]), Err(arguments));
    assert_eq!(
        call("aptos_account", "transfer", &[], &[to.clone(), u64_arg(1)[..7].to_vec()]),
        Err(arguments)
    );
    // type arguments it doesn't take, or not the one it does: a coin's type is a struct
    let apt = struct_tag(&FRAMEWORK, "aptos_coin", "AptosCoin", &[]);
    assert_eq!(
        call("aptos_account", "transfer", std::slice::from_ref(&apt), &[to.clone(), u64_arg(1)]),
        Err(types)
    );
    assert_eq!(call("aptos_account", "transfer_coins", &[], &[to.clone(), u64_arg(1)]), Err(types));
    assert_eq!(call("coin", "transfer", &[plain(1)], &[to.clone(), u64_arg(1)]), Err(types));
    assert_eq!(call("coin", "transfer", &[apt.clone(), apt.clone()], &[to.clone(), u64_arg(1)]), Err(types));
    assert_eq!(
        call(
            "primary_fungible_store",
            "transfer",
            &[plain(6).raw(&plain(1).0)],
            &[a(USDC).to_vec(), to.clone(), u64_arg(1)]
        ),
        Err(types)
    );
    assert!(call("coin", "transfer", std::slice::from_ref(&apt), &[to.clone(), u64_arg(1)]).is_ok());
    // several payments: as many recipients as amounts, each vector whole and nothing after it
    let recipients = |n: usize| Bcs::default().uleb(n as u64).raw(&to.repeat(n)).0;
    let amounts = |n: usize| Bcs::default().uleb(n as u64).raw(&u64_arg(1).repeat(n)).0;
    assert!(call("aptos_account", "batch_transfer", &[], &[recipients(3), amounts(3)]).is_ok());
    assert_eq!(
        call("aptos_account", "batch_transfer", &[], &[recipients(2), amounts(3)]),
        Err(tx::Error::Invalid("recipients and amounts that don't pair up: Aptos would refuse it"))
    );
    assert_eq!(
        call("aptos_account", "batch_transfer", &[], &[[recipients(2), vec![0]].concat(), amounts(2)]),
        Err(arguments)
    );
    assert_eq!(
        call("aptos_account", "batch_transfer", &[], &[recipients(2)[..60].to_vec(), amounts(2)]),
        Err(arguments)
    );
    assert_eq!(call("aptos_account", "batch_transfer", &[], &[vec![0x80, 0x00], amounts(0)]), Err(arguments));
    // no payments at all: Aptos does nothing, and maki says so
    let tx = call("aptos_account", "batch_transfer", &[], &[recipients(0), amounts(0)]).unwrap();
    let r = review(&tx, &me(), Network::Mainnet, None).unwrap();
    assert_eq!(r.pages[1], p("Nothing", "no payments", "", "It pays nothing but the fee."));
    assert_eq!(r.summary, "sends nothing; fee up to 0.002 APT");
    // a withdrawal of nothing, which the pool refuses; staking nothing, which it does nothing with
    let pool = a(POOL).to_vec();
    assert_eq!(
        call("delegation_pool", "withdraw", &[], &[pool.clone(), u64_arg(0)]),
        Err(tx::Error::Invalid("nothing withdrawn: Aptos would refuse it"))
    );
    let tx = call("delegation_pool", "add_stake", &[], &[pool.clone(), u64_arg(0)]).unwrap();
    assert_eq!(
        review(&tx, &me(), Network::Mainnet, None).unwrap().summary,
        "stakes 0 APT; fee up to 0.002 APT"
    );
    // an empty argument, which no type is
    let unknown = Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), "m", "f", &[], &[vec![]]))));
    assert_eq!(unknown, Err(tx::Error::Invalid("an empty argument: Aptos would refuse it")));
}

#[test]
fn what_maki_wont_sign() {
    // another account's, before anything else
    assert_eq!(review(&parsed("not-mine"), &me(), Network::Mainnet, None), Err(Error::NotMine));
    assert_eq!(review(&parsed("not-mine"), &me(), Network::Testnet, None), Err(Error::NotMine));
    // another network's: what the computer says the network is must be what the transaction says
    assert_eq!(
        review(&parsed("apt"), &me(), Network::Testnet, None),
        Err(Error::Invalid("a transaction for Aptos's own network, not its testnet"))
    );
    assert_eq!(
        review(&parsed("testnet-apt"), &me(), Network::Mainnet, None),
        Err(Error::Invalid("a transaction for Aptos's testnet, not its own network"))
    );
    let mut local = fixture("apt");
    *local.last_mut().unwrap() = 4;
    let local = Transaction::parse(&local).unwrap();
    assert_eq!(local.chain_id, 4);
    assert_eq!(
        review(&local, &me(), Network::Mainnet, None),
        Err(Error::Invalid("a transaction for another Aptos network"))
    );
    // whatever would change who controls this account, by any of Aptos's ways to
    let key = "it changes this account's key: maki won't sign that";
    let control = |module: &str, function: &str| {
        let tx = Transaction::parse(&transaction(
            7,
            &calls(&entry(&FRAMEWORK, module, function, &[], &[vec![0]])),
        ))
        .unwrap();
        review(&tx, &me(), Network::Mainnet, None).unwrap_err().to_string()
    };
    for function in [
        "rotate_authentication_key",
        "rotate_authentication_key_call",
        "rotate_authentication_key_from_public_key",
        "rotate_authentication_key_with_rotation_capability",
        "upsert_ed25519_backup_key_on_keyless_account",
        "upsert_ed25519_backup_key_and_encrypt_dk",
    ] {
        assert_eq!(control("account", function), key, "{function}");
    }
    assert_eq!(
        control("account", "offer_rotation_capability"),
        "it lets another change this account's key: maki won't sign that"
    );
    assert_eq!(
        control("account", "offer_signer_capability"),
        "it lets another act as this account: maki won't sign that"
    );
    assert_eq!(
        control("account_abstraction", "add_dispatchable_authentication_function"),
        "it lets another's code sign for this account: maki won't sign that"
    );
    for function in ["create_with_existing_account", "create_with_existing_account_and_revoke_auth_key"] {
        assert_eq!(
            control("multisig_account", function),
            "it makes this account a multisig account, others' to control: maki won't sign that"
        );
    }
    // the same names anywhere but Aptos's own modules are just calls maki can't read
    let tx = Transaction::parse(&transaction(
        7,
        &calls(&entry(&a(DEX), "account", "rotate_authentication_key_call", &[], &[vec![0]])),
    ))
    .unwrap();
    assert_eq!(tx.call, Call::Other);
    assert_eq!(
        review(&tx, &me(), Network::Mainnet, None).unwrap().summary,
        "maki can't read all of it; fee up to 0.002 APT"
    );
}

#[test]
fn the_most_a_review_shows_fits_the_screen() {
    // as many payments as a message from the computer can hold
    let mut n = 0;
    let mut most = Vec::new();
    loop {
        let recipients = Bcs::default().uleb(n + 1).raw(&a(RECIPIENT).repeat(n as usize + 1)).0;
        let amounts = Bcs::default().uleb(n + 1).raw(&u64::MAX.to_le_bytes().repeat(n as usize + 1)).0;
        let f = entry(
            &FRAMEWORK,
            "aptos_account",
            "batch_transfer_coins",
            &[struct_tag(&a(ISSUER), "meme", "MEME", &[])],
            &[recipients, amounts],
        );
        let tx = transaction(7, &calls(&f));
        if tx.len() > 4090 {
            break;
        }
        most = tx;
        n += 1;
    }
    let r = review(&Transaction::parse(&most).unwrap(), &me(), Network::Mainnet, Some(MADE)).unwrap();
    assert_eq!(r.pages.len(), n as usize + 4);
    fits_the_screen(&r);
    // a call maki can't read, with as many types and arguments as fit: shown as far as a page goes
    let long = vec![7u8; 100];
    let r = review(
        &Transaction::parse(&transaction(
            7,
            &calls(&entry(&a(DEX), "m", "f", &[], std::slice::from_ref(&long))),
        ))
        .unwrap(),
        &me(),
        Network::Mainnet,
        None,
    )
    .unwrap();
    assert_eq!(r.pages[1].mono, format!("{DEX}::m::f\n1: {}… (100 bytes)", "07".repeat(32)));
    let types: Vec<Bcs> = (0..60).map(|_| struct_tag(&a(ISSUER), "meme", "MEME", &[])).collect();
    let args: Vec<Vec<u8>> = (0..400).map(|_| vec![1]).collect();
    let tx = Transaction::parse(&transaction(7, &calls(&entry(&a(DEX), "m", "f", &types, &args)))).unwrap();
    let r = review(&tx, &me(), Network::Mainnet, None).unwrap();
    assert!(r.pages[1].mono.ends_with('…'));
    fits_the_screen(&r);
}
