//! maki-ada against Cardano's own libraries: transactions EMURGO's cardano-serialization-lib built
//! (`fixtures/make.mjs`), read as they are and shown as they should be, and signed by maki's keys
//! as CSL signs them with the same account (the test phrase's first, as Eternl, Lace and Yoroi make
//! it); addresses as CSL writes them and as CIP-19 publishes them. And what Cardano would refuse,
//! and what maki won't sign, written by hand, refused.

use maki_ada::address::{self, Credential, Kind, RewardAccount, Stake};
use maki_ada::body::{self, Body, Certificate, DRep, Datum};
use maki_ada::display::{self, Account, Error, Own, Page, Review, review};
use maki_ada::request::{self, Change, Key, Request};
use maki_ada::{Address, Hash28, Network, hex, key_hash, key_path, stake_path, tokens, tx_id};
use maki_hd::seed::SeedKeys;

/// The test phrase's first address, as Eternl, Lace, Yoroi and CSL make it (maki-hd's vectors).
const ME: &str =
    "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv";
const REWARDS: &str = "stake1u8j40zgr2gy4788kl54h6x3gu0pukq5lfr8nflufpg5dzaskqlx2l";
/// Where the fixtures send: the account of BIP39's "legal winner" phrase, and its other addresses.
const RECIPIENT: &str =
    "addr1qxttdu6d96klw8xvme7ctwuv0jg7xns0vm35ksv4l722aupyayzk39uascqj78hynwh3ax5w8ch5n9062k0vpnj3dlps3a8a9a";
const RECIPIENT_TEST: &str = "addr_test1qzttdu6d96klw8xvme7ctwuv0jg7xns0vm35ksv4l722aupyayzk39uascqj78hynwh3ax5w8ch5n9062k0vpnj3dlpsjt6afz";
const ENTERPRISE: &str = "addr1vxttdu6d96klw8xvme7ctwuv0jg7xns0vm35ksv4l722auqgh3swh";
const POINTER: &str = "addr1gxttdu6d96klw8xvme7ctwuv0jg7xns0vm35ksv4l722auypnz75xxcrvv3js6";
const BYRON: &str = "Ae2tdPwUPEZ9AUU2uP6wNsSt3x5D2ghYvPx7UYYHTbVUGuPNP3KY7inFeai";
const SCRIPT: &str =
    "addr1zx30qwmf5yz34fe9zcaazdmnsxxdgnjh7uqqtrxnur7dssfyayzk39uascqj78hynwh3ax5w8ch5n9062k0vpnj3dlps4dzhuh";
const POOL: &str = "pool1wpc8qurswpc8qurswpc8qurswpc8qurswpc8qurswpc8q524kv3";
const DREP: &str = "drep1ytgar5w368gar5w368gar5w368gar5w368gar5w368gar5g56c396";
const DREP_SCRIPT: &str = "drep1y02at4w46h2at4w46h2at4w46h2at4w46h2at4w46h2at4gcdtea8";
/// Mainnet's tip when the fixtures were made (2026-10-02 04:01:50 UTC): their slots count from it.
const TIP: u64 = 199_347_419;
const NOW: u64 = 1_790_913_710;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

struct Fixture {
    name: String,
    network: Network,
    body: Vec<u8>,
    hash: Vec<u8>,
    /// Each key that witnesses it: its role, index, public key and CSL's signature.
    witnesses: Vec<(u8, u32, Vec<u8>, Vec<u8>)>,
    change: Vec<Change>,
}

/// The transactions CSL built.
fn fixtures() -> Vec<Fixture> {
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: if f["network"] == "mainnet" { Network::Mainnet } else { Network::Preprod },
            body: unhex(f["body"].as_str().unwrap()),
            hash: unhex(f["hash"].as_str().unwrap()),
            witnesses: f["witnesses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| {
                    (
                        w["role"].as_u64().unwrap() as u8,
                        w["index"].as_u64().unwrap() as u32,
                        unhex(w["key"].as_str().unwrap()),
                        unhex(w["signature"].as_str().unwrap()),
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

/// The test phrase's keys, Cardano's made from its entropy (sixteen zeros), as maki makes them.
fn keys() -> SeedKeys {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let mut keys = SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap();
    keys.with_cardano(&maki_seed::to_entropy(&words).unwrap());
    keys
}

/// A key's public key, as maki gives it (the first half of key and chain code).
fn public(keys: &SeedKeys, path: &[u32]) -> [u8; 32] {
    keys.cardano_public(path).unwrap()[..32].try_into().unwrap()
}

/// Account 0, on `network`, as the app makes it from maki's keys.
fn account(keys: &SeedKeys, network: Network) -> Account {
    Account { network, stake: key_hash(&public(keys, &stake_path(0))) }
}

/// The change the computer says, with the keys maki makes for it.
fn own(keys: &SeedKeys, change: &[Change]) -> Vec<Own> {
    change
        .iter()
        .map(|c| Own {
            output: c.output,
            key: c.key,
            payment: key_hash(&public(keys, &key_path(0, c.key.role, c.key.index))),
        })
        .collect()
}

/// A fixture as maki would show it, by maki's clock (seconds since 1970) or without one.
fn shown_at(name: &str, now: Option<u64>) -> Result<Review, Error> {
    let keys = keys();
    let f = fixture(name);
    let body = Body::parse(&f.body).unwrap();
    review(&body, &account(&keys, f.network), &own(&keys, &f.change), f.witnesses.len(), now)
}

/// A fixture as maki shows it with its clock at the fixtures' time.
fn shown(name: &str) -> Review { shown_at(name, Some(NOW)).unwrap() }

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

fn network() -> Page { p("Network", "Cardano", "", "") }

fn fee(value: &str) -> Page {
    p(
        "Fee",
        value,
        "",
        "All it costs beyond what it pays: Cardano takes it only if the coins it spends, which maki can't see, add up exactly to what goes out.",
    )
}

fn change(value: &str, prose: &str) -> Page { p("Change", value, "", prose) }

const CHANGE_0: &str = "Back to this account: its change address #0.";

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
fn addresses_as_cardanos_wallets_make_them() {
    let keys = keys();
    let stake = key_hash(&public(&keys, &stake_path(0)));
    let base = |network, role, index| {
        Address::base(network, &key_hash(&public(&keys, &key_path(0, role, index))), &stake).text()
    };
    let a = &json()["addresses"];
    assert_eq!(base(Network::Mainnet, 0, 0), ME);
    assert_eq!(base(Network::Mainnet, 0, 0), a["base"]);
    assert_eq!(base(Network::Mainnet, 1, 0), a["change"]);
    assert_eq!(base(Network::Preprod, 0, 0), a["baseTest"]);
    assert_eq!(RewardAccount::new(Network::Mainnet, &stake).text(), REWARDS);
    assert_eq!(RewardAccount::new(Network::Mainnet, &stake).text(), a["reward"]);
    assert_eq!(RewardAccount::new(Network::Preprod, &stake).text(), a["rewardTest"]);
    assert_eq!(maki_hd::format_path(&key_path(3, 1, 7)), "m/1852'/1815'/3'/1/7");
    assert_eq!(maki_hd::format_path(&stake_path(0)), "m/1852'/1815'/0'/2/0");
    // every other kind CSL wrote, read and written again the same
    for (name, kind) in [
        ("recipient", "base"),
        ("recipientTest", "base"),
        ("enterprise", "enterprise"),
        ("pointer", "pointer"),
        ("byron", "byron"),
        ("byronTest", "byron"),
        ("script", "script"),
    ] {
        let text = a[name].as_str().unwrap();
        let address = Address::from_text(text).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(address.text(), text, "{name}");
        assert_eq!(Address::parse(&address.bytes).unwrap(), address);
        let is = match address.kind {
            Kind::Shelley { payment: Credential::Script(_), .. } => "script",
            Kind::Shelley { stake: Stake::Credential(_), .. } => "base",
            Kind::Shelley { stake: Stake::Pointer { .. }, .. } => "pointer",
            Kind::Shelley { stake: Stake::None, .. } => "enterprise",
            Kind::Byron { .. } => "byron",
        };
        assert_eq!(is, kind, "{name}");
        assert_eq!(address.network, (!name.ends_with("Test")) as u8, "{name}");
    }
    assert_eq!(Address::from_text(BYRON).unwrap().kind, Kind::Byron { magic: None });
    assert_eq!(
        Address::from_text(a["byronTest"].as_str().unwrap()).unwrap().kind,
        Kind::Byron { magic: Some(1) }
    );
    match Address::from_text(POINTER).unwrap().kind {
        Kind::Shelley { stake, .. } => assert_eq!(stake, Stake::Pointer { slot: 2_498_243, tx: 27, cert: 3 }),
        k => panic!("{k:?}"),
    }
    // pools' and DReps' IDs, CIP-129's
    assert_eq!(address::pool_id(&[0x70; 28]), POOL);
    assert_eq!(address::pool_id(&[0x70; 28]), a["pool"]);
    assert_eq!(address::drep_id(&Credential::Key([0xd1; 28])), DREP);
    assert_eq!(address::drep_id(&Credential::Key([0xd1; 28])), a["drep"]);
    assert_eq!(address::drep_id(&Credential::Script([0xd5; 28])), DREP_SCRIPT);
    // CIP-129's own vector
    assert_eq!(
        address::drep_id(&Credential::Key([0; 28])),
        "drep1ygqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq7vlc9n"
    );
    // a key's hash, as CSL hashed the first payment key for the address
    let payment = public(&keys, &key_path(0, 0, 0));
    assert_eq!(hex(&key_hash(&payment)), "0fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42");
}

/// CIP-19's test vectors: every kind of address, from its payment key, stake key, script and
/// pointer, on both networks.
#[test]
fn cip19s_test_vectors() {
    let decode = |text: &str, hrp: &str| {
        let (h, bytes) = address::from_bech32(text).unwrap();
        assert_eq!(h, hrp);
        bytes
    };
    let payment: Hash28 = key_hash(
        &decode("addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd", "addr_vk")
            .try_into()
            .unwrap(),
    );
    let stake: Hash28 = key_hash(
        &decode("stake_vk1px4j0r2fk7ux5p23shz8f3y5y2qam7s954rgf3lg5merqcj6aetsft99wu", "stake_vk")
            .try_into()
            .unwrap(),
    );
    let script: Hash28 =
        decode("script1cda3khwqv60360rp5m7akt50m6ttapacs8rqhn5w342z7r35m37", "script").try_into().unwrap();
    // the pointer (2498243, 27, 3), seven bits a byte, most significant first
    let pointer = [0x81, 0x98, 0xbd, 0x43, 0x1b, 0x03];
    let vectors = [
        (
            0x00u8,
            "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
        ),
        (
            0x10,
            "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh",
            "addr_test1zrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgsxj90mg",
        ),
        (
            0x20,
            "addr1yx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs2z78ve",
            "addr_test1yz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shsf5r8qx",
        ),
        (
            0x30,
            "addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g",
            "addr_test1xrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs4p04xh",
        ),
        (
            0x40,
            "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k",
            "addr_test1gz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrdw5vky",
        ),
        (
            0x50,
            "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu",
            "addr_test12rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcryqrvmw",
        ),
        (
            0x60,
            "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8",
            "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz",
        ),
        (
            0x70,
            "addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx",
            "addr_test1wrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcl6szpr",
        ),
    ];
    for (header, mainnet, testnet) in vectors {
        let kind = header >> 4;
        let first = if kind & 1 == 1 { script } else { payment };
        let second: &[u8] = match kind {
            0 | 1 => &stake,
            2 | 3 => &script,
            4 | 5 => &pointer,
            _ => &[],
        };
        for (network, text) in [(1u8, mainnet), (0, testnet)] {
            let bytes = [&[header | network][..], &first, second].concat();
            let a = Address::parse(&bytes).unwrap();
            assert_eq!(a.text(), text, "{header:02x}");
            assert_eq!(Address::from_text(text).unwrap().bytes, bytes, "{header:02x}");
        }
    }
    for (credential, mainnet, testnet) in [
        (
            Credential::Key(stake),
            "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw",
            "stake_test1uqehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gssrtvn",
        ),
        (
            Credential::Script(script),
            "stake178phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcccycj5",
            "stake_test17rphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcljw6kf",
        ),
    ] {
        for (network, text) in [(1, mainnet), (0, testnet)] {
            let a = RewardAccount { network, stake: credential };
            assert_eq!(a.text(), text);
            assert_eq!(RewardAccount::from_text(text), Some(a));
            assert_eq!(RewardAccount::parse(&a.bytes()), Ok(a));
        }
    }
}

#[test]
fn addresses_cardano_doesnt_have() {
    let me = Address::from_text(ME).unwrap().bytes;
    let refused = |b: &[u8]| Address::parse(b).unwrap_err();
    // a network the low bit alone doesn't name, a header bit for networks that aren't yet
    for header in [0x02u8, 0x03, 0x05, 0x0f] {
        assert_eq!(refused(&[&[header][..], &me[1..]].concat()), maki_ada::Error::Address, "{header:02x}");
    }
    // a base address cut short or with more after it; an enterprise one with a stake part
    assert_eq!(refused(&me[..56]), maki_ada::Error::Address);
    assert_eq!(refused(&[&me[..], &[0]].concat()), maki_ada::Error::Address);
    assert_eq!(refused(&[&[0x61][..], &me[1..]].concat()), maki_ada::Error::Address);
    assert_eq!(refused(&[]), maki_ada::Error::Address);
    // a reward account's header, which an output can't pay (its high bit makes it Byron's, which it
    // isn't)
    let reward = RewardAccount::from_text(REWARDS).unwrap().bytes();
    assert_eq!(refused(&reward), maki_ada::Error::Address);
    assert!(RewardAccount::parse(&me).is_err());
    assert!(RewardAccount::parse(&reward[..28]).is_err());
    // pointers: a slot past 32 bits, a transaction's index past 16, a number that never ends, more
    // after it; the ledger's own odd forms (a leading zero group) still taken
    let pointer = |tail: &[u8]| [&[0x41][..], &me[1..29], tail].concat();
    assert!(Address::parse(&pointer(&[0x01, 0x02, 0x03])).is_ok());
    assert!(Address::parse(&pointer(&[0x80, 0x01, 0x02, 0x03])).is_ok());
    assert!(Address::parse(&pointer(&[0x8f, 0xff, 0xff, 0xff, 0x7f, 0x02, 0x03])).is_ok());
    assert!(Address::parse(&pointer(&[0x90, 0x80, 0x80, 0x80, 0x00, 0x02, 0x03])).is_err());
    assert!(Address::parse(&pointer(&[0x01, 0x83, 0xff, 0x7f, 0x03])).is_ok());
    assert!(Address::parse(&pointer(&[0x01, 0x84, 0x80, 0x00, 0x03])).is_err());
    assert!(Address::parse(&pointer(&[0x01, 0x02])).is_err());
    assert!(Address::parse(&pointer(&[0x01, 0x02, 0x83])).is_err());
    assert!(Address::parse(&pointer(&[0x01, 0x02, 0x03, 0x04])).is_err());
    // Byron's: its checksum, its shape
    let byron = Address::from_text(BYRON).unwrap().bytes;
    let mut wrong = byron.clone();
    let last = wrong.len() - 1;
    wrong[last] ^= 1;
    assert!(Address::parse(&wrong).is_err());
    assert!(Address::parse(&byron[..byron.len() - 1]).is_err());
    // text: a character changed, uppercase, another prefix, a Shelley address in base58 and a Byron
    // one in bech32
    let mut changed = String::from(ME);
    changed.replace_range(20..21, "x");
    assert!(Address::from_text(&changed).is_none());
    assert!(Address::from_text(&ME.to_uppercase()).is_none());
    assert!(Address::from_text(REWARDS).is_none());
    assert!(Address::from_text(&address::bech32("addr_test", &me)).is_none(), "mainnet's, as a test address");
    assert!(Address::from_text(&address::bech32("addr", &byron)).is_none());
    assert!(Address::from_text("0OIl").is_none());
    assert!(RewardAccount::from_text(&address::bech32("stake", &me)).is_none());
}

#[test]
fn amounts_times_and_names() {
    assert_eq!(display::decimals(0, 6), "0");
    assert_eq!(display::decimals(1, 6), "0.000001");
    assert_eq!(display::decimals(1_500_000, 6), "1.5");
    assert_eq!(display::decimals(42, 0), "42");
    assert_eq!(display::ada(168_581, Network::Mainnet), "0.168581 ADA");
    assert_eq!(display::ada(maki_ada::MAX_LOVELACE, Network::Preprod), "45000000000 tADA");
    assert_eq!(display::ada(u64::MAX, Network::Mainnet), "18446744073709.551615 ADA");
    // slots and times, as Koios had the tips: mainnet's, Preprod's, and Byron's twenty seconds
    assert_eq!(Network::Mainnet.slot_time(TIP), NOW);
    assert_eq!(Network::Mainnet.slot_at(NOW), TIP);
    assert_eq!(Network::Preprod.slot_time(135_230_479), 1_790_913_679);
    assert_eq!(Network::Preprod.slot_at(1_790_913_679), 135_230_479);
    assert_eq!(Network::Mainnet.slot_time(4_492_800), 1_596_059_091);
    assert_eq!(Network::Mainnet.slot_time(4_492_799), 1_596_059_071);
    assert_eq!(Network::Mainnet.slot_time(0), 1_506_203_091);
    assert_eq!(Network::Mainnet.slot_time(u64::MAX), u64::MAX);
    assert_eq!(display::utc(NOW), "2026-10-02 04:01:50 UTC");
    assert_eq!(display::utc(951_782_400), "2000-02-29 00:00:00 UTC");
    assert_eq!(display::utc(u64::MAX), "584554051223-11-09 07:00:15 UTC");
    assert_eq!(display::span(3 * 86_400), "3 days");
    assert_eq!(display::span(86_400 + 3_600), "1 day 1 hour");
    assert_eq!(display::span(5_400), "1 hour 30 minutes");
    assert_eq!(display::span(30), "30 seconds");
    // CIP-67's test vectors: a label, its checksum
    for (label, bytes) in [
        (0u16, "00000000"),
        (1, "00001070"),
        (23, "00017650"),
        (99, "000632e0"),
        (533, "00215410"),
        (2000, "007d0550"),
        (4567, "011d7690"),
        (11111, "02b670b0"),
        (49328, "0c0b0f40"),
        (65535, "0ffff240"),
    ] {
        assert_eq!(display::label(&unhex(bytes)), Some((label, &[][..])), "{label}");
    }
    assert_eq!(display::label(&unhex("000de140aa")), Some((222, &[0xaa][..])));
    assert_eq!(display::label(&unhex("000de141")), None, "a bracket that isn't zero");
    assert_eq!(display::label(&unhex("000de150")), None, "a checksum that isn't the label's");
    assert_eq!(display::label(&unhex("000de1")), None);
    // names: text, a label and text, bytes, none
    assert_eq!(display::asset_name(b"HOSKY").0, "HOSKY");
    assert_eq!(display::asset_name(&unhex("0014df105553444d")).0, "(333) USDM");
    assert_eq!(display::asset_name(&unhex("000de140")).0, "000de140", "a label and no text");
    assert_eq!(display::asset_name(&unhex("de0a00ff")).0, "de0a00ff");
    assert_eq!(display::asset_name(b"tab\there").0, "7461620968657265");
    assert_eq!(display::asset_name(b"").0, "");
    // the tokens maki knows, and on Cardano's own network alone
    let usdm = tokens::TOKENS.iter().find(|t| t.symbol == "USDM").unwrap();
    assert_eq!(hex(&usdm.policy), "c48cbb3d5e57ed56e276bc45f99ab39abe94e6cd7ac39fb402da47ad");
    assert_eq!(hex(usdm.name), "0014df105553444d");
    assert!(tokens::known(Network::Mainnet, &usdm.policy, usdm.name).is_some());
    assert!(tokens::known(Network::Preprod, &usdm.policy, usdm.name).is_none());
    assert!(tokens::known(Network::Mainnet, &usdm.policy, b"USDM").is_none(), "another name, another token");
}

#[test]
fn maki_signs_what_csl_signs() {
    let keys = keys();
    let mut signed = 0;
    for f in fixtures() {
        // the transaction's ID is what's signed: the BLAKE2b-256 of the body as it goes on chain
        assert_eq!(tx_id(&f.body).to_vec(), f.hash, "{}", f.name);
        for (role, index, key, signature) in &f.witnesses {
            let path = key_path(0, *role, *index);
            assert_eq!(public(&keys, &path).to_vec(), *key, "{}", f.name);
            assert_eq!(keys.sign_cardano(&path, &tx_id(&f.body)).unwrap().to_vec(), *signature, "{}", f.name);
            signed += 1;
        }
    }
    assert_eq!(signed, 54);
}

/// What maki refuses of the fixtures, and why.
const REFUSED: &[(&str, &str)] = &[
    ("collateral", "a transaction that runs Plutus scripts: maki doesn't sign those"),
    ("required-signer", "a transaction with required signers, for scripts: maki doesn't sign those"),
    ("reference-input", "a transaction that refers to scripts or data on chain: maki doesn't sign those"),
    ("pool-retirement", "a stake pool's retirement: maki doesn't sign those"),
    ("drep-registration", "a DRep's registration: maki doesn't sign those"),
    ("voting", "votes on Cardano's governance: maki doesn't sign those"),
    ("proposal", "governance proposals: maki doesn't sign those"),
    ("their-delegation", "a certificate for another stake key than this account's"),
    ("their-withdrawal", "a withdrawal of rewards that aren't this account's"),
];

#[test]
fn every_transaction_csl_made_reads_as_it_should() {
    let keys = keys();
    for f in fixtures() {
        let result = Body::parse(&f.body).map_err(|e| e.to_string()).and_then(|body| {
            review(&body, &account(&keys, f.network), &own(&keys, &f.change), f.witnesses.len(), Some(NOW))
                .map_err(|e| e.to_string())
        });
        match REFUSED.iter().find(|(name, _)| *name == f.name) {
            Some((_, why)) => assert_eq!(result, Err(why.to_string()), "{}", f.name),
            None => fits_the_screen(&result.unwrap_or_else(|e| panic!("{}: {e}", f.name))),
        }
    }
}

#[test]
fn payments_and_change() {
    let r = shown("payment");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "1.5 ADA", RECIPIENT, ""),
            change("8.331419 ADA", CHANGE_0),
            fee("0.168581 ADA")
        ]
    );
    assert_eq!(r.summary, "sends 1.5 ADA; fee 0.168581 ADA");
    let body = Body::parse(&fixture("payment").body).unwrap();
    assert_eq!(body.inputs, [body::Input { tx: [0x10; 32], index: 0 }]);
    assert_eq!((body.fee, body.ttl, body.tagged, body.size), (168_581, Some(TIP + 7200), true, 186));
    // three payments, to an enterprise address, a Byron one and a pointer
    let r = shown("two-keys");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send 1/3", "2 ADA", ENTERPRISE, ""),
            p("Send 2/3", "1.2 ADA", BYRON, "A Byron address, from Cardano's first years."),
            p(
                "Send 3/3",
                "1 ADA",
                POINTER,
                "A pointer address, an old kind: it names its stake key by where that was registered on chain."
            ),
            change("2.822487 ADA", "Back to this account: its change address #1."),
            fee("0.177513 ADA")
        ]
    );
    assert_eq!(r.summary, "sends 4.2 ADA in 3 payments; fee 0.177513 ADA");
    // on Preprod: test ADA
    let r = shown_at("preprod", None).unwrap();
    assert_eq!(
        r.pages,
        [
            p("Network", "Preprod (test)", "", "Cardano's test network, whose ADA is worth nothing."),
            p("Send", "1.5 tADA", RECIPIENT_TEST, ""),
            change("8.331419 tADA", CHANGE_0),
            p(
                "Valid until",
                "2026-10-02 06:01:19 UTC",
                "",
                "Slot 135237679: maki can't tell how far off that is, without the time."
            ),
            fee("0.168581 tADA")
        ]
    );
    assert_eq!(r.summary, "sends 1.5 tADA; fee 0.168581 tADA");
    // change the computer doesn't claim is a payment, to the account's own address, shown in full
    let keys = keys();
    let f = fixture("payment");
    let body = Body::parse(&f.body).unwrap();
    let r = review(&body, &account(&keys, Network::Mainnet), &[], 1, Some(NOW)).unwrap();
    let mine = Address::base(
        Network::Mainnet,
        &key_hash(&public(&keys, &key_path(0, 1, 0))),
        &key_hash(&public(&keys, &stake_path(0))),
    );
    assert_eq!(r.pages[2], p("Send 2/2", "8.331419 ADA", &mine.text(), ""));
    assert_eq!(r.summary, "sends 9.831419 ADA in 2 payments; fee 0.168581 ADA");
    // seventy payments, a body bigger than one of maki's messages
    let r = shown("seventy");
    assert_eq!(r.pages.len(), 73);
    assert_eq!(r.pages[70], p("Send 70/70", "1.00007 ADA", RECIPIENT, ""));
    assert_eq!(r.pages[71], change("49.619494 ADA", "Back to this account: its change address #4."));
    assert_eq!(r.summary, "sends 70.002485 ADA in 70 payments; fee 0.378021 ADA");
    fits_the_screen(&r);
}

#[test]
fn tokens_by_policy_and_name() {
    let policy = "a2f03b69a1051aa725163bd13773818cd44e57f700058cd3e0fcd841";
    let unknown = "A token maki doesn't know, in its smallest units:";
    let r = shown("tokens");
    assert_eq!(
        r.pages,
        [
            network(),
            p("Send", "2 ADA", RECIPIENT, "And 6 tokens, on the next pages."),
            p("Send: token", "5 units", &"7f".repeat(28), &format!("{unknown} its policy (it has no name).")),
            p("Send: token", "1000 HOSKY", "", ""),
            p(
                "Send: token",
                "42 units",
                &format!("{policy}\nMAKI"),
                &format!("{unknown} its policy, then its name.")
            ),
            p(
                "Send: token",
                "1 unit",
                &format!("{policy}\nde0a00ff"),
                &format!("{unknown} its policy, then its name in hex.")
            ),
            p(
                "Send: token",
                "7 units",
                &format!("{policy}\n(333) BADGE"),
                &format!("{unknown} its policy, then its name (CIP-67's label, then text).")
            ),
            p("Send: token", "5.25 USDM", "", ""),
            change("17.815975 ADA", "Back to this account: its change address #0, with 4 tokens."),
            fee("0.184025 ADA")
        ]
    );
    assert_eq!(r.summary, "sends 2 ADA and 6 tokens; fee 0.184025 ADA");
    // as read: each policy's tokens, in CIP-21's order (a shorter name first)
    let body = Body::parse(&fixture("tokens").body).unwrap();
    let names: Vec<Vec<u8>> = body.outputs[0].tokens[2].tokens.iter().map(|t| t.name.clone()).collect();
    assert_eq!(names, [b"MAKI".to_vec(), unhex("de0a00ff"), unhex("0014df104241444745")]);
    assert_eq!(body.outputs[1].tokens.len(), 4);
}

#[test]
fn staking_rewards_and_votes() {
    let register = "This account's stake key, so it can delegate and earn rewards. The deposit comes back when the key is deregistered.";
    let delegate = p(
        "Delegate",
        "to a stake pool",
        POOL,
        "This account's stake counts toward that pool, which earns it rewards; its ADA stays its own, to spend. Check the pool's ID.",
    );
    let r = shown("delegation");
    assert_eq!(
        r.pages,
        [
            network(),
            change("7.825083 ADA", CHANGE_0),
            p("Register", "2 ADA deposit", "", register),
            delegate.clone(),
            fee("0.174917 ADA")
        ]
    );
    assert_eq!(r.summary, "registers its stake key, delegates to a pool; fee 0.174917 ADA");
    let body = Body::parse(&fixture("delegation").body).unwrap();
    assert_eq!(
        body.certificates[1],
        Certificate::Delegate {
            stake: Credential::Key(account(&keys(), Network::Mainnet).stake),
            pool: [0x70; 28]
        }
    );
    // Shelley's registration, which doesn't say its deposit
    assert_eq!(
        shown("delegation-shelley").pages[2],
        p(
            "Register",
            "key deposit",
            "",
            "This account's stake key, so it can delegate and earn rewards. It pays Cardano's key deposit (2 ADA as of 2026), which this kind of certificate doesn't state: it comes back when the key is deregistered."
        )
    );
    let r = shown("withdrawal");
    assert_eq!(
        r.pages[1..3],
        [
            change("17.173841 ADA", CHANGE_0),
            p(
                "Withdraw",
                "12.345678 ADA",
                "",
                "This account's rewards, taken into this transaction: they go where its outputs say."
            )
        ]
    );
    assert_eq!(r.summary, "withdraws 12.345678 ADA of rewards; fee 0.171837 ADA");
    for (name, value, mono, prose) in [
        (
            "vote",
            "to a DRep",
            DREP,
            "That DRep votes as this account's stake on Cardano's governance; its ADA stays its own. Check the DRep's ID.",
        ),
        (
            "vote-script",
            "to a script DRep",
            DREP_SCRIPT,
            "A script decides how that DRep votes, as this account's stake, on Cardano's governance; its ADA stays its own. Check the DRep's ID.",
        ),
        (
            "vote-abstain",
            "always abstain",
            "",
            "This account's stake abstains from every vote on Cardano's governance; its ADA stays its own.",
        ),
        (
            "vote-no-confidence",
            "no confidence",
            "",
            "This account's stake votes no confidence in Cardano's constitutional committee, on every vote it can; its ADA stays its own.",
        ),
    ] {
        let r = shown(name);
        assert_eq!(r.pages[2], p("Delegate votes", value, mono, prose), "{name}");
        assert!(r.summary.starts_with("delegates its votes; fee "), "{name}");
    }
    let deregister = "This account's stake key: it stops earning rewards, and its delegation and votes end. Its deposit comes back into this transaction, to go where its outputs say.";
    let r = shown("deregistration");
    assert_eq!(r.pages[2], p("Deregister", "2 ADA back", "", deregister));
    assert_eq!(r.pages[3].value, "1.234567 ADA");
    assert_eq!(r.summary, "deregisters its stake key, withdraws 1.234567 ADA of rewards; fee 0.173773 ADA");
    assert_eq!(shown("deregistration-shelley").pages[2], p("Deregister", "deposit back", "", deregister));
    // Conway's certificates that do more than one thing, each thing on a page
    let headings =
        |name: &str| -> Vec<String> { shown(name).pages.iter().map(|p| p.heading.clone()).collect() };
    assert_eq!(headings("delegate-and-vote")[2..4], ["Delegate", "Delegate votes"]);
    assert_eq!(headings("register-and-delegate")[2..4], ["Register", "Delegate"]);
    assert_eq!(headings("register-and-vote")[2..4], ["Register", "Delegate votes"]);
    assert_eq!(headings("register-delegate-and-vote")[2..5], ["Register", "Delegate", "Delegate votes"]);
    let r = shown("register-delegate-and-vote");
    assert_eq!(r.pages[2].value, "2 ADA deposit");
    assert_eq!(r.pages[4].mono, DREP_SCRIPT);
    assert_eq!(
        r.summary,
        "registers its stake key, delegates to a pool, delegates its votes; fee 0.174829 ADA"
    );
}

#[test]
fn mints_donations_metadata_and_scripts() {
    let mine = "f0b04391174930199b53a76217fab964ce4532a63ffee37e3c04728c\nMAKI";
    let unknown = "A token maki doesn't know, in its smallest units: its policy, then its name.";
    let r = shown("mint");
    assert_eq!(
        r.pages[1..5],
        [
            p("Send", "1.14646 ADA", RECIPIENT, "And a token, on the next page."),
            p("Send: token", "1000 units", mine, unknown),
            change("8.679723 ADA", CHANGE_0),
            p(
                "Mint",
                "1000 units",
                mine,
                &format!("New tokens under its policy: where they go, the outputs say. {unknown}")
            )
        ]
    );
    assert_eq!(r.summary, "sends 1.14646 ADA and a token, mints tokens; fee 0.173817 ADA");
    let r = shown("burn");
    assert_eq!(
        r.pages[2],
        p(
            "Burn",
            "10 units",
            mine,
            &format!("Tokens destroyed for good, out of what this transaction spends. {unknown}")
        )
    );
    assert_eq!(r.summary, "burns tokens!; fee 0.169065 ADA");
    let r = shown("donation");
    assert_eq!(r.pages[2], p("Donate", "1 ADA", "", "To Cardano's treasury, for good."));
    assert_eq!(r.summary, "donates 1 ADA to the treasury!; fee 0.165985 ADA");
    let r = shown("treasury");
    assert_eq!(
        r.pages[2],
        p(
            "Treasury",
            "1700000000 ADA",
            "",
            "Cardano takes it only while its treasury holds exactly this: a check, nothing paid."
        )
    );
    assert_eq!(r.summary, "sends only change; fee 0.166161 ADA");
    let r = shown("metadata");
    assert_eq!(
        r.pages[3],
        p(
            "Metadata",
            "maki can't read it",
            "",
            "It carries data maki isn't shown, for anyone to read on chain: a message, or something an app reads. Only its hash is in what's signed."
        )
    );
    assert_eq!(r.summary, "sends 1.5 ADA, with metadata; fee 0.171485 ADA");
    assert_eq!(Body::parse(&fixture("network-id").body).unwrap().network, Some(1));
    assert_eq!(shown("network-id").pages, shown("payment").pages);
    // what's for scripts: an inline datum, a datum's hash, neither (which may lock it for good), and
    // a script to refer to
    let script = "A script's address: what can be done with what's sent there is up to the script, which maki can't read.";
    let r = shown("scripts");
    assert_eq!(
        r.pages[1..5],
        [
            p("Send 1/4", "3 ADA", SCRIPT, &format!("{script} With 2 bytes of data for a script to read.")),
            p("Send 2/4", "2 ADA", SCRIPT, &format!("{script} With a datum's hash, for a script to read.")),
            p(
                "Send 3/4",
                "2 ADA",
                SCRIPT,
                &format!(
                    "{script} Without a datum: a Plutus V1 or V2 script can never spend it, nor anyone else."
                )
            ),
            p("Send 4/4", "2 ADA", RECIPIENT, "With a script any transaction can use from here (34 bytes).")
        ]
    );
    assert_eq!(r.summary, "may lock ADA in a script for good!; fee 0.180901 ADA");
    let body = Body::parse(&fixture("scripts").body).unwrap();
    assert_eq!(body.outputs[0].datum, Some(Datum::Inline(2)));
    assert!(matches!(body.outputs[1].datum, Some(Datum::Hash(_))));
    assert_eq!((body.outputs[2].datum, body.outputs[3].script), (None, Some(34)));
    assert!(body.outputs[2].pays_script() && !body.outputs[3].pays_script());
}

#[test]
fn when_its_valid_out_of_the_ordinary_says_so() {
    // two hours, as wallets make them: nothing to say
    let r = shown("payment");
    assert!(
        r.pages
            .iter()
            .all(|p| !["Valid until", "Valid for", "Expired!", "Not before"].contains(&p.heading.as_str()))
    );
    assert_eq!(
        shown("no-ttl").pages[3],
        p(
            "Valid until",
            "no limit",
            "",
            "Whoever has it can send it at any time, as long as the coins it spends haven't been."
        )
    );
    assert_eq!(
        shown("three-days").pages[3],
        p(
            "Valid for",
            "3 days",
            "",
            "Whoever has it can send it until 2026-10-05 04:01:50 UTC (slot 199606619)."
        )
    );
    // expired, by maki's clock
    let r = shown_at("payment", Some(NOW + 7200)).unwrap();
    assert_eq!(
        r.pages[3],
        p(
            "Expired!",
            "2026-10-02 06:01:50 UTC",
            "",
            "It was valid until slot 199354619, which is past by maki's clock: Cardano won't take it."
        )
    );
    assert_eq!(r.summary, "already expired!; fee 0.168581 ADA");
    assert!(shown_at("payment", Some(NOW + 7199)).unwrap().pages.iter().all(|p| p.heading != "Expired!"));
    // from tomorrow, for an hour; from a minute ago (nothing to say)
    assert_eq!(
        shown("valid-later").pages[3..5],
        [
            p(
                "Valid for",
                "1 day 1 hour",
                "",
                "Whoever has it can send it until 2026-10-03 05:01:50 UTC (slot 199437419)."
            ),
            p(
                "Not before",
                "2026-10-03 04:01:50 UTC",
                "",
                "Cardano takes it only from slot 199433819: whoever has it can send it then."
            )
        ]
    );
    assert_eq!(shown("valid-from").pages.len(), 4);
    // without a clock, said as it is
    let r = shown_at("valid-from", None).unwrap();
    assert_eq!(
        r.pages[3..5],
        [
            p(
                "Valid until",
                "2026-10-02 06:01:50 UTC",
                "",
                "Slot 199354619: maki can't tell how far off that is, without the time."
            ),
            p(
                "Valid from",
                "2026-10-02 04:00:50 UTC",
                "",
                "Slot 199347359: Cardano takes it only from then."
            )
        ]
    );
}

#[test]
fn what_maki_wont_sign() {
    let keys = keys();
    let refused = |name: &str| Body::parse(&fixture(name).body).unwrap_err();
    assert_eq!(refused("collateral"), maki_ada::Error::Unsupported("a transaction that runs Plutus scripts"));
    assert_eq!(refused("voting"), maki_ada::Error::Unsupported("votes on Cardano's governance"));
    // another account's stake: its delegation, its rewards
    let shown = |name: &str, network| {
        let f = fixture(name);
        review(&Body::parse(&f.body).unwrap(), &account(&keys, network), &own(&keys, &f.change), 1, None)
    };
    assert_eq!(
        shown("their-delegation", Network::Mainnet),
        Err(Error::NotMine("a certificate for another stake key than this account's"))
    );
    assert_eq!(
        shown("their-withdrawal", Network::Mainnet),
        Err(Error::NotMine("a withdrawal of rewards that aren't this account's"))
    );
    // for another network than maki's told: mainnet's said to be a test network's (real money
    // passed off as play money), and Preprod's said to be mainnet's
    assert_eq!(
        shown("payment", Network::Preprod),
        Err(Error::Network("for Cardano's own network, not a test network"))
    );
    assert_eq!(
        shown("preprod", Network::Mainnet),
        Err(Error::Network("for a test network, not Cardano's own"))
    );
    assert_eq!(
        shown("network-id", Network::Preprod),
        Err(Error::Network("for Cardano's own network, not a test network"))
    );
    assert_eq!(
        shown("withdrawal", Network::Preprod),
        Err(Error::Network("for Cardano's own network, not a test network"))
    );
    // change that isn't: another index's key, the receiving chain's, a payment's output, one it
    // doesn't have
    let f = fixture("payment");
    let body = Body::parse(&f.body).unwrap();
    let me = account(&keys, Network::Mainnet);
    let claim = |output, role, index| own(&keys, &[Change { output, key: Key { role, index } }]);
    let not_change = Err(Error::NotMine(
        "an output said to be change that doesn't pay this account's address for that key",
    ));
    assert_eq!(review(&body, &me, &claim(1, 1, 1), 1, None), not_change);
    assert_eq!(review(&body, &me, &claim(1, 0, 0), 1, None), not_change);
    assert_eq!(review(&body, &me, &claim(0, 1, 0), 1, None), not_change);
    assert_eq!(
        review(&body, &me, &claim(2, 1, 0), 1, None),
        Err(Error::Invalid("change said to be an output it doesn't have"))
    );
    // this account's change address, but staking with another key: not change
    let other = Account { network: Network::Mainnet, stake: [7; 28] };
    assert!(review(&body, &other, &claim(1, 1, 0), 1, None).is_err());
    // a receiving address is change too, if the computer says so and it's the account's
    let f = fixture("two-keys");
    let body = Body::parse(&f.body).unwrap();
    assert!(review(&body, &me, &own(&keys, &f.change), 2, None).is_ok());
}

/// CBOR written by hand, for what CSL wouldn't make.
#[derive(Clone, Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(mut self, major: u8, n: u64) -> Cbor {
        let m = major << 5;
        match n {
            0..=23 => self.0.push(m | n as u8),
            24..=0xff => self.0.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                self.0.push(m | 25);
                self.0.extend((n as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(m | 26);
                self.0.extend((n as u32).to_be_bytes());
            }
            _ => {
                self.0.push(m | 27);
                self.0.extend(n.to_be_bytes());
            }
        }
        self
    }

    fn uint(self, n: u64) -> Cbor { self.head(0, n) }

    /// -1 - n
    fn nint(self, n: u64) -> Cbor { self.head(1, n) }

    fn bytes(mut self, b: &[u8]) -> Cbor {
        self = self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }

    fn array(self, n: u64) -> Cbor { self.head(4, n) }

    fn map(self, n: u64) -> Cbor { self.head(5, n) }

    fn tag(self, t: u64) -> Cbor { self.head(6, t) }

    fn raw(mut self, b: &[u8]) -> Cbor {
        self.0.extend_from_slice(b);
        self
    }

    fn then(self, c: &Cbor) -> Cbor { self.raw(&c.0) }
}

fn c() -> Cbor { Cbor::default() }

fn recipient() -> Vec<u8> { Address::from_text(RECIPIENT).unwrap().bytes }

/// A coin spent: `[id, index]`.
fn input(n: u8) -> Cbor { c().array(2).bytes(&[n; 32]).uint(0) }

/// A payment of ADA alone to the recipient, in Alonzo's form.
fn output(lovelace: u64) -> Cbor { c().array(2).bytes(&recipient()).uint(lovelace) }

/// A body of these fields, in this order.
fn body(fields: &[(u64, Cbor)]) -> Vec<u8> {
    let mut out = c().map(fields.len() as u64);
    for (key, value) in fields {
        out = out.uint(*key).then(value);
    }
    out.0
}

/// The fields of a plain payment: inputs (tagged), an output, the fee, a TTL.
fn plain() -> Vec<(u64, Cbor)> {
    vec![
        (0, c().tag(258).array(1).then(&input(1))),
        (1, c().array(1).then(&output(1_500_000))),
        (2, c().uint(170_000)),
        (3, c().uint(TIP + 7200)),
    ]
}

fn with(field: (u64, Cbor)) -> Vec<u8> {
    let mut fields = plain();
    fields.push(field);
    fields.sort_by_key(|f| f.0);
    body(&fields)
}

fn refused(b: &[u8]) -> maki_ada::Error { Body::parse(b).unwrap_err() }

/// An output whose value is these tokens: `[ADA, {policy: {name: amount}}]`.
fn with_tokens(tokens: Cbor) -> Vec<u8> {
    let value = c().array(2).uint(2_000_000).then(&tokens);
    let o = c().array(2).bytes(&recipient()).then(&value);
    let mut fields = plain();
    fields[1] = (1, c().array(1).then(&o));
    body(&fields)
}

#[test]
fn bodies_cardano_would_refuse_maki_refuses() {
    use maki_ada::Error::*;
    let good = body(&plain());
    assert!(Body::parse(&good).is_ok());
    // as CSL wrote the same
    assert_eq!(Body::parse(&good).unwrap().outputs[0].address.text(), RECIPIENT);
    // cut short, more after it, too big
    assert_eq!(refused(&good[..good.len() - 1]), Encoding);
    assert_eq!(refused(&[&good[..], &[0]].concat()), Encoding);
    assert_eq!(refused(&vec![0xa0; body::MAX_BODY + 1]), TooBig);
    // not CIP-21's canonical CBOR: a number longer than it need be, an indefinite length, keys out
    // of order or twice
    let long_fee = c().raw(&[0x1b, 0, 0, 0, 0, 0x00, 0x02, 0x98, 0x10]);
    let mut fields = plain();
    fields[2] = (2, long_fee);
    assert_eq!(refused(&body(&fields)), Encoding);
    let mut fields = plain();
    fields[1] = (1, c().raw(&[0x9f]).then(&output(1)).raw(&[0xff]));
    assert_eq!(refused(&body(&fields)), Encoding);
    let mut fields = plain();
    fields.swap(2, 3);
    assert_eq!(refused(&body(&fields)), Encoding);
    let mut fields = plain();
    fields.insert(3, (2, c().uint(170_000)));
    assert_eq!(refused(&body(&fields)), Duplicate);
    // a field maki doesn't know (an update, Conway's next fields), or of the wrong kind
    assert_eq!(refused(&with((6, c().uint(0)))), Unknown);
    assert_eq!(refused(&with((23, c().uint(0)))), Unknown);
    let mut fields = plain();
    fields[2] = (2, c().bytes(&[1]));
    assert_eq!(refused(&body(&fields)), Shape);
    // without what every transaction has: inputs, outputs, the fee; with no inputs
    let without = "a body without its inputs, its outputs or its fee: Cardano would refuse it";
    assert_eq!(refused(&body(&plain()[1..])), Invalid(without));
    assert_eq!(refused(&body(&[plain()[0].clone(), plain()[1].clone()])), Invalid(without));
    let mut fields = plain();
    fields[0] = (0, c().tag(258).array(0));
    assert_eq!(refused(&body(&fields)).to_string(), "no coins spent: Cardano would refuse it");
    // inputs: one twice, an index past 16 bits, a hash too short
    let mut fields = plain();
    fields[0] = (0, c().tag(258).array(2).then(&input(1)).then(&input(1)));
    assert_eq!(refused(&body(&fields)), Duplicate);
    let mut fields = plain();
    fields[0] = (0, c().tag(258).array(1).array(2).bytes(&[1; 32]).uint(65_536));
    assert_eq!(refused(&body(&fields)), Shape);
    let mut fields = plain();
    fields[0] = (0, c().tag(258).array(1).array(2).bytes(&[1; 31]).uint(0));
    assert_eq!(refused(&body(&fields)), Shape);
    // sets: untagged is taken, a tag other than 258 isn't, and one way for every set (CIP-21)
    let mut fields = plain();
    fields[0] = (0, c().array(1).then(&input(1)));
    assert!(!Body::parse(&body(&fields)).unwrap().tagged);
    let mut fields = plain();
    fields[0] = (0, c().tag(259).array(1).then(&input(1)));
    assert_eq!(refused(&body(&fields)), Shape);
    let stake = Credential::Key([3; 28]);
    let cert = c().array(2).uint(0).array(2).uint(0).bytes(stake.hash());
    let mut fields = plain();
    fields[0] = (0, c().array(1).then(&input(1)));
    fields.push((4, c().tag(258).array(1).then(&cert)));
    assert_eq!(
        refused(&body(&fields)).to_string(),
        "sets written two ways, with Cardano's set tag and without: CIP-21 has a transaction write them one way"
    );
    // amounts: more ADA than there is, outputs that add up to more
    let mut fields = plain();
    fields[2] = (2, c().uint(maki_ada::MAX_LOVELACE + 1));
    assert!(matches!(refused(&body(&fields)), Invalid(_)));
    let mut fields = plain();
    fields[1] = (1, c().array(2).then(&output(maki_ada::MAX_LOVELACE)).then(&output(1)));
    assert!(matches!(refused(&body(&fields)), Invalid(_)));
    // a network that isn't 0 or 1; a donation of nothing
    assert_eq!(refused(&with((15, c().uint(2)))), Shape);
    assert!(matches!(refused(&with((22, c().uint(0)))), Invalid(_)));
    assert_eq!(Body::parse(&with((22, c().uint(5)))).unwrap().donation, Some(5));
    // an output to an address Cardano doesn't have, or to a reward account
    let mut fields = plain();
    fields[1] = (1, c().array(1).array(2).bytes(&recipient()[..56]).uint(1));
    assert_eq!(refused(&body(&fields)), Address);
    let reward = RewardAccount::from_text(REWARDS).unwrap().bytes();
    let mut fields = plain();
    fields[1] = (1, c().array(1).array(2).bytes(&reward).uint(1));
    assert!(Body::parse(&body(&fields)).is_err());
}

#[test]
fn outputs_values_and_tokens_cardano_would_refuse() {
    use maki_ada::Error::*;
    let policy = [0xab; 28];
    let tokens = |names: &[(&[u8], u64)]| {
        let mut m = c().map(1).bytes(&policy).map(names.len() as u64);
        for (name, n) in names {
            m = m.bytes(name).uint(*n);
        }
        m
    };
    assert!(Body::parse(&with_tokens(tokens(&[(b"A", 1), (b"BB", 2)]))).is_ok());
    // names in CIP-21's order: shorter first, then byte by byte; none twice
    assert_eq!(refused(&with_tokens(tokens(&[(b"BB", 1), (b"A", 2)]))), Encoding);
    assert_eq!(refused(&with_tokens(tokens(&[(b"B", 1), (b"A", 2)]))), Encoding);
    assert_eq!(refused(&with_tokens(tokens(&[(b"A", 1), (b"A", 2)]))), Duplicate);
    // none of a token; a name past 32 bytes; a policy with no tokens; ADA alone as `[ADA, {}]`
    assert!(matches!(refused(&with_tokens(tokens(&[(b"A", 0)]))), Invalid(_)));
    assert!(matches!(refused(&with_tokens(tokens(&[(&[b'n'; 33], 1)]))), Invalid(_)));
    assert!(Body::parse(&with_tokens(tokens(&[(&[b'n'; 32], 1)]))).is_ok());
    assert!(matches!(refused(&with_tokens(c().map(1).bytes(&policy).map(0))), Invalid(_)));
    assert_eq!(
        refused(&with_tokens(c().map(0))).to_string(),
        "ADA alone written with an empty map of tokens: CIP-21 writes it as ADA alone"
    );
    // policies in order, none twice
    let two = |a: [u8; 28], b: [u8; 28]| {
        c().map(2).bytes(&a).map(1).bytes(b"A").uint(1).bytes(&b).map(1).bytes(b"A").uint(1)
    };
    assert!(Body::parse(&with_tokens(two([1; 28], [2; 28]))).is_ok());
    assert_eq!(refused(&with_tokens(two([2; 28], [1; 28]))), Encoding);
    assert_eq!(refused(&with_tokens(two([1; 28], [1; 28]))), Duplicate);
    // Babbage's map: its keys in order, its address and value both there, nothing else
    let map = |entries: &[(u64, Cbor)]| {
        let mut o = c().map(entries.len() as u64);
        for (k, v) in entries {
            o = o.uint(*k).then(v);
        }
        let mut fields = plain();
        fields[1] = (1, c().array(1).then(&o));
        body(&fields)
    };
    let address = c().bytes(&recipient());
    let ada = c().uint(2_000_000);
    let b = Body::parse(&map(&[(0, address.clone()), (1, ada.clone())])).unwrap();
    assert_eq!((b.outputs[0].coin, b.outputs[0].datum, b.outputs[0].script), (2_000_000, None, None));
    assert_eq!(refused(&map(&[(1, ada.clone()), (0, address.clone())])), Encoding);
    assert_eq!(refused(&map(&[(0, address.clone())])), Shape);
    assert_eq!(refused(&map(&[(0, address.clone()), (1, ada.clone()), (4, c().uint(0))])), Unknown);
    // a datum: by hash, inline (CBOR inside tag 24), neither empty
    let inline = |b: &[u8]| c().array(2).uint(1).tag(24).bytes(b);
    assert_eq!(
        Body::parse(&map(&[(0, address.clone()), (1, ada.clone()), (2, inline(&[0x01]))])).unwrap().outputs
            [0]
        .datum,
        Some(Datum::Inline(1))
    );
    assert!(matches!(refused(&map(&[(0, address.clone()), (1, ada.clone()), (2, inline(&[]))])), Invalid(_)));
    let untagged = c().array(2).uint(1).bytes(&[1]);
    assert_eq!(refused(&map(&[(0, address.clone()), (1, ada.clone()), (2, untagged)])), Shape);
    let hashed = c().array(2).uint(0).bytes(&[9; 32]);
    assert!(Body::parse(&map(&[(0, address.clone()), (1, ada.clone()), (2, hashed)])).is_ok());
    assert_eq!(
        refused(&map(&[(0, address.clone()), (1, ada.clone()), (2, c().array(2).uint(2).bytes(&[1]))])),
        Shape
    );
    // Alonzo's list: two or three things
    let mut fields = plain();
    fields[1] = (1, c().array(1).array(4).bytes(&recipient()).uint(1).bytes(&[9; 32]).uint(0));
    assert_eq!(refused(&body(&fields)), Shape);
    let mut fields = plain();
    fields[1] = (1, c().array(1).array(3).bytes(&recipient()).uint(1).bytes(&[9; 32]));
    assert_eq!(Body::parse(&body(&fields)).unwrap().outputs[0].datum, Some(Datum::Hash([9; 32])));
    // tokens minted: a 64-bit number other than zero, below as well as above
    let mint = |n: Cbor| c().map(1).bytes(&policy).map(1).bytes(b"A").then(&n);
    assert_eq!(Body::parse(&with((9, mint(c().nint(9))))).unwrap().mint[0].tokens[0].amount, -10);
    assert_eq!(
        Body::parse(&with((9, mint(c().nint(i64::MAX as u64))))).unwrap().mint[0].tokens[0].amount,
        i64::MIN
    );
    assert_eq!(refused(&with((9, mint(c().nint(i64::MAX as u64 + 1))))), Shape);
    assert_eq!(refused(&with((9, mint(c().uint(i64::MAX as u64 + 1))))), Shape);
    assert!(matches!(refused(&with((9, mint(c().uint(0))))), Invalid(_)));
    assert!(matches!(refused(&with((9, c().map(0)))), Invalid(_)));
}

#[test]
fn certificates_and_withdrawals_cardano_would_refuse() {
    use maki_ada::Error::*;
    let me = Credential::Key([3; 28]);
    let cred = |c_: &Credential| match c_ {
        Credential::Key(h) => c().array(2).uint(0).bytes(h),
        Credential::Script(h) => c().array(2).uint(1).bytes(h),
    };
    let certs = |list: &[Cbor]| {
        let mut s = c().tag(258).array(list.len() as u64);
        for x in list {
            s = s.then(x);
        }
        with((4, s))
    };
    let read = |list: &[Cbor]| Body::parse(&certs(list)).map(|b| b.certificates);
    let register = c().array(3).uint(7).then(&cred(&me)).uint(2_000_000);
    assert_eq!(
        read(std::slice::from_ref(&register)),
        Ok(vec![Certificate::Register { stake: me, deposit: Some(2_000_000) }])
    );
    // DReps: by key or script, abstaining, no confidence; nothing else
    let vote = |d: Cbor| c().array(3).uint(9).then(&cred(&me)).then(&d);
    assert_eq!(
        read(&[vote(c().array(1).uint(2))]),
        Ok(vec![Certificate::Vote { stake: me, drep: DRep::Abstain }])
    );
    assert_eq!(
        read(&[vote(c().array(1).uint(3))]),
        Ok(vec![Certificate::Vote { stake: me, drep: DRep::NoConfidence }])
    );
    assert_eq!(
        read(&[vote(c().array(2).uint(1).bytes(&[5; 28]))]),
        Ok(vec![Certificate::Vote { stake: me, drep: DRep::Credential(Credential::Script([5; 28])) }])
    );
    assert_eq!(read(&[vote(c().array(2).uint(2).bytes(&[5; 28]))]), Err(Shape));
    assert_eq!(read(&[vote(c().array(1).uint(4))]), Err(Shape));
    // the same certificate twice; none at all; a certificate of the wrong length
    assert_eq!(read(&[register.clone(), register.clone()]), Err(Duplicate));
    assert!(matches!(read(&[]), Err(Invalid(_))));
    assert_eq!(read(&[c().array(4).uint(7).then(&cred(&me)).uint(2_000_000).uint(1)]), Err(Shape));
    assert_eq!(read(&[c().array(2).uint(0).array(2).uint(2).bytes(&[3; 28])]), Err(Shape));
    // the kinds maki doesn't sign, by name, and ones Conway doesn't have
    let kind = |n: u64, fields: u64| {
        let mut x = c().array(fields).uint(n);
        for _ in 1..fields {
            x = x.uint(0);
        }
        x
    };
    assert_eq!(read(&[kind(3, 10)]), Err(Unsupported("a stake pool's registration")));
    assert_eq!(read(&[kind(4, 3)]), Err(Unsupported("a stake pool's retirement")));
    assert_eq!(read(&[kind(14, 3)]), Err(Unsupported("a constitutional committee member's hot key")));
    assert_eq!(read(&[kind(16, 4)]), Err(Unsupported("a DRep's registration")));
    assert_eq!(
        read(&[kind(5, 3)]),
        Err(Invalid("a certificate Conway doesn't have: Cardano would refuse it"))
    );
    assert_eq!(
        read(&[kind(6, 2)]),
        Err(Invalid("a certificate Conway doesn't have: Cardano would refuse it"))
    );
    // withdrawals: in order, none twice, none empty, from a reward account
    let reward = |n: u8| RewardAccount { network: 1, stake: Credential::Key([n; 28]) }.bytes();
    let withdrawals = |list: &[[u8; 29]]| {
        let mut m = c().map(list.len() as u64);
        for a in list {
            m = m.bytes(a).uint(1_000_000);
        }
        Body::parse(&with((5, m))).map(|b| b.withdrawals.len())
    };
    assert_eq!(withdrawals(&[reward(1), reward(2)]), Ok(2));
    assert_eq!(withdrawals(&[reward(2), reward(1)]), Err(Encoding));
    assert_eq!(withdrawals(&[reward(1), reward(1)]), Err(Duplicate));
    assert!(matches!(withdrawals(&[]), Err(Invalid(_))));
    assert_eq!(
        withdrawals(&[maki_ada::Address::from_text(ME).unwrap().bytes[..29].try_into().unwrap()]),
        Err(Address)
    );
}

#[test]
fn a_high_fee_is_called_out() {
    let keys = keys();
    let me = account(&keys, Network::Mainnet);
    let mut fields = plain();
    fields[2] = (2, c().uint(5_000_000));
    let b = Body::parse(&body(&fields)).unwrap();
    let r = review(&b, &me, &[], 1, Some(NOW)).unwrap();
    assert_eq!(
        r.pages.last().unwrap(),
        &p(
            "High fee!",
            "5 ADA",
            "",
            "More than twice what Cardano asks of a transaction this size, about 0.165633 ADA."
        )
    );
    assert_eq!(r.summary, "pays a high fee!; fee 5 ADA");
    // twice is still ordinary
    let mut fields = plain();
    fields[2] = (2, c().uint(331_266));
    let b = Body::parse(&body(&fields)).unwrap();
    assert_eq!(review(&b, &me, &[], 1, Some(NOW)).unwrap().pages.last().unwrap().heading, "Fee");
}

#[test]
fn more_than_maki_can_show_is_refused() {
    let keys = keys();
    let me = account(&keys, Network::Mainnet);
    // 130 payments: more pages than maki's review screen takes
    let mut outputs = c().array(130);
    for _ in 0..130 {
        outputs = outputs.then(&output(1_000_000));
    }
    let mut fields = plain();
    fields[1] = (1, outputs);
    let b = Body::parse(&body(&fields)).unwrap();
    assert_eq!(
        review(&b, &me, &[], 1, Some(NOW)),
        Err(Error::Invalid("more than maki's screen can show: send fewer outputs or tokens at once"))
    );
    // nothing in it names its network: said
    let mut fields = plain();
    fields[1] = (1, c().array(0));
    let b = Body::parse(&body(&fields)).unwrap();
    assert_eq!(
        review(&b, &me, &[], 1, Some(NOW)).unwrap().pages[0].prose,
        "Nothing in it says which network it's for: made for Cardano's own, it would work on a test network too."
    );
}

#[test]
fn requests_as_the_computer_writes_them() {
    let f = fixture("delegation");
    let request = Request {
        witnesses: vec![Key { role: 0, index: 0 }, Key::STAKE],
        change: vec![Change { output: 0, key: Key { role: 1, index: 0 } }],
        body: &f.body,
    };
    let bytes = request.write();
    assert_eq!(bytes[..18], [2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0]);
    assert_eq!(Request::parse(&bytes), Ok(request.clone()));
    let refused = |b: &[u8]| Request::parse(b).unwrap_err().to_string();
    let head = |witnesses: &[(u8, u32)], change: &[(u16, u8, u32)]| {
        let mut out = vec![witnesses.len() as u8];
        for (role, index) in witnesses {
            out.push(*role);
            out.extend(index.to_le_bytes());
        }
        out.push(change.len() as u8);
        for (output, role, index) in change {
            out.extend(output.to_le_bytes());
            out.push(*role);
            out.extend(index.to_le_bytes());
        }
        [out, f.body.clone()].concat()
    };
    assert!(Request::parse(&head(&[(0, 5), (1, 0x7fff_ffff)], &[])).is_ok());
    assert_eq!(refused(&head(&[], &[])), "no key asked to sign it");
    assert_eq!(refused(&head(&[(0, 1), (0, 1)], &[])), "a key asked to sign it twice");
    for key in [(2, 1), (3, 0), (0, 0x8000_0000)] {
        assert!(refused(&head(&[key], &[])).starts_with("a key that isn't one of the account's"), "{key:?}");
    }
    assert!(
        refused(&head(&[(0, 0)], &[(0, 2, 0)])).starts_with("change at a key that isn't a payment key's")
    );
    assert_eq!(refused(&head(&[(0, 0)], &[(0, 1, 0), (0, 1, 1)])), "an output said to be change twice");
    let many: Vec<(u8, u32)> = (0..43).map(|i| (0, i)).collect();
    assert!(Request::parse(&head(&many[..42], &[])).is_ok());
    assert_eq!(refused(&head(&many, &[])), "more keys asked to sign it than an answer holds: 42 at most");
    assert_eq!(refused(&[1, 0, 0, 0, 0, 0, 0]), "no transaction body");
    assert_eq!(refused(&[1, 0, 0, 0]), "a request cut short: not one maki takes");
    assert_eq!(Request::parse(&vec![1; request::MAX_REQUEST + 1]), Err(maki_ada::Error::TooBig));
}
