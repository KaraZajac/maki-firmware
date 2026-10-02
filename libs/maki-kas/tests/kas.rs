//! maki-kas against Kaspa's own code: rusty-kaspa's test vectors for its hash, its addresses, its
//! wallet's keys and its signature hash; transactions Kaspa's SDK made and signed
//! (`fixtures/make.mjs`), read as they are, shown as they should be, and signed by maki's keys with the
//! same account (the test phrase's, as Kaspium, Kaspa NG and Kastle have it) as the SDK checked they
//! must be; and transactions Kaspa's mainnet took (`fixtures/mainnet.py`), whose signatures check out
//! against maki's signature hash.

use maki_hd::seed::SeedKeys;
use maki_kas::address::{self, Kind};
use maki_kas::claims::{CLAIM, Claims, MAX_CLAIMS};
use maki_kas::display::{Page, date, decimals, kas};
use maki_kas::hash::Hasher;
use maki_kas::request::{self, Derivation, Input, NATIVE, Output, Script};
use maki_kas::sighash::*;
use maki_kas::{Account, Error, MAX_SOMPI, Network, Request};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The phrase's first address, as Kastle's tests publish it (forbole/kastle, signtx-unit.spec.ts).
const ME: &str = "kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh";
/// Keys that aren't this wallet's, as the SDK writes their addresses (`fixtures/make.mjs`).
const RECIPIENT: &str = "kaspa:qp8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc6547zhh9u4";
const RECIPIENT_TEST: &str = "kaspatest:qp8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc655cyvcmd3";
const ECDSA: &str = "kaspa:qypyvmtletjk8ewtpxsdrpctkkqrgjqyv9u8ng2ff88jy2zlrwhr7fcyqj098h4";
const P2SH: &str = "kaspa:pr89wgtzs5f9qphvrqvhhkqcggsua7j4nwc8npqsmxd9hwjmqlx36fyjy44yv";
const DATA: &str =
    "Everyone can read it, on chain, and software that reads the chain may act on it: maki can't tell how.";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn phrase_keys(phrase: &str) -> SeedKeys {
    SeedKeys::from_seed(&maki_seed::seed(&phrase.split(' ').collect::<Vec<_>>(), "")).unwrap()
}

fn json() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transactions.json"))
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// A transaction the SDK made: its network, the request, each input's signature hash, the SDK's
/// signatures, and maki's (None for one maki mustn't sign).
struct Fixture {
    name: String,
    network: Network,
    request: Vec<u8>,
    sighashes: Vec<Vec<u8>>,
    sdk: Vec<Vec<u8>>,
    signatures: Option<Vec<Vec<u8>>>,
}

fn fixtures() -> Vec<Fixture> {
    let list =
        |v: &serde_json::Value| v.as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
    json()["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Fixture {
            name: f["name"].as_str().unwrap().into(),
            network: Network::from_byte(f["network"].as_u64().unwrap() as u8).unwrap(),
            request: unhex(f["request"].as_str().unwrap()),
            sighashes: list(&f["sighashes"]),
            sdk: list(&f["sdk"]),
            signatures: (!f["signatures"].is_null()).then(|| list(&f["signatures"])),
        })
        .collect()
}

fn fixture(name: &str) -> Request {
    Request::parse(&fixtures().into_iter().find(|f| f.name == name).unwrap().request).unwrap()
}

fn p(heading: &str, value: &str, mono: &str, prose: &str) -> Page {
    Page { heading: heading.into(), value: value.into(), mono: mono.into(), prose: prose.into() }
}

#[test]
fn hashes_as_rusty_kaspa_hashes() {
    // rusty-kaspa's own vectors for the signature hash's hasher (crypto/hashes/src/hashers.rs), each
    // over everything before it too
    let inputs: [&[u8]; 5] = [
        &[],
        &[1],
        &[
            5, 199, 126, 44, 71, 32, 82, 139, 122, 217, 43, 48, 52, 112, 40, 209, 180, 83, 139, 231, 72, 48,
            136, 48, 168, 226, 133, 7, 60, 4, 160, 205,
        ],
        &[42; 64],
        &[0; 8],
    ];
    let expected = [
        "34c75037ad62740d4b3228f88f844f7901c07bfacd55a045be518eabc15e52ce",
        "8523b0471bcbea04575ccaa635eef9f9114f2890bda54367e5ff8caa3878bf82",
        "a51c49d9eb3d13f9de16e1aa8d1ff17668d55633ce00f36a643ac714b0fb137f",
        "487f199ef74c3e893e85bd37770e6334575a2d4d113b2e10474593c49807de93",
        "6392adc33a8e24e9a0a0c4c5f07f9c1cc958ad40c16d7a9a276e374cebb4e32b",
    ];
    let mut h = Hasher::signing();
    for (data, want) in inputs.iter().zip(expected) {
        h.bytes(data);
        assert_eq!(hex(&h.clone().finish()), want);
    }
}

/// An address made the long way, its version and payload as five-bit groups with `pad` in the
/// padding bits, and the checksum over them: for spellings `address::encode` never makes.
fn spelled(prefix: &str, version: u8, payload: &[u8], pad: u8) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let bits: Vec<u8> = [&[version][..], payload]
        .concat()
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    let mut groups: Vec<u8> = bits
        .chunks(5)
        .map(|c| c.iter().chain(std::iter::repeat(&0)).take(5).fold(0, |a, b| a << 1 | b))
        .collect();
    *groups.last_mut().unwrap() |= pad;
    let mut c = 1u64;
    for d in prefix.bytes().map(|b| b & 0x1f).chain([0]).chain(groups.iter().copied()).chain([0; 8]) {
        let top = c >> 35;
        c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64;
        for (i, g) in
            [0x98f2bc8e61u64, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470].iter().enumerate()
        {
            if (top >> i) & 1 == 1 {
                c ^= g;
            }
        }
    }
    let sum = c ^ 1;
    let rest: String = groups
        .iter()
        .copied()
        .chain((0..8).rev().map(|i| ((sum >> (5 * i)) & 31) as u8))
        .map(|g| CHARSET[g as usize] as char)
        .collect();
    format!("{prefix}:{rest}")
}

#[test]
fn addresses_as_kaspa_writes_them() {
    // rusty-kaspa's own vectors (crypto/addresses/src/lib.rs), test prefixes and all
    let ecdsa = unhex("ba01fc5f4e9d9879599c69a3dafdb835a7255e5f2e934e9322ecd3af190ab0f60e");
    let key = unhex("5fff3c4da18f45adcdd499e44611e9fff148ba69db3c4ea2ddd955fc46a59522");
    let cases: Vec<(&str, u8, &[u8], &str)> = vec![
        ("a", 0, b"", "a:qqeq69uvrh"),
        ("a", 8, b"", "a:pq99546ray"),
        ("b", 8, b" ", "b:pqsqzsjd64fv"),
        ("b", 8, b"-", "b:pqksmhczf8ud"),
        ("b", 8, b"0", "b:pqcq53eqrk0e"),
        ("b", 8, b"1", "b:pqcshg75y0vf"),
        ("b", 8, b"-1", "b:pqknzl4e9y0zy"),
        ("b", 8, b"11", "b:pqcnzt888ytdg"),
        ("b", 8, b"abc", "b:ppskycc8txxxn2w"),
        ("b", 8, b"1234598760", "b:pqcnyve5x5unsdekxqeusxeyu2"),
        ("b", 8, b"abcdefghijklmnopqrstuvwxyz", "b:ppskycmyv4nxw6rfdf4kcmtwdac8zunnw36hvamc09aqtpppz8lk"),
        (
            "b",
            8,
            b"000000000000000000000000000000000000000000",
            "b:pqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrq7ag684l3",
        ),
        ("kaspatest", 0, &[0; 32], "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqrxplya"),
        (
            "kaspatest",
            1,
            &[0; 33],
            "kaspatest:qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhe837j2d",
        ),
        ("kaspatest", 1, &ecdsa, "kaspatest:qxaqrlzlf6wes72en3568khahq66wf27tuhfxn5nytkd8tcep2c0vrse6gdmpks"),
        ("kaspa", 0, &[0; 32], "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e"),
        ("kaspa", 0, &key, "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj"),
    ];
    for (prefix, version, payload, text) in &cases {
        assert_eq!(address::encode(prefix, *version, payload), *text);
        assert_eq!(spelled(prefix, *version, payload, 0), *text);
        if prefix.starts_with("kaspa") {
            let a = address::decode(text).unwrap();
            assert_eq!(
                (a.network.prefix(), a.kind.version(), a.payload.as_slice()),
                (*prefix, *version, *payload)
            );
        }
    }
    // and its errors
    use address::Error::*;
    let zero = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    assert_eq!(address::decode(&zero.replacen('q', "1", 7)), Err(Character));
    assert_eq!(address::decode(&zero.replacen("qqqqqqq", "qqqqqq|", 1)), Err(Character));
    assert_eq!(address::decode(&zero.replacen("qqqqqqq", "qqqqqq\u{81}", 1)), Err(Character));
    assert_eq!(address::decode(&zero.replace("kaspa:", "kaspa1:")), Err(Prefix));
    assert_eq!(address::decode(&zero.replace("kaspa:", "kaspa")), Err(Prefix));
    assert_eq!(address::decode(&zero.replace("p4e", "p4l")), Err(Checksum));
    assert_eq!(address::decode(&zero.replacen('q', "", 1)), Err(Checksum));
    // one spelling each: lower case only, padding bits zero; payloads as long as their version
    // says, of versions Kaspa has; the networks maki signs for
    assert_eq!(address::decode(&zero.to_uppercase()), Err(Prefix));
    assert_eq!(address::decode(&format!("kaspa:{}", zero[6..].to_uppercase())), Err(Character));
    assert_eq!(address::decode(&spelled("kaspa", 0, &[0; 32], 1)), Err(Length));
    assert_eq!(address::decode(&spelled("kaspa", 1, &[0; 33], 4)), Err(Length));
    assert_eq!(address::decode(&address::encode("kaspa", 0, &[0; 33])), Err(Length));
    assert_eq!(address::decode(&address::encode("kaspa", 2, &[0; 32])), Err(Version));
    assert_eq!(address::decode(&address::encode("kaspasim", 0, &[0; 32])), Err(Prefix));
    assert_eq!(address::decode("kaspa:"), Err(Length));
    assert_eq!(address::decode("kaspa:qqqqqqqq"), Err(Length));
    assert_eq!(address::decode(&format!("{zero}q")), Err(Checksum));
    assert_eq!(address::decode(&format!("kaspa:{}", "q".repeat(address::MAX_ADDRESS))), Err(Length));
    // what scripts pay: the three kinds there are addresses for, and nothing else
    let script = |s: &str| Script { version: 0, script: unhex(s) };
    let me = address::decode(ME).unwrap();
    assert_eq!(me.kind, Kind::Schnorr);
    let mine = script(&format!("20{}ac", hex(&me.payload)));
    assert_eq!(address::of_script(Network::Mainnet, &mine).as_deref(), Some(ME));
    let p2sh = address::decode(P2SH).unwrap();
    assert_eq!(
        address::of_script(Network::Mainnet, &script(&format!("aa20{}87", hex(&p2sh.payload)))).as_deref(),
        Some(P2SH)
    );
    let ecdsa = address::decode(ECDSA).unwrap();
    assert_eq!(
        address::of_script(Network::Mainnet, &script(&format!("21{}ab", hex(&ecdsa.payload)))).as_deref(),
        Some(ECDSA)
    );
    assert_eq!(address::of_script(Network::Mainnet, &Script { version: 1, ..mine.clone() }), None);
    assert_eq!(address::of_script(Network::Mainnet, &script("6a0461626364")), None);
    assert_eq!(address::of_script(Network::Mainnet, &script(&format!("20{}ab", hex(&me.payload)))), None);
}

#[test]
fn the_phrase_makes_the_account_kaspas_wallets_make() {
    let json = json();
    let keys = phrase_keys(PHRASE);
    let account = Account::new(&keys, Network::Mainnet).unwrap();
    assert_eq!(hex(&account.public.key), json["account"]["key"].as_str().unwrap());
    assert_eq!(hex(&account.public.chain_code), json["account"]["chainCode"].as_str().unwrap());
    assert_eq!(account.address(Derivation { chain: 0, index: 0 }).unwrap(), ME);
    for a in json["addresses"].as_array().unwrap() {
        let network = Network::from_byte(a["network"].as_u64().unwrap() as u8).unwrap();
        let key =
            Derivation::new(a["chain"].as_u64().unwrap() as u8, a["index"].as_u64().unwrap() as u32).unwrap();
        let account = Account::new(&keys, network).unwrap();
        assert_eq!(hex(&account.key(key).unwrap()), a["key"].as_str().unwrap());
        assert_eq!(account.address(key).unwrap(), a["address"].as_str().unwrap());
    }
    let others = &json["others"];
    assert_eq!(
        [RECIPIENT, RECIPIENT_TEST, ECDSA, P2SH],
        ["recipient", "recipientTestnet", "ecdsa", "p2sh"].map(|k| others[k].as_str().unwrap())
    );
    // rusty-kaspa's own wallet tests (wallet/keys/src/derivation/gen1/hd.rs): a phrase's account key
    // (its kpub, as the SDK reads it), and another's receive #1 on the test network
    let fringe = phrase_keys(
        "fringe ceiling crater inject pilot travel gas nurse bulb bullet horn segment snack harbor dice laugh vital cigar push couple plastic into slender worry",
    );
    let account = Account::new(&fringe, Network::Mainnet).unwrap();
    assert_eq!(hex(&account.public.key), json["fringe"]["key"].as_str().unwrap());
    assert_eq!(hex(&account.public.chain_code), json["fringe"]["chainCode"].as_str().unwrap());
    let hunt = phrase_keys(
        "hunt bitter praise lift buyer topic crane leopard uniform network inquiry over grain pass match crush marine strike doll relax fortune trumpet sunny silk",
    );
    assert_eq!(
        Account::new(&hunt, Network::Testnet).unwrap().address(Derivation { chain: 0, index: 1 }).unwrap(),
        "kaspatest:qrc2959g0pqda53glnfd238cdnmk24zxzkj8n5x83rkktx4h73dkc4ave6wyg"
    );
}

/// rusty-kaspa's own transaction for its signature hash's tests (consensus/core/src/hashing/
/// sighash.rs): three inputs of one transaction, two outputs.
fn official(version: u16) -> Request {
    let txid: [u8; 32] =
        unhex("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").try_into().unwrap();
    let script = |s: &str| Script { version: 0, script: unhex(&format!("20{s}ac")) };
    let (one, two) = (
        script("8325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8"),
        script("fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8"),
    );
    let input = |index: u32, amount: u64, script: &Script| Input {
        txid,
        index,
        sequence: index as u64,
        sig_op_count: 0,
        compute_budget: if version == 0 { 0 } else { 11 * (index as u16 + 1) },
        amount,
        script: script.clone(),
        key: Derivation { chain: 0, index: 0 },
    };
    Request {
        version,
        inputs: vec![input(0, 100, &one), input(1, 200, &two), input(2, 300, &two)],
        outputs: vec![
            Output { value: 300, script: two.clone(), ours: None },
            Output { value: 300, script: one.clone(), ours: None },
        ],
        lock_time: 1615462089000,
        subnetwork: NATIVE,
        gas: 0,
        payload: vec![],
    }
}

#[test]
fn signature_hashes_as_rusty_kaspa_computes_them() {
    enum Change {
        None,
        Output(usize),
        Input(usize),
        ComputeBudget(usize),
        SigOpCount(usize),
        AmountSpent(usize),
        PrevScript(usize),
        Sequence(usize),
        Payload,
        Gas,
        Subnetwork,
    }
    let native = official(0);
    let v1 = official(1);
    let mut subnetwork = official(0);
    subnetwork.subnetwork = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    subnetwork.gas = 250;
    subnetwork.payload = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
    let ty = |b: u8| SigHashType::from_u8(b).unwrap();
    let (all, none, single) = (SIG_HASH_ALL, SIG_HASH_NONE, SIG_HASH_SINGLE);
    use Change::*;
    // its test vectors, every one
    let vectors: Vec<(&str, &Request, SigHashType, usize, Change, &str)> = vec![
        (
            "native-all-0",
            &native,
            all,
            0,
            None,
            "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5",
        ),
        (
            "native-all-0-modify-input-1",
            &native,
            all,
            0,
            Input(1),
            "a9f563d86c0ef19ec2e4f483901d202e90150580b6123c3d492e26e7965f488c",
        ),
        (
            "native-all-0-modify-compute-mass-1",
            &native,
            all,
            0,
            ComputeBudget(1),
            "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5",
        ),
        (
            "native-v1-all-0-modify-sigopcount-0",
            &v1,
            all,
            0,
            SigOpCount(0),
            "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075",
        ),
        (
            "native-v1-all-0-modify-sigopcount-1",
            &v1,
            all,
            0,
            SigOpCount(1),
            "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075",
        ),
        (
            "native-v1-all-0-modify-compute-budget-0",
            &v1,
            all,
            0,
            ComputeBudget(0),
            "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075",
        ),
        (
            "native-v1-all-0-modify-compute-budget-1",
            &v1,
            all,
            0,
            ComputeBudget(1),
            "5b2657524be672e019897646b56da3d192b453d78ae5e6e5c07f029a69f5f075",
        ),
        (
            "native-all-0-modify-output-1",
            &native,
            all,
            0,
            Output(1),
            "aad2b61bd2405dfcf7294fc2be85f325694f02dda22d0af30381cb50d8295e0a",
        ),
        (
            "native-all-0-modify-sequence-1",
            &native,
            all,
            0,
            Sequence(1),
            "0818bd0a3703638d4f01014c92cf866a8903cab36df2fa2506dc0d06b94295e8",
        ),
        (
            "native-all-anyonecanpay-0",
            &native,
            ty(0x81),
            0,
            None,
            "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2",
        ),
        (
            "native-all-anyonecanpay-0-modify-input-0",
            &native,
            ty(0x81),
            0,
            Input(0),
            "d09cb639f335ee69ac71f2ad43fd9e59052d38a7d0638de4cf989346588a7c38",
        ),
        (
            "native-all-anyonecanpay-0-modify-input-1",
            &native,
            ty(0x81),
            0,
            Input(1),
            "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2",
        ),
        (
            "native-all-anyonecanpay-0-modify-sequence",
            &native,
            ty(0x81),
            0,
            Sequence(1),
            "24821e466e53ff8e5fa93257cb17bb06131a48be4ef282e87f59d2bdc9afebc2",
        ),
        (
            "native-none-0",
            &native,
            none,
            0,
            None,
            "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba",
        ),
        (
            "native-none-0-modify-output-1",
            &native,
            none,
            0,
            Output(1),
            "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba",
        ),
        (
            "native-none-0-modify-sequence-0",
            &native,
            none,
            0,
            Sequence(0),
            "d9efdd5edaa0d3fd0133ee3ab731d8c20e0a1b9f3c0581601ae2075db1109268",
        ),
        (
            "native-none-0-modify-sequence-1",
            &native,
            none,
            0,
            Sequence(1),
            "38ce4bc93cf9116d2e377b33ff8449c665b7b5e2f2e65303c543b9afdaa4bbba",
        ),
        (
            "native-none-anyonecanpay-0",
            &native,
            ty(0x82),
            0,
            None,
            "06aa9f4239491e07bb2b6bda6b0657b921aeae51e193d2c5bf9e81439cfeafa0",
        ),
        (
            "native-none-anyonecanpay-0-modify-amount-spent",
            &native,
            ty(0x82),
            0,
            AmountSpent(0),
            "f07f45f3634d3ea8c0f2cb676f56e20993edf9be07a83bf0dfdb3debcf1441bf",
        ),
        (
            "native-none-anyonecanpay-0-modify-script-public-key",
            &native,
            ty(0x82),
            0,
            PrevScript(0),
            "20a525c54dc33b2a61201f05233c086dbe8e06e9515775181ed96550b4f2d714",
        ),
        (
            "native-single-0",
            &native,
            single,
            0,
            None,
            "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005",
        ),
        (
            "native-single-0-modify-output-1",
            &native,
            single,
            0,
            Output(1),
            "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005",
        ),
        (
            "native-single-0-modify-sequence-0",
            &native,
            single,
            0,
            Sequence(0),
            "83796d22879718eee1165d4aace667bb6778075dab579c32c57be945f466a451",
        ),
        (
            "native-single-0-modify-sequence-1",
            &native,
            single,
            0,
            Sequence(1),
            "44a0b407ff7b239d447743dd503f7ad23db5b2ee4d25279bd3dffaf6b474e005",
        ),
        (
            "native-single-2-no-corresponding-output",
            &native,
            single,
            2,
            None,
            "022ad967192f39d8d5895d243e025ec14cc7a79708c5e364894d4eff3cecb1b0",
        ),
        (
            "native-single-2-no-corresponding-output-modify-output-1",
            &native,
            single,
            2,
            Output(1),
            "022ad967192f39d8d5895d243e025ec14cc7a79708c5e364894d4eff3cecb1b0",
        ),
        (
            "native-single-anyonecanpay-0",
            &native,
            ty(0x84),
            0,
            None,
            "43b20aba775050cf9ba8d5e48fc7ed2dc6c071d23f30382aea58b7c59cfb8ed7",
        ),
        (
            "native-single-anyonecanpay-2-no-corresponding-output",
            &native,
            ty(0x84),
            2,
            None,
            "846689131fb08b77f83af1d3901076732ef09d3f8fdff945be89aa4300562e5f",
        ),
        (
            "native-all-0-modify-payload",
            &native,
            all,
            0,
            Payload,
            "72ea6c2871e0f44499f1c2b556f265d9424bfea67cca9cb343b4b040ead65525",
        ),
        (
            "subnetwork-all-0",
            &subnetwork,
            all,
            0,
            None,
            "b2f421c933eb7e1a91f1d9e1efa3f120fe419326c0dbac487752189522550e0c",
        ),
        (
            "subnetwork-all-modify-payload",
            &subnetwork,
            all,
            0,
            Payload,
            "12ab63b9aea3d58db339245a9b6e9cb6075b2253615ce0fb18104d28de4435a1",
        ),
        (
            "subnetwork-all-modify-gas",
            &subnetwork,
            all,
            0,
            Gas,
            "2501edfc0068d591160c4bd98646c6e6892cdc051182a8be3ccd6d67f104fd17",
        ),
        (
            "subnetwork-all-subnetwork-id",
            &subnetwork,
            all,
            0,
            Subnetwork,
            "a5d1230ede0dfcfd522e04123a7bcd721462fed1d3a87352031a4f6e3c4389b6",
        ),
    ];
    for (name, tx, hash_type, input, change, expected) in vectors {
        let mut tx = tx.clone();
        match change {
            None => {}
            Output(i) => tx.outputs[i].value = 100,
            Input(i) => tx.inputs[i].index = 2,
            // a compute budget in place of a version 0 input's count, which hashes as none
            ComputeBudget(i) => {
                tx.inputs[i].sig_op_count = 0;
                tx.inputs[i].compute_budget = 1234;
            }
            SigOpCount(i) => tx.inputs[i].sig_op_count = 123,
            AmountSpent(i) => tx.inputs[i].amount = 666,
            PrevScript(i) => tx.inputs[i].script.script.extend([1, 2, 3]),
            Sequence(i) => tx.inputs[i].sequence = 12345,
            Payload => tx.payload = vec![6, 6, 6, 4, 2, 0, 1, 3, 3, 7],
            Gas => tx.gas = 1234,
            Subnetwork => tx.subnetwork = [6, 6, 6, 4, 2, 0, 1, 3, 3, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
        let hash = signature_hash(&tx, input, hash_type, &mut Reused::default()).unwrap();
        assert_eq!(hex(&hash), expected, "{name}");
    }
    // the types consensus allows, and no others; and no hash for an input there isn't
    for b in 0..=255u8 {
        assert_eq!(SigHashType::from_u8(b).is_some(), [1, 2, 4, 0x81, 0x82, 0x84].contains(&b), "{b}");
    }
    assert_eq!(signature_hash(&native, 3, all, &mut Reused::default()), Option::None);
}

#[test]
fn maki_signs_what_kaspas_sdk_signs() {
    let keys = phrase_keys(PHRASE);
    let all = fixtures();
    assert_eq!(all.len(), 13);
    for f in all {
        let request = Request::parse(&f.request).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        // the request reads back as it was written
        assert_eq!(request.bytes(), f.request, "{}", f.name);
        let account = Account::new(&keys, f.network).unwrap();
        // maki's signature hash is Kaspa's: the SDK's own signatures (fresh randomness) check against it
        let mut reused = Reused::default();
        for (i, input) in request.inputs.iter().enumerate() {
            let digest = signature_hash(&request, i, SIG_HASH_ALL, &mut reused).unwrap();
            assert_eq!(digest.to_vec(), f.sighashes[i], "{} input {i}", f.name);
            let key = k256::schnorr::VerifyingKey::from_bytes(&input.script.script[1..33]).unwrap();
            let sdk = &f.sdk[i];
            assert_eq!(sdk[64], 1, "SIGHASH_ALL");
            let sig = k256::schnorr::Signature::try_from(&sdk[..64]).unwrap();
            key.verify_raw(&digest, &sig).unwrap_or_else(|_| panic!("{} input {i}", f.name));
        }
        match f.signatures {
            // and maki's own, with no aux randomness, byte for byte the ones the SDK checked
            Some(signatures) => {
                let checked = account.check(&request).unwrap_or_else(|e| panic!("{}: {e}", f.name));
                let made: Vec<Vec<u8>> = account.sign(&checked).unwrap().iter().map(|s| s.to_vec()).collect();
                assert_eq!(made, signatures, "{}", f.name);
            }
            None => assert_eq!(account.check(&request).err(), Some(Error::NotOurs(0)), "{}", f.name),
        }
    }
}

/// Transactions Kaspa's mainnet took (`fixtures/mainnet.py`): the coins each input spent, and the
/// signature scripts that spent them.
fn mainnet() -> Vec<(String, Request, Vec<Vec<u8>>)> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mainnet.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let script = |s: &serde_json::Value| Script { version: 0, script: unhex(s.as_str().unwrap()) };
    json.as_array()
        .unwrap()
        .iter()
        .map(|t| {
            let inputs: Vec<Input> = t["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| Input {
                    txid: unhex(i["txid"].as_str().unwrap()).try_into().unwrap(),
                    index: i["index"].as_u64().unwrap() as u32,
                    sequence: i["sequence"].as_str().unwrap().parse().unwrap(),
                    sig_op_count: i["sigOpCount"].as_u64().unwrap() as u8,
                    compute_budget: i["computeBudget"].as_u64().unwrap() as u16,
                    amount: i["amount"].as_u64().unwrap(),
                    script: script(&i["script"]),
                    key: Derivation { chain: 0, index: 0 },
                })
                .collect();
            let outputs = t["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| Output {
                    value: o["value"].as_u64().unwrap(),
                    script: script(&o["script"]),
                    ours: None,
                })
                .collect();
            let signatures = t["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| unhex(i["signatureScript"].as_str().unwrap()))
                .collect();
            let tx = Request {
                version: t["version"].as_u64().unwrap() as u16,
                inputs,
                outputs,
                lock_time: 0,
                subnetwork: unhex(t["subnetwork"].as_str().unwrap()).try_into().unwrap(),
                gas: 0,
                payload: unhex(t["payload"].as_str().unwrap()),
            };
            (t["txid"].as_str().unwrap().to_string(), tx, signatures)
        })
        .collect()
}

#[test]
fn signatures_kaspas_mainnet_took_check_out_against_makis_hash() {
    let all = mainnet();
    assert_eq!(all.len(), 5);
    let mut checked = 0;
    for (id, tx, signatures) in &all {
        let mut reused = Reused::default();
        for (i, input) in tx.inputs.iter().enumerate() {
            // OP_DATA_65, the signature, SIGHASH_ALL: as maki's answer has them, 0x41 before
            let script = &signatures[i];
            assert_eq!((script.len(), script[0], script[65]), (66, 0x41, 1), "{id} input {i}");
            let digest = signature_hash(tx, i, SIG_HASH_ALL, &mut reused).unwrap();
            let key = k256::schnorr::VerifyingKey::from_bytes(&input.script.script[1..33]).unwrap();
            let sig = k256::schnorr::Signature::try_from(&script[1..65]).unwrap();
            key.verify_raw(&digest, &sig).unwrap_or_else(|_| panic!("{id} input {i}"));
            checked += 1;
        }
    }
    assert_eq!(checked, 47);
    // a lane's transaction is one maki won't sign: it can't show what it does
    let (_, lane, _) = &all[3];
    assert_eq!((lane.version, lane.check()), (1, Err(Error::Subnetwork)));
    // the others are as Kaspa takes them, and none of them this wallet's
    let keys = phrase_keys(PHRASE);
    let account = Account::new(&keys, Network::Mainnet).unwrap();
    for (id, tx, _) in all.iter().filter(|(_, tx, _)| tx.version == 0) {
        assert_eq!(tx.check(), Ok(()), "{id}");
        assert_eq!(account.check(tx).err(), Some(Error::NotOurs(0)), "{id}");
    }
}

fn review(name: &str) -> maki_kas::display::Review {
    let keys = phrase_keys(PHRASE);
    let f = fixtures().into_iter().find(|f| f.name == name).unwrap();
    let account = Account::new(&keys, f.network).unwrap();
    maki_kas::display::review(&account.check(&Request::parse(&f.request).unwrap()).unwrap())
}

#[test]
fn payments_the_change_and_the_fee() {
    let r = review("payment");
    assert_eq!(
        r.pages,
        [
            p("Send", "1.5 KAS", RECIPIENT, ""),
            p("Change", "8.497964 KAS", "back to you", ""),
            p("Fee", "0.002036 KAS", "", "")
        ]
    );
    assert_eq!(r.summary, "sends 1.5 KAS; fee 0.002036 KAS");
    // the same on the test network: its addresses, and its coins named as test coins
    let r = review("payment-testnet");
    assert_eq!(
        r.pages[..2],
        [
            p(
                "Test network!",
                "kaspa testnet",
                "",
                "Kaspa's signatures don't say which network they're for, and its test network has the same keys: if these coins are real KAS, this spends them as shown."
            ),
            p("Send", "1.5 TKAS", RECIPIENT_TEST, "")
        ]
    );
    assert_eq!(r.summary, "sends 1.5 TKAS; fee 0.002036 TKAS");
    let r = review("three-payments");
    assert_eq!(
        r.pages,
        [
            p("Send 1/3", "1 KAS", RECIPIENT, ""),
            p("Send 2/3", "0.5 KAS", ECDSA, ""),
            p("Send 3/3", "0.25 KAS", P2SH, ""),
            p("Change", "3.247 KAS", "back to you", ""),
            p("Fee", "0.003 KAS", "", "")
        ]
    );
    assert_eq!(r.summary, "sends 1.75 KAS in 3 payments; fee 0.003 KAS");
    // to one of this wallet's own receive addresses: nothing leaves but the fee
    let r = review("consolidate");
    assert_eq!(r.pages, [p("Change", "5.49 KAS", "back to you", ""), p("Fee", "0.01 KAS", "", "")]);
    assert_eq!(r.summary, "moves 5.49 KAS within this wallet; fee 0.01 KAS");
    let r = review("high-fee");
    assert_eq!(
        r.pages,
        [
            p("Send", "0.5 KAS", RECIPIENT, ""),
            p("High fee!", "0.5 KAS", "", "More than a tenth of what it sends.")
        ]
    );
    assert_eq!(r.summary, "sends 0.5 KAS; high fee 0.5 KAS!");
    let r = review("version-1");
    assert_eq!(r.pages[1..], [p("Change", "8.697 KAS", "back to you", ""), p("Fee", "0.003 KAS", "", "")]);
    let r = review("many-inputs");
    assert_eq!(r.summary, "sends 30 KAS; fee 0.01 KAS");
}

#[test]
fn data_and_time_locks_are_shown() {
    let r = review("payload");
    assert_eq!(r.pages[2], p("Data", "", "thanks for the coffee", DATA));
    assert_eq!(r.summary, "sends 1.5 KAS with data; fee 0.002078 KAS");
    let r = review("payload-bytes");
    assert_eq!(r.pages[2], p("Data", "in hex", "00017f80feff", DATA));
    let r = review("lock-time");
    assert_eq!(
        r.pages[2],
        p(
            "Not before",
            "DAA score 480000000",
            "",
            "It can't be confirmed until Kaspa's DAA score, which goes up about ten a second, passes this."
        )
    );
    let r = review("lock-time-date");
    assert_eq!(
        r.pages[2],
        p("Not before", "2027-01-01 00:00:00 UTC", "", "It can't be confirmed before then.")
    );
    let r = review("sequence-lock");
    assert_eq!(
        r.pages[2],
        p(
            "Waits",
            "36000 DAA scores",
            "",
            "It can't be confirmed until the coins it spends are that old: about 1 hour after they arrived."
        )
    );
    // a lock time no input lets hold isn't one
    let keys = phrase_keys(PHRASE);
    let account = Account::new(&keys, Network::Mainnet).unwrap();
    let mut tx = fixture("lock-time");
    tx.inputs[0].sequence = u64::MAX;
    let r = maki_kas::display::review(&account.check(&tx).unwrap());
    assert!(r.pages.iter().all(|p| p.heading != "Not before" && p.heading != "Waits"), "{:?}", r.pages);
    // data with control characters in it is shown in hex
    let mut tx = fixture("payload");
    tx.payload = b"pay\x1b[2Jme".to_vec();
    let r = maki_kas::display::review(&account.check(&tx).unwrap());
    assert_eq!(r.pages[2].mono, hex(b"pay\x1b[2Jme"));
}

#[test]
fn what_kaspa_would_refuse_maki_refuses() {
    let good = fixture("payment");
    let bad = |tx: &Request, e: Error| assert_eq!(Request::parse(&tx.bytes()), Err(e));
    let bytes = good.bytes();
    assert_eq!(Request::parse(&bytes[..bytes.len() - 1]), Err(Error::Length));
    assert_eq!(Request::parse(&[&bytes[..], &[0]].concat()), Err(Error::Length));
    assert_eq!(Request::parse(&[]), Err(Error::Length));
    assert_eq!(Request::parse(&vec![0; request::MAX_REQUEST + 1]), Err(Error::TooBig));
    let mut tx = good.clone();
    tx.version = 2;
    bad(&tx, Error::Version);
    let mut tx = good.clone();
    tx.inputs.clear();
    bad(&tx, Error::Empty);
    let mut tx = good.clone();
    tx.outputs.clear();
    bad(&tx, Error::Empty);
    let mut tx = good.clone();
    tx.outputs = vec![Output { value: 1, ..good.outputs[0].clone() }; request::MAX_OUTPUTS + 1];
    bad(&tx, Error::TooMany);
    // more inputs than signatures fit an answer: refused before they're read
    assert_eq!(Request::parse(&[0, 0, request::MAX_INPUTS as u8 + 1]), Err(Error::TooMany));
    let mut tx = good.clone();
    tx.inputs =
        (0..=request::MAX_INPUTS as u32).map(|i| Input { index: i, ..good.inputs[0].clone() }).collect();
    assert_eq!(tx.check(), Err(Error::TooMany));
    // keys off the account's two chains
    let mut tx = good.clone();
    tx.inputs[0].key = Derivation { chain: 2, index: 0 };
    bad(&tx, Error::Path);
    let mut tx = good.clone();
    tx.outputs[1].ours = Some(Derivation { chain: 1, index: maki_hd::HARDENED });
    bad(&tx, Error::Path);
    // a flag that's neither, and an output bound to a covenant
    let mut b = bytes.clone();
    let at = b.len() - 38 - 5 - 1;
    assert_eq!(b[at], 1, "the change's flag");
    b[at] = 2;
    assert_eq!(Request::parse(&b), Err(Error::Flag));
    let v1 = fixture("version-1");
    let mut b = v1.bytes();
    // before the change (52 bytes) and the payment's own flag, after its script
    let at = b.len() - 38 - 52 - 2;
    assert_eq!(b[at - 1..at + 2], [0xac, 0, 0], "the payment's covenant flag");
    b[at] = 1;
    assert_eq!(Request::parse(&b), Err(Error::Covenant(0)));
    // a coin spent twice, a coin of nothing, an output of nothing
    let mut tx = fixture("three-payments");
    tx.inputs[1].txid = tx.inputs[0].txid;
    tx.inputs[1].index = tx.inputs[0].index;
    bad(&tx, Error::Duplicate(1));
    let mut tx = good.clone();
    tx.inputs[0].amount = 0;
    bad(&tx, Error::Amount);
    let mut tx = good.clone();
    tx.outputs[0].value = 0;
    bad(&tx, Error::Zero(0));
    // more than there can be, alone or added up; more paid than held
    let mut tx = good.clone();
    tx.inputs[0].amount = MAX_SOMPI + 1;
    bad(&tx, Error::Amount);
    let mut tx = good.clone();
    tx.inputs.push(Input { index: 1, amount: MAX_SOMPI, ..good.inputs[0].clone() });
    bad(&tx, Error::Amount);
    let mut tx = good.clone();
    tx.outputs[0].value = MAX_SOMPI;
    tx.outputs[1].value = u64::MAX - MAX_SOMPI + 1;
    bad(&tx, Error::Amount);
    let mut tx = good.clone();
    tx.outputs[0].value += 203_601;
    bad(&tx, Error::NegativeFee);
    // a lane's transaction, gas, and more data than maki shows
    let mut tx = good.clone();
    tx.subnetwork[1] = 1;
    bad(&tx, Error::Subnetwork);
    let mut tx = good.clone();
    tx.subnetwork[0] = 1;
    bad(&tx, Error::Subnetwork);
    let mut tx = good.clone();
    tx.gas = 1;
    bad(&tx, Error::Gas);
    let mut tx = good.clone();
    tx.payload = vec![b'a'; request::MAX_PAYLOAD + 1];
    bad(&tx, Error::Payload);
    let mut tx = good.clone();
    tx.payload = vec![b'a'; request::MAX_PAYLOAD];
    assert!(Request::parse(&tx.bytes()).is_ok());
    // every reason said
    for e in [Error::TooBig, Error::Covenant(3), Error::Claim(2), Error::Keys(maki_hd::Error::Locked)] {
        assert!(!e.to_string().is_empty());
    }
    assert_eq!(Error::Payload.to_string(), "more data than maki can show (2048 bytes)");
}

#[test]
fn what_isnt_this_wallets_maki_refuses() {
    let keys = phrase_keys(PHRASE);
    let account = Account::new(&keys, Network::Mainnet).unwrap();
    let good = fixture("payment");
    // a coin said to be receive #0's that another key's pays, or that receive #1's does
    let not_mine = fixture("not-mine");
    assert_eq!(account.check(&not_mine).err(), Some(Error::NotOurs(0)));
    let mut tx = good.clone();
    tx.inputs[0].key = Derivation { chain: 0, index: 1 };
    assert_eq!(account.check(&tx).err(), Some(Error::NotOurs(0)));
    // the same key's coin as ECDSA's, which this wallet's isn't
    let mut tx = good.clone();
    let key = account.key(Derivation { chain: 0, index: 0 }).unwrap();
    tx.inputs[0].script.script = [&[0x21][..], &key, &[0xab]].concat();
    assert_eq!(account.check(&tx).err(), Some(Error::NotOurs(0)));
    // more signature checks than its coin takes
    let mut tx = good.clone();
    tx.inputs[0].sig_op_count = 2;
    assert_eq!(account.check(&tx).err(), Some(Error::SigOps(0)));
    // change that isn't: it names change #0 and pays change #1
    let mut tx = good.clone();
    tx.outputs[1].ours = Some(Derivation { chain: 1, index: 1 });
    assert_eq!(account.check(&tx).err(), Some(Error::NotChange(1)));
    // a payment to no address: nodes won't relay it
    let mut tx = good.clone();
    tx.outputs[0].script = Script { version: 0, script: vec![0x6a, 0x01, 0x00] };
    assert_eq!(account.check(&tx).err(), Some(Error::NonStandard(0)));
    let mut tx = good.clone();
    tx.outputs[0].script.version = 1;
    assert_eq!(account.check(&tx).err(), Some(Error::NonStandard(0)));
    // and a request made by hand is held to what a parsed one is
    let mut tx = good.clone();
    tx.gas = 7;
    assert_eq!(account.check(&tx).err(), Some(Error::Gas));
    // a locked maki gives no account
    struct Locked;
    impl maki_hd::Keys for Locked {
        fn fingerprint(&self) -> Result<[u8; 4], maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn public(&self, _: &[u32]) -> Result<maki_hd::Public, maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn uncompressed(&self, _: &[u32]) -> Result<[u8; 65], maki_hd::Error> { Err(maki_hd::Error::Locked) }

        fn taproot_output(&self, _: &[u32]) -> Result<[u8; 32], maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }

        fn sign_ecdsa(&self, _: &[u32], _: &[u8; 32]) -> Result<([u8; 64], u8), maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }

        fn sign_schnorr(
            &self,
            _: &[u32],
            _: &[u8; 32],
            _: maki_hd::Tweak,
        ) -> Result<[u8; 64], maki_hd::Error> {
            Err(maki_hd::Error::Locked)
        }
    }
    assert_eq!(Account::new(&Locked, Network::Mainnet).err(), Some(Error::Keys(maki_hd::Error::Locked)));
}

#[test]
fn a_coin_said_to_hold_two_amounts_is_caught() {
    let tx = fixture("three-payments");
    let mut claims = Claims::default();
    assert_eq!(claims.check(&tx), Ok(()));
    claims.add(&tx);
    assert_eq!(claims.len(), 2);
    // asked again, the same: fine, and kept once
    assert_eq!(claims.check(&tx), Ok(()));
    claims.add(&tx);
    assert_eq!(claims.len(), 2);
    // the same transaction, the second coin now said to hold less: the first time or this, a lie
    let mut lie = tx.clone();
    lie.inputs[1].amount -= 100_000_000;
    lie.outputs[3].value -= 100_000_000;
    assert_eq!(claims.check(&lie), Err(Error::Claim(1)));
    // kept as the app keeps them, and read back
    let bytes = claims.bytes();
    assert_eq!(bytes.len(), 2 * CLAIM);
    assert_eq!(Claims::read(&bytes), claims);
    assert_eq!(Claims::read(&bytes[..CLAIM + 3]).len(), 1, "whole claims alone");
    // the newest MAX_CLAIMS: a coin's claim goes once that many others' have come after it
    let many = fixture("many-inputs");
    for round in 0..(MAX_CLAIMS / many.inputs.len() + 1) {
        let mut more = many.clone();
        for input in &mut more.inputs {
            input.txid[0] = round as u8 + 1;
            input.txid[1] = 0xee;
        }
        claims.add(&more);
    }
    assert_eq!(claims.len(), MAX_CLAIMS);
    assert_eq!(claims.check(&lie), Ok(()), "forgotten");
    assert_eq!(Claims::read(&[claims.bytes(), claims.bytes()].concat()).len(), MAX_CLAIMS);
}

#[test]
fn amounts_and_dates_exactly() {
    assert_eq!(decimals(0, 8), "0");
    assert_eq!(decimals(1, 8), "0.00000001");
    assert_eq!(decimals(150_000_000, 8), "1.5");
    assert_eq!(decimals(42, 0), "42");
    assert_eq!(kas(MAX_SOMPI, Network::Mainnet), "29000000000 KAS");
    assert_eq!(kas(u64::MAX, Network::Testnet), "184467440737.09551615 TKAS");
    assert_eq!(date(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(date(951_782_400_000), "2000-02-29 00:00:00 UTC");
    assert_eq!(date(1_798_761_599_999), "2026-12-31 23:59:59.999 UTC");
    assert_eq!(date(u64::MAX), "584556019-04-03 14:25:51.615 UTC");
}
