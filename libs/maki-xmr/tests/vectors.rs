//! The BIP39 test phrase's Monero wallet ("abandon" eleven times, then "about"), as two others
//! make it: Ledger's Monero app (its tests, which use this phrase: the keys, and the stagenet
//! address) and monero-python 1.1.1 (the 25 words, every network's address, subaddresses).
use maki_xmr::{Keys, Kind, Network, address, read_address, words};

/// The phrase's BIP32 key at m/44'/128'/0'/0/0 (rust-bitcoin).
const BIP32: &str = "db9e57474be8b64118b6acf6ecebd13f8f7c326b3bc1b19f4546573d6bac9dcf";
const SPEND: &str = "3b094ca7218f175e91fa2402b4ae239a2fe8262792a3e718533a1a357a1e4109";
const VIEW: &str = "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201";
const SPEND_PUBLIC: &str = "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d";
const VIEW_PUBLIC: &str = "865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa";
const WORDS: &str = "tavern judge beyond bifocals deepest mural onward dummy eagle diode gained vacation rally \
                     cause firm idled jerseys moat vigilant upload bobsled jobs cunning doing jobs";

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
    v.try_into().unwrap()
}

fn keys() -> Keys { Keys::from_bip32(&unhex(BIP32)) }

#[test]
fn keys_are_ledgers() {
    let k = keys();
    assert_eq!(hex(&k.spend_bytes()), SPEND);
    assert_eq!(hex(&k.view_bytes()), VIEW);
    let (spend, view) = k.public();
    assert_eq!((hex(&spend), hex(&view)), (SPEND_PUBLIC.into(), VIEW_PUBLIC.into()));
}

#[test]
fn addresses_are_every_wallets() {
    let (spend, view) = keys().public();
    for (network, expected) in [
        (
            Network::Mainnet,
            "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn",
        ),
        (
            Network::Testnet,
            "A1Tm6174Q22e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVKKfJLQ",
        ),
        // Ledger's test_crypto.py has this one
        (
            Network::Stagenet,
            "5A8FgbMkmG2e3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVHCRUaE",
        ),
    ] {
        let a = address(network, Kind::Standard, &spend, &view);
        assert_eq!(a, expected);
        assert_eq!(read_address(&a), Some((network, Kind::Standard, spend, view)));
    }
}

#[test]
fn subaddresses_are_every_wallets() {
    let k = keys();
    for (network, (major, minor), expected) in [
        (
            Network::Mainnet,
            (0, 1),
            "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ",
        ),
        (
            Network::Mainnet,
            (0, 2),
            "8696JpJ6Yvw8VtJqpQ7V8gNLBdgwLK5xYLQPfE7DpzdQGo4gKPWMJSubTt8rvvTrWagePa2q1P3k3TvRkGiHZGGUL1cuAwo",
        ),
        (
            Network::Mainnet,
            (1, 0),
            "8BwfMo73i9GeqjRg6vctzrL7vTuG3Ap6JDaT8cqWrLTJGsHuJP2aSq4NFutnw8giH7goWTFSbg5ny3Rukad8cBQeEv9KMst",
        ),
        (
            Network::Mainnet,
            (2, 7),
            "85mwm6zoWkeAydxd69jdubASfvsVFhy3f9Jt8a4FiNmKfzNd9epYvpTAkFQz33F97YLqKpUCGKCdk7DHBBVriZtyFxJFEoS",
        ),
        (
            Network::Testnet,
            (0, 1),
            "BfuEgMbFQXUdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QXUerjA",
        ),
        (
            Network::Stagenet,
            (0, 1),
            "79y5JZUvzJWdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QWJ9bkP",
        ),
        (
            Network::Stagenet,
            (2, 7),
            "75ZugG5qs9YAydxd69jdubASfvsVFhy3f9Jt8a4FiNmKfzNd9epYvpTAkFQz33F97YLqKpUCGKCdk7DHBBVriZtyG1F1MsE",
        ),
    ] {
        let (spend, view) = k.subaddress(major, minor);
        assert_eq!(address(network, Kind::Subaddress, &spend, &view), expected, "{major},{minor}");
    }
    // account 0's address 0 is the account's own
    assert_eq!(k.subaddress(0, 0), k.public());
}

#[test]
fn the_backup_is_the_25_words_monero_wallets_restore() {
    let k = keys();
    assert_eq!(k.words().join(" "), WORDS.split_whitespace().collect::<Vec<_>>().join(" "));
    let w: Vec<&str> = WORDS.split_whitespace().collect();
    assert_eq!(words::decode(&w), Some(unhex(SPEND)));
    // without the check word, too
    assert_eq!(words::decode(&w[..24]), Some(unhex(SPEND)));
    // a wrong check word, a word not on the list, too few words
    let mut wrong = w.clone();
    wrong[24] = "tavern";
    assert_eq!(words::decode(&wrong), None);
    let mut unknown = w.clone();
    unknown[3] = "bitcoin";
    assert_eq!(words::decode(&unknown), None);
    assert_eq!(words::decode(&w[..23]), None);
    // and any 32 bytes come back from their words
    let mut seed = [0u8; 32];
    for i in 0..64u32 {
        for (j, b) in seed.iter_mut().enumerate() {
            *b = (i.wrapping_mul(151).wrapping_add(j as u32 * 89) ^ (i << 3)) as u8;
        }
        assert_eq!(words::decode(&words::encode(&seed)), Some(seed), "{i}");
    }
    // three words saying more than four bytes hold aren't taken: 0, then 1625, then 1625 more
    // (1626 x 1627 x 1625 is past 2^32)
    let over: Vec<&str> = ["abbey", "zoom", "zones"].repeat(8);
    assert_eq!(words::decode(&over), None);
}

#[test]
fn addresses_that_arent_are_turned_away() {
    let (spend, view) = keys().public();
    let a = address(Network::Mainnet, Kind::Standard, &spend, &view);
    // a changed character: the check fails
    let mut changed = a.clone().into_bytes();
    changed[40] = if changed[40] == b'a' { b'b' } else { b'a' };
    assert_eq!(read_address(core::str::from_utf8(&changed).unwrap()), None);
    // not base58, cut short, too long
    assert_eq!(read_address(&a.replace('4', "0")), None);
    assert_eq!(read_address(&a[..94]), None);
    assert_eq!(read_address(&format!("{a}1")), None);
    // an integrated address (with a payment ID) isn't one maki makes
    assert_eq!(
        read_address(
            "4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK"
        ),
        None
    );
}
