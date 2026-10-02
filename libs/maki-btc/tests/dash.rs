//! Dash: Bitcoin's transactions before SegWit, which it never took, with special transactions of
//! its own (DIP-2). Its account pays to a key's hash (BIP44, `m/44'/5'/0'`, as Dash Core, Ledger
//! and Trezor make it); its signatures are the old digest, which commits to no amount. Held to what
//! Dash's own library, @dashevo/dashcore-lib, makes (`fixtures/make-dash.mjs`, deriving the test
//! phrase's keys itself): the test phrase's addresses, and a payment spending a plain coin and one
//! a withdrawal from Dash Platform paid (an asset unlock: no inputs, and a payload the txid hashes),
//! shown in DASH and signed byte for byte as dashcore-lib signs it, the whole signed transaction
//! dashcore-lib's, and its spends taken by Bitcoin Core's script interpreter, whose rules for paying
//! to a key's hash Dash's are. And what maki refuses: special transactions, by name; versions Dash
//! doesn't relay; a coin without its transaction; another network's account.

use maki_btc::display::{amount, fee_rate_unit, network_name, unit};
use maki_btc::psbt::{self, Pair, Psbt};
use maki_btc::tx::{Tx, dash_type, dash_version};
use maki_btc::wallet::{self, Error, Kind};
use maki_btc::{Account, Network};
use maki_hd::Keys;
use maki_hd::seed::SeedKeys;
use sha2::{Digest, Sha256};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn keys() -> &'static SeedKeys {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    Box::leak(Box::new(SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap()))
}

fn dash(network: Network) -> Account<'static> { Account::new(keys(), network, Kind::Legacy).unwrap() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn sha256d(b: &[u8]) -> [u8; 32] { Sha256::digest(Sha256::digest(b)).into() }

fn fixtures() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dash.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn addresses_are_the_ones_dashs_wallets_make() {
    let f = fixtures();
    let a = &f["addresses"];
    let account = dash(Network::Dash);
    // BIP44's first, as wallets make it for the test phrase
    assert_eq!(account.address(false, 0).unwrap(), "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5");
    assert_eq!(account.address(false, 0).unwrap(), a["m/44'/5'/0'/0/0"]);
    assert_eq!(account.address(false, 1).unwrap(), a["m/44'/5'/0'/0/1"]);
    assert_eq!(account.address(true, 0).unwrap(), a["m/44'/5'/0'/1/0"]);
    // the test network's: coin type 1, `y…`
    assert_eq!(dash(Network::DashTest).address(false, 0).unwrap(), a["m/44'/1'/0'/0/0"]);
    // the account key as Dash Core and dashcore-lib write it (Bitcoin's xpub)
    assert_eq!(account.zpub(), f["xpub"].as_str().unwrap());
    let descriptor = account.descriptor();
    let body = format!("pkh([73c5da0a/44h/5h/0h]{}/<0;1>/*)", f["xpub"].as_str().unwrap());
    assert_eq!(descriptor, format!("{body}#{}", wallet::descriptor_checksum(&body)));
    // a script's hash, as Dash's P2SH (`7…`, and `8…` on its test network)
    let p2sh = [&[0xa9, 0x14][..], &[0x11; 20], &[0x87]].concat();
    assert_eq!(maki_btc::address::describe(&p2sh, Network::Dash), f["p2sh"]["livenet"].as_str().unwrap());
    assert_eq!(maki_btc::address::describe(&p2sh, Network::DashTest), f["p2sh"]["testnet"].as_str().unwrap());
}

#[test]
fn dash_has_one_kind_of_account_and_its_own_units() {
    for network in [Network::Dash, Network::DashTest] {
        for kind in [Kind::Segwit, Kind::Taproot] {
            assert!(matches!(Account::new(keys(), network, kind), Err(Error::Unsupported(_))));
        }
    }
    // SegWit's scripts have no address on Dash: they're shown as scripts
    let p2wpkh = [&[0x00, 0x14][..], &[0x22; 20]].concat();
    assert!(maki_btc::address::describe(&p2wpkh, Network::Dash).starts_with("script 0014"));
    assert_eq!((unit(Network::Dash), unit(Network::DashTest)), ("DASH", "tDASH"));
    assert_eq!((network_name(Network::Dash), network_name(Network::DashTest)), ("dash", "dash testnet"));
    assert_eq!((Network::Dash.coin_type(), Network::DashTest.coin_type()), (5, 1));
    assert_eq!(amount(Network::Dash.max_money(), Network::Dash), "21000000 DASH");
    assert_eq!(fee_rate_unit(Network::Dash), "duff/B");
    assert!(Network::Dash.is_dash() && !Network::Dogecoin.is_dash() && !Network::Dash.has_segwit());
}

#[test]
fn a_special_transaction_reads_with_its_payload() {
    let f = fixtures();
    let p = &f["payment"];
    // the withdrawal from Dash Platform: an asset unlock (type 9, version 3), no inputs, a payload
    let bytes = unhex(p["previous"][1].as_str().unwrap());
    let (tx, payload) = Tx::parse_dash(&bytes).unwrap();
    assert_eq!((dash_version(tx.version), dash_type(tx.version)), (3, 9));
    assert_eq!((tx.inputs.len(), tx.outputs.len(), payload.len()), (0, 1, 145));
    assert_eq!(tx.outputs[0].value, 25_000_000);
    // its txid, as dashcore-lib has it, hashes the payload too: the bytes as they are
    let mut id = sha256d(&bytes);
    id.reverse();
    assert_eq!(hex(&id), p["previousIds"][1].as_str().unwrap());
    // Bitcoin's reader takes no such thing: it has bytes after the lock time
    assert!(Tx::parse(&bytes).is_err());
    // and a plain transaction reads the same either way, with no payload
    let plain = unhex(p["previous"][0].as_str().unwrap());
    let (dash_tx, payload) = Tx::parse_dash(&plain).unwrap();
    assert_eq!((dash_tx, payload.is_empty()), (Tx::parse(&plain).unwrap(), true));
    // cut short, or with more after it, or a payload too long for Dash: not a transaction
    assert!(Tx::parse_dash(&bytes[..bytes.len() - 1]).is_err());
    assert!(Tx::parse_dash(&[&bytes[..], &[0]].concat()).is_err());
    // no inputs is only a special transaction's
    let mut plain_nothing = bytes.clone();
    plain_nothing[2..4].copy_from_slice(&[0, 0]);
    assert!(Tx::parse_dash(&plain_nothing).is_err());
}

/// The test phrase's key at a path, and that path as a PSBT's derivation has it (the master key's
/// fingerprint, then each step).
fn derivation(path: &str) -> ([u8; 33], Vec<u8>) {
    let path = maki_hd::parse_path(path).unwrap();
    let key = keys().public(&path).unwrap().key;
    let mut value = keys().fingerprint().unwrap().to_vec();
    path.iter().for_each(|n| value.extend_from_slice(&n.to_le_bytes()));
    (key, value)
}

/// dashcore-lib's payment as a PSBT, as Dash Core and maki desktop make one: the transaction, the
/// whole transaction each input spends, each key's derivation, and the change's. Written out by
/// hand: rust-bitcoin can't read a special transaction.
fn payment_with(unsigned: &[u8], previous: &[Vec<u8>]) -> Psbt {
    let f = fixtures();
    let p = &f["payment"];
    let pair = |key: Vec<u8>, value: Vec<u8>| Pair { key, value };
    let inputs = previous
        .iter()
        .zip(p["paths"].as_array().unwrap())
        .map(|(prev, path)| {
            let (key, value) = derivation(path.as_str().unwrap());
            vec![
                pair(vec![psbt::IN_NON_WITNESS_UTXO], prev.clone()),
                pair([&[psbt::IN_BIP32_DERIVATION][..], &key].concat(), value),
            ]
        })
        .collect();
    let (key, value) = derivation(p["change"].as_str().unwrap());
    let change = vec![pair([&[psbt::OUT_BIP32_DERIVATION][..], &key].concat(), value)];
    let (tx, _) = Tx::parse_dash(unsigned).unwrap();
    let outputs = vec![vec![], change];
    Psbt { global: vec![pair(vec![psbt::GLOBAL_UNSIGNED_TX], unsigned.to_vec())], inputs, outputs, tx }
}

fn payment() -> Psbt {
    let f = fixtures();
    let p = &f["payment"];
    let previous: Vec<Vec<u8>> =
        p["previous"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
    payment_with(&unhex(p["unsigned"].as_str().unwrap()), &previous)
}

fn accounts() -> [Account<'static>; 1] { [dash(Network::Dash)] }

#[test]
fn a_payment_is_shown_in_dash() {
    let f = fixtures();
    let psbt = Psbt::parse_on(&payment().serialize(), Network::Dash).unwrap();
    let r = wallet::review(&psbt, &accounts()).unwrap();
    assert_eq!((r.network, r.inputs, r.fee), (Network::Dash, 2, 10_000));
    assert_eq!(
        (r.outputs[0].address.as_str(), amount(r.outputs[0].amount, r.network), r.outputs[0].change),
        (f["payment"]["payee"].as_str().unwrap(), "1 DASH".to_string(), false)
    );
    assert_eq!(
        (r.outputs[1].address.as_str(), amount(r.outputs[1].amount, r.network), r.outputs[1].change),
        ("XeBdurzVrhrFtgqf9SxzQqvhHodb53njW4", "0.7499 DASH".to_string(), true)
    );
    let pages = r.pages();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Change", "Fee"]);
    assert_eq!((pages[2].value.as_str(), pages[2].mono.as_str()), ("0.0001 DASH", "27 duff/B"));
    assert_eq!(r.summary(), "Total 1.0001 DASH");
}

#[test]
fn a_payment_is_signed_as_dashcore_lib_signs_it() {
    let f = fixtures();
    let p = &f["payment"];
    let mut psbt = Psbt::parse_on(&payment().serialize(), Network::Dash).unwrap();
    assert_eq!(wallet::signatures(&psbt, &accounts()).unwrap(), 2);
    assert_eq!(wallet::sign(&mut psbt, &accounts()).unwrap(), 2);
    // the very signatures dashcore-lib makes: the old digest, RFC 6979, low S, SIGHASH_ALL
    let signed = Psbt::parse_on(&psbt.serialize(), Network::Dash).unwrap();
    let mut sigs = Vec::new();
    for (i, theirs) in p["signatures"].as_array().unwrap().iter().enumerate() {
        let pair = signed.inputs[i].iter().find(|p| p.key.first() == Some(&psbt::IN_PARTIAL_SIG)).unwrap();
        assert_eq!(hex(&pair.value), theirs.as_str().unwrap(), "input {i}");
        sigs.push((pair.value.clone(), pair.key[1..].to_vec()));
    }
    // each input's script its signature and its key: the whole transaction, as dashcore-lib signs it
    let mut tx = signed.tx.clone();
    for (input, (sig, key)) in tx.inputs.iter_mut().zip(&sigs) {
        input.script_sig = [&[sig.len() as u8][..], sig, &[key.len() as u8], key].concat();
    }
    assert_eq!(hex(&tx.serialize()), p["signed"].as_str().unwrap());
    // and Bitcoin Core's interpreter takes the spends (the payment is a plain transaction, which
    // Bitcoin reads as Dash does; the coins it spends are given as Dash reads them)
    let spent: Vec<bitcoin::TxOut> = p["previous"]
        .as_array()
        .unwrap()
        .iter()
        .zip(p["vouts"].as_array().unwrap())
        .map(|(prev, vout)| {
            let (prev, _) = Tx::parse_dash(&unhex(prev.as_str().unwrap())).unwrap();
            let o = &prev.outputs[vout.as_u64().unwrap() as usize];
            bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(o.value),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(o.script_pubkey.clone()),
            }
        })
        .collect();
    let theirs: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx.serialize()).unwrap();
    let ids: Vec<[u8; 32]> = signed.tx.inputs.iter().map(|i| i.prev_txid).collect();
    theirs
        .verify(|o| {
            use bitcoin::hashes::Hash;
            ids.iter().position(|id| *id == o.txid.to_byte_array()).map(|i| spent[i].clone())
        })
        .unwrap();
}

#[test]
fn special_transactions_are_refused_by_name() {
    let f = fixtures();
    let review = |unsigned: &[u8], previous: &[Vec<u8>]| {
        let psbt = Psbt::parse_on(&payment_with(unsigned, previous).serialize(), Network::Dash).unwrap();
        wallet::review(&psbt, &accounts())
    };
    let p = &f["payment"];
    let previous: Vec<Vec<u8>> =
        p["previous"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
    // an asset lock as dashcore-lib makes it: credit for Dash Platform
    let lock = unhex(f["assetLock"]["unsigned"].as_str().unwrap());
    assert_eq!(
        review(&lock, &previous[..1]).unwrap_err().to_string(),
        "a Dash asset lock (credit for Dash Platform): maki signs payments only"
    );
    // every type Dash has, each by its name, after the payment's lock time a payload
    let unsigned = unhex(p["unsigned"].as_str().unwrap());
    let names = ["ProRegTx", "ProUpServTx", "ProUpRegTx", "ProUpRevTx", "CbTx", "QcTx", "MnHfTx"];
    for (kind, name) in (1u16..=7).zip(names) {
        let mut special = [&unsigned[..], &[2, 0xaa, 0xbb]].concat();
        special[2..4].copy_from_slice(&kind.to_le_bytes());
        let why = review(&special, &previous).unwrap_err().to_string();
        assert!(why.contains(name) && why.ends_with("maki signs payments only"), "{why}");
    }
    let mut unlock = [&unsigned[..], &[2, 0xaa, 0xbb]].concat();
    unlock[2..4].copy_from_slice(&9u16.to_le_bytes());
    assert!(review(&unlock, &previous).unwrap_err().to_string().contains("withdrawal from Dash Platform"));
    // a type below version 3, which Dash refuses; a version it doesn't relay
    let mut low = unsigned.clone();
    low[..4].copy_from_slice(&[2, 0, 5, 0]);
    assert_eq!(
        review(&low, &previous).unwrap_err().to_string(),
        "a special transaction type below version 3, which Dash refuses"
    );
    for version in [0u32, 4, 0xffff] {
        let mut odd = unsigned.clone();
        odd[..4].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            review(&odd, &previous).unwrap_err(),
            Error::Unsupported("a transaction version Dash doesn't relay (it relays 1 to 3)"),
            "version {version}"
        );
    }
    // versions 1 and 2 are payments too, as Dash Core's wallet makes them
    for version in [1u32, 2] {
        let mut plain = unsigned.clone();
        plain[..4].copy_from_slice(&version.to_le_bytes());
        assert!(review(&plain, &previous).is_ok(), "version {version}");
    }
}

#[test]
fn a_coin_needs_the_transaction_it_comes_from() {
    let f = fixtures();
    let p = &f["payment"];
    let mut previous: Vec<Vec<u8>> =
        p["previous"].as_array().unwrap().iter().map(|t| unhex(t.as_str().unwrap())).collect();
    let unsigned = unhex(p["unsigned"].as_str().unwrap());
    // without it, an amount would be the PSBT's word, which a signature that commits to no amount
    // can't check
    let mut without = payment();
    without.inputs[1].retain(|pair| pair.key != [psbt::IN_NON_WITNESS_UTXO]);
    let without = Psbt::parse_on(&without.serialize(), Network::Dash).unwrap();
    assert_eq!(wallet::review(&without, &accounts()), Err(Error::NoPreviousTx(1)));
    // another transaction, or the right one with its payload changed: not what the input spends
    previous[1][100] ^= 1;
    let changed = Psbt::parse_on(&payment_with(&unsigned, &previous).serialize(), Network::Dash).unwrap();
    assert_eq!(wallet::review(&changed, &accounts()), Err(Error::PreviousTxMismatch(1)));
    // the test network's account, and Dogecoin's, have other keys
    let psbt = Psbt::parse_on(&payment().serialize(), Network::Dash).unwrap();
    assert_eq!(wallet::review(&psbt, &[dash(Network::DashTest)]), Err(Error::NotOurs(0)));
    let doge = [Account::new(keys(), Network::Dogecoin, Kind::Legacy).unwrap()];
    assert_eq!(wallet::review(&psbt, &doge), Err(Error::NotOurs(0)));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The payment above, unsigned and as maki signs it: for the Dash app's tests, the emulator's demo
/// and maki desktop's. Regenerate (only if the fixture changes) with
///     cargo test -p maki-btc --test dash -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    let unsigned = payment().serialize();
    std::fs::write(format!("{FIXTURES}/dash-unsigned.psbt"), &unsigned).unwrap();
    let mut psbt = Psbt::parse_on(&unsigned, Network::Dash).unwrap();
    wallet::sign(&mut psbt, &accounts()).unwrap();
    std::fs::write(format!("{FIXTURES}/dash-signed.psbt"), psbt.serialize()).unwrap();
}

#[test]
fn the_fixtures_are_current() {
    let unsigned = payment().serialize();
    assert_eq!(std::fs::read(format!("{FIXTURES}/dash-unsigned.psbt")).unwrap(), unsigned);
    let mut psbt = Psbt::parse_on(&unsigned, Network::Dash).unwrap();
    wallet::sign(&mut psbt, &accounts()).unwrap();
    assert_eq!(std::fs::read(format!("{FIXTURES}/dash-signed.psbt")).unwrap(), psbt.serialize());
}
