//! Dogecoin and Bitcoin Cash: Bitcoin's transactions before SegWit, which neither took. Their
//! accounts pay to a key's hash (BIP44); Dogecoin signs the old digest, Bitcoin Cash BIP143's with
//! its fork ID (SIGHASH_ALL | SIGHASH_FORKID). Held to what those coins' own kind of libraries make
//! (`fixtures/make-forks.mjs`): Dogecoin's addresses and a payment's PSBT and signatures by
//! bitcoinjs-lib with Dogecoin Core's parameters, Bitcoin Cash's addresses (CashAddr), a payment's
//! digests and signatures by libauth, each library deriving the test phrase's keys itself; the
//! first addresses are the ones wallets publish for the test phrase. Dogecoin's spends pass Bitcoin
//! Core's script interpreter too, whose rules for paying to a key's hash Dogecoin's are.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::consensus::deserialize;
use bitcoin::psbt::Psbt as BPsbt;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{ScriptBuf, Transaction, TxOut};
use maki_btc::display::{amount, network_name, unit};
use maki_btc::psbt::Psbt;
use maki_btc::wallet::{self, Error, Kind, SIGHASH_ALL_FORKID};
use maki_btc::{Account, Network};
use maki_hd::seed::SeedKeys;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn keys() -> &'static SeedKeys {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    Box::leak(Box::new(SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap()))
}

fn legacy(network: Network) -> Account<'static> { Account::new(keys(), network, Kind::Legacy).unwrap() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn fixtures() -> serde_json::Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/forks.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn dogecoin_addresses_are_the_ones_its_wallets_make() {
    let f = fixtures();
    let a = &f["dogecoin"]["addresses"];
    let doge = legacy(Network::Dogecoin);
    // BIP44's first, as wallets publish it for the test phrase
    assert_eq!(doge.address(false, 0).unwrap(), "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
    assert_eq!(doge.address(false, 0).unwrap(), a["m/44'/3'/0'/0/0"]);
    assert_eq!(doge.address(false, 1).unwrap(), a["m/44'/3'/0'/0/1"]);
    assert_eq!(doge.address(true, 0).unwrap(), a["m/44'/3'/0'/1/0"]);
    assert_eq!(legacy(Network::DogecoinTest).address(false, 0).unwrap(), a["m/44'/1'/0'/0/0"]);
    let descriptor = doge.descriptor();
    assert!(descriptor.starts_with("pkh([73c5da0a/44h/3h/0h]xpub"), "{descriptor}");
    let body = descriptor.split('#').next().unwrap();
    assert_eq!(descriptor, format!("{body}#{}", wallet::descriptor_checksum(body)));
}

#[test]
fn bitcoin_cash_addresses_are_cashaddr_as_its_wallets_make_them() {
    let f = fixtures();
    let a = &f["bitcoinCash"]["addresses"];
    let bch = legacy(Network::BitcoinCash);
    // BIP44's first, as Electron Cash and the others publish it for the test phrase
    assert_eq!(bch.address(false, 0).unwrap(), "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6");
    assert_eq!(bch.address(false, 1).unwrap(), a["m/44'/145'/0'/0/1"]);
    assert_eq!(bch.address(true, 0).unwrap(), a["m/44'/145'/0'/1/0"]);
    assert_eq!(legacy(Network::BitcoinCashTest).address(false, 0).unwrap(), a["m/44'/1'/0'/0/0"]);
    assert!(bch.descriptor().starts_with("pkh([73c5da0a/44h/145h/0h]xpub"));
    // a P2SH output, as CashAddr's type 1 (`p…`)
    let p2sh = [&[0xa9, 0x14][..], &[0x11; 20], &[0x87]].concat();
    assert!(maki_btc::address::describe(&p2sh, Network::BitcoinCash).starts_with("bitcoincash:p"));
}

#[test]
fn each_network_has_its_own_kinds_of_account() {
    for network in [Network::Dogecoin, Network::BitcoinCash, Network::DogecoinTest] {
        for kind in [Kind::Segwit, Kind::Taproot] {
            assert!(matches!(Account::new(keys(), network, kind), Err(Error::Unsupported(_))));
        }
    }
    for network in [Network::Bitcoin, Network::Litecoin] {
        assert!(matches!(Account::new(keys(), network, Kind::Legacy), Err(Error::Unsupported(_))));
    }
    // and SegWit's scripts have no address where there's no SegWit: they're shown as scripts
    let p2wpkh = [&[0x00, 0x14][..], &[0x22; 20]].concat();
    assert!(maki_btc::address::describe(&p2wpkh, Network::Dogecoin).starts_with("script 0014"));
    assert_eq!((unit(Network::Dogecoin), unit(Network::BitcoinCashTest)), ("DOGE", "tBCH"));
    assert_eq!(network_name(Network::BitcoinCash), "bitcoin cash");
    assert_eq!(Network::Dogecoin.coin_type(), 3);
    assert_eq!(Network::BitcoinCash.coin_type(), 145);
}

fn dogecoin_payment() -> (Vec<u8>, Vec<Vec<u8>>, String) {
    let f = fixtures();
    let p = &f["dogecoin"]["payment"];
    let signatures = p["signatures"].as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
    (unhex(p["unsigned"].as_str().unwrap()), signatures, p["payee"].as_str().unwrap().into())
}

#[test]
fn a_dogecoin_payment_is_shown_and_signed_as_bitcoinjs_signs_it() {
    let (unsigned, theirs, payee) = dogecoin_payment();
    let accounts = [legacy(Network::Dogecoin)];
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    let r = wallet::review(&psbt, &accounts).unwrap();
    assert_eq!((r.network, r.inputs, r.fee), (Network::Dogecoin, 2, 1_000_000));
    assert_eq!((r.outputs[0].address.as_str(), r.outputs[0].change), (payee.as_str(), false));
    assert_eq!(amount(r.outputs[0].amount, r.network), "10 DOGE");
    assert_eq!(
        (r.outputs[1].address.as_str(), amount(r.outputs[1].amount, r.network), r.outputs[1].change),
        ("D7ReBLrRv12mi9pYh5HtfFLTt1PSoeAa7e", "11.49 DOGE".to_string(), true)
    );
    assert_eq!(wallet::sign(&mut psbt, &accounts).unwrap(), 2);
    // the very signatures bitcoinjs-lib makes: the old digest, RFC 6979, low S
    let signed = BPsbt::deserialize(&psbt.serialize()).unwrap();
    for (i, input) in signed.inputs.iter().enumerate() {
        let (_, sig) = input.partial_sigs.iter().next().unwrap();
        assert_eq!(sig.to_vec(), theirs[i], "input {i}");
    }
    // and Bitcoin Core's interpreter takes the spends: <signature> <key> for each
    let mut done = signed.clone();
    for input in done.inputs.iter_mut() {
        let (pk, sig) = input.partial_sigs.pop_first().unwrap();
        input.final_script_sig =
            Some(bitcoin::script::Builder::new().push_slice(sig.serialize()).push_key(&pk).into_script());
    }
    let prevs: Vec<Transaction> = done.inputs.iter().map(|i| i.non_witness_utxo.clone().unwrap()).collect();
    let tx = done.extract_tx().unwrap();
    tx.verify(|o| {
        prevs.iter().find(|p| p.compute_txid() == o.txid).map(|p| p.output[o.vout as usize].clone())
    })
    .unwrap();
    // the size maki reckoned with covers what was signed
    let size = bitcoin::consensus::serialize(&tx).len() as u64;
    assert!(r.vbytes >= size && r.vbytes <= size + 2, "reckoned {} for {}", r.vbytes, size);
}

#[test]
fn a_dogecoin_coin_needs_the_transaction_it_comes_from() {
    let (unsigned, _, _) = dogecoin_payment();
    let mut b = BPsbt::deserialize(&unsigned).unwrap();
    let prev = b.inputs[1].non_witness_utxo.take().unwrap();
    // an amount on the PSBT's word alone: never, before SegWit or after
    b.inputs[1].witness_utxo = Some(prev.output[1].clone());
    let accounts = [legacy(Network::Dogecoin)];
    assert_eq!(wallet::review(&Psbt::parse(&b.serialize()).unwrap(), &accounts), Err(Error::NoPreviousTx(1)));
    // a Dogecoin coin isn't Bitcoin Cash's: other keys (coin type 145)
    let bch = [legacy(Network::BitcoinCash)];
    assert_eq!(wallet::review(&Psbt::parse(&unsigned).unwrap(), &bch), Err(Error::NotOurs(0)));
}

/// libauth's Bitcoin Cash payment as a PSBT, the way maki desktop makes one: the transaction, the
/// whole transaction each input spends, each key's derivation, and the change's.
fn bitcoin_cash_payment() -> (BPsbt, Vec<Vec<u8>>, String) {
    let f = fixtures();
    let p = &f["bitcoinCash"]["payment"];
    let tx: Transaction = deserialize(&unhex(p["unsigned"].as_str().unwrap())).unwrap();
    let mut psbt = BPsbt::from_unsigned_tx(tx).unwrap();
    let fp = Fingerprint::from_str("73c5da0a").unwrap();
    let key = |path: &str| -> PublicKey {
        let path = maki_hd::parse_path(path).unwrap();
        PublicKey::from_slice(&maki_hd::Keys::public(keys(), &path).unwrap().key).unwrap()
    };
    for (i, (prev, path)) in
        p["previous"].as_array().unwrap().iter().zip(p["paths"].as_array().unwrap()).enumerate()
    {
        let path = path.as_str().unwrap();
        psbt.inputs[i].non_witness_utxo = Some(deserialize(&unhex(prev.as_str().unwrap())).unwrap());
        psbt.inputs[i].bip32_derivation.insert(key(path), (fp, DerivationPath::from_str(path).unwrap()));
    }
    let change = p["change"].as_str().unwrap();
    psbt.outputs[1].bip32_derivation.insert(key(change), (fp, DerivationPath::from_str(change).unwrap()));
    let signatures = p["signatures"].as_array().unwrap().iter().map(|s| unhex(s.as_str().unwrap())).collect();
    (psbt, signatures, p["payee"].as_str().unwrap().into())
}

#[test]
fn a_bitcoin_cash_payment_is_shown_and_signed_as_libauth_signs_it() {
    let (b, theirs, payee) = bitcoin_cash_payment();
    let accounts = [legacy(Network::BitcoinCash)];
    let mut psbt = Psbt::parse(&b.serialize()).unwrap();
    let r = wallet::review(&psbt, &accounts).unwrap();
    assert_eq!((r.network, r.inputs, r.fee), (Network::BitcoinCash, 2, 500));
    assert_eq!(
        (r.outputs[0].address.as_str(), amount(r.outputs[0].amount, r.network), r.outputs[0].change),
        (payee.as_str(), "0.0007 BCH".to_string(), false)
    );
    assert_eq!(
        (r.outputs[1].address.as_str(), r.outputs[1].change),
        ("bitcoincash:qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx", true)
    );
    wallet::sign(&mut psbt, &accounts).unwrap();
    // BIP143's digest with SIGHASH_FORKID, signed as libauth (libsecp256k1, RFC 6979) signs it
    // (read with maki's own reader: rust-bitcoin's won't take a hash type Bitcoin hasn't)
    let signed = Psbt::parse(&psbt.serialize()).unwrap();
    for i in 0..2 {
        let pair = signed.inputs[i].iter().find(|p| p.key.first() == Some(&maki_btc::psbt::IN_PARTIAL_SIG));
        let sig = pair.unwrap().value.clone();
        assert_eq!(sig, theirs[i], "input {i}");
        assert_eq!(*sig.last().unwrap(), SIGHASH_ALL_FORKID);
    }
    // the same with the hash type written out, as Electron Cash's kind would have it
    let mut written = b.clone();
    for input in written.inputs.iter_mut() {
        input.sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(SIGHASH_ALL_FORKID as u32));
    }
    assert!(wallet::review(&Psbt::parse(&written.serialize()).unwrap(), &accounts).is_ok());
}

#[test]
fn bitcoin_cash_refuses_signatures_without_its_fork_id_and_cashtokens() {
    let (b, _, _) = bitcoin_cash_payment();
    let accounts = [legacy(Network::BitcoinCash)];
    // SIGHASH_ALL alone: a signature that would replay on Bitcoin's rules
    let mut plain = b.clone();
    plain.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(1));
    assert_eq!(wallet::review(&Psbt::parse(&plain.serialize()).unwrap(), &accounts), Err(Error::Sighash(0)));
    // an output carrying CashTokens (its locking bytecode starts with PREFIX_TOKEN)
    let mut tokens = b.clone();
    tokens.unsigned_tx.output.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes([&[0xef][..], &[0x33; 34], &[0x76, 0xa9]].concat()),
    });
    tokens.outputs.push(Default::default());
    let r = wallet::review(&Psbt::parse(&tokens.serialize()).unwrap(), &accounts);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    // a Bitcoin Cash coin isn't Dogecoin's
    let doge = [legacy(Network::Dogecoin)];
    assert_eq!(wallet::review(&Psbt::parse(&b.serialize()).unwrap(), &doge), Err(Error::NotOurs(0)));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Each payment, unsigned and as maki signs it: for the Dogecoin and Bitcoin Cash apps' tests, the
/// emulator's demo and maki desktop's. Regenerate (only if the fixtures change) with
///     cargo test -p maki-btc --test forks -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    for (name, unsigned, network) in [
        ("dogecoin", dogecoin_payment().0, Network::Dogecoin),
        ("bitcoincash", bitcoin_cash_payment().0.serialize(), Network::BitcoinCash),
    ] {
        std::fs::write(format!("{FIXTURES}/{name}-unsigned.psbt"), &unsigned).unwrap();
        let mut psbt = Psbt::parse(&unsigned).unwrap();
        wallet::sign(&mut psbt, &[legacy(network)]).unwrap();
        std::fs::write(format!("{FIXTURES}/{name}-signed.psbt"), psbt.serialize()).unwrap();
    }
}

#[test]
fn the_fixtures_are_current() {
    for (name, unsigned, network) in [
        ("dogecoin", dogecoin_payment().0, Network::Dogecoin),
        ("bitcoincash", bitcoin_cash_payment().0.serialize(), Network::BitcoinCash),
    ] {
        assert_eq!(std::fs::read(format!("{FIXTURES}/{name}-unsigned.psbt")).unwrap(), unsigned, "{name}");
        let mut psbt = Psbt::parse(&unsigned).unwrap();
        wallet::sign(&mut psbt, &[legacy(network)]).unwrap();
        assert_eq!(
            std::fs::read(format!("{FIXTURES}/{name}-signed.psbt")).unwrap(),
            psbt.serialize(),
            "{name}"
        );
    }
}
