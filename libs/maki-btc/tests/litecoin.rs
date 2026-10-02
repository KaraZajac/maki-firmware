//! Litecoin: Bitcoin's transactions, signatures and PSBTs, with addresses of its own. The test
//! phrase's addresses as bitcoinjs-lib makes them with Litecoin Core's parameters (and as wallets
//! publish them: `ltc1qjmxnz…` is BIP84's first), and a PSBT spending a native SegWit and a
//! taproot coin signed as rust-bitcoin signs it, each signature checked against its sighash and
//! Bitcoin Core's script interpreter, whose rules Litecoin's are.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv as BXpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::psbt::Psbt as BPsbt;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, ScriptHash, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, transaction,
};
use maki_btc::display::{amount, network_name, unit};
use maki_btc::psbt::Psbt;
use maki_btc::wallet::{self, Error, Kind};
use maki_btc::{Account, Network};
use maki_hd::seed::SeedKeys;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> [u8; 64] {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    maki_seed::seed(&words, "")
}

fn keys() -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(&seed()).unwrap())) }

fn account(network: Network, kind: Kind) -> Account<'static> { Account::new(keys(), network, kind).unwrap() }

#[test]
fn addresses_are_litecoins() {
    // bitcoinjs-lib, with Litecoin Core's chainparams (bech32 `ltc`, P2PKH 48, P2SH 50)
    let segwit = account(Network::Litecoin, Kind::Segwit);
    assert_eq!(segwit.address(false, 0).unwrap(), "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh");
    assert_eq!(segwit.address(false, 1).unwrap(), "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn");
    assert_eq!(segwit.address(true, 0).unwrap(), "ltc1qyeljcy9v88jg8sqvnqh0m5q390xruc5r98q9yy");
    assert_eq!(segwit.address(true, 1).unwrap(), "ltc1qzenvkhkqqazfanrjs6htluwlm2sdwt0sgc3jh8");
    let taproot = account(Network::Litecoin, Kind::Taproot);
    assert_eq!(
        taproot.address(false, 0).unwrap(),
        "ltc1puht8rk95c53q3u9w3pf9h3jfcutcrl9lxc7rqsdthjrse4k6sn7q9tuqm9"
    );
    assert_eq!(
        taproot.address(true, 1).unwrap(),
        "ltc1prpas0sz74px6juj240kpx4j7ww65ldqlu0s7s875gtsmv2m7jeasy93njw"
    );
    // the test network's: Bitcoin testnet's keys (coin type 1), Litecoin's `tltc`
    let test = account(Network::LitecoinTest, Kind::Segwit);
    assert_eq!(test.address(false, 0).unwrap(), "tltc1q6rz28mcfaxtmd6v789l9rrlrusdprr9pesrjxk");
    assert_eq!(test.address(true, 1).unwrap(), "tltc1qkwgskuzmmwwvqajnyr7yp9hgvh5y45kg7xwnty");
    assert_eq!(
        account(Network::LitecoinTest, Kind::Taproot).address(false, 1).unwrap(),
        "tltc1p90h6z3p36n9hrzy7580h5l429uwchyg8uc9sz4jwzhdtuhqdl5eqyzjp9v"
    );
}

#[test]
fn other_outputs_show_as_litecoins_wallets_write_them() {
    // the first BIP84 key's hash, as P2PKH and as P2SH-wrapped SegWit: L… and M…, Q… on test
    let secp = Secp256k1::new();
    let master = BXpriv::new_master(bitcoin::NetworkKind::Main, &seed()).unwrap();
    let k = master.derive_priv(&secp, &DerivationPath::from_str("m/84'/2'/0'/0/0").unwrap()).unwrap();
    let key = CompressedPublicKey(k.private_key.public_key(&secp));
    let p2pkh = ScriptBuf::new_p2pkh(&key.pubkey_hash());
    let p2sh = ScriptBuf::new_p2sh(&ScriptHash::hash(ScriptBuf::new_p2wpkh(&key.wpubkey_hash()).as_bytes()));
    let describe = maki_btc::address::describe;
    assert_eq!(describe(p2pkh.as_bytes(), Network::Litecoin), "LYyKS4hm5QcmAWntuZSA6Kp5TKg9fCeLQn");
    assert_eq!(describe(p2sh.as_bytes(), Network::Litecoin), "MUi6eFEWq7Sj3XaWUzJTDvSFTpaSdDR3fq");
    assert_eq!(describe(p2pkh.as_bytes(), Network::LitecoinTest), "muGKTuUuomoxgpaMSzREeDxe76uaTDbmde");
    assert_eq!(describe(p2sh.as_bytes(), Network::LitecoinTest), "QhQvX7cpWZ9jazhCgLy16vcYVrdzKW6DCC");
}

#[test]
fn the_account_key_and_descriptor_are_what_litecoins_wallets_take() {
    // Litecoin Core and Electrum-LTC take Bitcoin's version bytes: xpub, and zpub for BIP84
    let segwit = account(Network::Litecoin, Kind::Segwit);
    let xpub = "xpub6CjGURuDpczf6uNrCCwfhVizn5J3hsWcvZ2m6GAdmAjZnoWJPrx6TFPjGSftc2o5fvox6ubQjSXmjjaHZjwYMH7SGFpHHb9Jg24zBf66mbE";
    let body = format!("wpkh([73c5da0a/84h/2h/0h]{xpub}/<0;1>/*)");
    assert_eq!(segwit.descriptor(), format!("{body}#{}", wallet::descriptor_checksum(&body)));
    assert!(segwit.zpub().starts_with("zpub"));
    let taproot = account(Network::Litecoin, Kind::Taproot);
    assert!(taproot.descriptor().starts_with(
        "tr([73c5da0a/86h/2h/0h]xpub6D39rno4TW2oi3tGmu8RUcukFtU7wFnAkdFkYAcSpGZY9yoPNbkRgTbEUYyhkqacm7dyNfc5uK8oQ71M2hTALqqDQeE2JAQn9YDteoW2cQC/<0;1>/*)#"
    ));
    let test = account(Network::LitecoinTest, Kind::Segwit);
    assert!(test.descriptor().starts_with("wpkh([73c5da0a/84h/1h/0h]tpub"));
    assert!(test.zpub().starts_with("vpub"));
}

#[test]
fn amounts_are_in_litecoin() {
    assert_eq!(amount(70_000, Network::Litecoin), "0.0007 LTC");
    assert_eq!(amount(100_000_000, Network::LitecoinTest), "1 tLTC");
    assert_eq!(amount(Network::Litecoin.max_money(), Network::Litecoin), "84000000 LTC");
    assert_eq!((unit(Network::Litecoin), network_name(Network::Litecoin)), ("LTC", "litecoin"));
    assert_eq!(network_name(Network::LitecoinTest), "litecoin testnet");
    assert_eq!(Network::Litecoin.coin_type(), 2);
    assert_eq!(Network::LitecoinTest.coin_type(), 1);
}

fn path(purpose: u32, chain: u32, index: u32) -> DerivationPath {
    DerivationPath::from_str(&format!("m/{purpose}'/2'/0'/{chain}/{index}")).unwrap()
}

fn funding(salt: u8, output: TxOut) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([salt; 32]), vout: 1 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
        }],
        output: vec![output],
    }
}

/// A Litecoin payment: a native SegWit coin (60,000) and a taproot one (40,000) of the test
/// phrase's, 70,000 to someone's legacy `L…` address, 25,000 back to SegWit change, 5,000 fee.
struct Fixture {
    secp: Secp256k1<bitcoin::secp256k1::All>,
    master: BXpriv,
    psbt: BPsbt,
    prevs: Vec<Transaction>,
}

impl Fixture {
    fn new(value: u64) -> Fixture {
        let secp = Secp256k1::new();
        let master = BXpriv::new_master(bitcoin::NetworkKind::Main, &seed()).unwrap();
        let fp = master.fingerprint(&secp);
        let key = |p: &DerivationPath| master.derive_priv(&secp, p).unwrap().private_key.public_key(&secp);
        let segwit = key(&path(84, 0, 4));
        let tap = key(&path(86, 0, 2)).x_only_public_key().0;
        let change = key(&path(84, 1, 0));
        let prevs = vec![
            funding(
                1,
                TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&CompressedPublicKey(segwit).wpubkey_hash()),
                },
            ),
            funding(
                2,
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, tap, None),
                },
            ),
        ];
        let payee = {
            let other = BXpriv::new_master(bitcoin::NetworkKind::Main, &[9u8; 32]).unwrap();
            ScriptBuf::new_p2pkh(&CompressedPublicKey(other.private_key.public_key(&secp)).pubkey_hash())
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(3_000_000),
            input: prevs
                .iter()
                .map(|p| TxIn {
                    previous_output: OutPoint { txid: p.compute_txid(), vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![
                TxOut { value: Amount::from_sat(value + 30_000), script_pubkey: payee },
                TxOut {
                    value: Amount::from_sat(25_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&CompressedPublicKey(change).wpubkey_hash()),
                },
            ],
        };
        let mut psbt = BPsbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevs[0].output[0].clone());
        psbt.inputs[0].non_witness_utxo = Some(prevs[0].clone());
        psbt.inputs[0].bip32_derivation.insert(segwit, (fp, path(84, 0, 4)));
        psbt.inputs[1].witness_utxo = Some(prevs[1].output[0].clone());
        psbt.inputs[1].tap_internal_key = Some(tap);
        psbt.inputs[1].tap_key_origins.insert(tap, (vec![], (fp, path(86, 0, 2))));
        psbt.outputs[1].bip32_derivation.insert(change, (fp, path(84, 1, 0)));
        Fixture { secp, master, psbt, prevs }
    }

    fn accounts() -> Vec<Account<'static>> {
        vec![account(Network::Litecoin, Kind::Segwit), account(Network::Litecoin, Kind::Taproot)]
    }

    fn ours(&self) -> Psbt { Psbt::parse(&self.psbt.serialize()).unwrap() }
}

#[test]
fn a_litecoin_payment_is_shown_in_litecoin() {
    let f = Fixture::new(40_000);
    let r = wallet::review(&f.ours(), &Fixture::accounts()).unwrap();
    assert_eq!((r.network, r.inputs, r.fee), (Network::Litecoin, 2, 5_000));
    assert!(r.outputs[0].address.starts_with('L') && !r.outputs[0].change);
    assert_eq!(amount(r.outputs[0].amount, r.network), "0.0007 LTC");
    assert_eq!(
        (r.outputs[1].address.as_str(), r.outputs[1].change),
        ("ltc1qyeljcy9v88jg8sqvnqh0m5q390xruc5r98q9yy", true)
    );
    // Bitcoin's accounts don't sign Litecoin's coins: other keys (coin type 0)
    let bitcoin = vec![account(Network::Bitcoin, Kind::Segwit), account(Network::Bitcoin, Kind::Taproot)];
    assert_eq!(wallet::review(&f.ours(), &bitcoin), Err(Error::NotOurs(0)));
}

#[test]
fn litecoin_signatures_match_rust_bitcoins_and_verify() {
    let f = Fixture::new(40_000);
    let mut ours = f.ours();
    assert_eq!(wallet::sign(&mut ours, &Fixture::accounts()).unwrap(), 2);
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();
    // rust-bitcoin signs what the PSBT says, for any chain of Bitcoin's rules: the same signatures
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(signed, theirs, "maki's PSBT, signed, is rust-bitcoin's");

    let tx = &signed.unsigned_tx;
    let spent: Vec<TxOut> = signed.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
    let mut cache = SighashCache::new(tx);
    let (pk, sig) = signed.inputs[0].partial_sigs.iter().next().unwrap();
    let sighash = cache
        .p2wpkh_signature_hash(0, &spent[0].script_pubkey, spent[0].value, EcdsaSighashType::All)
        .unwrap();
    f.secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sig.signature, &pk.inner).unwrap();
    let tap = signed.inputs[1].tap_key_sig.unwrap();
    let sighash =
        cache.taproot_key_spend_signature_hash(1, &Prevouts::All(&spent), TapSighashType::Default).unwrap();
    let (output_key, _) = signed.inputs[1].tap_internal_key.unwrap().tap_tweak(&f.secp, None);
    f.secp
        .verify_schnorr(
            &tap.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &output_key.to_x_only_public_key(),
        )
        .unwrap();

    // and the script interpreter takes both spends
    let mut done = signed.clone();
    done.inputs[0].final_script_witness = Some(Witness::p2wpkh(sig, &pk.inner));
    done.inputs[0].partial_sigs.clear();
    done.inputs[1].final_script_witness = Some(Witness::p2tr_key_spend(&tap));
    let tx = done.extract_tx().unwrap();
    let spent_by = |o: &OutPoint| {
        f.prevs.iter().find(|p| p.compute_txid() == o.txid).map(|p| p.output[o.vout as usize].clone())
    };
    tx.verify(spent_by).unwrap();
}

#[test]
fn amounts_up_to_litecoins_cap_are_taken_and_beyond_it_refused() {
    // 30 million LTC: more than bitcoin will ever have, less than litecoin will
    let thirty_million = 30_000_000 * 100_000_000;
    let f = Fixture::new(thirty_million);
    assert_eq!(wallet::review(&f.ours(), &Fixture::accounts()).unwrap().fee, 5_000);
    let beyond = Fixture::new(Network::Litecoin.max_money());
    assert_eq!(wallet::review(&beyond.ours(), &Fixture::accounts()), Err(Error::Amount));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The Litecoin payment above, unsigned and as maki signs it: for the Litecoin app's tests, the
/// emulator's demo and maki desktop's. Regenerate (only if the fixture changes) with
///     cargo test -p maki-btc --test litecoin -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    let f = Fixture::new(40_000);
    std::fs::write(format!("{FIXTURES}/litecoin-unsigned.psbt"), f.psbt.serialize()).unwrap();
    let mut psbt = f.ours();
    wallet::sign(&mut psbt, &Fixture::accounts()).unwrap();
    std::fs::write(format!("{FIXTURES}/litecoin-signed.psbt"), psbt.serialize()).unwrap();
}

#[test]
fn the_fixtures_are_current_and_rust_bitcoin_agrees() {
    let f = Fixture::new(40_000);
    let unsigned = std::fs::read(format!("{FIXTURES}/litecoin-unsigned.psbt")).unwrap();
    let signed = std::fs::read(format!("{FIXTURES}/litecoin-signed.psbt")).unwrap();
    assert_eq!(unsigned, f.psbt.serialize());
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    wallet::sign(&mut psbt, &Fixture::accounts()).unwrap();
    assert_eq!(psbt.serialize(), signed);
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(BPsbt::deserialize(&signed).unwrap(), theirs);
}
