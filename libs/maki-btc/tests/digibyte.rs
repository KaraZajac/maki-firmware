//! DigiByte: Bitcoin's transactions, SegWit and taproot (buried in DigiByte Core since 2025) among
//! them, with addresses of its own; three accounts, as its wallets have made them: native SegWit
//! (BIP84, `m/84'/20'/0'`, `dgb1q…`), taproot (BIP86, `dgb1p…`) and legacy (BIP44, `D…`). Held to
//! DigiByte's own JavaScript library (`digibyte`, DigiByte-Core's digibyte-lib), which signs SegWit
//! and legacy inputs, and to bitcoinjs-lib with DigiByte Core's parameters for taproot
//! (`fixtures/make-digibyte.mjs`, each deriving the test phrase's keys itself): the test phrase's
//! addresses, and a payment spending a native SegWit, a taproot and a legacy coin, shown in DGB,
//! signed byte for byte as those libraries sign it, and its spends taken by Bitcoin Core's script
//! interpreter, whose rules DigiByte's are. And what maki refuses: DigiDollar's transactions and its
//! tokens' coins, which it can't show.

use bitcoin::psbt::Psbt as BPsbt;
use bitcoin::{Amount, OutPoint, Transaction, TxOut, Witness};
use maki_btc::display::{amount, network_name, unit};
use maki_btc::psbt::{self, Psbt};
use maki_btc::wallet::{self, Error, Kind};
use maki_btc::{Account, Network};
use maki_hd::seed::SeedKeys;

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn keys() -> &'static SeedKeys {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    Box::leak(Box::new(SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap()))
}

fn account(network: Network, kind: Kind) -> Account<'static> { Account::new(keys(), network, kind).unwrap() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn fixtures() -> serde_json::Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/digibyte.json"))
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn addresses_are_the_ones_digibytes_wallets_make() {
    let f = fixtures();
    let a = &f["addresses"];
    let segwit = account(Network::DigiByte, Kind::Segwit);
    assert_eq!(segwit.address(false, 0).unwrap(), a["m/84'/20'/0'/0/0"]);
    assert_eq!(segwit.address(false, 1).unwrap(), a["m/84'/20'/0'/0/1"]);
    assert_eq!(segwit.address(true, 0).unwrap(), a["m/84'/20'/0'/1/0"]);
    let legacy = account(Network::DigiByte, Kind::Legacy);
    // BIP44's first, as Ledger and the other BIP44 wallets make it for the test phrase
    assert_eq!(legacy.address(false, 0).unwrap(), "DG1KhhBKpsyWXTakHNezaDQ34focsXjN1i");
    assert_eq!(legacy.address(false, 0).unwrap(), a["m/44'/20'/0'/0/0"]);
    assert_eq!(legacy.address(true, 0).unwrap(), a["m/44'/20'/0'/1/0"]);
    let taproot = account(Network::DigiByte, Kind::Taproot);
    assert_eq!(taproot.address(false, 0).unwrap(), a["m/86'/20'/0'/0/0"]);
    assert_eq!(taproot.address(true, 1).unwrap(), a["m/86'/20'/0'/1/1"]);
    // the test network's: coin type 1, `dgbt`, `s…`
    assert_eq!(account(Network::DigiByteTest, Kind::Segwit).address(false, 0).unwrap(), a["m/84'/1'/0'/0/0"]);
    assert_eq!(account(Network::DigiByteTest, Kind::Legacy).address(false, 0).unwrap(), a["m/44'/1'/0'/0/0"]);
    assert_eq!(
        account(Network::DigiByteTest, Kind::Taproot).address(false, 0).unwrap(),
        a["m/86'/1'/0'/0/0"]
    );
}

#[test]
fn account_keys_and_scripts_are_as_digibytes_wallets_write_them() {
    let f = fixtures();
    // the accounts' keys, Bitcoin's version bytes (DigiByte Core's chainparams): zpub for SegWit
    let segwit = account(Network::DigiByte, Kind::Segwit);
    assert!(segwit.zpub().starts_with("zpub"));
    let xpub = f["xpubs"]["m/84'/20'/0'"].as_str().unwrap();
    let body = format!("wpkh([73c5da0a/84h/20h/0h]{xpub}/<0;1>/*)");
    assert_eq!(segwit.descriptor(), format!("{body}#{}", wallet::descriptor_checksum(&body)));
    let legacy = account(Network::DigiByte, Kind::Legacy);
    assert_eq!(legacy.zpub(), f["xpubs"]["m/44'/20'/0'"].as_str().unwrap());
    assert!(legacy.descriptor().starts_with("pkh([73c5da0a/44h/20h/0h]xpub"));
    assert!(
        account(Network::DigiByte, Kind::Taproot).descriptor().starts_with("tr([73c5da0a/86h/20h/0h]xpub")
    );
    assert!(account(Network::DigiByteTest, Kind::Segwit).zpub().starts_with("vpub"));
    // a script's hash, as DigiByte's P2SH (`S…`), and its test network's
    let p2sh = [&[0xa9, 0x14][..], &[0x11; 20], &[0x87]].concat();
    let describe = maki_btc::address::describe;
    assert_eq!(describe(&p2sh, Network::DigiByte), f["p2sh"]["livenet"].as_str().unwrap());
    assert_eq!(describe(&p2sh, Network::DigiByteTest), f["p2sh"]["testnet"].as_str().unwrap());
}

#[test]
fn digibyte_has_all_three_kinds_of_account_and_its_own_units() {
    for network in [Network::DigiByte, Network::DigiByteTest] {
        for kind in [Kind::Segwit, Kind::Taproot, Kind::Legacy] {
            assert!(kind.on(network) && Account::new(keys(), network, kind).is_ok());
        }
    }
    // the networks before it keep theirs
    assert!(!Kind::Legacy.on(Network::Litecoin) && !Kind::Segwit.on(Network::Dogecoin));
    assert_eq!((unit(Network::DigiByte), unit(Network::DigiByteTest)), ("DGB", "tDGB"));
    assert_eq!(
        (network_name(Network::DigiByte), network_name(Network::DigiByteTest)),
        ("digibyte", "digibyte testnet")
    );
    assert_eq!((Network::DigiByte.coin_type(), Network::DigiByteTest.coin_type()), (20, 1));
    assert_eq!(amount(Network::DigiByte.max_money(), Network::DigiByte), "21000000000 DGB");
}

fn accounts() -> Vec<Account<'static>> {
    [Kind::Segwit, Kind::Taproot, Kind::Legacy].into_iter().map(|k| account(Network::DigiByte, k)).collect()
}

fn payment() -> BPsbt {
    BPsbt::deserialize(&unhex(fixtures()["payment"]["unsigned"].as_str().unwrap())).unwrap()
}

fn ours(b: &BPsbt) -> Psbt { Psbt::parse(&b.serialize()).unwrap() }

#[test]
fn a_payment_is_shown_in_digibyte() {
    let f = fixtures();
    let r = wallet::review(&ours(&payment()), &accounts()).unwrap();
    assert_eq!((r.network, r.inputs, r.fee), (Network::DigiByte, 3, 10_000_000));
    assert_eq!(
        (r.outputs[0].address.as_str(), amount(r.outputs[0].amount, r.network), r.outputs[0].change),
        (f["payment"]["payee"].as_str().unwrap(), "1000 DGB".to_string(), false)
    );
    assert_eq!(
        (r.outputs[1].address.as_str(), amount(r.outputs[1].amount, r.network), r.outputs[1].change),
        (f["addresses"]["m/84'/20'/0'/1/0"].as_str().unwrap(), "249.9 DGB".to_string(), true)
    );
    let pages = r.pages();
    let headings: Vec<&str> = pages.iter().map(|p| p.heading.as_str()).collect();
    assert_eq!(headings, ["Send", "Change", "Fee"]);
    assert_eq!(pages[2].value, "0.1 DGB");
    assert!(pages[2].mono.ends_with(" sat/vB"), "{}", pages[2].mono);
    assert_eq!(r.summary(), "Total 1000.1 DGB");
    // Litecoin's accounts don't sign DigiByte's coins: other keys (coin type 2)
    let litecoin = [account(Network::Litecoin, Kind::Segwit), account(Network::Litecoin, Kind::Taproot)];
    assert_eq!(wallet::review(&ours(&payment()), &litecoin), Err(Error::NotOurs(0)));
}

#[test]
fn a_payment_is_signed_as_digibytes_library_and_bitcoinjs_sign_it() {
    let f = fixtures();
    let mut psbt = ours(&payment());
    assert_eq!(wallet::sign(&mut psbt, &accounts()).unwrap(), 3);
    // byte for byte: the SegWit and legacy inputs' as DigiByte's library signs them (RFC 6979, low
    // S), the taproot one's as bitcoinjs-lib does (BIP340, its key tweaked BIP86's way)
    let theirs: Vec<&str> =
        f["payment"]["signatures"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    for (i, want) in theirs.iter().enumerate() {
        let kind = if i == 1 { psbt::IN_TAP_KEY_SIG } else { psbt::IN_PARTIAL_SIG };
        let pair = psbt.inputs[i].iter().find(|p| p.key.first() == Some(&kind)).unwrap();
        assert_eq!(hex(&pair.value), *want, "input {i}");
    }
    // and Bitcoin Core's interpreter takes all three spends
    let mut done = BPsbt::deserialize(&psbt.serialize()).unwrap();
    let (pk, sig) = done.inputs[0].partial_sigs.pop_first().unwrap();
    done.inputs[0].final_script_witness = Some(Witness::p2wpkh(&sig, &pk.inner));
    let tap = done.inputs[1].tap_key_sig.unwrap();
    done.inputs[1].final_script_witness = Some(Witness::p2tr_key_spend(&tap));
    let (pk, sig) = done.inputs[2].partial_sigs.pop_first().unwrap();
    done.inputs[2].final_script_sig =
        Some(bitcoin::script::Builder::new().push_slice(sig.serialize()).push_key(&pk).into_script());
    let spent: Vec<(OutPoint, TxOut)> = done
        .inputs
        .iter()
        .zip(&done.unsigned_tx.input)
        .map(|(i, txin)| {
            let o = txin.previous_output;
            let out = match &i.non_witness_utxo {
                Some(prev) => prev.output[o.vout as usize].clone(),
                None => i.witness_utxo.clone().unwrap(),
            };
            (o, out)
        })
        .collect();
    // (a fee of 0.1 DGB is nothing on DigiByte, and an absurd rate by Bitcoin's measure)
    let tx: Transaction = done.extract_tx_unchecked_fee_rate();
    tx.verify(|o| spent.iter().find(|(p, _)| p == o).map(|(_, out)| out.clone())).unwrap();
}

#[test]
fn digidollars_are_refused() {
    // a DigiDollar transfer (its version's low 16 bits the marker, its type in the top byte): maki
    // can't show what it does with the tokens
    let mut dd = payment();
    dd.unsigned_tx.version = bitcoin::transaction::Version(0x0d1d_0770);
    assert_eq!(
        wallet::review(&ours(&dd), &accounts()),
        Err(Error::Unsupported("a DigiDollar transaction, which maki can't show"))
    );
    // a coin of no DGB is a DigiDollar token's: spent by a plain transaction, the tokens are lost
    let mut token = payment();
    token.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::ZERO;
    assert_eq!(
        wallet::review(&ours(&token), &accounts()),
        Err(Error::Unsupported("a coin of no DGB: a DigiDollar token's, which maki can't show"))
    );
    // the marker means nothing on other networks: there, it's a version like any other, and the
    // transaction is read on (to find these coins aren't Litecoin's)
    let mut other = payment();
    other.unsigned_tx.version = bitcoin::transaction::Version(0x0d1d_0770);
    let litecoin = [account(Network::Litecoin, Kind::Segwit)];
    assert_eq!(wallet::review(&ours(&other), &litecoin), Err(Error::NotOurs(0)));
}

#[test]
fn amounts_up_to_digibytes_cap_are_taken_and_beyond_it_refused() {
    let mut beyond = payment();
    beyond.unsigned_tx.output[0].value = Amount::from_sat(Network::DigiByte.max_money() + 1);
    assert_eq!(wallet::review(&ours(&beyond), &accounts()), Err(Error::Amount));
    // more than 21 million: Bitcoin's cap isn't DigiByte's (the outputs then pay more than the
    // inputs hold, and that's what's said)
    let mut big = payment();
    big.unsigned_tx.output[0].value = Amount::from_sat(30_000_000 * 100_000_000);
    assert_eq!(wallet::review(&ours(&big), &accounts()), Err(Error::NegativeFee));
}

#[test]
fn a_coin_on_the_wrong_side_of_its_transaction_is_caught() {
    // the SegWit coin's transaction, one byte changed: not the one the input spends
    let mut b = payment();
    let prev = b.inputs[0].non_witness_utxo.as_mut().unwrap();
    prev.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
    assert_eq!(wallet::review(&ours(&b), &accounts()), Err(Error::PreviousTxMismatch(0)));
    // a legacy coin without its whole transaction: its amount would be the PSBT's word
    let mut b = payment();
    let prev = b.inputs[2].non_witness_utxo.take().unwrap();
    b.inputs[2].witness_utxo = Some(prev.output[1].clone());
    assert_eq!(wallet::review(&ours(&b), &accounts()), Err(Error::NoPreviousTx(2)));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The payment above, unsigned and as maki signs it: for the DigiByte app's tests, the emulator's
/// demo and maki desktop's. Regenerate (only if the fixture changes) with
///     cargo test -p maki-btc --test digibyte -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    let unsigned = payment().serialize();
    std::fs::write(format!("{FIXTURES}/digibyte-unsigned.psbt"), &unsigned).unwrap();
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    wallet::sign(&mut psbt, &accounts()).unwrap();
    std::fs::write(format!("{FIXTURES}/digibyte-signed.psbt"), psbt.serialize()).unwrap();
}

#[test]
fn the_fixtures_are_current() {
    let unsigned = payment().serialize();
    assert_eq!(std::fs::read(format!("{FIXTURES}/digibyte-unsigned.psbt")).unwrap(), unsigned);
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    wallet::sign(&mut psbt, &accounts()).unwrap();
    assert_eq!(std::fs::read(format!("{FIXTURES}/digibyte-signed.psbt")).unwrap(), psbt.serialize());
}
