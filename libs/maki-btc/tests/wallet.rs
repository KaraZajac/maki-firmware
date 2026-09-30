//! maki-btc against the BIPs' test vectors and against rust-bitcoin, which signs the same PSBTs
//! independently: its signatures must come out byte for byte the same (both use RFC 6979).

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv as BXpriv, Xpub as BXpub};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt as BPsbt;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute, transaction, Address, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use maki_btc::bip32::{xpub, HARDENED};
use maki_btc::psbt::Psbt;
use maki_btc::wallet::{self, descriptor_checksum, Error};
use maki_btc::{Account, Network};
use maki_hd::seed::SeedKeys;
use maki_hd::Keys;

const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

/// maki's keys for a seed, for as long as the tests run.
fn keys(seed: &[u8]) -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(seed).unwrap())) }

fn seed(phrase: &str) -> [u8; 64] {
    let words: Vec<&str> = phrase.split(' ').collect();
    maki_seed::seed(&words, "")
}

fn path_string(path: &[u32]) -> String {
    let mut s = String::from("m");
    for &i in path {
        if i >= HARDENED {
            s += &format!("/{}'", i - HARDENED);
        } else {
            s += &format!("/{}", i);
        }
    }
    s
}

#[test]
fn bip32_test_vector_1() {
    let m = keys(&hex("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(
        xpub(XPUB, 0, 0, &m.public(&[]).unwrap()),
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    );
    assert_eq!(
        xpub(XPUB, 1, HARDENED, &m.public(&[HARDENED]).unwrap()),
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    );
}

#[test]
fn derivation_agrees_with_rust_bitcoin() {
    let secp = Secp256k1::new();
    let seeds: Vec<Vec<u8>> = vec![
        hex("000102030405060708090a0b0c0d0e0f"),
        hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),
        hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"),
        seed(ABANDON).to_vec(),
    ];
    let paths: [&[u32]; 6] = [
        &[],
        &[HARDENED, 1, 2 | HARDENED, 2, 1_000_000_000],
        &[84 | HARDENED, HARDENED, HARDENED, 0, 0],
        &[84 | HARDENED, 1 | HARDENED, HARDENED, 1, 7],
        &[0, 2147483647 | HARDENED, 1, 2147483646 | HARDENED, 2],
        &[44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0],
    ];
    for s in &seeds {
        let ours = keys(s);
        let theirs = BXpriv::new_master(bitcoin::NetworkKind::Main, s).unwrap();
        assert_eq!(ours.fingerprint().unwrap(), theirs.fingerprint(&secp).to_bytes());
        for path in paths {
            let p = DerivationPath::from_str(&path_string(path)).unwrap();
            let expected = BXpub::from_priv(&secp, &theirs.derive_priv(&secp, &p).unwrap());
            let got = ours.public(path).unwrap();
            let child = path.last().copied().unwrap_or(0);
            assert_eq!(xpub(XPUB, path.len() as u8, child, &got), expected.to_string(), "{}", path_string(path));
            assert_eq!(got.key, expected.public_key.serialize());
        }
    }
}

#[test]
fn bip84_test_vectors() {
    let account = Account::segwit(keys(&seed(ABANDON)), Network::Bitcoin).unwrap();
    assert_eq!(account.master_fingerprint, hex("73c5da0a")[..]);
    assert_eq!(
        account.zpub(),
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    );
    assert_eq!(account.address(false, 0).unwrap(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(account.address(false, 1).unwrap(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    assert_eq!(account.address(true, 0).unwrap(), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    assert!(account.address(false, HARDENED).is_err());
}

#[test]
fn testnet_keys_and_addresses_agree_with_rust_bitcoin() {
    let secp = Secp256k1::new();
    let s = seed(ABANDON);
    let account = Account::segwit(keys(&s), Network::Testnet).unwrap();
    let master = BXpriv::new_master(bitcoin::NetworkKind::Test, &s).unwrap();
    let key = master.derive_priv(&secp, &DerivationPath::from_str("m/84'/1'/0'").unwrap()).unwrap();
    // vpub: the tpub's key under BIP84's testnet version bytes
    let vpub = bitcoin::base58::decode_check(&account.zpub()).unwrap();
    let tpub = bitcoin::base58::decode_check(&BXpub::from_priv(&secp, &key).to_string()).unwrap();
    assert_eq!(vpub[..4], [0x04, 0x5f, 0x1c, 0xf6]);
    assert_eq!(vpub[4..], tpub[4..]);
    assert!(account.zpub().starts_with("vpub"));
    for (change, index) in [(false, 0), (false, 5), (true, 0), (true, 3)] {
        let k = key.derive_priv(&secp, &DerivationPath::from_str(&format!("m/{}/{}", change as u32, index)).unwrap()).unwrap();
        let pk = CompressedPublicKey(k.private_key.public_key(&secp));
        assert_eq!(account.address(change, index).unwrap(), Address::p2wpkh(&pk, bitcoin::Network::Testnet).to_string());
    }
}

#[test]
fn descriptor_checksums() {
    // BIP380's test vector
    assert_eq!(descriptor_checksum("raw(deadbeef)"), "89f8spxm");
}

#[test]
fn the_descriptor_is_one_wallet_software_reads() {
    use miniscript::{Descriptor, DescriptorPublicKey};
    for (network, btc) in [(Network::Bitcoin, bitcoin::Network::Bitcoin), (Network::Testnet, bitcoin::Network::Testnet)] {
        let account = Account::segwit(keys(&seed(ABANDON)), network).unwrap();
        let text = account.descriptor();
        // parsing checks the checksum
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&text).unwrap();
        let chains = desc.into_single_descriptors().unwrap();
        assert_eq!(chains.len(), 2);
        for (chain, d) in chains.iter().enumerate() {
            for index in [0, 1, 19] {
                let address = d.at_derivation_index(index).unwrap().address(btc).unwrap().to_string();
                assert_eq!(address, account.address(chain == 1, index).unwrap(), "{text} {chain}/{index}");
            }
        }
    }
    let account = Account::segwit(keys(&seed(ABANDON)), Network::Bitcoin).unwrap();
    assert!(account.descriptor().starts_with("wpkh([73c5da0a/84h/0h/0h]xpub"), "{}", account.descriptor());
}

/// A wallet's keys, both ways, and a PSBT spending two of its coins: 70,000 sats to someone
/// else, 25,000 back as change, 5,000 in fees.
struct Fixture {
    secp: Secp256k1<secp256k1::All>,
    master: BXpriv,
    account: Account<'static>,
    psbt: BPsbt,
    payee: ScriptBuf,
}

fn key_path(chain: u32, index: u32) -> DerivationPath {
    DerivationPath::from_str(&format!("m/84'/0'/0'/{chain}/{index}")).unwrap()
}

fn funding(salt: u8, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([salt; 32]), vout: 3 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            // a SegWit serialization, which the txid leaves out
            witness: Witness::from_slice(&[vec![0x30; 71], vec![0x02; 33]]),
        }],
        output: outputs,
    }
}

impl Fixture {
    fn new() -> Fixture {
        let secp = Secp256k1::new();
        let s = seed(ABANDON);
        let master = BXpriv::new_master(bitcoin::NetworkKind::Main, &s).unwrap();
        let account = Account::segwit(keys(&s), Network::Bitcoin).unwrap();
        let script = |chain, index| {
            let k = master.derive_priv(&secp, &key_path(chain, index)).unwrap();
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(k.private_key.public_key(&secp)).wpubkey_hash())
        };
        let payee = {
            let other = BXpriv::new_master(bitcoin::NetworkKind::Main, &[7u8; 32]).unwrap();
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(other.private_key.public_key(&secp)).wpubkey_hash())
        };
        let other = TxOut { value: Amount::from_sat(1_234), script_pubkey: payee.clone() };
        let prev0 = funding(1, vec![TxOut { value: Amount::from_sat(60_000), script_pubkey: script(0, 0) }]);
        let prev1 = funding(2, vec![other, TxOut { value: Amount::from_sat(40_000), script_pubkey: script(0, 1) }]);
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(850_000),
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: prev0.compute_txid(), vout: 0 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint { txid: prev1.compute_txid(), vout: 1 },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut { value: Amount::from_sat(70_000), script_pubkey: payee.clone() },
                TxOut { value: Amount::from_sat(25_000), script_pubkey: script(1, 0) },
            ],
        };
        let mut psbt = BPsbt::from_unsigned_tx(tx).unwrap();
        let fp = master.fingerprint(&secp);
        for (i, (prev, vout, index)) in [(prev0, 0, 0), (prev1, 1, 1)].into_iter().enumerate() {
            let k = master.derive_priv(&secp, &key_path(0, index)).unwrap();
            psbt.inputs[i].witness_utxo = Some(prev.output[vout].clone());
            psbt.inputs[i].non_witness_utxo = Some(prev);
            psbt.inputs[i].bip32_derivation.insert(k.private_key.public_key(&secp), (fp, key_path(0, index)));
        }
        let change = master.derive_priv(&secp, &key_path(1, 0)).unwrap();
        psbt.outputs[1].bip32_derivation.insert(change.private_key.public_key(&secp), (fp, key_path(1, 0)));
        Fixture { secp, master, account, psbt, payee }
    }

    fn ours(&self) -> Psbt { Psbt::parse(&self.psbt.serialize()).unwrap() }

    fn review(&self) -> Result<wallet::Review, Error> { wallet::review(&self.ours(), std::slice::from_ref(&self.account)) }

    fn fingerprint(&self) -> Fingerprint { self.master.fingerprint(&self.secp) }
}

#[test]
fn a_psbt_reads_and_writes_back_unchanged() {
    let f = Fixture::new();
    let bytes = f.psbt.serialize();
    assert_eq!(Psbt::parse(&bytes).unwrap().serialize(), bytes);
}

#[test]
fn review_shows_payments_change_and_fee() {
    let f = Fixture::new();
    let r = f.review().unwrap();
    assert_eq!(r.inputs, 2);
    assert_eq!(r.fee, 5_000);
    assert_eq!(r.outputs.len(), 2);
    let payee = Address::from_script(&f.payee, bitcoin::Network::Bitcoin).unwrap().to_string();
    assert_eq!((r.outputs[0].address.as_str(), r.outputs[0].amount, r.outputs[0].change), (payee.as_str(), 70_000, false));
    assert_eq!(
        (r.outputs[1].address.as_str(), r.outputs[1].amount, r.outputs[1].change),
        ("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", 25_000, true)
    );
}

#[test]
fn signatures_match_rust_bitcoins_and_verify() {
    let f = Fixture::new();
    let mut ours = f.ours();
    assert_eq!(wallet::sign(&mut ours, std::slice::from_ref(&f.account)).unwrap(), 2);
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();

    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(signed, theirs, "maki's PSBT, signed, is rust-bitcoin's");

    // and each signature checks out against rust-bitcoin's sighash
    let tx = &signed.unsigned_tx;
    let mut cache = SighashCache::new(tx);
    for (i, input) in signed.inputs.iter().enumerate() {
        let spent = input.witness_utxo.as_ref().unwrap();
        let (pk, sig) = input.partial_sigs.iter().next().unwrap();
        assert_eq!(sig.sighash_type, EcdsaSighashType::All);
        let sighash = cache.p2wpkh_signature_hash(i, &spent.script_pubkey, spent.value, EcdsaSighashType::All).unwrap();
        f.secp.verify_ecdsa(&Message::from_digest(sighash.to_byte_array()), &sig.signature, &pk.inner).unwrap();
    }

    // the size maki estimated covers the signed transaction's
    let review = f.review().unwrap();
    let mut done = signed.clone();
    for input in done.inputs.iter_mut() {
        let (pk, sig) = input.partial_sigs.iter().next().unwrap();
        input.final_script_witness = Some(Witness::p2wpkh(sig, &pk.inner));
        input.partial_sigs.clear();
    }
    let vsize = done.extract_tx().unwrap().vsize() as u64;
    assert!(review.vbytes >= vsize && review.vbytes <= vsize + 1, "estimated {} for {}", review.vbytes, vsize);
    assert_eq!(review.fee_rate(), 5_000u64.div_ceil(review.vbytes));
}

#[test]
fn an_amount_the_previous_transaction_doesnt_back_is_refused() {
    // the 2020 SegWit fee attack: a witness UTXO claiming less than the coin holds
    let mut f = Fixture::new();
    f.psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(50_000);
    assert_eq!(f.review(), Err(Error::PreviousTxMismatch(0)));
}

#[test]
fn a_previous_transaction_that_isnt_the_one_spent_is_refused() {
    let mut f = Fixture::new();
    let prev = f.psbt.inputs[1].non_witness_utxo.as_mut().unwrap();
    prev.output[1].value = Amount::from_sat(90_000);
    assert_eq!(f.review(), Err(Error::PreviousTxMismatch(1)));

    let mut f = Fixture::new();
    f.psbt.inputs[1].non_witness_utxo = None;
    assert_eq!(f.review(), Err(Error::NoPreviousTx(1)));

    // the right transaction, the wrong output of it
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.input[1].previous_output.vout = 0;
    f.psbt.inputs[1].witness_utxo = None;
    assert_eq!(f.review(), Err(Error::NotOurs(1)));
    f.psbt.unsigned_tx.input[1].previous_output.vout = 2;
    assert_eq!(f.review(), Err(Error::PreviousTxMismatch(1)));
}

#[test]
fn inputs_that_arent_this_wallets_are_refused() {
    // someone else's fingerprint
    let mut f = Fixture::new();
    let (_, (fp, _)) = f.psbt.inputs[0].bip32_derivation.iter_mut().next().unwrap();
    *fp = Fingerprint::from([1, 2, 3, 4]);
    assert_eq!(f.review(), Err(Error::NotOurs(0)));

    // a path that doesn't make the key named
    let mut f = Fixture::new();
    let (_, (_, path)) = f.psbt.inputs[0].bip32_derivation.iter_mut().next().unwrap();
    *path = key_path(0, 5);
    assert_eq!(f.review(), Err(Error::NotOurs(0)));

    // another account, and paths that aren't BIP84's
    for bad in ["m/84'/0'/1'/0/0", "m/84'/1'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/2/0", "m/84'/0'/0'/0"] {
        let mut f = Fixture::new();
        let fp = f.fingerprint();
        let k = f.master.derive_priv(&f.secp, &DerivationPath::from_str(bad).unwrap()).unwrap();
        f.psbt.inputs[0].bip32_derivation.clear();
        f.psbt.inputs[0].bip32_derivation.insert(k.private_key.public_key(&f.secp), (fp, DerivationPath::from_str(bad).unwrap()));
        assert_eq!(f.review(), Err(Error::NotOurs(0)), "{bad}");
    }

    // our key, but the coin isn't paid to it
    let mut f = Fixture::new();
    let prev = f.psbt.inputs[0].non_witness_utxo.as_mut().unwrap();
    prev.output[0].script_pubkey = f.payee.clone();
    let txid = prev.compute_txid();
    f.psbt.unsigned_tx.input[0].previous_output.txid = txid;
    f.psbt.inputs[0].witness_utxo = None;
    assert_eq!(f.review(), Err(Error::NotOurs(0)));

    // a wallet from another phrase signs nothing
    let f = Fixture::new();
    let stranger = Account::segwit(keys(&[9u8; 64]), Network::Bitcoin).unwrap();
    let mut psbt = f.ours();
    assert_eq!(wallet::sign(&mut psbt, std::slice::from_ref(&stranger)), Err(Error::NotOurs(0)));
    assert_eq!(psbt.serialize(), f.psbt.serialize());

    // the testnet wallet doesn't sign for bitcoin's
    let testnet = Account::segwit(keys(&seed(ABANDON)), Network::Testnet).unwrap();
    assert_eq!(wallet::review(&f.ours(), std::slice::from_ref(&testnet)), Err(Error::NotOurs(0)));
}

#[test]
fn only_sighash_all_is_signed() {
    for t in [EcdsaSighashType::None, EcdsaSighashType::Single, EcdsaSighashType::AllPlusAnyoneCanPay] {
        let mut f = Fixture::new();
        f.psbt.inputs[1].sighash_type = Some(t.into());
        assert_eq!(f.review(), Err(Error::Sighash(1)));
    }
    let mut f = Fixture::new();
    f.psbt.inputs[1].sighash_type = Some(EcdsaSighashType::All.into());
    assert!(f.review().is_ok());
}

#[test]
fn change_is_only_what_the_change_chain_makes() {
    // a derivation on the receiving chain: it's shown as a payment
    let mut f = Fixture::new();
    let fp = f.fingerprint();
    let k = f.master.derive_priv(&f.secp, &key_path(0, 0)).unwrap();
    let script = ScriptBuf::new_p2wpkh(&CompressedPublicKey(k.private_key.public_key(&f.secp)).wpubkey_hash());
    f.psbt.unsigned_tx.output[1].script_pubkey = script;
    f.psbt.outputs[1].bip32_derivation.clear();
    f.psbt.outputs[1].bip32_derivation.insert(k.private_key.public_key(&f.secp), (fp, key_path(0, 0)));
    assert!(!f.review().unwrap().outputs[1].change);

    // a change derivation on an output that pays someone else
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.output[1].script_pubkey = f.payee.clone();
    let r = f.review().unwrap();
    assert!(!r.outputs[1].change);
}

#[test]
fn outputs_beyond_the_inputs_are_refused() {
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.output[0].value = Amount::from_sat(75_001);
    assert_eq!(f.review(), Err(Error::NegativeFee));
    f.psbt.unsigned_tx.output[0].value = Amount::from_sat(u64::MAX - 10);
    assert_eq!(f.review(), Err(Error::Amount));
}

#[test]
fn malformed_psbts_are_refused() {
    let f = Fixture::new();
    let good = f.psbt.serialize();
    // bytes after the end
    let mut long = good.clone();
    long.push(0);
    assert!(Psbt::parse(&long).is_err());
    // cut short
    assert!(Psbt::parse(&good[..good.len() - 1]).is_err());
    // not a PSBT
    assert!(Psbt::parse(b"psbu\xff\x00").is_err());
    // version 2
    let mut v2 = f.psbt.clone();
    v2.version = 2;
    assert!(Psbt::parse(&v2.serialize()).is_err());
    // a duplicate key: the global transaction twice
    let tx = bitcoin::consensus::serialize(&f.psbt.unsigned_tx);
    let mut dup = b"psbt\xff".to_vec();
    for _ in 0..2 {
        dup.extend_from_slice(&[0x01, 0x00]);
        dup.extend_from_slice(&[0xfd, (tx.len() & 0xff) as u8, (tx.len() >> 8) as u8]);
        dup.extend_from_slice(&tx);
    }
    assert!(Psbt::parse(&dup).is_err());
    // a transaction that's already signed
    let mut signed = f.psbt.unsigned_tx.clone();
    signed.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    let tx = bitcoin::consensus::serialize(&signed);
    let mut pre = b"psbt\xff\x01\x00".to_vec();
    pre.push(tx.len() as u8);
    pre.extend_from_slice(&tx);
    pre.extend_from_slice(&[0, 0, 0, 0, 0]);
    assert!(Psbt::parse(&pre).is_err());
}

#[test]
fn non_minimal_lengths_are_refused() {
    use maki_btc::tx::Tx;
    let tx = bitcoin::consensus::serialize(&Fixture::new().psbt.unsigned_tx);
    assert!(Tx::parse(&tx).is_ok());
    // the input count, 2, written as 0xfd 0x02 0x00
    let mut padded = tx[..4].to_vec();
    padded.extend_from_slice(&[0xfd, 0x02, 0x00]);
    padded.extend_from_slice(&tx[5..]);
    assert!(Tx::parse(&padded).is_err());
}

#[test]
fn amounts_are_shown_exactly() {
    use maki_btc::display::amount;
    assert_eq!(amount(70_000, Network::Bitcoin), "0.0007 BTC");
    assert_eq!(amount(100_000_000, Network::Bitcoin), "1 BTC");
    assert_eq!(amount(123_456_789, Network::Bitcoin), "1.23456789 BTC");
    assert_eq!(amount(1, Network::Testnet), "0.00000001 tBTC");
    assert_eq!(amount(0, Network::Bitcoin), "0 BTC");
    assert_eq!(amount(wallet::MAX_MONEY, Network::Bitcoin), "21000000 BTC");
}

#[test]
fn the_review_shows_each_payment_then_change_then_the_fee() {
    use maki_btc::display::Page;
    let f = Fixture::new();
    let r = f.review().unwrap();
    let payee = Address::from_script(&f.payee, bitcoin::Network::Bitcoin).unwrap().to_string();
    let page = |h: &str, v: &str, m: &str| Page { heading: h.into(), value: v.into(), mono: m.into(), prose: String::new() };
    assert_eq!(
        r.pages(),
        vec![
            page("Send", "0.0007 BTC", &payee),
            page("Change", "0.00025 BTC", "back to you"),
            page("Fee", "0.00005 BTC", &format!("{} sat/vB", r.fee_rate())),
        ]
    );
    assert_eq!(r.summary(), "Total 0.00075 BTC");
    assert!(!r.fee_is_high());

    // two payments are numbered; a fee over a tenth of them is called out
    let mut f = Fixture::new();
    f.psbt.unsigned_tx.output[1].script_pubkey = f.payee.clone();
    f.psbt.outputs[1].bip32_derivation.clear();
    f.psbt.unsigned_tx.output[0].value = Amount::from_sat(45_000);
    f.psbt.unsigned_tx.output[1].value = Amount::from_sat(50_000);
    let r = f.review().unwrap();
    let headings: Vec<String> = r.pages().into_iter().map(|p| p.heading).collect();
    assert_eq!(headings, ["Send 1/2", "Send 2/2", "Fee"]);
    f.psbt.unsigned_tx.output[1].value = Amount::from_sat(10_000);
    let r = f.review().unwrap();
    assert!(r.fee_is_high());
    assert_eq!(r.pages().last().unwrap().heading, "High fee!");
}

#[test]
fn refusals_say_why() {
    assert_eq!(
        Error::NoPreviousTx(1).to_string(),
        "input 1 doesn't come with what it spends (the PSBT needs non_witness_utxo, or for taproot witness_utxo)"
    );
    assert_eq!(Error::ScriptPath(2).to_string(), "input 2 spends a taproot script, and maki signs with its key alone");
    assert!(Error::NotOurs(0).to_string().starts_with("input 0 isn't this wallet's"));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Writes tests/fixtures: the fixture's PSBT, unsigned and as maki signs it, for the emulator's
/// demo and the desktop app's tests. Regenerate (only if the fixture changes) with
///     cargo test -p maki-btc -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    let f = Fixture::new();
    std::fs::create_dir_all(FIXTURES).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-unsigned.psbt"), f.psbt.serialize()).unwrap();
    let mut psbt = f.ours();
    wallet::sign(&mut psbt, std::slice::from_ref(&f.account)).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-signed.psbt"), psbt.serialize()).unwrap();
}

#[test]
fn the_fixtures_are_current_and_rust_bitcoin_agrees() {
    let f = Fixture::new();
    let unsigned = std::fs::read(format!("{FIXTURES}/abandon-unsigned.psbt")).unwrap();
    let signed = std::fs::read(format!("{FIXTURES}/abandon-signed.psbt")).unwrap();
    assert_eq!(unsigned, f.psbt.serialize());
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    wallet::sign(&mut psbt, std::slice::from_ref(&f.account)).unwrap();
    assert_eq!(psbt.serialize(), signed);
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(BPsbt::deserialize(&signed).unwrap(), theirs);
}

#[test]
fn bitcoin_cores_script_interpreter_accepts_what_maki_signs() {
    // libbitcoinconsensus: Bitcoin Core's own consensus code, built from source
    let f = Fixture::new();
    let mut psbt = f.ours();
    wallet::sign(&mut psbt, std::slice::from_ref(&f.account)).unwrap();
    let mut signed = BPsbt::deserialize(&psbt.serialize()).unwrap();
    for input in signed.inputs.iter_mut() {
        let (pk, sig) = input.partial_sigs.pop_first().unwrap();
        input.final_script_witness = Some(Witness::p2wpkh(&sig, &pk.inner));
    }
    let spent: Vec<TxOut> = signed.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
    let prevouts: Vec<OutPoint> = signed.unsigned_tx.input.iter().map(|i| i.previous_output).collect();
    let tx = signed.extract_tx().unwrap();
    tx.verify(|outpoint| prevouts.iter().position(|p| p == outpoint).map(|i| spent[i].clone())).unwrap();

    // and a signature over anything else is refused: the check is real
    let mut tampered = tx.clone();
    tampered.output[0].value = Amount::from_sat(69_999);
    assert!(tampered.verify(|outpoint| prevouts.iter().position(|p| p == outpoint).map(|i| spent[i].clone())).is_err());
}
