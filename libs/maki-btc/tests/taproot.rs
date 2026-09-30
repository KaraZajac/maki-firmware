//! Taproot (BIP86): BIP86's own test vectors, the descriptor wallet software reads, and PSBTs
//! signed as rust-bitcoin signs them (both follow BIP340 with the same auxiliary randomness),
//! each signature checked against rust-bitcoin's sighash.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv as BXpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, XOnlyPublicKey};
use bitcoin::psbt::Psbt as BPsbt;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Address, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, transaction,
};
use maki_btc::bip32::HARDENED;
use maki_btc::psbt::Psbt;
use maki_btc::wallet::{self, Error, Kind};
use maki_btc::{Account, Network};
use maki_hd::seed::SeedKeys;
use maki_hd::{Keys, Public, Tweak};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> [u8; 64] {
    let words: Vec<&str> = ABANDON.split(' ').collect();
    maki_seed::seed(&words, "")
}

/// maki's keys for a seed, for as long as the tests run.
fn keys(seed: &[u8]) -> &'static SeedKeys { Box::leak(Box::new(SeedKeys::from_seed(seed).unwrap())) }

/// maki's keys, with fresh randomness in their Schnorr signatures, as on maki.
struct Aux(SeedKeys, [u8; 32]);

impl Keys for Aux {
    fn fingerprint(&self) -> Result<[u8; 4], maki_hd::Error> { self.0.fingerprint() }

    fn public(&self, path: &[u32]) -> Result<Public, maki_hd::Error> { self.0.public(path) }

    fn uncompressed(&self, path: &[u32]) -> Result<[u8; 65], maki_hd::Error> { self.0.uncompressed(path) }

    fn taproot_output(&self, path: &[u32]) -> Result<[u8; 32], maki_hd::Error> { self.0.taproot_output(path) }

    fn sign_ecdsa(&self, path: &[u32], digest: &[u8; 32]) -> Result<([u8; 64], u8), maki_hd::Error> {
        self.0.sign_ecdsa(path, digest)
    }

    fn sign_schnorr(
        &self,
        path: &[u32],
        digest: &[u8; 32],
        tweak: Tweak,
    ) -> Result<[u8; 64], maki_hd::Error> {
        self.0.sign_schnorr_with(path, digest, tweak, &self.1)
    }
}

fn taproot(network: Network) -> Account<'static> {
    Account::new(keys(&seed()), network, Kind::Taproot).unwrap()
}

#[test]
fn bip86_test_vectors() {
    let account = taproot(Network::Bitcoin);
    assert_eq!(
        account.zpub(),
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
    );
    assert_eq!(
        account.address(false, 0).unwrap(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
    assert_eq!(
        account.address(false, 1).unwrap(),
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
    );
    assert_eq!(
        account.address(true, 0).unwrap(),
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
    );
    // the internal and output keys BIP86 gives for the first address
    let path = [86 | HARDENED, HARDENED, HARDENED, 0, 0];
    let k = keys(&seed());
    assert_eq!(
        maki_btc::taproot::x_only(&k.public(&path).unwrap().key).to_vec(),
        hex("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
    );
    assert_eq!(
        k.taproot_output(&path).unwrap().to_vec(),
        hex("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
    );
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn addresses_and_the_descriptor_agree_with_rust_bitcoin_and_miniscript() {
    use miniscript::{Descriptor, DescriptorPublicKey};
    let secp = Secp256k1::new();
    for (network, btc, kind) in [
        (Network::Bitcoin, bitcoin::Network::Bitcoin, bitcoin::NetworkKind::Main),
        (Network::Testnet, bitcoin::Network::Testnet, bitcoin::NetworkKind::Test),
    ] {
        let account = taproot(network);
        let master = BXpriv::new_master(kind, &seed()).unwrap();
        for (change, index) in [(false, 0), (false, 7), (true, 0), (true, 2)] {
            let path = DerivationPath::from_str(&format!(
                "m/86'/{}'/0'/{}/{}",
                network.coin_type(),
                change as u32,
                index
            ))
            .unwrap();
            let key = master.derive_priv(&secp, &path).unwrap();
            let (internal, _) = key.private_key.public_key(&secp).x_only_public_key();
            assert_eq!(
                account.address(change, index).unwrap(),
                Address::p2tr(&secp, internal, None, btc).to_string()
            );
        }
        let text = account.descriptor();
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&text).unwrap();
        for (chain, d) in desc.into_single_descriptors().unwrap().iter().enumerate() {
            for index in [0, 1, 19] {
                let address = d.at_derivation_index(index).unwrap().address(btc).unwrap().to_string();
                assert_eq!(address, account.address(chain == 1, index).unwrap(), "{text} {chain}/{index}");
            }
        }
    }
    assert!(taproot(Network::Bitcoin).descriptor().starts_with("tr([73c5da0a/86h/0h/0h]xpub"));
    assert!(taproot(Network::Testnet).zpub().starts_with("tpub"));
}

/// A PSBT spending two taproot coins of the wallet's and one native SegWit coin: 70,000 sats to
/// someone else, 25,000 back to the taproot change chain, 5,000 in fees.
struct Fixture {
    secp: Secp256k1<secp256k1::All>,
    master: BXpriv,
    accounts: Vec<Account<'static>>,
    psbt: BPsbt,
}

fn tap_path(chain: u32, index: u32) -> DerivationPath {
    DerivationPath::from_str(&format!("m/86'/0'/0'/{chain}/{index}")).unwrap()
}

fn funding(salt: u8, output: TxOut) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([salt; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x42; 64]]),
        }],
        output: vec![output],
    }
}

impl Fixture {
    fn new(segwit_input: bool) -> Fixture {
        let secp = Secp256k1::new();
        let master = BXpriv::new_master(bitcoin::NetworkKind::Main, &seed()).unwrap();
        let fp = master.fingerprint(&secp);
        let tap_key = |chain, index| {
            let k = master.derive_priv(&secp, &tap_path(chain, index)).unwrap();
            k.private_key.public_key(&secp).x_only_public_key().0
        };
        let payee = ScriptBuf::new_p2tr(
            &secp,
            XOnlyPublicKey::from_slice(&[0x79; 32]).unwrap_or(tap_key(0, 99)),
            None,
        );
        let mut prevs = vec![
            funding(
                1,
                TxOut {
                    value: Amount::from_sat(60_000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, tap_key(0, 0), None),
                },
            ),
            funding(
                2,
                TxOut {
                    value: Amount::from_sat(15_000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, tap_key(0, 3), None),
                },
            ),
        ];
        let segwit_path = DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap();
        let segwit_key = master.derive_priv(&secp, &segwit_path).unwrap().private_key.public_key(&secp);
        if segwit_input {
            prevs.push(funding(
                3,
                TxOut {
                    value: Amount::from_sat(25_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&CompressedPublicKey(segwit_key).wpubkey_hash()),
                },
            ));
        }
        let fee_in = if segwit_input { 25_000 } else { 0 };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(870_000),
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
                TxOut { value: Amount::from_sat(45_000 + fee_in), script_pubkey: payee },
                TxOut {
                    value: Amount::from_sat(25_000),
                    script_pubkey: ScriptBuf::new_p2tr(&secp, tap_key(1, 0), None),
                },
            ],
        };
        let mut psbt = BPsbt::from_unsigned_tx(tx).unwrap();
        for (i, (index, prev)) in [0u32, 3].into_iter().zip(&prevs).enumerate() {
            let key = tap_key(0, index);
            psbt.inputs[i].witness_utxo = Some(prev.output[0].clone());
            psbt.inputs[i].tap_internal_key = Some(key);
            psbt.inputs[i].tap_key_origins.insert(key, (vec![], (fp, tap_path(0, index))));
        }
        if segwit_input {
            psbt.inputs[2].witness_utxo = Some(prevs[2].output[0].clone());
            psbt.inputs[2].non_witness_utxo = Some(prevs[2].clone());
            psbt.inputs[2].bip32_derivation.insert(segwit_key, (fp, segwit_path));
        }
        let change = tap_key(1, 0);
        psbt.outputs[1].tap_internal_key = Some(change);
        psbt.outputs[1].tap_key_origins.insert(change, (vec![], (fp, tap_path(1, 0))));
        let accounts =
            vec![Account::segwit(keys(&seed()), Network::Bitcoin).unwrap(), taproot(Network::Bitcoin)];
        Fixture { secp, master, accounts, psbt }
    }

    fn ours(&self) -> Psbt { Psbt::parse(&self.psbt.serialize()).unwrap() }

    fn review(&self) -> Result<wallet::Review, Error> { wallet::review(&self.ours(), &self.accounts) }
}

#[test]
fn review_shows_payments_change_and_fee() {
    let f = Fixture::new(false);
    let r = f.review().unwrap();
    assert_eq!((r.inputs, r.fee), (2, 5_000));
    assert!(!r.outputs[0].change);
    assert_eq!(
        (r.outputs[1].address.as_str(), r.outputs[1].amount, r.outputs[1].change),
        ("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", 25_000, true)
    );
    // taproot alone signs nothing without the taproot account
    assert_eq!(wallet::review(&f.ours(), &f.accounts[..1]), Err(Error::NotOurs(0)));
}

/// Checks each taproot signature against rust-bitcoin's sighash and the output key.
fn verify(f: &Fixture, signed: &BPsbt) {
    let tx = &signed.unsigned_tx;
    let spent: Vec<TxOut> = signed.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
    let mut cache = SighashCache::new(tx);
    for (i, input) in signed.inputs.iter().enumerate() {
        let Some(sig) = input.tap_key_sig else { continue };
        let hash_type =
            input.sighash_type.map(|t| t.taproot_hash_ty().unwrap()).unwrap_or(TapSighashType::Default);
        assert_eq!(sig.sighash_type, hash_type);
        let sighash = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&spent), hash_type).unwrap();
        let (output_key, _) = input.tap_internal_key.unwrap().tap_tweak(&f.secp, None);
        f.secp
            .verify_schnorr(
                &sig.signature,
                &Message::from_digest(sighash.to_byte_array()),
                &output_key.to_x_only_public_key(),
            )
            .unwrap();
    }
}

#[test]
fn taproot_signatures_match_rust_bitcoins_and_verify() {
    let f = Fixture::new(false);
    let mut ours = f.ours();
    // rust-bitcoin signs without auxiliary randomness, which BIP340 takes as 32 zero bytes
    assert_eq!(wallet::sign(&mut ours, &f.accounts).unwrap(), 2);
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(signed, theirs, "maki's PSBT, signed, is rust-bitcoin's");
    verify(&f, &signed);

    // with randomness, other signatures, just as good
    let mut random = f.ours();
    let aux: &'static Aux = Box::leak(Box::new(Aux(SeedKeys::from_seed(&seed()).unwrap(), [0x5a; 32])));
    let accounts = vec![
        Account::segwit(aux, Network::Bitcoin).unwrap(),
        Account::new(aux, Network::Bitcoin, Kind::Taproot).unwrap(),
    ];
    wallet::sign(&mut random, &accounts).unwrap();
    let random = BPsbt::deserialize(&random.serialize()).unwrap();
    assert_ne!(random.inputs[0].tap_key_sig, signed.inputs[0].tap_key_sig);
    verify(&f, &random);

    // SIGHASH_ALL written out: the same digest but for its type, and a byte on the signature
    let mut all = f.psbt.clone();
    all.inputs[1].sighash_type = Some(TapSighashType::All.into());
    let mut ours = Psbt::parse(&all.serialize()).unwrap();
    wallet::sign(&mut ours, &f.accounts).unwrap();
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();
    assert_eq!(signed.inputs[1].tap_key_sig.unwrap().sighash_type, TapSighashType::All);
    verify(&f, &signed);

    // the size maki estimated covers the signed transaction's
    let review = f.review().unwrap();
    let mut done = BPsbt::deserialize(&f.ours().serialize()).unwrap();
    let mut ours = f.ours();
    wallet::sign(&mut ours, &f.accounts).unwrap();
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();
    for (i, input) in done.inputs.iter_mut().enumerate() {
        input.final_script_witness = Some(Witness::p2tr_key_spend(&signed.inputs[i].tap_key_sig.unwrap()));
    }
    let vsize = done.extract_tx().unwrap().vsize() as u64;
    assert!(
        review.vbytes >= vsize && review.vbytes <= vsize + 1,
        "estimated {} for {}",
        review.vbytes,
        vsize
    );
}

#[test]
fn native_segwit_and_taproot_inputs_sign_together() {
    let f = Fixture::new(true);
    let r = f.review().unwrap();
    assert_eq!((r.inputs, r.fee), (3, 5_000));
    let mut ours = f.ours();
    assert_eq!(wallet::sign(&mut ours, &f.accounts).unwrap(), 3);
    let signed = BPsbt::deserialize(&ours.serialize()).unwrap();
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(signed, theirs);
    verify(&f, &signed);
    assert_eq!(signed.inputs[2].partial_sigs.len(), 1);
}

#[test]
fn what_maki_wont_sign_for_taproot() {
    // a script path: maki signs with the key alone
    let mut f = Fixture::new(false);
    f.psbt.inputs[1].tap_merkle_root = Some(bitcoin::taproot::TapNodeHash::from_byte_array([7; 32]));
    assert_eq!(f.review(), Err(Error::ScriptPath(1)));
    // a derivation for script leaves, not the key
    let mut f = Fixture::new(false);
    let (key, (_, origin)) = f.psbt.inputs[0].tap_key_origins.pop_first().unwrap();
    let leaf = bitcoin::taproot::TapLeafHash::from_byte_array([9; 32]);
    f.psbt.inputs[0].tap_key_origins.insert(key, (vec![leaf], origin));
    assert_eq!(f.review(), Err(Error::NotOurs(0)));
    // an internal key other than the one the derivation makes
    let mut f = Fixture::new(false);
    f.psbt.inputs[0].tap_internal_key = f.psbt.inputs[1].tap_internal_key;
    assert_eq!(f.review(), Err(Error::NotOurs(0)));
    // a coin that isn't the key's: the witness UTXO pays another script
    let mut f = Fixture::new(false);
    f.psbt.inputs[0].witness_utxo = f.psbt.inputs[1].witness_utxo.clone();
    assert_eq!(f.review(), Err(Error::NotOurs(0)));
    // nothing to say what it spends
    let mut f = Fixture::new(false);
    f.psbt.inputs[1].witness_utxo = None;
    assert_eq!(f.review(), Err(Error::NoPreviousTx(1)));
    // signatures other than the default and ALL
    let mut f = Fixture::new(false);
    f.psbt.inputs[0].sighash_type = Some(TapSighashType::SinglePlusAnyoneCanPay.into());
    assert_eq!(f.review(), Err(Error::Sighash(0)));
    // change only where it's the change chain's own key
    let mut f = Fixture::new(false);
    let (key, (leaves, (fp, _))) = f.psbt.outputs[1].tap_key_origins.pop_first().unwrap();
    f.psbt.outputs[1].tap_key_origins.insert(key, (leaves, (fp, tap_path(0, 0))));
    assert!(!f.review().unwrap().outputs[1].change);
    // a witness UTXO that disagrees with the whole previous transaction, when it's there
    let mut f = Fixture::new(true);
    f.psbt.inputs[2].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
    assert_eq!(f.review(), Err(Error::PreviousTxMismatch(2)));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// Writes the taproot fixture's PSBT, unsigned and as maki signs it with no auxiliary randomness
/// (as the fake maki does), for the desktop app's tests. Regenerate (only if the fixture
/// changes) with
///     cargo test -p maki-btc --test taproot -- --ignored write_fixtures
#[test]
#[ignore]
fn write_fixtures() {
    let f = Fixture::new(false);
    std::fs::create_dir_all(FIXTURES).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-taproot-unsigned.psbt"), f.psbt.serialize()).unwrap();
    let mut psbt = f.ours();
    wallet::sign(&mut psbt, &f.accounts).unwrap();
    std::fs::write(format!("{FIXTURES}/abandon-taproot-signed.psbt"), psbt.serialize()).unwrap();
}

#[test]
fn the_fixtures_are_current_and_rust_bitcoin_agrees() {
    let f = Fixture::new(false);
    let unsigned = std::fs::read(format!("{FIXTURES}/abandon-taproot-unsigned.psbt")).unwrap();
    let signed = std::fs::read(format!("{FIXTURES}/abandon-taproot-signed.psbt")).unwrap();
    assert_eq!(unsigned, f.psbt.serialize());
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    wallet::sign(&mut psbt, &f.accounts).unwrap();
    assert_eq!(psbt.serialize(), signed);
    let mut theirs = f.psbt.clone();
    theirs.sign(&f.master, &f.secp).unwrap();
    assert_eq!(BPsbt::deserialize(&signed).unwrap(), theirs);
}
