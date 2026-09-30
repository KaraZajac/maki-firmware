//! Multisig, against rust-bitcoin and miniscript: a 2-of-3 wallet with maki's key (the BIP39 test
//! phrase's) and two others, its addresses as miniscript makes them, and a spend that maki signs,
//! another key signs, miniscript finalizes and Bitcoin Core's script interpreter (libbitcoinconsensus)
//! accepts. And what maki refuses: a key swapped, another wallet's script, change that isn't the
//! wallet's.

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub as BitcoinXpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{absolute, transaction, Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use maki_btc::bip32::Xpub;
use maki_btc::multisig::{cosigner, Multisig, Signer};
use maki_btc::psbt::Psbt;
use maki_btc::wallet::Error;
use maki_btc::Network;
use maki_hd::seed::SeedKeys;
use maki_hd::Keys;
use miniscript::psbt::PsbtExt;
use miniscript::{Descriptor, DescriptorPublicKey};

fn maki() -> SeedKeys {
    let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ').collect();
    SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap()
}

const PATH: &str = "m/48'/1'/0'/2'";

/// Another wallet's master key, and its account key at BIP48's P2WSH path, as a descriptor writes it.
fn other(seed: u8) -> (Xpriv, String) {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap();
    let account = master.derive_priv(&secp, &DerivationPath::from_str(PATH).unwrap()).unwrap();
    let xpub = BitcoinXpub::from_priv(&secp, &account);
    (master, format!("[{}/48h/1h/0h/2h]{}", master.fingerprint(&secp), xpub))
}

/// maki's key, as its cosigner export says it (the Vpub written as a tpub, as descriptors take it).
fn makis() -> String {
    let text = cosigner(&maki(), Network::Testnet).unwrap();
    let (origin, key) = text.split_once(']').unwrap();
    format!("{origin}]{}", Xpub::parse(key).unwrap().encode(Network::Testnet.xpub_version()))
}

fn two_of_three() -> (String, Xpriv) {
    let (second, b) = other(0x22);
    let (_, c) = other(0x33);
    (format!("wsh(sortedmulti(2,{},{b}/<0;1>/*,{c}/<0;1>/*))", format!("{}/<0;1>/*", makis())), second)
}

#[test]
fn xpubs_derive_as_bitcoin_does() {
    let text = cosigner(&maki(), Network::Testnet).unwrap();
    assert!(text.starts_with("[73c5da0a/48h/1h/0h/2h]Vpub"), "{text}");
    let key = Xpub::parse(text.split_once(']').unwrap().1).unwrap();
    let theirs = BitcoinXpub::from_str(&key.encode(Network::Testnet.xpub_version())).unwrap();
    let secp = Secp256k1::new();
    for chain in [0u32, 1] {
        for index in [0u32, 1, 7, 1000, 0x7fff_ffff] {
            let ours = key.child(chain).unwrap().child(index).unwrap();
            let path = DerivationPath::from_str(&format!("m/{chain}/{index}")).unwrap();
            let want = theirs.derive_pub(&secp, &path).unwrap();
            assert_eq!(ours.key, want.public_key.serialize());
            assert_eq!(ours.chain_code, want.chain_code.to_bytes());
            assert_eq!(ours.parent_fingerprint, want.parent_fingerprint.to_bytes());
        }
    }
    assert!(key.child(0x8000_0000).is_none(), "hardened");
    // the same key under another version, and a checksum that's off
    assert_eq!(Xpub::parse(&theirs.to_string()).unwrap(), key);
    let mut broken = theirs.to_string();
    broken.replace_range(10..11, if &broken[10..11] == "a" { "b" } else { "a" });
    assert!(Xpub::parse(&broken).is_none());
}

#[test]
fn a_wallet_reads_the_same_from_a_descriptor_or_coldcards_file_with_miniscripts_addresses() {
    let (desc, _) = two_of_three();
    let wallet = Multisig::parse(&desc, "Family vault").unwrap();
    assert_eq!((wallet.threshold, wallet.keys.len(), wallet.sorted, wallet.network), (2, 3, true, Network::Testnet));
    assert_eq!(wallet.name, "Family vault");
    // with its checksum, and as Coldcard's file has it
    let theirs = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();
    assert_eq!(Multisig::parse(&theirs.to_string(), "Family vault").unwrap(), wallet);
    let file = {
        let mut f = String::from("# Coldcard Multisig setup file (created by Sparrow)\n#\nName: Family vault\nPolicy: 2 of 3\nDerivation: m/48'/1'/0'/2'\nFormat: P2WSH\n\n");
        for k in &wallet.keys {
            f.push_str(&format!("{}: {}\n", k.fingerprint.iter().map(|b| format!("{b:02X}")).collect::<String>(), k.xpub.encode([0x02, 0x57, 0x54, 0x83])));
        }
        f
    };
    let from_file = Multisig::parse(&file, "").unwrap();
    assert_eq!(from_file.descriptor(), wallet.descriptor());
    assert_eq!(from_file.name, "Family vault");
    // its own descriptor reads back to it, and miniscript reads it too
    assert_eq!(Multisig::parse(&wallet.descriptor(), "Family vault").unwrap(), wallet);
    Descriptor::<DescriptorPublicKey>::from_str(&wallet.descriptor()).unwrap();
    // every address, as miniscript makes them
    let chains = wallet.chains().unwrap();
    let singles = theirs.into_single_descriptors().unwrap();
    for (change, single) in singles.iter().enumerate() {
        for index in [0u32, 1, 2, 50] {
            let want = single.at_derivation_index(index).unwrap().address(bitcoin::Network::Testnet).unwrap();
            assert_eq!(wallet.address(&chains, change == 1, index).unwrap(), want.to_string());
        }
    }
    // multi keeps the keys in the order they're given
    let unsorted = desc.replace("sortedmulti", "multi");
    let multi = Multisig::parse(&unsorted, "").unwrap();
    assert!(!multi.sorted);
    let want = Descriptor::<DescriptorPublicKey>::from_str(&unsorted).unwrap().into_single_descriptors().unwrap()[0]
        .at_derivation_index(3)
        .unwrap()
        .address(bitcoin::Network::Testnet)
        .unwrap();
    assert_eq!(multi.address(&multi.chains().unwrap(), false, 3).unwrap(), want.to_string());
    assert_eq!(multi.name, "2 of 3 multisig");
}

#[test]
fn a_wallet_maki_wont_take() {
    let (desc, _) = two_of_three();
    let bad_checksum = format!("{}#aaaaaaaa", desc);
    let (_, d) = other(0x44);
    let (_, e) = other(0x55);
    let not_makis = format!("wsh(sortedmulti(2,{d}/<0;1>/*,{e}/<0;1>/*))");
    // maki's fingerprint, with someone else's key
    let impostor = format!("wsh(sortedmulti(2,[73c5da0a/48h/1h/0h/2h]{}/<0;1>/*,{e}/<0;1>/*))", d.split_once(']').unwrap().1);
    let wrapped = format!("sh({})", desc);
    let nested_path = desc.replace("48h/1h/0h/2h", "48h/1h/0h/1h");
    let twice = format!("wsh(sortedmulti(2,{m}/<0;1>/*,{m}/<0;1>/*))", m = makis());
    let too_many = format!("wsh(sortedmulti(4,{},{d}/<0;1>/*,{e}/<0;1>/*))", format!("{}/<0;1>/*", makis()));
    for (text, why) in [
        (bad_checksum.as_str(), "checksum"),
        (wrapped.as_str(), "P2SH"),
        (nested_path.as_str(), "BIP48"),
        (twice.as_str(), "twice"),
        (too_many.as_str(), "1 to 15"),
        ("wsh(sortedmulti(1,[73c5da0a/48h/1h/0h/2h]nonsense/<0;1>/*))", "xpub"),
    ] {
        let e = Multisig::parse(text, "").unwrap_err().to_string();
        assert!(e.contains(why), "{why}: {e}");
    }
    let keys = maki();
    let e = Signer::new(Multisig::parse(&not_makis, "").unwrap(), &keys).err().unwrap().to_string();
    assert!(e.contains("isn't one of its keys"), "{e}");
    let e = Signer::new(Multisig::parse(&impostor, "").unwrap(), &keys).err().unwrap().to_string();
    assert!(e.contains("isn't maki's"), "{e}");
}

/// A spend from the wallet: two of its coins (receive 0 and 1), a payment and change (change 0);
/// the PSBT as a coordinator makes it, every key's derivation on inputs and change.
struct Spend {
    psbt: bitcoin::Psbt,
    funding: Transaction,
    payee: bitcoin::Address,
}

fn spend(wallet: &Multisig, desc: &str) -> Spend {
    let theirs = Descriptor::<DescriptorPublicKey>::from_str(desc).unwrap().into_single_descriptors().unwrap();
    let at = |change: usize, index: u32| theirs[change].at_derivation_index(index).unwrap();
    let funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![
            TxOut { value: Amount::from_sat(60_000), script_pubkey: at(0, 0).script_pubkey() },
            TxOut { value: Amount::from_sat(40_000), script_pubkey: at(0, 1).script_pubkey() },
        ],
    };
    let payee = bitcoin::Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap().assume_checked();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..2)
            .map(|v| TxIn { previous_output: OutPoint::new(funding.compute_txid(), v), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() })
            .collect(),
        output: vec![
            TxOut { value: Amount::from_sat(70_000), script_pubkey: payee.script_pubkey() },
            TxOut { value: Amount::from_sat(29_000), script_pubkey: at(1, 0).script_pubkey() },
        ],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(tx).unwrap();
    let derivations = |change: u32, index: u32| {
        wallet
            .keys
            .iter()
            .map(|k| {
                let public = k.xpub.child(change).unwrap().child(index).unwrap();
                let path = DerivationPath::from_str(&format!("m/48'/1'/0'/2'/{change}/{index}")).unwrap();
                (bitcoin::secp256k1::PublicKey::from_slice(&public.key).unwrap(), (Fingerprint::from(k.fingerprint), path))
            })
            .collect()
    };
    for (i, index) in [0u32, 1].into_iter().enumerate() {
        let input = &mut psbt.inputs[i];
        input.non_witness_utxo = Some(funding.clone());
        input.witness_utxo = Some(funding.output[i].clone());
        input.witness_script = Some(at(0, index).explicit_script().unwrap());
        input.bip32_derivation = derivations(0, index);
    }
    psbt.outputs[1].witness_script = Some(at(1, 0).explicit_script().unwrap());
    psbt.outputs[1].bip32_derivation = derivations(1, 0);
    Spend { psbt, funding, payee }
}

fn ours(psbt: &bitcoin::Psbt) -> Psbt { Psbt::parse(&psbt.serialize()).unwrap() }

#[test]
fn maki_signs_what_spends_from_the_wallet_and_with_another_key_it_spends() {
    let (desc, second) = two_of_three();
    let wallet = Multisig::parse(&desc, "Family vault").unwrap();
    let keys = maki();
    let signer = Signer::new(wallet.clone(), &keys).unwrap();
    assert_eq!(signer.ours, wallet.keys.iter().position(|k| k.fingerprint == keys.fingerprint().unwrap()).unwrap());
    let Spend { psbt, funding, payee } = spend(&wallet, &desc);
    let mut mine = ours(&psbt);
    let review = signer.review(&mine).unwrap();
    assert_eq!(review.wallet.as_deref(), Some("Family vault (2 of 3)"));
    assert_eq!((review.fee, review.inputs), (1_000, 2));
    assert_eq!((review.outputs[0].address.as_str(), review.outputs[0].amount, review.outputs[0].change), (payee.to_string().as_str(), 70_000, false));
    assert!(review.outputs[1].change);
    let pages = review.pages();
    assert_eq!((pages[1].heading.as_str(), pages[1].prose.as_str()), ("Change", "back to Family vault (2 of 3)"));
    // two inputs of 2-of-3 P2WSH, a P2WPKH payment and P2WSH change: about 290 vbytes signed
    assert!((280..300).contains(&review.vbytes), "{}", review.vbytes);
    assert_eq!(signer.sign(&mut mine).unwrap(), 2);

    // the second key signs too; miniscript puts the witnesses together; Bitcoin Core's
    // interpreter says the transaction may spend what it spends
    let secp = Secp256k1::new();
    let mut signed = bitcoin::Psbt::deserialize(&mine.serialize()).unwrap();
    assert_eq!(signed.inputs.iter().map(|i| i.partial_sigs.len()).collect::<Vec<_>>(), [1, 1]);
    signed.sign(&second, &secp).unwrap();
    signed.finalize_mut(&secp).unwrap();
    let tx = signed.extract_tx().unwrap();
    tx.verify(|op| (op.txid == funding.compute_txid()).then(|| funding.output[op.vout as usize].clone())).unwrap();
}

#[test]
fn maki_signs_nothing_a_computer_passes_off_as_the_wallets() {
    let (desc, _) = two_of_three();
    let wallet = Multisig::parse(&desc, "Family vault").unwrap();
    let keys = maki();
    let signer = Signer::new(wallet.clone(), &keys).unwrap();

    // another wallet's script with maki's key in it (1 of 3 of the same keys): not this wallet's
    let one_of_three = desc.replace("sortedmulti(2,", "sortedmulti(1,");
    let loose = Multisig::parse(&one_of_three, "").unwrap();
    let Spend { psbt, .. } = spend(&loose, &one_of_three);
    assert_eq!(signer.review(&ours(&psbt)).unwrap_err(), Error::NotOurs(0));

    // change to a wallet with maki's key and two of the computer's: a payment, not change
    let (_, d) = other(0x66);
    let (_, e) = other(0x77);
    let theirs_too = format!("wsh(sortedmulti(2,{}/<0;1>/*,{d}/<0;1>/*,{e}/<0;1>/*))", makis());
    let other_wallet = Multisig::parse(&theirs_too, "").unwrap();
    let Spend { mut psbt, .. } = spend(&wallet, &desc);
    let stranger = Descriptor::<DescriptorPublicKey>::from_str(&theirs_too).unwrap().into_single_descriptors().unwrap()[1]
        .at_derivation_index(0)
        .unwrap();
    psbt.unsigned_tx.output[1].script_pubkey = stranger.script_pubkey();
    psbt.outputs[1].witness_script = Some(stranger.explicit_script().unwrap());
    psbt.outputs[1].bip32_derivation = other_wallet
        .keys
        .iter()
        .map(|k| {
            let public = k.xpub.child(1).unwrap().child(0).unwrap();
            (bitcoin::secp256k1::PublicKey::from_slice(&public.key).unwrap(), (Fingerprint::from(k.fingerprint), DerivationPath::from_str("m/48'/1'/0'/2'/1/0").unwrap()))
        })
        .collect();
    let review = signer.review(&ours(&psbt)).unwrap();
    assert!(!review.outputs[1].change, "change to another wallet is a payment");
    assert_eq!(review.pages().iter().filter(|p| p.heading.starts_with("Send")).count(), 2);

    // no previous transaction, a sighash other than ALL, a claimed amount that isn't the real one
    let Spend { psbt, .. } = spend(&wallet, &desc);
    let mut bare = psbt.clone();
    bare.inputs[1].non_witness_utxo = None;
    assert_eq!(signer.review(&ours(&bare)).unwrap_err(), Error::NoPreviousTx(1));
    let mut none = psbt.clone();
    none.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(2));
    assert_eq!(signer.review(&ours(&none)).unwrap_err(), Error::Sighash(0));
    let mut lying = psbt.clone();
    lying.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(1);
    assert_eq!(signer.review(&ours(&lying)).unwrap_err(), Error::PreviousTxMismatch(0));
    // a witness script that isn't the wallet's there, though its output is
    let mut swapped = psbt.clone();
    swapped.inputs[0].witness_script = psbt.inputs[1].witness_script.clone();
    assert_eq!(signer.review(&ours(&swapped)).unwrap_err(), Error::NotOurs(0));
    // maki's key named at a place in the wallet the input isn't
    let mut elsewhere = psbt.clone();
    let (k, (fp, _)) = elsewhere.inputs[0].bip32_derivation.iter().find(|(_, (fp, _))| fp.to_bytes() == keys.fingerprint().unwrap()).map(|(k, v)| (*k, v.clone())).unwrap();
    elsewhere.inputs[0].bip32_derivation.insert(k, (fp, DerivationPath::from_str("m/48'/1'/0'/2'/0/5").unwrap()));
    assert_eq!(signer.review(&ours(&elsewhere)).unwrap_err(), Error::NotOurs(0));
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// The 2-of-3 wallet's descriptor, its Coldcard file, and a PSBT spending from it, unsigned and
/// with maki's signatures: for the Bitcoin app's tests and maki desktop's. Regenerate (only if the
/// fixture changes) with
///     cargo test -p maki-btc --test multisig -- --ignored write_fixtures
fn fixtures() -> [(String, Vec<u8>); 4] {
    let (desc, _) = two_of_three();
    let wallet = Multisig::parse(&desc, "Family vault").unwrap();
    let mut file = String::from("# Coldcard Multisig setup file (created by Sparrow)\n#\nName: Family vault\nPolicy: 2 of 3\nDerivation: m/48'/1'/0'/2'\nFormat: P2WSH\n\n");
    for k in &wallet.keys {
        file.push_str(&format!("{}: {}\n", k.fingerprint.iter().map(|b| format!("{b:02X}")).collect::<String>(), k.xpub.encode([0x02, 0x57, 0x54, 0x83])));
    }
    let unsigned = spend(&wallet, &desc).psbt.serialize();
    let keys = maki();
    let mut psbt = Psbt::parse(&unsigned).unwrap();
    Signer::new(wallet.clone(), &keys).unwrap().sign(&mut psbt).unwrap();
    [
        ("multisig.txt".into(), wallet.descriptor().into_bytes()),
        ("multisig-coldcard.txt".into(), file.into_bytes()),
        ("multisig-unsigned.psbt".into(), unsigned),
        ("multisig-signed.psbt".into(), psbt.serialize()),
    ]
}

#[test]
#[ignore]
fn write_fixtures() {
    for (name, bytes) in fixtures() {
        std::fs::write(format!("{FIXTURES}/{name}"), bytes).unwrap();
    }
}

#[test]
fn the_fixtures_are_current() {
    for (name, bytes) in fixtures() {
        assert_eq!(std::fs::read(format!("{FIXTURES}/{name}")).unwrap(), bytes, "{name}");
    }
}
