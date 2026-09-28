//! maki-hd's keys against rust-bitcoin's (BIP32, BIP86 and libsecp256k1's signatures), on the
//! BIP39 test phrase, and the addresses every wallet agrees it makes.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::{Address, CompressedPublicKey, KnownHrp, NetworkKind};
use maki_hd::seed::SeedKeys;
use maki_hd::{format_path, parse_path, Keys, Tweak};
use sha3::{Digest, Keccak256};

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> [u8; 64] { maki_seed::seed(&PHRASE.split(' ').collect::<Vec<_>>(), "") }

fn theirs(path: &str) -> Xpriv {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Main, &seed()).unwrap();
    master.derive_priv(&secp, &path.parse::<DerivationPath>().unwrap()).unwrap()
}

const PATHS: [&str; 6] = ["m", "m/84'/0'/0'", "m/84'/0'/0'/0/0", "m/86'/1'/0'/1/5", "m/44'/60'/0'/0/0", "m/0'/1/2'/2/1000000000"];

#[test]
fn bip32_as_rust_bitcoin_has_it() {
    let secp = Secp256k1::new();
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    let master = Xpriv::new_master(NetworkKind::Main, &seed()).unwrap();
    assert_eq!(ours.fingerprint().unwrap(), master.fingerprint(&secp).to_bytes());
    for p in PATHS {
        let xpub = Xpub::from_priv(&secp, &theirs(p));
        let public = ours.public(&parse_path(p).unwrap()).unwrap();
        assert_eq!(public.key, xpub.public_key.serialize(), "{p}");
        assert_eq!(public.chain_code, xpub.chain_code.to_bytes(), "{p}");
        assert_eq!(public.parent_fingerprint, xpub.parent_fingerprint.to_bytes(), "{p}");
        assert_eq!(ours.uncompressed(&parse_path(p).unwrap()).unwrap(), xpub.public_key.serialize_uncompressed(), "{p}");
    }
}

#[test]
fn the_addresses_every_wallet_makes() {
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    // BIP84 and BIP86's own test vectors
    let key = ours.public(&parse_path("m/84'/0'/0'/0/0").unwrap()).unwrap().key;
    let segwit = Address::p2wpkh(&CompressedPublicKey::from_slice(&key).unwrap(), KnownHrp::Mainnet);
    assert_eq!(segwit.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    let output = ours.taproot_output(&parse_path("m/86'/0'/0'/0/0").unwrap()).unwrap();
    let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(bitcoin::XOnlyPublicKey::from_slice(&output).unwrap());
    assert_eq!(Address::p2tr_tweaked(tweaked, KnownHrp::Mainnet).to_string(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
    // MetaMask's and Ledger's first Ethereum account for the phrase
    let point = ours.uncompressed(&parse_path("m/44'/60'/0'/0/0").unwrap()).unwrap();
    let address = &Keccak256::digest(&point[1..])[12..];
    assert_eq!(hex(address), "9858effd232b4033e47d90003d41ec34ecaeda94");
}

#[test]
fn taproot_output_keys_as_rust_bitcoin_tweaks_them() {
    let secp = Secp256k1::new();
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    for p in ["m/86'/0'/0'/0/0", "m/86'/0'/0'/1/3", "m/86'/1'/0'/0/9"] {
        let internal: UntweakedPublicKey = theirs(p).private_key.x_only_public_key(&secp).0;
        let (tweaked, _) = internal.tap_tweak(&secp, None);
        assert_eq!(ours.taproot_output(&parse_path(p).unwrap()).unwrap(), tweaked.to_x_only_public_key().serialize(), "{p}");
    }
}

#[test]
fn ecdsa_as_libsecp256k1_signs() {
    let secp = Secp256k1::new();
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    for (n, p) in ["m/84'/0'/0'/0/0", "m/44'/60'/0'/0/0", "m/44'/60'/0'/0/7"].iter().enumerate() {
        let digest: [u8; 32] = core::array::from_fn(|i| (i * 7 + n * 13) as u8);
        let (sig, recid) = ours.sign_ecdsa(&parse_path(p).unwrap(), &digest).unwrap();
        // both are RFC 6979 and low-S, so the very same signature
        let msg = Message::from_digest(digest);
        let theirs = secp.sign_ecdsa_recoverable(&msg, &theirs(p).private_key);
        let (their_recid, their_sig) = theirs.serialize_compact();
        assert_eq!(sig, their_sig, "{p}");
        assert_eq!(recid as i32, their_recid.to_i32(), "{p}");
    }
}

#[test]
fn schnorr_verifies_for_the_key_and_for_its_taproot_output() {
    let secp = Secp256k1::new();
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    let digest = [0x42u8; 32];
    let msg = Message::from_digest(digest);

    let p = "m/86'/0'/0'/0/0";
    let sig = ours.sign_schnorr(&parse_path(p).unwrap(), &digest, Tweak::Taproot).unwrap();
    let output = bitcoin::XOnlyPublicKey::from_slice(&ours.taproot_output(&parse_path(p).unwrap()).unwrap()).unwrap();
    secp.verify_schnorr(&schnorr::Signature::from_slice(&sig).unwrap(), &msg, &output).unwrap();

    let sig = ours.sign_schnorr(&parse_path(p).unwrap(), &digest, Tweak::None).unwrap();
    let internal = theirs(p).private_key.x_only_public_key(&secp).0;
    secp.verify_schnorr(&schnorr::Signature::from_slice(&sig).unwrap(), &msg, &internal).unwrap();
    // and the tweak matters: it doesn't verify for the other key
    assert!(secp.verify_schnorr(&schnorr::Signature::from_slice(&sig).unwrap(), &msg, &output).is_err());

    // fresh aux randomness gives another signature, as valid
    let other = ours.sign_schnorr_with(&parse_path(p).unwrap(), &digest, Tweak::Taproot, &[9u8; 32]).unwrap();
    assert_ne!(other, ours.sign_schnorr(&parse_path(p).unwrap(), &digest, Tweak::Taproot).unwrap());
    secp.verify_schnorr(&schnorr::Signature::from_slice(&other).unwrap(), &msg, &output).unwrap();
}

#[test]
fn paths_round_trip() {
    for p in PATHS {
        assert_eq!(format_path(&parse_path(p).unwrap()), p);
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
