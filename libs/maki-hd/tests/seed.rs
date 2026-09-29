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

#[test]
fn monero_as_ledger_and_every_wallet_has_it() {
    use maki_hd::{op, seed::answer, Error};
    use maki_xmr::{address, Kind, Network};
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    let path = parse_path("m/44'/128'/0'/0/0").unwrap();
    let ask = |which: u8, digest: &[u8]| answer(&ours, which, &path, digest, &[0; 32]);
    // Ledger's Monero app's public keys for this phrase, and the address every wallet makes
    let public = ask(op::MONERO_PUBLIC, &[]).unwrap();
    let hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "dae41d6b13568fdd71ec3d20c2f614c65fe819f36ca5da8d24df3bd89b2bad9d865cbfab852a1d1ccdfc7328e4dac90f78fc2154257d07522e9b79e637326dfa"
    );
    let (spend, view): ([u8; 32], [u8; 32]) = (public[..32].try_into().unwrap(), public[32..].try_into().unwrap());
    assert_eq!(
        address(Network::Mainnet, Kind::Standard, &spend, &view),
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn"
    );
    // subaddress 1 of account 0: its account and index in the digest
    let sub = ask(op::MONERO_SUBADDRESS, &[0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
    assert_eq!(
        address(Network::Mainnet, Kind::Subaddress, &sub[..32].try_into().unwrap(), &sub[32..].try_into().unwrap()),
        "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ"
    );
    assert_eq!(ask(op::MONERO_SUBADDRESS, &[0; 4]).err(), Some(Error::Failed));
    // the words Monero wallets restore it from
    assert_eq!(
        String::from_utf8(ask(op::MONERO_WORDS, &[]).unwrap()).unwrap(),
        "tavern judge beyond bifocals deepest mural onward dummy eagle diode gained vacation rally cause firm idled \
         jerseys moat vigilant upload bobsled jobs cunning doing jobs"
    );
    // the view key: the one every wallet makes from the spend key
    let view_key: String = ask(op::MONERO_VIEW_KEY, &[]).unwrap().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(view_key, "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201");
    // an output of the account's: its key image and proof; one that isn't, none
    use maki_xmr::sign::{self, Scalar, G};
    let r = Scalar::from_bytes_mod_order([3; 32]);
    let out = sign::pay(&r, &sign::point(&view).unwrap(), &sign::point(&spend).unwrap(), 4, 1000);
    let output = [&(G * r).compress().to_bytes()[..], &4u64.to_le_bytes(), &[0; 8], &out.key].concat();
    let image = ask(op::MONERO_KEY_IMAGE, &output).unwrap();
    assert_eq!(image.len(), 96);
    let mut theirs = output.clone();
    theirs[40] = 1;
    assert_eq!(ask(op::MONERO_KEY_IMAGE, &theirs).err(), Some(Error::Key));
    assert_eq!(ask(op::MONERO_KEY_IMAGE, &output[..79]).err(), Some(Error::Failed));
    // a transaction: signed, or why not
    let to = "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ";
    let ring: Vec<maki_xmr::request::Member> = (0..16u64)
        .map(|i| maki_xmr::request::Member {
            global: 10 + i,
            key: if i == 3 { out.key } else { (G * Scalar::from(i + 7)).compress().to_bytes() },
            commitment: if i == 3 { out.commitment } else { sign::commit(&Scalar::from(i), i).compress().to_bytes() },
        })
        .collect();
    let request = maki_xmr::request::Request {
        network: Network::Mainnet,
        account: 0,
        fee: 100,
        change: 0,
        payments: vec![maki_xmr::request::Payment { address: to.into(), amount: 900, destination: maki_xmr::request::read_destination(to).unwrap().1 }],
        inputs: vec![maki_xmr::request::Input { amount: 1000, tx_key: output[..32].try_into().unwrap(), index: 4, subaddress: 0, real: 3, ring }],
    };
    let signed = ask(op::MONERO_SIGN, &request.to_bytes()).unwrap();
    assert_eq!(signed[0], 0);
    assert!(maki_xmr::spend::Signed::from_bytes(&signed[1..]).is_some());
    let mut lie = request.clone();
    lie.fee = 101;
    lie.inputs[0].amount = 1001;
    assert_eq!(ask(op::MONERO_SIGN, &lie.to_bytes()).unwrap(), [&[1u8][..], b"input 1's amount isn't what the chain has"].concat());
    assert_eq!(ask(op::MONERO_SIGN, &[1, 2, 3]).unwrap(), [&[1u8][..], b"not a request maki can read"].concat());
    // on Monero's coin type alone: no other coin's key becomes a Monero wallet
    for other in ["m/44'/60'/0'/0/0", "m/84'/0'/0'/0/0", "m/44'", "m"] {
        let p = parse_path(other).unwrap();
        for which in [op::MONERO_PUBLIC, op::MONERO_WORDS, op::MONERO_VIEW_KEY] {
            assert_eq!(answer(&ours, which, &p, &[], &[0; 32]).err(), Some(Error::Path), "{other}");
        }
    }
}
