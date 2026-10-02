//! Cardano's keys (BIP32-Ed25519 from the phrase's entropy, Icarus) against EMURGO's
//! cardano-serialization-lib, which Yoroi, Eternl and most of Cardano's wallets build on
//! (`fixtures/make-cardano.cjs`): the CIP-1852 account's public key and chain code, the first
//! payment, change and stake keys, a deeper path, and signatures byte for byte, for the BIP39 test
//! phrase and a phrase of twenty-four words, as maki makes them. And the account's public key and
//! chain code giving the keys below it, as a wallet on a computer works out addresses.

use curve25519_dalek::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use hmac::{Hmac, Mac};
use maki_hd::seed::{SeedKeys, answer};
use maki_hd::{Error, HARDENED, op, parse_path};
use sha2::Sha512;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn vectors() -> Vec<serde_json::Value> {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cardano.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn keys_for(v: &serde_json::Value) -> SeedKeys {
    let words: Vec<&str> = v["phrase"].as_str().unwrap().split(' ').collect();
    let mut keys = SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap();
    let entropy = maki_seed::to_entropy(&words).unwrap();
    assert_eq!(entropy, unhex(v["entropy"].as_str().unwrap()));
    keys.with_cardano(&entropy);
    keys
}

fn path(p: &str) -> Vec<u32> { parse_path(p).unwrap() }

#[test]
fn keys_are_cardano_serialization_libs() {
    for v in vectors() {
        let keys = keys_for(&v);
        let account = keys.cardano_public(&path("m/1852'/1815'/0'")).unwrap();
        assert_eq!(account.to_vec(), unhex(v["account"].as_str().unwrap()), "{}", v["phrase"]);
        for (p, want) in [
            ("m/1852'/1815'/0'/0/0", "payment0"),
            ("m/1852'/1815'/0'/1/0", "change0"),
            ("m/1852'/1815'/0'/2/0", "stake0"),
            ("m/1852'/1815'/7'/0/3", "deep"),
        ] {
            assert_eq!(
                keys.cardano_public(&path(p)).unwrap()[..32],
                unhex(v[want].as_str().unwrap())[..],
                "{p}"
            );
        }
        let message = unhex(v["message"].as_str().unwrap());
        assert_eq!(
            keys.sign_cardano(&path("m/1852'/1815'/0'/0/0"), &message).unwrap().to_vec(),
            unhex(v["signature"].as_str().unwrap())
        );
        assert_eq!(
            keys.sign_cardano(&path("m/1852'/1815'/0'/2/0"), &message).unwrap().to_vec(),
            unhex(v["stakeSignature"].as_str().unwrap())
        );
        // and as maki-keys answers an app host
        let a = answer(&keys, op::CARDANO_PUBLIC, &path("m/1852'/1815'/0'"), &[], &[0; 32]).unwrap();
        assert_eq!(a, account.to_vec());
        let s = answer(&keys, op::CARDANO_SIGN, &path("m/1852'/1815'/0'/0/0"), &message, &[0; 32]).unwrap();
        assert_eq!(s, unhex(v["signature"].as_str().unwrap()));
    }
}

/// A key's child, worked out from its public key and chain code alone (BIP32-Ed25519, V2): the
/// point gains eight times the first 28 bytes of an HMAC times the base point.
fn public_child(parent: &[u8; 64], index: u32) -> [u8; 64] {
    assert!(index < HARDENED);
    let hmac = |tag: u8| -> [u8; 64] {
        let mut mac = Hmac::<Sha512>::new_from_slice(&parent[32..]).unwrap();
        mac.update(&[tag]);
        mac.update(&parent[..32]);
        mac.update(&index.to_le_bytes());
        mac.finalize().into_bytes().into()
    };
    let (z, i) = (hmac(0x02), hmac(0x03));
    let mut eight_zl = [0u8; 32];
    let mut carry = 0u16;
    for n in 0..32 {
        let v = if n < 28 { (z[n] as u16) << 3 } else { 0 } + carry;
        eight_zl[n] = v as u8;
        carry = v >> 8;
    }
    let a = CompressedEdwardsY(parent[..32].try_into().unwrap()).decompress().unwrap();
    let child = a + EdwardsPoint::mul_base(&curve25519_dalek::Scalar::from_bytes_mod_order(eight_zl));
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&child.compress().to_bytes());
    out[32..].copy_from_slice(&i[32..]);
    out
}

#[test]
fn an_accounts_public_key_gives_its_addresses_keys() {
    for v in vectors() {
        let keys = keys_for(&v);
        let account = keys.cardano_public(&path("m/1852'/1815'/0'")).unwrap();
        for (role, index) in [(0, 0), (0, 9), (1, 0), (2, 0)] {
            let derived = public_child(&public_child(&account, role), index);
            let private = keys.cardano_public(&path(&format!("m/1852'/1815'/0'/{role}/{index}"))).unwrap();
            assert_eq!(derived, private, "{role}/{index}");
        }
    }
}

#[test]
fn cardanos_keys_are_cardanos_alone_and_only_once_made() {
    let v = &vectors()[0];
    let words: Vec<&str> = v["phrase"].as_str().unwrap().split(' ').collect();
    let keys = SeedKeys::from_seed(&maki_seed::seed(&words, "")).unwrap();
    // before the entropy's been given: nothing to answer with
    assert!(!keys.has_cardano());
    assert_eq!(keys.cardano_public(&path("m/1852'/1815'/0'")), Err(Error::Locked));
    let keys = keys_for(v);
    for p in ["m/44'/1815'/0'", "m/1852'/1815'", "m/1852'/1'/0'", "m/1852'/1815'/0", "m/84'/0'/0'/0/0"] {
        assert_eq!(keys.cardano_public(&path(p)), Err(Error::Path), "{p}");
    }
}

/// A passphrase wallet's Cardano keys: Icarus takes the BIP39 passphrase as PBKDF2's password, as
/// cardano-serialization-lib 17.0.0's `Bip32PrivateKey.from_bip39_entropy(entropy, passphrase)`
/// makes them (and Trezor): the test phrase's first account, with none, "TREZOR" (BIP39's own
/// vectors' passphrase) and another.
#[test]
fn a_passphrase_wallets_keys_are_cardano_serialization_libs_too() {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let entropy = maki_seed::to_entropy(&words).unwrap();
    for (passphrase, account) in [
        (
            "",
            "beb7e770b3d0f1932b0a2f3a63285bf9ef7d3e461d55446d6a3911d8f0ee55c0b0e2df16538508046649d0e6d5b32969555a23f2f1ebf2db2819359b0d88bd16",
        ),
        (
            "TREZOR",
            "5bb6c3570740996de8a87a5146fa5f4679f0af1c7175328af754df625b346f5886a4f832d326a6fe09b6bf608c9b208d1479ff23ae30e5215ccd6de102e232cb",
        ),
        (
            "maki passphrase",
            "c7db220a489a06bbc24d9e1d6550761c150513bac5b5f97d2f7dfc89356656a7f7b362346939521d0840d5d5d1c8e4bd59fe1f7b76564565d7134cb231737a20",
        ),
    ] {
        let mut keys = SeedKeys::from_seed(&maki_seed::seed(&words, passphrase)).unwrap();
        keys.with_cardano_passphrase(&entropy, passphrase.as_bytes());
        let got = keys.cardano_public(&path("m/1852'/1815'/0'")).unwrap();
        assert_eq!(got.to_vec(), unhex(account), "{passphrase:?}");
    }
}
