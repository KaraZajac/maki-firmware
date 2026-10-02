//! maki-hd's keys against rust-bitcoin's (BIP32, BIP86 and libsecp256k1's signatures), on the
//! BIP39 test phrase, and the addresses every wallet agrees it makes.

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1::{Message, Secp256k1, schnorr};
use bitcoin::{Address, CompressedPublicKey, KnownHrp, NetworkKind};
use maki_hd::seed::SeedKeys;
use maki_hd::{Keys, Tweak, format_path, parse_path};
use sha3::{Digest, Keccak256};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn seed() -> [u8; 64] { maki_seed::seed(&PHRASE.split(' ').collect::<Vec<_>>(), "") }

fn theirs(path: &str) -> Xpriv {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(NetworkKind::Main, &seed()).unwrap();
    master.derive_priv(&secp, &path.parse::<DerivationPath>().unwrap()).unwrap()
}

const PATHS: [&str; 6] =
    ["m", "m/84'/0'/0'", "m/84'/0'/0'/0/0", "m/86'/1'/0'/1/5", "m/44'/60'/0'/0/0", "m/0'/1/2'/2/1000000000"];

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
        assert_eq!(
            ours.uncompressed(&parse_path(p).unwrap()).unwrap(),
            xpub.public_key.serialize_uncompressed(),
            "{p}"
        );
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
    let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
        bitcoin::XOnlyPublicKey::from_slice(&output).unwrap(),
    );
    assert_eq!(
        Address::p2tr_tweaked(tweaked, KnownHrp::Mainnet).to_string(),
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    );
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
        assert_eq!(
            ours.taproot_output(&parse_path(p).unwrap()).unwrap(),
            tweaked.to_x_only_public_key().serialize(),
            "{p}"
        );
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
    let output =
        bitcoin::XOnlyPublicKey::from_slice(&ours.taproot_output(&parse_path(p).unwrap()).unwrap()).unwrap();
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
    use maki_hd::{Error, op, seed::answer};
    use maki_xmr::{Kind, Network, address};
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
    let (spend, view): ([u8; 32], [u8; 32]) =
        (public[..32].try_into().unwrap(), public[32..].try_into().unwrap());
    assert_eq!(
        address(Network::Mainnet, Kind::Standard, &spend, &view),
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn"
    );
    // subaddress 1 of account 0: its account and index in the digest
    let sub = ask(op::MONERO_SUBADDRESS, &[0, 0, 0, 0, 1, 0, 0, 0]).unwrap();
    assert_eq!(
        address(
            Network::Mainnet,
            Kind::Subaddress,
            &sub[..32].try_into().unwrap(),
            &sub[32..].try_into().unwrap()
        ),
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
    let view_key: String =
        ask(op::MONERO_VIEW_KEY, &[]).unwrap().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(view_key, "0f3fe25d0c6d4c94dde0c0bcc214b233e9c72927f813728b0f01f28f9d5e1201");
    // an output of the account's: its key image and proof; one that isn't, none
    use maki_xmr::sign::{self, G, Scalar};
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
    let to =
        "8AB7PQPtducdkghYFN2prK3rZ7zPeL9f2REEdqE4WXYbSZr3797Aqti5xAjRsVy4jTdcwMW11GWejQtqk2kNXxj2QZxJwPZ";
    let ring: Vec<maki_xmr::request::Member> = (0..16u64)
        .map(|i| maki_xmr::request::Member {
            global: 10 + i,
            key: if i == 3 { out.key } else { (G * Scalar::from(i + 7)).compress().to_bytes() },
            commitment: if i == 3 {
                out.commitment
            } else {
                sign::commit(&Scalar::from(i), i).compress().to_bytes()
            },
        })
        .collect();
    let request = maki_xmr::request::Request {
        network: Network::Mainnet,
        account: 0,
        fee: 100,
        change: 0,
        payments: vec![maki_xmr::request::Payment {
            address: to.into(),
            amount: 900,
            destination: maki_xmr::request::read_destination(to).unwrap().1,
        }],
        inputs: vec![maki_xmr::request::Input {
            amount: 1000,
            tx_key: output[..32].try_into().unwrap(),
            index: 4,
            subaddress: 0,
            real: 3,
            ring,
        }],
    };
    let signed = ask(op::MONERO_SIGN, &request.to_bytes()).unwrap();
    assert_eq!(signed[0], 0);
    assert!(maki_xmr::spend::Signed::from_bytes(&signed[1..]).is_some());
    let mut lie = request.clone();
    lie.fee = 101;
    lie.inputs[0].amount = 1001;
    assert_eq!(
        ask(op::MONERO_SIGN, &lie.to_bytes()).unwrap(),
        [&[1u8][..], b"input 1's amount isn't what the chain has"].concat()
    );
    assert_eq!(
        ask(op::MONERO_SIGN, &[1, 2, 3]).unwrap(),
        [&[1u8][..], b"not a request maki can read"].concat()
    );
    // on Monero's coin type alone: no other coin's key becomes a Monero wallet
    for other in ["m/44'/60'/0'/0/0", "m/84'/0'/0'/0/0", "m/44'", "m"] {
        let p = parse_path(other).unwrap();
        for which in [op::MONERO_PUBLIC, op::MONERO_WORDS, op::MONERO_VIEW_KEY] {
            assert_eq!(answer(&ours, which, &p, &[], &[0; 32]).err(), Some(Error::Path), "{other}");
        }
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn ed25519_as_slip10_has_it() {
    use maki_hd::{Error, op, seed::answer};
    // SLIP-0010's test vectors for ed25519: each chain's public key (without SLIP-10's 00 before it)
    let vectors: [(&str, &[(&str, &str)]); 2] = [
        (
            "000102030405060708090a0b0c0d0e0f",
            &[
                ("m", "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                ("m/0'", "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
                ("m/0'/1'", "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
                ("m/0'/1'/2'", "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"),
                ("m/0'/1'/2'/2'", "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"),
                (
                    "m/0'/1'/2'/2'/1000000000'",
                    "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
                ),
            ],
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            &[
                ("m", "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"),
                ("m/0'", "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"),
                ("m/0'/2147483647'", "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d"),
                ("m/0'/2147483647'/1'", "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45"),
                (
                    "m/0'/2147483647'/1'/2147483646'",
                    "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
                ),
                (
                    "m/0'/2147483647'/1'/2147483646'/2'",
                    "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
                ),
            ],
        ),
    ];
    for (seed, chains) in vectors {
        let keys = SeedKeys::from_seed(&unhex(seed)).unwrap();
        for (path, public) in chains {
            assert_eq!(
                hex(&answer(&keys, op::ED25519_PUBLIC, &parse_path(path).unwrap(), &[], &[0; 32]).unwrap()),
                *public,
                "{path}"
            );
        }
    }
    // Solana's account 0 on the BIP39 test phrase, as Phantom and Solflare have it
    // (HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk), and what it signs, as Node's Ed25519 does
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    let account = parse_path("m/44'/501'/0'/0'").unwrap();
    assert_eq!(
        hex(&answer(&ours, op::ED25519_PUBLIC, &account, &[], &[0; 32]).unwrap()),
        "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7"
    );
    assert_eq!(
        hex(&answer(&ours, op::ED25519_SIGN, &account, b"maki signs this for Solana", &[0; 32]).unwrap()),
        "d225d29f65ea59711c459af79bcd109e511c5fa1d16ce35221280c50a305e7d586212248f3331da27126e75e4250e874d7628eb2d3dc8322af7fc6da20149000"
    );
    // a message of any length, whole: none at all, or 16 KiB
    for message in [&[][..], &[7u8; 16 * 1024][..]] {
        assert_eq!(answer(&ours, op::ED25519_SIGN, &account, message, &[0; 32]).unwrap().len(), 64);
    }
    // SLIP-10 has no unhardened Ed25519 keys
    for p in ["m/44'/501'/0'/0", "m/44'/501'/0/0'"] {
        assert_eq!(
            answer(&ours, op::ED25519_PUBLIC, &parse_path(p).unwrap(), &[], &[0; 32]).err(),
            Some(Error::Path),
            "{p}"
        );
    }
}

/// BIP-85's test vectors (bitcoin/bips, bip-0085.mediawiki), from its master key: the key each
/// path derives, the entropy BIP-85 makes of it, and for BIP39, the words.
#[test]
fn bip85_child_seeds_as_the_bip_has_them() {
    use std::str::FromStr;
    let secp = Secp256k1::new();
    let master = Xpriv::from_str(
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
    )
    .unwrap();
    let k = |path: &str| -> [u8; 32] {
        master
            .derive_priv(&secp, &path.parse::<DerivationPath>().unwrap())
            .unwrap()
            .private_key
            .secret_bytes()
    };
    for (path, key, entropy) in [
        (
            "m/83696968'/0'/0'",
            "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
            "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
        ),
        (
            "m/83696968'/0'/1'",
            "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
            "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
        ),
    ] {
        assert_eq!(hex(&k(path)), key, "{path}");
        assert_eq!(hex(&maki_hd::seed::bip85_entropy(&k(path))), entropy, "{path}");
    }
    for (words, entropy, phrase) in [
        (
            12,
            "6250b68daf746d12a24d58b4787a714b",
            "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
        ),
        (
            18,
            "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc",
            "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token",
        ),
        (
            24,
            "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
            "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano",
        ),
    ] {
        let path = format!("m/83696968'/39'/0'/{words}'/0'");
        let made = maki_hd::seed::bip85_entropy(&k(&path));
        let n = entropy.len() / 2;
        assert_eq!(hex(&made[..n]), entropy, "{path}");
        assert_eq!(maki_seed::to_words(&made[..n]).join(" "), phrase, "{path}");
        assert_eq!(maki_hd::child_seed(&parse_path(&path).unwrap()), Some((words, 0)));
    }
}

#[test]
fn bip85_child_seeds_from_the_phrase_and_nowhere_else() {
    use maki_hd::{op, seed::answer};
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    // the phrase's own child seeds, as the BIP's steps make them from rust-bitcoin's keys
    for (words, index) in [(12, 0), (18, 1), (24, 7), (12, 2_147_483_647)] {
        let path = format!("m/83696968'/39'/0'/{words}'/{index}'");
        let k = theirs(&path).private_key.secret_bytes();
        let entropy = maki_hd::seed::bip85_entropy(&k);
        let phrase = maki_seed::to_words(&entropy[..words as usize * 4 / 3]).join(" ");
        let p = parse_path(&path).unwrap();
        assert_eq!(maki_hd::words_op(&p), op::BIP85_WORDS);
        let made = String::from_utf8(answer(&ours, op::BIP85_WORDS, &p, &[], &[0; 32]).unwrap()).unwrap();
        assert_eq!(made, phrase, "{path}");
        assert_eq!(made.split(' ').count(), words as usize);
        // a real phrase: its checksum holds
        assert!(maki_seed::to_entropy(&made.split(' ').collect::<Vec<_>>()).is_ok());
    }
    // every other path is refused: another language or app, a length BIP39 hasn't, a step not
    // hardened, too short or too long; and a Monero account's words aren't a child seed's
    for path in [
        "m/83696968'/39'/1'/12'/0'",
        "m/83696968'/2'/0'/12'/0'",
        "m/83696968'/39'/0'/15'/0'",
        "m/83696968'/39'/0'/12'/0",
        "m/83696968'/39'/0'/12",
        "m/83696968'/39'/0'/12'/0'/0'",
        "m/83696968'/39/0'/12'/0'",
        "m/84'/39'/0'/12'/0'",
        "m/44'/128'/0'/0/0",
    ] {
        let p = parse_path(path).unwrap();
        assert_eq!(maki_hd::child_seed(&p), None, "{path}");
        assert!(answer(&ours, op::BIP85_WORDS, &p, &[], &[0; 32]).is_err(), "{path}");
    }
    assert_eq!(maki_hd::words_op(&parse_path("m/44'/128'/0'/0/0").unwrap()), op::MONERO_WORDS);
    assert_eq!(maki_hd::coin(&parse_path("m/83696968'/39'/0'").unwrap()), Some("child seeds"));
}

/// BIP-85's password vectors (bitcoin/bips, bip-0085.mediawiki): base64 (707764') and base85
/// (707785') from its master key, the entropy and the password each path makes.
#[test]
fn bip85_passwords_as_the_bip_has_them() {
    use std::str::FromStr;

    use maki_hd::{Bip85Password, bip85_password, seed::bip85_password_text};
    let secp = Secp256k1::new();
    let master = Xpriv::from_str(
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
    )
    .unwrap();
    for (path, entropy, password, kind) in [
        (
            "m/83696968'/707764'/21'/0'",
            "74a2e87a9ba0cdd549bdd2f9ea880d554c6c355b08ed25088cfa88f3f1c4f74632b652fd4a8f5fda43074c6f6964a3753b08bb5210c8f5e75c07a4c2a20bf6e9",
            "dKLoepugzdVJvdL56ogNV",
            Bip85Password::Base64,
        ),
        (
            "m/83696968'/707785'/12'/0'",
            "f7cfe56f63dca2490f65fcbf9ee63dcd85d18f751b6b5e1c1b8733af6459c904a75e82b4a22efff9b9e69de2144b293aa8714319a054b6cb55826a8e51425209",
            "_s`{TW89)i4`",
            Bip85Password::Base85,
        ),
    ] {
        let k = master
            .derive_priv(&secp, &path.parse::<DerivationPath>().unwrap())
            .unwrap()
            .private_key
            .secret_bytes();
        let made = maki_hd::seed::bip85_entropy(&k);
        assert_eq!(hex(&made), entropy, "{path}");
        let (kind_read, len, index) = bip85_password(&parse_path(path).unwrap()).unwrap();
        assert_eq!((kind_read, index), (kind, 0));
        assert_eq!(bip85_password_text(kind, &made, len as usize), password, "{path}");
    }
}

#[test]
fn bip85_passwords_from_the_phrase_and_nowhere_else() {
    use maki_hd::{Bip85Password, op, seed::answer, seed::bip85_password_text};
    let ours = SeedKeys::from_seed(&seed()).unwrap();
    for (path, kind, len) in [
        ("m/83696968'/707764'/20'/0'", Bip85Password::Base64, 20),
        ("m/83696968'/707764'/86'/3'", Bip85Password::Base64, 86),
        ("m/83696968'/707785'/10'/0'", Bip85Password::Base85, 10),
        ("m/83696968'/707785'/80'/2147483647'", Bip85Password::Base85, 80),
    ] {
        let k = theirs(path).private_key.secret_bytes();
        let want = bip85_password_text(kind, &maki_hd::seed::bip85_entropy(&k), len);
        let made = String::from_utf8(
            answer(&ours, op::BIP85_PASSWORD, &parse_path(path).unwrap(), &[], &[0; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(made, want, "{path}");
        assert_eq!(made.len(), len, "{path}");
        // printable ASCII only; base64's never reaches its padding ('=' is one of base85's digits)
        assert!(made.bytes().all(|b| (0x21..0x7f).contains(&b)), "{path}: {made}");
        assert!(kind == Bip85Password::Base85 || !made.contains('='), "{path}: {made}");
    }
    // every other path is refused: too short or long for its encoding, another application, a
    // step not hardened, a level missing
    for path in [
        "m/83696968'/707764'/19'/0'",
        "m/83696968'/707764'/87'/0'",
        "m/83696968'/707785'/9'/0'",
        "m/83696968'/707785'/81'/0'",
        "m/83696968'/707765'/20'/0'",
        "m/83696968'/707764'/20'/0",
        "m/83696968'/707764'/20'",
        "m/83696968'/39'/0'/12'/0'",
    ] {
        let p = parse_path(path).unwrap();
        assert_eq!(maki_hd::bip85_password(&p), None, "{path}");
        assert!(answer(&ours, op::BIP85_PASSWORD, &p, &[], &[0; 32]).is_err(), "{path}");
    }
    // and the install screen names them
    assert_eq!(maki_hd::coin(&parse_path("m/83696968'/707785'").unwrap()), Some("passwords"));
    assert_eq!(maki_hd::coin(&parse_path("m/83696968'/39'/0'").unwrap()), Some("child seeds"));
}
