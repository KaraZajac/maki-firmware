use maki_seed::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn the_word_list_is_the_bips() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(include_bytes!("../src/english.txt"));
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
    assert_eq!(wordlist().count(), 2048);
    assert_eq!((word(0), word(2047)), (Some("abandon"), Some("zoo")));
}

#[test]
fn every_trezor_vector_round_trips_and_seeds() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    for case in v["english"].as_array().unwrap() {
        let (entropy, phrase, seed_hex) =
            (case[0].as_str().unwrap(), case[1].as_str().unwrap(), case[2].as_str().unwrap());
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(to_words(&hex(entropy)), words, "{entropy}");
        assert_eq!(to_entropy(&words).unwrap(), hex(entropy), "{phrase}");
        assert_eq!(seed(&words, "TREZOR").to_vec(), hex(seed_hex), "{phrase}");
    }
}

#[test]
fn a_wrong_or_swapped_word_is_usually_caught() {
    // The checksum is a word count / 3 bits long: a 12-word phrase's 4 bits miss 1 change in 16,
    // a 24-word phrase's 8 bits miss 1 in 256. (Swapping words 0 and 2 of this one is a miss.)
    let words: Vec<&str> =
        "legal winner thank year wave sausage worth useful legal winner thank yellow".split(' ').collect();
    assert!(to_entropy(&words).is_ok());
    let mut swapped = words.clone();
    swapped.swap(0, 1);
    assert_eq!(to_entropy(&swapped), Err(Error::Checksum));
    let caught = (0..2048)
        .filter(|&i| {
            let mut changed = words.clone();
            changed[5] = word(i).unwrap();
            changed[5] != words[5] && to_entropy(&changed) == Err(Error::Checksum)
        })
        .count();
    assert!(caught > 2047 * 14 / 16, "{caught} of 2047 changes caught");
    let mut unknown = words.clone();
    unknown[3] = "yearn";
    assert_eq!(to_entropy(&unknown), Err(Error::UnknownWord(3)));
    assert_eq!(to_entropy(&words[..11]), Err(Error::Length));
}

#[test]
fn four_letters_fix_every_word() {
    for w in wordlist() {
        let prefix = &w[..w.len().min(4)];
        assert_eq!(starting_with(prefix).filter(|x| x.len() >= 4 || *x == w).count().min(1), 1);
        assert_eq!(starting_with(prefix).filter(|x| x[..x.len().min(4)] == *prefix).count(), 1, "{w}");
    }
}

#[test]
fn the_backup_key_depends_only_on_the_seed() {
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let a = backup_key(&seed(&words, ""));
    assert_eq!(a, backup_key(&seed(&words, "")));
    assert_ne!(a, backup_key(&seed(&words, "other")));
}

#[test]
fn fido_keys_are_hkdf_of_the_seed() {
    // computed apart from this crate: RFC 5869 HKDF-SHA256 (salt "maki", info "fido v1") written
    // out in Python over the test phrase's BIP39 seed
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let k = fido_keys(&seed(&words, ""));
    let all: Vec<u8> = [&k.encryption[..], &k.authentication[..], &k.cred_random[..]].concat();
    assert_eq!(
        all,
        hex(
            "44c97ef1beb4a0dcb3988aa0d3634b2a58147e72ce1b4b92784c45b0b2c3298338711e230b49d3b84a3209f265c4ae43d4e6ca89ff730166ade90873855833b3d5ddb9ac507b40fafe35d9b4a6413b9f6b2c2d0e326ba4e5cc16c60633e7219378f41d01bd7158b3ead57d53394186c4c73a95e79dfd07d3f8c6c82df8f437b4"
        )
    );
    // nothing shared with the backup's key
    let b = backup_key(&seed(&words, ""));
    assert!(all.windows(32).all(|w| w != b));
}

#[test]
fn app_secrets_are_hkdf_of_the_seed_for_each_app_developer_and_label() {
    // computed apart from this crate: RFC 5869 HKDF-SHA256 (salt "maki", info "app v1", the ID
    // and the label each after its length) written out in Python over the test phrase's seed
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split(' ')
            .collect();
    let s = seed(&words, "");
    let dev = [0x11u8; 32];
    let app = |id: &str, dev: &[u8; 32], label: &str| app_secret(&s, id, dev, label).unwrap().to_vec();
    assert_eq!(
        app("com.example.ssh", &dev, "ssh"),
        hex("dece6d0a8e7730741701528e79f1adce0b7f90402aff947c8b38797bc36554c9")
    );
    assert_eq!(
        app("com.example.ssh", &dev, "ssh 2"),
        hex("cf40e19734dafaae00a8282457b74b75a322f5fc104aaf08728a7599f1997c4c")
    );
    assert_eq!(
        app("com.example.ssh", &[0x22; 32], "ssh"),
        hex("7990b5e4643b6154d487d8798fcf8d3903d3ff8ca81f4fe783823265aa8f24d3")
    );
    assert_eq!(
        app("com.example.ssh", &dev, ""),
        hex("979d716e471d2ee39c13b6184e70359b7566cfb8d2b9535f00795ad881efa0cf")
    );
    // the lengths keep one app's ID and label from running into another's
    assert_ne!(app("com.example.ss", &dev, "hssh"), app("com.example.ssh", &dev, "ssh"));
    // nothing shared with maki's own keys
    assert_ne!(app("com.example.ssh", &dev, "ssh"), backup_key(&s).to_vec());
    assert!(app_secret(&s, &"x".repeat(256), &dev, "ssh").is_none());
    assert!(app_secret(&s, "com.example.ssh", &dev, &"x".repeat(256)).is_none());
}
