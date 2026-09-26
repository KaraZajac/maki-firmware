use maki_seed::*;

fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

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
        let (entropy, phrase, seed_hex) = (case[0].as_str().unwrap(), case[1].as_str().unwrap(), case[2].as_str().unwrap());
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
    let words: Vec<&str> = "legal winner thank year wave sausage worth useful legal winner thank yellow".split(' ').collect();
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
    let words: Vec<&str> = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split(' ').collect();
    let a = backup_key(&seed(&words, ""));
    assert_eq!(a, backup_key(&seed(&words, "")));
    assert_ne!(a, backup_key(&seed(&words, "other")));
}
