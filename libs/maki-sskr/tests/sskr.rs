//! maki-sskr held to Blockchain Commons' own code: the vectors in tests/fixtures/vectors.json,
//! which tests/fixtures/make.rs made with their `sskr`, `bc-shamir`, `bc-rand` and `bc-ur` crates
//! and their seedtool; what their C libraries made (tests/fixtures/make-c.c), from their own
//! test's generator and from seedtool's `--deterministic` one; and the SSKR spec's example. The
//! shares and secrets from Blockchain Commons' documents and tests are theirs, under the license
//! in tests/fixtures/LICENSE-blockchain-commons.

use hkdf::Hkdf;
use maki_sskr::{Error, Share, bytewords, combine, expected_words, split, split_groups, word_count};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vectors.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn strings(v: &Value) -> Vec<&str> { v.as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect() }

fn joined(share: &Share) -> String { share.words().iter().collect::<Vec<_>>().join(" ") }

fn secret_of(shares: &[Share]) -> String { hex(combine(shares).unwrap().as_bytes()) }

/// The sskr crate's tests' generator: 0, 17, 34… from the start each time it's asked.
fn fake(bytes: &mut [u8]) {
    let mut b = 0u8;
    for x in bytes {
        *x = b;
        b = b.wrapping_add(17);
    }
}

/// bc-rand's `SeededRandomNumberGenerator`: Xoshiro256** (rand_xoshiro's, whose state is the
/// seed's four words), a byte from each `next_u64`.
struct Xoshiro([u64; 4]);

impl Xoshiro {
    fn next_u64(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    fn fill(&mut self, bytes: &mut [u8]) {
        for b in bytes {
            *b = self.next_u64() as u8;
        }
    }

    /// make.rs's `case_seed`.
    fn case(i: usize) -> Xoshiro {
        let h = Sha256::digest(format!("maki-sskr seed {i}"));
        Xoshiro(std::array::from_fn(|j| u64::from_le_bytes(h[j * 8..j * 8 + 8].try_into().unwrap())))
    }
}

/// make.rs's `case_secret`.
fn case_secret(i: usize, len: usize) -> Vec<u8> {
    Sha256::digest(format!("maki-sskr secret {i}"))[..len].to_vec()
}

/// A small generator of the tests' own, for picking shares.
struct Pick(u64);

impl Pick {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, self.below(i + 1));
        }
    }
}

/// Shares grouped by their group, in order.
fn by_group(shares: &[Share]) -> Vec<Vec<Share>> {
    let mut groups = vec![vec![]; shares[0].group_count()];
    for s in shares {
        groups[s.group_index()].push(s.clone());
    }
    groups
}

/// Quorums from a split's shares, by group: the first groups' first shares, the last groups' last
/// ones, random ones in a random order, and all of them.
fn quorums(groups: &[Vec<Share>], pick: &mut Pick) -> Vec<Vec<Share>> {
    let need = groups[0][0].group_threshold();
    let take = |gs: &mut dyn Iterator<Item = &Vec<Share>>, last: bool| -> Vec<Share> {
        gs.take(need)
            .flat_map(|g| {
                let k = g[0].member_threshold();
                if last { g[g.len() - k..].to_vec() } else { g[..k].to_vec() }
            })
            .collect()
    };
    let mut random = vec![];
    let mut order: Vec<usize> = (0..groups.len()).collect();
    pick.shuffle(&mut order);
    for &g in &order[..need] {
        let mut members = groups[g].clone();
        pick.shuffle(&mut members);
        random.extend(members.into_iter().take(groups[g][0].member_threshold()));
    }
    pick.shuffle(&mut random);
    vec![
        take(&mut groups.iter(), false),
        take(&mut groups.iter().rev(), true),
        random,
        groups.iter().flatten().cloned().collect(),
    ]
}

#[test]
fn words_are_bc_urs() {
    let v = vectors();
    assert_eq!(strings(&v["words"]), bytewords::WORDS);
    for case in v["bytewords"].as_array().unwrap() {
        let bytes = unhex(case["hex"].as_str().unwrap());
        let crc = bytewords::crc32(&bytes).to_be_bytes();
        let spelled: Vec<u8> = bytes.iter().chain(&crc).copied().collect();
        let words: Vec<&str> = spelled.iter().map(|&b| bytewords::word(b)).collect();
        assert_eq!(words.join(" "), case["standard"].as_str().unwrap());
        assert_eq!(words.join("-"), case["uri"].as_str().unwrap());
        let minimal: String = words.iter().map(|w| format!("{}{}", &w[..1], &w[3..])).collect();
        assert_eq!(minimal, case["minimal"].as_str().unwrap());
        for form in ["standard", "uri", "minimal"] {
            assert_eq!(&bytewords::decode(case[form].as_str().unwrap()).unwrap()[..], &bytes[..], "{form}");
        }
    }
    // BCR-2020-012's example: a seed's CBOR in its standard and minimal forms, and the checksum
    let seed = "tuna next jazz oboe acid good slot axis limp lava brag holy door puff monk brag guru frog \
                luau drop roof grim also safe chef fuel twin solo aqua work bald";
    let cbor = unhex("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
    assert_eq!(&bytewords::decode(seed).unwrap()[..], &cbor[..]);
    assert_eq!(bytewords::crc32(&cbor), 0xc904_f40b);
    let minimal = "tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd";
    assert_eq!(&bytewords::decode(minimal).unwrap()[..], &cbor[..]);
    // and its brutal encoding: the seed alone, with its checksum
    let brutal =
        "slot axis limp lava brag holy door puff monk brag guru frog luau drop roof grim zone plus belt wand";
    assert_eq!(hex(&bytewords::decode(brutal).unwrap()), "c7098580125e2ab0981253468b2dbc52");
    assert_eq!(bytewords::crc32(&unhex("c7098580125e2ab0981253468b2dbc52")), 0xfeac_0dea);
    assert_eq!(&bytewords::decode("staslplabghydrpfmkbggufgludprfgmzepsbtwd").unwrap()[..], &cbor[6..22]);
}

/// The sskr crate's tests (test_split_3_5, test_split_2_7, test_split_2_3_2_3), with their fake
/// generator: the same sizes asked for in the same order, the same shares, in each of the forms
/// seedtool prints, and the same secret back.
#[test]
fn shares_are_sskrs() {
    let v = vectors();
    for case in v["fake"].as_array().unwrap() {
        let secret = unhex(case["secret"].as_str().unwrap());
        let groups: Vec<(usize, usize)> = case["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| (g[0].as_u64().unwrap() as usize, g[1].as_u64().unwrap() as usize))
            .collect();
        let mut asked = vec![];
        let made = split_groups(&secret, case["group_threshold"].as_u64().unwrap() as usize, &groups, |b| {
            asked.push(b.len() as u64);
            fake(b)
        })
        .unwrap();
        let expected: Vec<u64> =
            case["asked"].as_array().unwrap().iter().map(|a| a.as_u64().unwrap()).collect();
        assert_eq!(asked, expected);
        let made: Vec<Share> = made.into_iter().flatten().collect();
        let printed = case["shares"].as_array().unwrap();
        assert_eq!(made.len(), printed.len());
        for (share, forms) in made.iter().zip(printed) {
            assert_eq!(hex(&share.to_bytes()), forms["hex"].as_str().unwrap());
            assert_eq!(joined(share), forms["btw"].as_str().unwrap());
            for form in ["btw", "btwu", "btwm", "ur"] {
                let text = forms[form].as_str().unwrap();
                assert_eq!(Share::parse(text).as_ref(), Ok(share), "{form}");
                assert_eq!(Share::parse(&text.to_ascii_uppercase()).as_ref(), Ok(share), "{form}");
            }
            assert_eq!(Share::from_word_bytes(share.words().bytes()).as_ref(), Ok(share));
            assert_eq!(Share::from_bytes(&share.to_bytes()).as_ref(), Ok(share));
            assert_eq!(Share::from_cbor(&share.to_cbor()).as_ref(), Ok(share));
        }
        let given: Vec<Share> = case["recovered"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| made[i.as_u64().unwrap() as usize].clone())
            .collect();
        assert_eq!(hex(combine(&given).unwrap().as_bytes()), case["secret"].as_str().unwrap());
        assert_eq!(secret_of(&made), case["secret"].as_str().unwrap());
    }
}

#[test]
fn xoshiro_is_bc_rands() {
    // bc-rand 0.5.0's test_next_u64 and the start of test_next_50
    let mut rng =
        Xoshiro([17295166580085024720, 422929670265678780, 5577237070365765850, 7953171132032326923]);
    assert_eq!(rng.next_u64(), 1104683000648959614);
    assert_eq!(rng.next_u64(), 9817345228149227957);
    assert_eq!(rng.next_u64(), 546276821344993881);
}

/// Every one-group k of n up to 16, for 12- and 24-word phrases' entropy, split as `sskr` splits
/// it with bc-rand's seeded generator: the same shares (their SHA-256), and the secret back from
/// several quorums of them, and from all of them.
#[test]
fn every_k_of_n_is_sskrs() {
    let v = vectors();
    let hashes = strings(&v["one_group"]);
    let mut case = 0;
    let mut pick = Pick(0x5eed_55c2);
    for len in [16, 32] {
        for count in 1..=16 {
            for threshold in 1..=count {
                let secret = case_secret(case, len);
                let mut rng = Xoshiro::case(case);
                let shares = split(&secret, threshold, count, |b| rng.fill(b)).unwrap();
                let all: Vec<u8> = shares.iter().flat_map(|s| s.to_bytes().to_vec()).collect();
                assert_eq!(hex(&Sha256::digest(&all)), hashes[case], "case {case}: {threshold} of {count}");
                assert!(shares.iter().all(|s| s.words().len() == word_count(len)));
                for quorum in quorums(std::slice::from_ref(&shares), &mut pick) {
                    assert_eq!(combine(&quorum).unwrap().as_bytes(), &secret[..], "case {case}");
                }
                if threshold > 1 {
                    let mut short = shares[..threshold - 1].to_vec();
                    pick.shuffle(&mut short);
                    assert_eq!(
                        combine(&short).unwrap_err(),
                        Error::TooFew { need: threshold, have: threshold - 1 }
                    );
                }
                case += 1;
            }
        }
    }
}

/// The layouts the sskr crate's fuzz test draws, up to 16 groups of up to 16: the same shares, and
/// the secret back from quorums of them.
#[test]
fn layouts_are_sskrs() {
    let v = vectors();
    let mut pick = Pick(0x1a_7075);
    for case in v["layouts"].as_array().unwrap() {
        let i = case["case"].as_u64().unwrap() as usize;
        let secret = case_secret(i, case["len"].as_u64().unwrap() as usize);
        let groups: Vec<(usize, usize)> = case["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| (g[0].as_u64().unwrap() as usize, g[1].as_u64().unwrap() as usize))
            .collect();
        let group_threshold = case["group_threshold"].as_u64().unwrap() as usize;
        let mut rng = Xoshiro::case(i);
        let made = split_groups(&secret, group_threshold, &groups, |b| rng.fill(b)).unwrap();
        let all: Vec<u8> = made.iter().flatten().flat_map(|s| s.to_bytes().to_vec()).collect();
        assert_eq!(hex(&Sha256::digest(&all)), case["sha256"].as_str().unwrap(), "case {i}");
        for quorum in quorums(&made, &mut pick) {
            assert_eq!(combine(&quorum).unwrap().as_bytes(), &secret[..], "case {i}");
        }
    }
}

/// BCR-2020-011's example, as the spec prints it: eight shares (2 of 3 and 3 of 5, both groups
/// needed) in hex, in ByteWords and as URs.
#[test]
fn the_specs_example() {
    let hexes = [
        "4bbf1101003e990c1f0435e2b33c721535c74603d0",
        "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f",
        "4bbf1101025abd490ee65b6084859854ee67736e75",
        "4bbf11120044ef453f66923d32653b377de5c94b39",
        "4bbf1112016ffb1b0cc5ab485f5a67136c802bc67b",
        "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd",
        "4bbf11120388626f665fc4c0e545e0c2ff0c26368f",
        "4bbf1112046334a0db7838a5c6c4d2dcb2e5b65911",
    ];
    let words = [
        "tuna next keep gyro gear runs body acid able film nail barn cost aqua epic veto quad fern jump buzz epic slot frog apex taxi grim fern twin leaf",
        "tuna next keep gyro gear runs body acid acid barn luau omit navy keep also omit data wave aunt redo toil miss tent redo bias fuel work king kick",
        "tuna next keep gyro gear runs body acid also heat ruby gala beta visa help horn liar limp monk gush waxy into junk jolt keep lion leaf ruby purr",
        "tuna next keep gyro gear runs body brag able foxy webs free fish inky memo figs easy inch fair exam kiwi view solo gear eyes ruin tuna gala iris",
        "tuna next keep gyro gear runs body brag acid jowl zero claw barn silk play fund hope heat into brew jazz lava down skew king sets very whiz crux",
        "tuna next keep gyro gear runs body brag also omit keno each gyro zest zinc race logo kiln roof visa waxy iron sets rock swan leaf tent navy redo",
        "tuna next keep gyro gear runs body brag apex logo iced jowl inky hope sets rust view free vast saga zoom barn days even many yoga wall curl what",
        "tuna next keep gyro gear runs body brag aqua idea edge numb ugly keys exit open skew sets tied undo purr view ramp hawk body skew redo data unit",
    ];
    let urs = [
        "ur:sskr/gogrrsbyadaefmnlbnctaaecvoqdfnjpbzecstfgaxtifpsskbfw",
        "ur:sskr/gogrrsbyadadbnluotnykpaootdaweatrotlmsttrobsghbnurrh",
        "ur:sskr/gogrrsbyadaohtrygabavahphnlrlpmkghwyiojkjtkpmdkncfjp",
        "ur:sskr/gogrrsbybgaefywsfefhiymofseyihfremkivwsogrespmclwepd",
        "ur:sskr/gogrrsbybgadjlzocwbnskpyfdhehtiobwjzladnswkgtscfhfvt",
        "ur:sskr/gogrrsbybgaootkoehgoztzcreloknrfvawyinssrksnmedtfmks",
        "ur:sskr/gogrrsbybgaxloidjliyhessrtvwfevtsazmbndsenmywmbylpdy",
        "ur:sskr/gogrrsbybgaaiaeenbuyksetonswsstduoprvwrphkbytlfzlyca",
    ];
    let mut shares = vec![];
    for ((hex_, words), ur) in hexes.iter().zip(words).zip(urs) {
        let share = Share::from_bytes(&unhex(hex_)).unwrap();
        assert_eq!(joined(&share), words);
        assert_eq!(Share::parse(words).as_ref(), Ok(&share));
        assert_eq!(Share::parse(ur).as_ref(), Ok(&share));
        shares.push(share);
    }
    // the spec's breakdown of the third share: 2 groups needed of 2, group 0, 2 of its shares
    // needed, and it's share 2 (counting from 0)
    let third = &shares[2];
    assert_eq!(third.identifier(), 0x4bbf);
    assert_eq!(third.identifier_words(), ["gear", "runs"]);
    assert_eq!((third.group_threshold(), third.group_count(), third.group_index()), (2, 2, 0));
    assert_eq!((third.member_threshold(), third.member_index()), (2, 2));
    assert_eq!(hex(&third.to_cbor()), "d99d75554bbf1101025abd490ee65b6084859854ee67736e75");
    let mut pick = Pick(0x2020_0011);
    for quorum in quorums(&by_group(&shares), &mut pick) {
        assert_eq!(secret_of(&quorum), "7daa851251002874e1a1995f0897e6b1");
    }
    // one group isn't enough
    assert_eq!(combine(&shares[..3]).unwrap_err(), Error::TooFewGroups { need: 2, have: 1 });
    assert_eq!(combine(&shares[..5]).unwrap_err(), Error::TooFewGroups { need: 2, have: 1 });
    let mut most = shares[..2].to_vec();
    most.extend_from_slice(&shares[3..5]);
    assert_eq!(combine(&most).unwrap_err(), Error::TooFewGroups { need: 2, have: 1 });
}

/// Shares printed in the spec and in seedtool's manuals (Rust's, tagged 40309, and C++'s, tagged
/// 309), and the secret `sskr_combine` got from them: what each document says it is, where it says.
#[test]
fn documented_shares() {
    let v = vectors();
    let mut pick = Pick(0xd0c5);
    for example in v["documented"].as_array().unwrap() {
        let source = example["source"].as_str().unwrap();
        let shares: Vec<Share> = strings(&example["shares"])
            .iter()
            .zip(strings(&example["hex"]))
            .map(|(text, hex_)| {
                let share = if text.bytes().all(|c| c.is_ascii_hexdigit()) {
                    Share::from_bytes(&unhex(text)).unwrap()
                } else {
                    Share::parse(text).unwrap()
                };
                assert_eq!(hex(&share.to_bytes()), hex_, "{source}");
                share
            })
            .collect();
        let secret = example["secret"].as_str().unwrap();
        assert_eq!(secret_of(&shares), secret, "{source}");
        // each prints at least a quorum of each of its groups
        for quorum in quorums(&by_group(&shares), &mut pick) {
            assert_eq!(secret_of(&quorum), secret, "{source}");
        }
    }
}

/// Blockchain Commons' C library, as its own test (test1) calls it: the spec's example secret and
/// layout, split with that test's generator, which starts glibc's rand() over each time it's asked
/// (tests/fixtures/make-c.c printed both). The library takes the identifier's two random bytes as
/// a little-endian u16, and writes it big-endian: the other way round from their Rust library,
/// which maki follows. Given the two bytes swapped, maki makes the same shares.
#[test]
fn c_library() {
    let rand = unhex("50ca0f5e22a6eb4fea30c66c72dc7415a5f9f6d7a7fbef6f4a4c9c2f3a57f08a");
    let c = [
        "ca50110100ce7bf4694251079c3bd86e7497fbb0b2",
        "ca50110101c01670a8bc1d39383814fd0d9820424b",
        "ca50110102d2a1e7f0a5c97bcf3d5b538689564f5b",
        "ca5011120050ca0f5e22a6eb4fea30c66c72dc7415",
        "ca5011120141d59bebdd20f2c12afb27059fa0a631",
        "ca50111202cac978b8bb84ff9e5721935f7ddd1949",
        "ca50111203dbd6ec0d4402e61097ea723690a1cb6d",
        "ca50111204a938eae3e0365b8313546aa37917cbfd",
    ];
    let secret = unhex("7daa851251002874e1a1995f0897e6b1");
    let mut first = true;
    let shares = split_groups(&secret, 2, &[(2, 3), (3, 5)], |bytes| {
        bytes.copy_from_slice(&rand[..bytes.len()]);
        if std::mem::take(&mut first) {
            bytes.swap(0, 1);
        }
    })
    .unwrap();
    let shares: Vec<Share> = shares.into_iter().flatten().collect();
    assert_eq!(shares.iter().map(|s| hex(&s.to_bytes())).collect::<Vec<_>>(), c);
    let mut pick = Pick(0xc11b);
    for quorum in quorums(&by_group(&shares), &mut pick) {
        assert_eq!(hex(combine(&quorum).unwrap().as_bytes()), hex(&secret));
    }
}

/// seedtool's C++ manual makes its 2 of 3 example with `--deterministic FOOBAR`: its generator is
/// HKDF-SHA256 keyed by SHA-256("FOOBAR"), salted with a count of the times it's asked (a u64,
/// little-endian), and their C library splits with it (tests/fixtures/make-c.c made the same
/// shares). Given the identifier's two bytes swapped, as for `c_library`, maki makes them too.
#[test]
fn seedtools_deterministic_example() {
    let secret = unhex("5cd271b50b98a869da1c26a526e1d3a8");
    let documented = [
        "tuna acid epic gyro urge body able acid able exam fern lung visa barn yawn flap open inky drum chef grim paid lion owls vows veto yank curl soap",
        "tuna acid epic gyro urge body able acid acid cost zaps paid hard hard purr time yawn also horn ugly quad leaf film vast part toys lion bulb game",
        "tuna acid epic gyro urge body able acid also into play slot lazy onyx knob knob apex pool purr lion luau zest wave diet item kiwi flap taco many",
    ];
    let seedtool = |swap: bool| {
        let key = Sha256::digest(b"FOOBAR");
        let mut salt = 0u64;
        split(&secret, 2, 3, |bytes| {
            salt += 1;
            Hkdf::<Sha256>::new(Some(&salt.to_le_bytes()), &key).expand(&[], bytes).unwrap();
            if swap && salt == 1 {
                bytes.swap(0, 1);
            }
        })
        .unwrap()
    };
    let shares = seedtool(true);
    for (share, words) in shares.iter().zip(documented) {
        assert_eq!(Share::parse(words).as_ref(), Ok(share));
        // maki writes them with version 2's tag: the same words but the first four, and the
        // checksum's four
        let (ours, theirs): (Vec<&str>, Vec<&str>) =
            (share.words().iter().collect(), words.split(' ').collect());
        assert_eq!(ours[4..25], theirs[4..25]);
        assert_eq!(ours[..4], ["tuna", "next", "keep", "gyro"]);
    }
    assert_eq!(shares[0].identifier_words(), ["urge", "body"]);
    // the Rust library's order: the same shares, but for the identifier
    let rust = seedtool(false);
    assert_eq!(rust[0].identifier_words(), ["body", "urge"]);
    assert!(rust.iter().zip(&shares).all(|(r, c)| r.to_bytes()[2..] == c.to_bytes()[2..]));
    assert_eq!(hex(combine(&shares[1..]).unwrap().as_bytes()), hex(&secret));
}

/// What seedtool 0.4.0 printed, in every form it prints: read, and put back together from quorums
/// and from all of them. Its default form, a Gordian Envelope holding an encrypted seed and a share
/// of its key, isn't SSKR's shares, and maki doesn't read it.
#[test]
fn seedtools_shares() {
    let v = vectors();
    let mut pick = Pick(0x5eed_7001);
    for run in v["seedtool"].as_array().unwrap() {
        let args = strings(&run["args"]).join(" ");
        let secret = run["secret"].as_str().unwrap();
        let printed = strings(&run["shares"]);
        if run["envelope"].as_bool() == Some(true) {
            assert!(printed.iter().all(|s| Share::parse(s) == Err(Error::NotAShare)), "{args}");
            continue;
        }
        let shares: Vec<Share> = printed.iter().map(|s| Share::parse(s).unwrap()).collect();
        assert!(shares.iter().all(|s| s.secret_len() * 2 == secret.len()), "{args}");
        for quorum in quorums(&by_group(&shares), &mut pick) {
            assert_eq!(secret_of(&quorum), secret, "{args}");
        }
        // and one share short of the first quorum isn't enough
        let mut short = quorums(&by_group(&shares), &mut pick).swap_remove(0);
        short.pop();
        match combine(&short) {
            Err(Error::TooFew { .. }) | Err(Error::TooFewGroups { .. }) | Err(Error::NoShares) => {}
            other => panic!("{args}: {other:?}"),
        }
    }
}

/// Shares in the words maki shows, made as maki makes them (`sskr` made the same ones from the
/// same randomness), and what `seedtool -i sskr` 0.4.0 made of them: the secret.
#[test]
fn seedtool_restores_what_maki_writes() {
    let v = vectors();
    for case in v["restored"].as_array().unwrap() {
        let secret = unhex(case["secret"].as_str().unwrap());
        let (k, n) = (case["threshold"].as_u64().unwrap() as usize, case["count"].as_u64().unwrap() as usize);
        let mut rng = Xoshiro::case(case["case"].as_u64().unwrap() as usize);
        let shares = split(&secret, k, n, |b| rng.fill(b)).unwrap();
        let words: Vec<String> = shares.iter().map(joined).collect();
        assert_eq!(words, strings(&case["words"]));
        assert!(strings(&case["seedtool"]).iter().all(|answer| *answer == hex(&secret)));
    }
}

/// maki's own use: a 12-word phrase's entropy and a 24-word phrase's, split 2 of 3.
#[test]
fn phrases_shares() {
    assert_eq!(word_count(16), 29);
    assert_eq!(word_count(32), 46);
    let counts: Vec<usize> = (16..=32).step_by(2).map(word_count).collect();
    assert_eq!(counts, [29, 31, 34, 36, 38, 40, 42, 44, 46]);
    let mut pick = Pick(0x1234);
    for (len, start) in [(16, "tuna next keep gyro"), (32, "tuna next keep hard data")] {
        let secret: Vec<u8> = (0..len as u8).collect();
        let mut rng = Xoshiro::case(5000 + len);
        let shares = split(&secret, 2, 3, |b| rng.fill(b)).unwrap();
        for (i, share) in shares.iter().enumerate() {
            let words = share.words();
            assert_eq!(words.len(), word_count(len));
            assert!(joined(share).starts_with(start));
            // the identifier, then the layout: one group of one, 2 needed, share i
            let after = start.split(' ').count();
            assert_eq!(words.get(after), Some(share.identifier_words()[0]));
            assert_eq!(words.get(after + 2), Some("able"));
            assert_eq!(words.get(after + 3), Some("acid"));
            assert_eq!(words.get(after + 4), Some(bytewords::word(i as u8)));
            assert_eq!(words.get(words.len()), None);
            // how many words, as soon as the first ones say
            for p in 0..=words.len() {
                let expected = if p < after { None } else { Some(word_count(len)) };
                assert_eq!(expected_words(&words.bytes()[..p]), Ok(expected), "{len} bytes, {p} words");
            }
            // whole words, first and last letters, either case, mixed, and lines of them
            let list: Vec<&str> = words.iter().collect();
            assert_eq!(Share::from_words(&list).as_ref(), Ok(share));
            let short: Vec<String> = list.iter().map(|w| format!("{}{}", &w[..1], &w[3..])).collect();
            let short: Vec<&str> = short.iter().map(|s| s.as_str()).collect();
            assert_eq!(Share::from_words(&short).as_ref(), Ok(share));
            let mixed: Vec<String> = list
                .iter()
                .enumerate()
                .map(|(j, w)| match j % 3 {
                    0 => w.to_ascii_uppercase(),
                    1 => format!("{}{}", &w[..1], &w[3..]),
                    _ => w.to_string(),
                })
                .collect();
            assert_eq!(Share::parse(&mixed.join(" ")).as_ref(), Ok(share));
            let lines: Vec<String> = list.chunks(4).map(|c| c.join(" ")).collect();
            assert_eq!(Share::parse(&format!("\n  {}\n", lines.join("\n"))).as_ref(), Ok(share));
        }
        for quorum in quorums(std::slice::from_ref(&shares), &mut pick) {
            assert_eq!(combine(&quorum).unwrap().as_bytes(), &secret[..]);
        }
    }
}

/// A share's words with one word changed are never read as a share, nor with two side by side
/// swapped (CRC-32 catches every error within 32 bits of each other).
#[test]
fn a_wrong_word_is_caught() {
    let mut rng = Xoshiro::case(6000);
    let secret = case_secret(6000, 32);
    let share = split(&secret, 2, 3, |b| rng.fill(b)).unwrap().swap_remove(1);
    let bytes = share.words().bytes().to_vec();
    for i in 0..bytes.len() {
        for b in 0..=255u8 {
            if b != bytes[i] {
                let mut wrong = bytes.clone();
                wrong[i] = b;
                assert_eq!(Share::from_word_bytes(&wrong), Err(Error::Checksum), "word {i} as {b}");
            }
        }
        if i + 1 < bytes.len() && bytes[i] != bytes[i + 1] {
            let mut swapped = bytes.clone();
            swapped.swap(i, i + 1);
            assert_eq!(Share::from_word_bytes(&swapped), Err(Error::Checksum));
        }
    }
}

/// Re-checksummed words: what's inside must be a share, written in the shortest form.
fn with_crc(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&bytewords::crc32(body).to_be_bytes());
    out
}

#[test]
fn refusals_reading() {
    let mut rng = Xoshiro::case(7000);
    let share = split(&case_secret(7000, 16), 2, 3, |b| rng.fill(b)).unwrap().swap_remove(0);
    let words: Vec<&str> = share.words().iter().collect();
    let text = words.join(" ");

    let mut unknown = words.clone();
    unknown[6] = "abba";
    assert_eq!(Share::from_words(&unknown), Err(Error::UnknownWord(6)));
    unknown[6] = "abl";
    assert_eq!(Share::from_words(&unknown), Err(Error::UnknownWord(6)));
    assert_eq!(Share::parse(&text.replace(words[3], "qua")), Err(Error::UnknownWord(3)));
    assert_eq!(Share::from_words(&words[1..]), Err(Error::WordCount(28)));
    let mut longer = words.clone();
    longer.push("able");
    assert_eq!(Share::from_words(&longer), Err(Error::WordCount(30)));
    assert_eq!(Share::from_words(&[]), Err(Error::WordCount(0)));
    assert_eq!(Share::parse(""), Err(Error::WordCount(0)));
    let mut swapped = words.clone();
    let other = (11..words.len()).find(|&j| words[j] != words[10]).unwrap();
    swapped.swap(10, other);
    assert_eq!(Share::from_words(&swapped), Err(Error::Checksum));

    // something else in ByteWords: a seed (BCR-2020-012's example, 31 words like a share of 18
    // bytes), and a share's bytes tagged as a seed
    let seed = "tuna next jazz oboe acid good slot axis limp lava brag holy door puff monk brag guru frog \
                luau drop roof grim also safe chef fuel twin solo aqua work bald";
    assert_eq!(Share::parse(seed), Err(Error::NotAShare));
    let cbor = share.to_cbor();
    let mut retagged = cbor.to_vec();
    retagged[1..3].copy_from_slice(&[0x9d, 0x6c]);
    assert_eq!(Share::from_word_bytes(&with_crc(&retagged)), Err(Error::NotAShare));
    // untagged, or a byte string's length in a longer form than it needs, or cut short, or more
    assert_eq!(Share::from_word_bytes(&with_crc(&[&cbor[3..], &[0, 0, 0]].concat())), Err(Error::NotAShare));
    let long_form = [&cbor[..3], &[0x58, 21], &cbor[4..]].concat();
    assert_eq!(Share::from_cbor(&long_form), Err(Error::NotAShare));
    assert_eq!(Share::from_cbor(&[&cbor[..], &[0, 0]].concat()), Err(Error::Malformed));
    assert_eq!(Share::from_cbor(&cbor[..cbor.len() - 2]), Err(Error::Malformed));
    assert_eq!(Share::from_cbor(&cbor), Ok(share.clone()));

    // fields that can't be
    let bytes = share.to_bytes().to_vec();
    let bent = |at: usize, value: u8| {
        let mut b = bytes.clone();
        b[at] = value;
        b
    };
    assert_eq!(Share::from_bytes(&bent(4, 0x10)), Err(Error::Malformed), "reserved bits");
    assert_eq!(Share::from_bytes(&bent(2, 0x10)), Err(Error::Malformed), "2 groups needed of 1");
    assert_eq!(Share::from_bytes(&bent(3, 0x11)), Err(Error::Malformed), "group 1 of 1");
    assert!(Share::from_bytes(&bent(2, 0x11)).is_ok_and(|s| s.group_count() == 2));
    assert_eq!(Share::from_bytes(&bytes[..20]), Err(Error::Malformed));
    assert_eq!(Share::from_bytes(&[&bytes[..], &[0]].concat()), Err(Error::Malformed), "odd length");
    assert_eq!(Share::from_bytes(&[&bytes[..], &[0; 18]].concat()), Err(Error::Malformed), "34 bytes");
    assert_eq!(Share::from_bytes(&[]), Err(Error::Malformed));
    let mut text_bent = with_crc(&[&cbor[..6], &[0x10], &cbor[7..]].concat());
    assert_eq!(Share::from_word_bytes(&text_bent), Err(Error::Malformed));
    text_bent[0] = 0;
    assert_eq!(Share::from_word_bytes(&text_bent), Err(Error::Checksum));

    // URs: sskr's are untagged, crypto-sskr's may be tagged 309, and a share is one part
    let ur_body: Vec<u8> = cbor[3..].to_vec();
    let minimal = |bytes: &[u8]| -> String {
        with_crc(bytes)
            .iter()
            .map(|&b| bytewords::word(b))
            .map(|w| format!("{}{}", &w[..1], &w[3..]))
            .collect()
    };
    assert_eq!(Share::parse(&format!("ur:sskr/{}", minimal(&ur_body))).as_ref(), Ok(&share));
    assert_eq!(Share::parse(&format!("UR:SSKR/{}", minimal(&ur_body).to_uppercase())).as_ref(), Ok(&share));
    assert_eq!(Share::parse(&format!("ur:crypto-sskr/{}", minimal(&ur_body))).as_ref(), Ok(&share));
    let v1 = [&[0xd9, 0x01, 0x35][..], &ur_body].concat();
    assert_eq!(Share::parse(&format!("ur:crypto-sskr/{}", minimal(&v1))).as_ref(), Ok(&share));
    assert_eq!(Share::parse(&format!("ur:sskr/{}", minimal(&v1))), Err(Error::NotAShare));
    assert_eq!(Share::parse(&format!("ur:sskr/{}", minimal(&cbor))), Err(Error::NotAShare));
    assert_eq!(Share::parse(&format!("ur:crypto-sskr/{}", minimal(&cbor))), Err(Error::NotAShare));
    assert_eq!(Share::parse(&format!("ur:seed/{}", minimal(&ur_body))), Err(Error::NotAShare));
    assert_eq!(Share::parse(&format!("ur:sskr/1-2/{}", minimal(&ur_body))), Err(Error::NotAShare));
    assert_eq!(Share::parse(&format!("ur:sskr/{}", words.join("-"))), Err(Error::NotAShare));
    assert_eq!(Share::parse("ur:sskr"), Err(Error::NotAShare));
    assert_eq!(Share::parse("ur:"), Err(Error::NotAShare));
    // version 1's tag in words: read, and written as version 2's
    let v1_words: Vec<&str> =
        with_crc(&[&[0xd9, 0x01, 0x35][..], &ur_body].concat()).iter().map(|&b| bytewords::word(b)).collect();
    assert_eq!(&v1_words[..4], ["tuna", "acid", "epic", "gyro"]);
    assert_eq!(Share::from_words(&v1_words).as_ref(), Ok(&share));
}

#[test]
fn refusals_while_typing() {
    let first = |words: &str| -> Vec<u8> { words.split(' ').map(|w| bytewords::byte(w).unwrap()).collect() };
    assert_eq!(expected_words(&first("tuna acid epic gyro")), Ok(Some(29)));
    assert_eq!(expected_words(&first("tuna acid epic hard data")), Ok(Some(46)));
    assert_eq!(expected_words(&first("tuna next keep hang")), Ok(Some(31)));
    assert_eq!(expected_words(&first("tuna next keep hard chef")), Ok(Some(34)));
    assert_eq!(expected_words(&first("tuna next")), Ok(None));
    assert_eq!(expected_words(&[]), Ok(None));
    // a seed's ByteWords (BCR-2020-012's example), and other words
    assert_eq!(expected_words(&first("tuna next jazz")), Err(Error::NotAShare));
    assert_eq!(expected_words(&first("tuna acid jazz")), Err(Error::NotAShare));
    assert_eq!(expected_words(&first("able")), Err(Error::NotAShare));
    assert_eq!(expected_words(&first("tuna next keep each")), Err(Error::NotAShare));
    // byte strings a share can't be: of 20 bytes (a 15-byte secret), 13 (8), 38 (33) and 32 (27),
    // and of 16 with its length in a longer form than it needs
    assert_eq!(expected_words(&first("tuna next keep gush")), Err(Error::Malformed));
    assert_eq!(expected_words(&first("tuna next keep gift")), Err(Error::Malformed));
    assert_eq!(expected_words(&first("tuna next keep hard days")), Err(Error::Malformed));
    assert_eq!(expected_words(&first("tuna next keep hard crux")), Err(Error::Malformed));
    assert_eq!(expected_words(&first("tuna next keep hard blue")), Err(Error::NotAShare));
}

#[test]
fn refusals_splitting() {
    let secret = [7u8; 32];
    for len in [0, 15, 17, 31, 33, 34, 64] {
        assert_eq!(split(&vec![1; len], 2, 3, fake).unwrap_err(), Error::SecretLength(len));
    }
    for (k, n) in [(0, 3), (4, 3), (1, 0), (0, 0), (2, 17), (17, 17)] {
        assert_eq!(split(&secret, k, n, fake).unwrap_err(), Error::Layout, "{k} of {n}");
    }
    assert_eq!(split_groups(&secret, 1, &[], fake).unwrap_err(), Error::Layout);
    assert_eq!(split_groups(&secret, 0, &[(2, 3)], fake).unwrap_err(), Error::Layout);
    assert_eq!(split_groups(&secret, 2, &[(2, 3)], fake).unwrap_err(), Error::Layout);
    assert_eq!(split_groups(&secret, 1, &[(1, 1); 17], fake).unwrap_err(), Error::Layout);
    assert!(split_groups(&secret, 16, &[(16, 16); 16], fake).is_ok());
    assert!(split(&secret, 16, 16, fake).is_ok());
    // nothing asked of the generator before a refusal
    let mut asked = false;
    assert!(split(&secret, 4, 3, |_| asked = true).is_err());
    assert!(!asked);
    // 1 of n: every share is the secret, whole
    let copies = split(&secret, 1, 3, fake).unwrap();
    assert!(copies.iter().all(|s| s.to_bytes()[5..] == secret));
}

#[test]
fn refusals_combining() {
    let mut rng = Xoshiro::case(8000);
    let secret = case_secret(8000, 16);
    let shares = split(&secret, 3, 5, |b| rng.fill(b)).unwrap();
    assert_eq!(combine(&[]).unwrap_err(), Error::NoShares);
    assert_eq!(combine(&shares[..2]).unwrap_err(), Error::TooFew { need: 3, have: 2 });
    assert_eq!(
        combine(&[shares[0].clone(), shares[2].clone(), shares[0].clone()]).unwrap_err(),
        Error::Duplicate { first: 0, share: 2 }
    );
    // another split of the same secret: another identifier
    let mut rng2 = Xoshiro::case(8001);
    let others = split(&secret, 3, 5, |b| rng2.fill(b)).unwrap();
    let mixed = [shares[0].clone(), shares[1].clone(), others[2].clone()];
    assert_eq!(
        combine(&mixed).unwrap_err(),
        Error::OtherSet { share: 2, identifier: others[2].identifier(), set: shares[0].identifier() }
    );
    // two splits that drew the same identifier, as the fake generator always draws (00 11): the
    // digest catches it
    let a = split(&[1u8; 16], 2, 3, fake).unwrap();
    let b = split(&[2u8; 16], 2, 3, fake).unwrap();
    assert_eq!(a[0].identifier(), b[0].identifier());
    assert_eq!(combine(&[a[0].clone(), b[1].clone()]).unwrap_err(), Error::DontFit { group: None });
    assert_eq!(hex(combine(&[a[0].clone(), a[1].clone()]).unwrap().as_bytes()), hex(&[1u8; 16]));
    // a share beyond the threshold that doesn't fit isn't ignored
    assert_eq!(
        combine(&[a[0].clone(), a[1].clone(), b[2].clone()]).unwrap_err(),
        Error::DontFit { group: None }
    );
    // a damaged share, written down again with a right checksum
    let mut damaged = shares[1].to_bytes().to_vec();
    damaged[9] ^= 0x40;
    let damaged = Share::from_bytes(&damaged).unwrap();
    assert_eq!(
        combine(&[shares[0].clone(), damaged.clone(), shares[2].clone()]).unwrap_err(),
        Error::DontFit { group: None }
    );
    // the same identifier but another layout, or another length, or another threshold
    let relayout = |share: &Share, at: usize, value: u8| {
        let mut b = share.to_bytes().to_vec();
        b[at] = value;
        Share::from_bytes(&b).unwrap()
    };
    let in_two = relayout(&shares[3], 2, 0x01);
    assert_eq!(combine(&[shares[0].clone(), in_two]).unwrap_err(), Error::Mismatch { share: 1 });
    let needing_two = relayout(&shares[3], 3, 0x01);
    assert_eq!(combine(&[shares[0].clone(), needing_two]).unwrap_err(), Error::Mismatch { share: 1 });
    let longer = Share::from_bytes(&[&shares[3].to_bytes()[..], &[0, 0]].concat()).unwrap();
    assert_eq!(combine(&[shares[0].clone(), longer]).unwrap_err(), Error::Mismatch { share: 1 });
    // 1 of n: copies that differ
    let copies = split(&secret, 1, 3, fake).unwrap();
    let mut other = copies[1].to_bytes().to_vec();
    other[20] ^= 1;
    let other = Share::from_bytes(&other).unwrap();
    assert_eq!(combine(&[copies[0].clone(), other]).unwrap_err(), Error::DontFit { group: None });
    assert_eq!(combine(&copies[2..]).unwrap().as_bytes(), &secret[..]);
    // groups: one group's shares that don't fit, and not enough groups
    let mut rng3 = Xoshiro::case(8002);
    let groups = split_groups(&secret, 2, &[(2, 3), (2, 3), (1, 2)], |b| rng3.fill(b)).unwrap();
    let mut g1 = groups[1][0].to_bytes().to_vec();
    g1[12] ^= 0x80;
    let g1 = Share::from_bytes(&g1).unwrap();
    let given = [groups[0][0].clone(), groups[0][1].clone(), g1, groups[1][2].clone()];
    assert_eq!(combine(&given).unwrap_err(), Error::DontFit { group: Some(1) });
    assert_eq!(
        combine(&[groups[0][0].clone(), groups[1][1].clone(), groups[0][2].clone()]).unwrap_err(),
        Error::TooFewGroups { need: 2, have: 1 }
    );
    // a group short of its threshold is left out when the others are enough
    let given = [groups[2][1].clone(), groups[1][0].clone(), groups[0][2].clone(), groups[0][1].clone()];
    assert_eq!(combine(&given).unwrap().as_bytes(), &secret[..]);
}

#[test]
fn reasons_read_well() {
    let cases = [
        (Error::UnknownWord(6), "word 7 isn't one of ByteWords' words"),
        (
            Error::WordCount(28),
            "a share is 29 words (of a 12-word phrase) or 46 (of a 24-word one), and this is 28",
        ),
        (Error::Checksum, "the words don't add up: one is wrong, or two are swapped"),
        (Error::NotAShare, "not an SSKR share"),
        (
            Error::OtherSet { share: 2, identifier: 0x4bbf, set: 0xde11 },
            "share 3 is from another split (\"gear runs\", not \"urge body\"): leave it out",
        ),
        (Error::Duplicate { first: 0, share: 2 }, "shares 1 and 3 are the same share: leave one out"),
        (Error::TooFew { need: 3, have: 2 }, "it takes 3 shares, and these are 2: add 1 more"),
        (Error::TooFewGroups { need: 2, have: 1 }, "it takes shares from 2 groups, and 1 have enough"),
        (
            Error::DontFit { group: None },
            "the shares don't fit together: one is damaged, or from another split",
        ),
        (
            Error::DontFit { group: Some(1) },
            "group 2's shares don't fit together: one is damaged, or from another split",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}
