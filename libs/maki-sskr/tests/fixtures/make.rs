//! The vectors maki-sskr's tests hold it to, made by Blockchain Commons' own Rust code (`sskr`,
//! `bc-shamir`, `bc-rand`, `bc-ur`) and their seedtool-cli, and written to vectors.json:
//! - `words`: bc-ur's ByteWords list; `bytewords`: byte strings in its three forms.
//! - `fake`: the sskr crate's own tests, with their fake random number generator (0, 17, 34… from the start
//!   each time it's asked): each share in every form seedtool prints, and the sizes the split asked the
//!   generator for, in order.
//! - `one_group` and `layouts`: splits by bc-rand's seeded generator (Xoshiro256**, a byte from each
//!   `next_u64`), each with a seed and a secret made from its number (`case_seed`, `case_secret`), and the
//!   SHA-256 of all its shares: every one-group k of n up to 16 of 16 for 16- and 32-byte secrets, then the
//!   layouts the sskr crate's fuzz test draws (up to 16 groups). `sskr_combine` puts each back from a quorum
//!   picked as that test picks one.
//! - `documented`: shares printed in the SSKR spec (BCR-2020-011) and in seedtool's manuals, Rust's (0.4.0,
//!   tag 40309) and C++'s (0.11.0, tag 309), and the secret `sskr_combine` gets from them, which must be the
//!   one the document says, where it says one.
//! - `seedtool`: what seedtool 0.4.0 printed when this ran, in each of its forms, and the secret it was
//!   given; `restored`: shares in the words maki shows (made by `sskr` with a seeded generator, written as
//!   bc-ur's standard ByteWords of their `sskr`-tagged CBOR), and what `seedtool -i sskr` made of two quorums
//!   of them.
//! To make them again, in a scratch folder:
//!   cargo new --bin make && cd make && cp <this file> src/main.rs
//!   cargo add sskr@=0.12.0 bc-shamir@=0.13.0 bc-rand@=0.5.0 bc-ur@=0.19.2 rand@=0.9.2
//!   cargo add sha2@0.10 hex@0.4 serde_json@1
//!   cargo install seedtool-cli --version 0.4.0 --locked --root .
//!   SEEDTOOL=bin/seedtool cargo run --release > vectors.json
//! (bc-ur 0.19.2 resolved dcbor 0.25.1 and ur 0.4.1, whose ByteWords bc-ur uses.)

use std::io::Write as _;
use std::process::{Command, Stdio};

use bc_rand::{RandomNumberGenerator, SeededRandomNumberGenerator, rng_next_in_closed_range};
use bc_ur::prelude::*;
use rand::{CryptoRng, RngCore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sskr::{GroupSpec, Secret, Spec, sskr_combine, sskr_generate_using};

/// The sskr crate's tests' generator: 0, 17, 34… from the start each time it's asked.
struct Fake {
    asked: Vec<usize>,
}

impl RngCore for Fake {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _: &mut [u8]) { unimplemented!() }
}

impl CryptoRng for Fake {}

impl RandomNumberGenerator for Fake {
    fn random_data(&mut self, size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size];
        self.fill_random_data(&mut b);
        b
    }

    fn fill_random_data(&mut self, data: &mut [u8]) {
        self.asked.push(data.len());
        let mut b = 0u8;
        for x in data.iter_mut() {
            *x = b;
            b = b.wrapping_add(17);
        }
    }
}

const SSKR: u64 = 40309;
const SSKR_V1: u64 = 309;

fn hex(b: &[u8]) -> String { hex::encode(b) }

fn tagged(share: &[u8]) -> Vec<u8> { CBOR::to_tagged_value(SSKR, CBOR::to_byte_string(share)).to_cbor_data() }

/// A share in each form seedtool prints it.
fn forms(share: &[u8]) -> Value {
    let cbor = tagged(share);
    json!({
        "hex": hex(share),
        "btw": bytewords::encode(&cbor, bytewords::Style::Standard),
        "btwu": bytewords::encode(&cbor, bytewords::Style::Uri),
        "btwm": bytewords::encode(&cbor, bytewords::Style::Minimal),
        "ur": UR::new("sskr", CBOR::to_byte_string(share)).unwrap().string(),
    })
}

/// A share's bytes from text as seedtool reads it: ByteWords (standard, minimal or URI) of CBOR
/// tagged 40309 or 309, or a UR of type sskr (untagged) or crypto-sskr (untagged, or tagged 309).
fn read(text: &str) -> Vec<u8> {
    let (cbor, tags): (CBOR, &[u64]) = if text.starts_with("ur:") {
        let ur = UR::from_ur_string(text).unwrap();
        (ur.cbor(), if ur.ur_type_str() == "sskr" { &[] } else { &[SSKR_V1] })
    } else {
        let style = if text.contains(' ') {
            bytewords::Style::Standard
        } else if text.contains('-') {
            bytewords::Style::Uri
        } else {
            bytewords::Style::Minimal
        };
        (CBOR::try_from_data(bytewords::decode(text, style).unwrap()).unwrap(), &[SSKR, SSKR_V1])
    };
    let inner = match cbor.clone().into_case() {
        CBORCase::Tagged(tag, item) if tags.contains(&tag.value()) => item,
        _ => cbor,
    };
    inner.try_into_byte_string().unwrap()
}

fn spec(group_threshold: usize, groups: &[(usize, usize)]) -> Spec {
    Spec::new(group_threshold, groups.iter().map(|&(k, n)| GroupSpec::new(k, n).unwrap()).collect()).unwrap()
}

fn all_shares(shares: &[Vec<Vec<u8>>]) -> Vec<u8> { shares.iter().flatten().flatten().copied().collect() }

/// The sskr crate's tests: test_split_3_5, test_split_2_7 and test_split_2_3_2_3.
fn fake() -> Value {
    let cases: [(&str, usize, &[(usize, usize)], &[usize]); 3] = [
        ("0ff784df000c4380a5ed683f7e6e3dcf", 1, &[(3, 5)], &[1, 2, 4]),
        ("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a", 1, &[(2, 7)], &[3, 4]),
        (
            "204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a",
            2,
            &[(2, 3), (2, 3)],
            &[0, 1, 3, 5],
        ),
    ];
    let mut out = vec![];
    for (secret, group_threshold, groups, recovered) in cases {
        let secret = Secret::new(hex::decode(secret).unwrap()).unwrap();
        let mut rng = Fake { asked: vec![] };
        let shares = sskr_generate_using(&spec(group_threshold, groups), &secret, &mut rng).unwrap();
        let flat: Vec<Vec<u8>> = shares.iter().flatten().cloned().collect();
        let given: Vec<Vec<u8>> = recovered.iter().map(|&i| flat[i].clone()).collect();
        assert_eq!(sskr_combine(&given).unwrap(), secret);
        out.push(json!({
            "secret": hex(secret.data()),
            "group_threshold": group_threshold,
            "groups": groups,
            "asked": rng.asked,
            "shares": flat.iter().map(|s| forms(s)).collect::<Vec<_>>(),
            "recovered": recovered,
        }));
    }
    json!(out)
}

/// Case `i`'s seed for bc-rand's seeded generator, and its secret: hashes of its number, so that
/// the tests make them the same way.
fn case_seed(i: usize) -> [u64; 4] {
    let h = Sha256::digest(format!("maki-sskr seed {i}"));
    std::array::from_fn(|j| u64::from_le_bytes(h[j * 8..j * 8 + 8].try_into().unwrap()))
}

fn case_secret(i: usize, len: usize) -> Secret {
    Secret::new(&Sha256::digest(format!("maki-sskr secret {i}"))[..len]).unwrap()
}

/// `secret` split by bc-rand's seeded generator, with case `i`'s seed.
fn split_with(
    i: usize,
    secret: &Secret,
    group_threshold: usize,
    groups: &[(usize, usize)],
) -> Vec<Vec<Vec<u8>>> {
    let mut rng = SeededRandomNumberGenerator::new(case_seed(i));
    sskr_generate_using(&spec(group_threshold, groups), secret, &mut rng).unwrap()
}

fn shuffle<T>(v: &mut [T], rng: &mut SeededRandomNumberGenerator) {
    let mut i = v.len();
    while i > 1 {
        i -= 1;
        let j = rng_next_in_closed_range(rng, &(0..=i));
        v.swap(i, j);
    }
}

/// The SHA-256 of case `i`'s shares, all in turn, after `sskr_combine` has put a quorum of them
/// back as the sskr crate's fuzz test picks one: groups, then each one's members, then the order.
fn seeded_case(
    i: usize,
    len: usize,
    group_threshold: usize,
    groups: &[(usize, usize)],
    picker: &mut SeededRandomNumberGenerator,
) -> String {
    let shares = split_with(i, &case_secret(i, len), group_threshold, groups);
    let mut group_indexes: Vec<usize> = (0..groups.len()).collect();
    shuffle(&mut group_indexes, picker);
    let mut given = vec![];
    for &g in &group_indexes[..group_threshold] {
        let mut members: Vec<usize> = (0..groups[g].1).collect();
        shuffle(&mut members, picker);
        given.extend(members[..groups[g].0].iter().map(|&m| shares[g][m].clone()));
    }
    shuffle(&mut given, picker);
    assert_eq!(sskr_combine(&given).unwrap(), case_secret(i, len));
    hex(&Sha256::digest(all_shares(&shares)))
}

/// Every one-group k of n, for 16- and 32-byte secrets in turn (cases 0 to 271: n from 1 to 16,
/// k from 1 to n), and then (cases 272 to 371) the layouts the sskr crate's fuzz test draws with
/// bc-rand's fake generator: up to 16 groups of up to 16, secrets of 16 to 32 bytes.
fn seeded() -> (Value, Value) {
    let mut rng = bc_rand::make_fake_random_number_generator();
    let mut case = 0;
    let mut one_group = vec![];
    for len in [16, 32] {
        for count in 1..=16 {
            for threshold in 1..=count {
                one_group.push(json!(seeded_case(case, len, 1, &[(threshold, count)], &mut rng)));
                case += 1;
            }
        }
    }
    let mut layouts = vec![];
    for _ in 0..100 {
        let len = rng_next_in_closed_range(&mut rng, &(16..=32usize)) & !1;
        let group_count = rng_next_in_closed_range(&mut rng, &(1..=16usize));
        let groups: Vec<(usize, usize)> = (0..group_count)
            .map(|_| {
                let count = rng_next_in_closed_range(&mut rng, &(1..=16usize));
                (rng_next_in_closed_range(&mut rng, &(1..=count)), count)
            })
            .collect();
        let group_threshold = rng_next_in_closed_range(&mut rng, &(1..=group_count));
        let sha256 = seeded_case(case, len, group_threshold, &groups, &mut rng);
        layouts.push(json!({
            "case": case, "len": len, "group_threshold": group_threshold, "groups": groups, "sha256": sha256,
        }));
        case += 1;
    }
    (json!(one_group), json!(layouts))
}

/// Shares as the spec and seedtool's manuals print them, and the secret they say.
fn documented() -> Value {
    let examples: [(&str, &[&str], Option<&str>); 13] = [
        (
            "Research papers/bcr-2020-011-sskr.md (2 groups: 2 of 3, 3 of 5; both needed)",
            &[
                "4bbf1101003e990c1f0435e2b33c721535c74603d0",
                "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f",
                "4bbf1101025abd490ee65b6084859854ee67736e75",
                "4bbf11120044ef453f66923d32653b377de5c94b39",
                "4bbf1112016ffb1b0cc5ab485f5a67136c802bc67b",
                "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd",
                "4bbf11120388626f665fc4c0e545e0c2ff0c26368f",
                "4bbf1112046334a0db7838a5c6c4d2dcb2e5b65911",
            ],
            Some("7daa851251002874e1a1995f0897e6b1"),
        ),
        (
            "seedtool-cli-rust 0.4.0 MANUAL.md, Restoring Seeds with SSKR",
            &[
                "tuna next keep gyro acid yawn able acid able leaf idle mild legs play ugly atom liar slot scar film redo tent poem wasp maze calm scar need toil",
                "tuna next keep gyro acid yawn able acid acid holy keep when luau cook jazz yank rock grim toil stub dice keys very ruby work crux peck down iron",
            ],
            Some("59f2293a5bce7d4de59e71b4207ac5d2"),
        ),
        (
            "seedtool-cli-rust 0.4.0 MANUAL.md, seedtool -o sskr -g 2-of-3 -s btwm",
            &[
                "tantkpgokkmwaeadaehldwetvsenhfihlrcylogslkhlaotksovovwbenl",
                "tantkpgokkmwaeadaddmglwypehyvdfhntftylkkmerlndjttaecdaeheh",
                "tantkpgokkmwaeadaorkvsmyiyvadlttrphtkodsrpmodnmtwlgynnnefd",
            ],
            None,
        ),
        (
            "seedtool-cli-rust 0.4.0 MANUAL.md, seedtool -o sskr -g 2-of-3 3-of-5 1-of-2 -t 2 -s btwm",
            &[
                "tantkpgohllabgadaeptlkndfzrdwfihtdmtrpeovtsofnfxfzvwtypkot",
                "tantkpgohllabgadadyllamsenpklgcfceoxdycyjtvwfsjetbjtspuetl",
                "tantkpgohllabgadaobzmwlspsnybsntgowzoyhsvdmefmbwktfptolurp",
                "tantkpgohllabgbgaeiowpzmcksndlrybaynflmdbdbybslocnatimrpsp",
                "tantkpgohllabgbgadqdvajltsbswehpprnbttfmetptfxnbgegrjniyim",
                "tantkpgohllabgbgaohplnmwpdinzehlsfmerhjlecdissdtiorduorlbe",
                "tantkpgohllabgbgaxmylkaahspyfnrkjostdlssamneloadbaynuyiopr",
                "tantkpgohllabgbgaabzuyjpmdjprerdcnesptmhbnbgtletskldkgmnzt",
                "tantkpgohllabgcxaentdrecrfcxledmsklujndwmnmyurhkmnkihgenox",
                "tantkpgohllabgcxadntdrecrfcxledmsklujndwmnmyurhkmnzswnzcvd",
            ],
            Some("7042842963c788571776c4adfa4ed8df"),
        ),
        (
            "seedtool-cli-rust 0.4.0 MANUAL.md, seedtool -i hex 59f2293a5bce7d4de59e71b4207ac5d2 -o sskr -g 2-of-3 -s btwm",
            &[
                "tantkpgowkftaeadaehhmnrkdrlybzwpdlyaaededllbckcnrtdnqznduy",
                "tantkpgowkftaeadaddydttnwnfpsoptzopewnglprgylfahcnjoroctve",
                "tantkpgowkftaeadaolruykkltcyrpiynshfytvebacnfsjlcawpkpbgne",
            ],
            Some("59f2293a5bce7d4de59e71b4207ac5d2"),
        ),
        (
            "seedtool-cli-rust 0.4.0 src/formats/sskr.rs, test_legacy (ur:crypto-sskr, 2 groups)",
            &[
                "ur:crypto-sskr/taadecgomymwbyadaenndtrehegwjkktoljphehtkshhbnhgiofmsebabs",
                "ur:crypto-sskr/taadecgomymwbyadaobthhluwlfsishthsnngapdckhytpoteeeeglwfcm",
                "ur:crypto-sskr/taadecgomymwbybgaekiplylurmhglfsgtfeptwnlrknvwidbztbjlhfht",
                "ur:crypto-sskr/taadecgomymwbybgaoswleqddlidjnehclnbdaaawdvsosiachtbihzees",
                "ur:crypto-sskr/taadecgomymwbybgaaeconwemnhhcmeotivdpdftknsptyltjntamtmtvs",
            ],
            Some("9d347f841a4e2ce6bc886e1aee74d824"),
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, seedtool --out sskr",
            &[
                "tuna acid epic gyro king cola able able able bias ugly aqua leaf mild numb cusp judo undo ruby jowl vast zero fund taxi gush stub iced hawk acid",
            ],
            None,
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, seedtool --out sskr --count 32",
            &[
                "tuna acid epic hard data lava crux able able able love cost part wall monk gyro many play exit inch cats away eyes stub plus body wolf skew limp join wand twin deli idle days oval bald puma soap good beta city jazz knob tied down",
            ],
            None,
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, seedtool --out sskr --group 2-of-3",
            &[
                "tuna acid epic gyro waxy blue able acid able jolt pose task days taxi wasp beta wasp barn aqua tuna hawk jade rock figs obey horn horn figs race",
                "tuna acid epic gyro waxy blue able acid acid fund dice surf item math axis into ugly aqua lazy half apex horn slot miss item item curl twin cats",
                "tuna acid epic gyro waxy blue able acid also cusp road solo ruin good figs undo leaf code buzz undo wave kiwi flux jump draw runs task what acid",
            ],
            None,
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, --group-threshold 2 --group 2-of-3 --group 3-of-5 --group 3-of-5",
            &[
                "tuna acid epic gyro days rich brag acid able days brew rich cyan yawn belt ugly cost love roof kept flew wall inch safe saga very gush vibe acid",
                "tuna acid epic gyro days rich brag acid acid hang paid barn work bias swan code jade apex high whiz nail luck flux silk trip door oval oval kept",
                "tuna acid epic gyro days rich brag acid also sets knob soap mint cost mint girl yell legs into inky webs cyan diet solo yawn grim toil saga vast",
                "tuna acid epic gyro days rich brag brag able able game jazz luau cats sets jazz down guru undo rich inky belt slot purr figs quad yurt zinc quiz",
                "tuna acid epic gyro days rich brag brag acid lava cyan kiwi toil free real fair yoga item calm liar task menu keys pose need legs body sets yank",
                "tuna acid epic gyro days rich brag brag also miss onyx noon wall kiln numb logo deli hawk silk horn nail soap bald quiz curl undo atom math bald",
                "tuna acid epic gyro days rich brag brag apex cash swan many real deli time user work horn bias hill duty half quiz part list wasp waxy part game",
                "tuna acid epic gyro days rich brag brag aqua echo kiwi zone city maze easy luck safe roof lava peck join eyes tomb girl easy lava figs tomb down",
                "tuna acid epic gyro days rich brag cusp able keep noon flap wall hawk lung hope also navy nail next pose rich cash foxy gray leaf roof zest dark",
                "tuna acid epic gyro days rich brag cusp acid loud film maze also work vibe able roof grim brew gala inky gems tuna jump holy tiny buzz deli view",
                "tuna acid epic gyro days rich brag cusp also ruin quiz very arch luau veto taxi love yank grim loud cyan iris down able rust tuna back keys open",
                "tuna acid epic gyro days rich brag cusp apex flew bulb each waxy days luau many edge figs trip hill wand next view even task many omit omit idle",
            ],
            None,
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, recovering from the first and third of 2 of 3",
            &[
                "tuna acid epic gyro deli each able acid able cats loud kiwi kiln drop loud tent rock fizz keno jump eyes numb holy edge solo dull trip hawk yawn",
                "tuna acid epic gyro deli each able acid acid bald ruin toys zaps down film gush liar kite lung webs film toys drop roof barn king news frog taco",
                "tuna acid epic gyro deli each able acid also film void easy huts curl zest rust silk exit need guru exam girl redo fish hard runs owls hard very",
            ],
            Some("6bf9961f199c9a7293b4e9f26f40e83d"),
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, seedtool --deterministic FOOBAR --in hex --out sskr --group 2-of-3 5cd271b50b98a869da1c26a526e1d3a8",
            &[
                "tuna acid epic gyro urge body able acid able exam fern lung visa barn yawn flap open inky drum chef grim paid lion owls vows veto yank curl soap",
                "tuna acid epic gyro urge body able acid acid cost zaps paid hard hard purr time yawn also horn ugly quad leaf film vast part toys lion bulb game",
                "tuna acid epic gyro urge body able acid also into play slot lazy onyx knob knob apex pool purr lion luau zest wave diet item kiwi flap taco many",
            ],
            Some("5cd271b50b98a869da1c26a526e1d3a8"),
        ),
        (
            "seedtool-cli 0.11.0 (C++) Docs/MANUAL.md, Recover a SSKR seed using 2 of 3 shares. Each UR is one share.",
            &[
                "ur:crypto-sskr/taadecgoretkaeadaesacachmnnsjkpklslujtvscezernhylngassdtin",
                "ur:crypto-sskr/taadecgoretkaeadadrhfxlblgosbycerhiecfnesgnblfatmucedalboe",
                "ur:crypto-sskr/taadecgoretkaeadaoeeoystlowdrlutylgllaampyfwswwppsaocfbtns",
            ],
            Some("6546c39484fb4064f1a1279ba56dcec1"),
        ),
    ];
    let mut out = vec![];
    for (source, shares, says) in examples {
        let raw: Vec<Vec<u8>> =
            shares
                .iter()
                .map(|s| {
                    if s.len() % 2 == 0 && hex::decode(s).is_ok() { hex::decode(s).unwrap() } else { read(s) }
                })
                .collect();
        let secret = hex(sskr_combine(&raw).unwrap().data());
        if let Some(says) = says {
            assert_eq!(secret, says, "{source}");
        }
        out.push(json!({
            "source": source,
            "shares": shares,
            "hex": raw.iter().map(|r| hex(r)).collect::<Vec<_>>(),
            "secret": secret,
        }));
    }
    json!(out)
}

fn seedtool(args: &[&str], input: Option<&str>) -> String {
    let path = std::env::var("SEEDTOOL").expect("SEEDTOOL: the path of seedtool-cli 0.4.0");
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.unwrap_or("").as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "seedtool {args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// What seedtool 0.4.0 printed, and shares in maki's words that it restored.
fn from_seedtool() -> (Value, Value) {
    let mut rng = bc_rand::make_fake_random_number_generator();
    let secrets: Vec<String> = vec![
        // the test phrase's entropy (abandon × 11, about), and abandon × 23, art's
        "00".repeat(16),
        "00".repeat(32),
        hex(&rng.random_data(16)),
        hex(&rng.random_data(32)),
        hex(&rng.random_data(20)),
        hex(&rng.random_data(18)),
    ];
    let layouts: [&[&str]; 9] = [
        &["-g", "1-of-1"],
        &["-g", "1-of-3"],
        &["-g", "2-of-3"],
        &["-g", "3-of-5"],
        &["-g", "16-of-16"],
        &["-g", "2-of-16"],
        &["-g", "2-of-3", "2-of-3", "2-of-3", "-t", "2"],
        &["-g", "2-of-3", "3-of-5", "1-of-2", "-t", "2"],
        &["-g", "1-of-1", "2-of-2", "-t", "1"],
    ];
    let formats = ["btw", "btwm", "btwu", "ur"];
    let mut printed = vec![];
    for (i, secret) in secrets.iter().enumerate() {
        for (j, layout) in layouts.iter().enumerate() {
            // each layout in a different form for each secret, and the 16s only for the first two
            if layout[1].ends_with("-of-16") && i > 1 {
                continue;
            }
            let format = formats[(i + j) % formats.len()];
            let mut args = vec!["-i", "hex", secret.as_str(), "-o", "sskr", "-s", format];
            args.extend_from_slice(layout);
            let shares: Vec<String> = seedtool(&args, None).lines().map(String::from).collect();
            printed.push(json!({ "args": args, "secret": secret, "shares": shares }));
        }
    }
    // seedtool's default form: a Gordian Envelope, which maki doesn't read
    let args = ["-i", "hex", &secrets[0], "-o", "sskr", "-g", "2-of-3"];
    let shares: Vec<String> = seedtool(&args, None).lines().map(String::from).collect();
    printed.push(json!({ "args": args, "secret": secrets[0], "shares": shares, "envelope": true }));

    // cases 1000 to 1003, in the words maki shows
    let mut restored = vec![];
    let given = [(&secrets[0], 2, 3), (&secrets[1], 2, 3), (&secrets[2], 3, 5), (&secrets[3], 1, 1)];
    for (case, (secret, k, n)) in (1000..).zip(given) {
        let secret = Secret::new(hex::decode(secret).unwrap()).unwrap();
        let shares = split_with(case, &secret, 1, &[(k, n)]);
        let words: Vec<String> =
            shares[0].iter().map(|s| bytewords::encode(tagged(s), bytewords::Style::Standard)).collect();
        // the first k, and the last k, as seedtool reads shares: a line each
        let mut answers = vec![];
        for quorum in [&words[..k], &words[n - k..]] {
            answers.push(seedtool(&["-i", "sskr"], Some(&(quorum.join("\n") + "\n"))));
        }
        restored.push(json!({
            "case": case, "secret": hex(secret.data()), "threshold": k, "count": n, "words": words,
            "seedtool": answers,
        }));
    }
    (json!(printed), json!(restored))
}

fn main() {
    let mut bytes = vec![
        vec![0, 1, 2, 128, 255],
        // the 100 bytes of the ur crate's test_encoding
        vec![
            245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212, 19, 159,
            17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242, 254, 147, 204, 66,
            163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184, 197, 33, 113, 88, 14, 157, 31,
            177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144, 65, 240, 133, 69, 113, 247, 63, 53, 242,
            165, 160, 144, 26, 13, 79, 237, 133, 71, 82, 69, 254, 165, 138, 41, 85, 24,
        ],
        // BCR-2020-012's example: a seed's CBOR
        hex::decode("d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da").unwrap(),
        (0..=255).collect(),
    ];
    let mut rng = bc_rand::make_fake_random_number_generator();
    for len in [1, 7, 29, 46] {
        bytes.push(rng.random_data(len));
    }
    let bytewords: Vec<Value> = bytes
        .iter()
        .map(|b| {
            json!({
                "hex": hex(b),
                "standard": bytewords::encode(b, bytewords::Style::Standard),
                "uri": bytewords::encode(b, bytewords::Style::Uri),
                "minimal": bytewords::encode(b, bytewords::Style::Minimal),
            })
        })
        .collect();
    let (printed, restored) = from_seedtool();
    let (one_group, layouts) = seeded();
    let out = json!({
        "words": bc_ur::bytewords::BYTEWORDS.to_vec(),
        "bytewords": bytewords,
        "fake": fake(),
        "one_group": one_group,
        "layouts": layouts,
        "documented": documented(),
        "seedtool": printed,
        "restored": restored,
    });
    // a line for each item, to keep it small and its diffs readable
    let out = out.as_object().unwrap();
    println!("{{");
    for (n, (name, value)) in out.iter().enumerate() {
        let items = value.as_array().unwrap();
        println!("  {}: [", serde_json::to_string(name).unwrap());
        for (i, item) in items.iter().enumerate() {
            println!(
                "    {}{}",
                serde_json::to_string(item).unwrap(),
                if i + 1 < items.len() { "," } else { "" }
            );
        }
        println!("  ]{}", if n + 1 < out.len() { "," } else { "" });
    }
    println!("}}");
}
