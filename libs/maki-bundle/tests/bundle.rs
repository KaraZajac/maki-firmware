//! Bundles come from anywhere: what `write` makes, `read` takes back unchanged, and anything
//! else is turned away, with the reason.

use ed25519_dalek::{Signer, SigningKey};
use maki_bundle::*;
use sha2::{Digest, Sha256};

fn key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }

fn dice() -> Manifest {
    Manifest {
        id: "org.example.dice".into(),
        name: "Dice".into(),
        version: 3,
        label: "1.0.2".into(),
        kind: Kind::Wasm,
        api: 1,
        firmware: String::new(),
        permissions: vec![
            (Permission::Keys, "to sign your rolls".into()),
            (Permission::Motion, "shake to roll".into()),
        ],
        storage_kib: 4,
        memory_kib: 128,
        backup: true,
        description: "Rolls dice.".into(),
        wallet: None,
    }
}

const H: u32 = 0x8000_0000;

/// A wallet app's manifest: Bitcoin's paths, on bitcoin and the test networks.
fn wallet_app() -> Manifest {
    Manifest {
        id: "org.example.wallet".into(),
        name: "Wallet".into(),
        permissions: vec![
            (Permission::Link, "for wallet software".into()),
            (Permission::Wallet, "to sign what you approve".into()),
        ],
        wallet: Some(Wallet {
            curve: Curve::Secp256k1,
            paths: vec![vec![84 | H, H], vec![86 | H, H], vec![84 | H, 1 | H]],
        }),
        ..dice()
    }
}

#[test]
fn a_wallet_app_names_its_paths() {
    let bundle = write(&wallet_app(), CODE, None, &key()).unwrap();
    let back = read(&bundle).unwrap();
    assert_eq!(back.manifest, wallet_app());
    let w = back.manifest.wallet.unwrap();
    assert!(w.allows(&[84 | H, H, H, 0, 5]));
    assert!(w.allows(&[86 | H, H]));
    assert!(!w.allows(&[86 | H, 1 | H, H]), "not a path it named");
    assert!(!w.allows(&[44 | H, 60 | H, H, 0, 0]));
    assert!(!w.allows(&[84 | H]), "above its paths");
    assert_eq!(w.coins(), vec!["Bitcoin", "test networks"]);
    let odd = Wallet { curve: Curve::Secp256k1, paths: vec![vec![44 | H, 60 | H], vec![44 | H, 9999 | H]] };
    assert_eq!(odd.coins(), vec!["Ethereum", "coin type 9999"]);
    // Solana's, on Ed25519
    let solana = Manifest {
        wallet: Some(Wallet { curve: Curve::Ed25519, paths: vec![vec![44 | H, 501 | H]] }),
        ..wallet_app()
    };
    let back = read(&write(&solana, CODE, None, &key()).unwrap()).unwrap().manifest;
    assert_eq!(back, solana);
    assert_eq!(back.wallet.unwrap().coins(), vec!["Solana"]);
}

#[test]
fn wallet_paths_go_with_the_wallet_permission_and_are_checked() {
    let bad = |m: Manifest| assert!(write(&m, CODE, None, &key()).is_err(), "{:?}", m.wallet);
    // the permission without paths, and paths without the permission
    bad(Manifest { wallet: None, ..wallet_app() });
    bad(Manifest { permissions: vec![(Permission::Link, "because".into())], ..wallet_app() });
    let paths = |paths: Vec<Vec<u32>>| Manifest {
        wallet: Some(Wallet { curve: Curve::Secp256k1, paths }),
        ..wallet_app()
    };
    // a purpose alone would be every coin under it; the whole tree, everything
    bad(paths(vec![vec![84 | H]]));
    bad(paths(vec![vec![]]));
    // both hardened
    bad(paths(vec![vec![84 | H, 0]]));
    bad(paths(vec![vec![84, H]]));
    // none, too many, or one twice
    bad(paths(vec![]));
    bad(paths((0..=MAX_WALLET_PATHS as u32).map(|c| vec![84 | H, c | H]).collect()));
    bad(paths(vec![vec![84 | H, H], vec![84 | H, H]]));
    // deeper paths are fine: an account alone
    assert!(write(&paths(vec![vec![44 | H, 60 | H, H]]), CODE, None, &key()).is_ok());
}

const CODE: &[u8] = b"\0asm\x01\0\0\0";

fn icon() -> [u32; ICON_WORDS] { core::array::from_fn(|i| (i as u32).wrapping_mul(0x9e37_79b9)) }

/// Signs whatever it's given, as `write` would, without `write`'s checks.
fn sign_raw(manifest: &[u8], code: &[u8], icon: Option<&[u8]>, key: &SigningKey) -> Vec<u8> {
    let mut out = b"MAKI\x01".to_vec();
    let section = |out: &mut Vec<u8>, tag: u8, v: &[u8]| {
        out.push(tag);
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    };
    section(&mut out, 1, manifest);
    section(&mut out, 2, code);
    if let Some(icon) = icon {
        section(&mut out, 3, icon);
    }
    let mut message = b"maki bundle v1\0".to_vec();
    message.extend_from_slice(&Sha256::digest(&out));
    let mut sig = key.verifying_key().as_bytes().to_vec();
    sig.extend_from_slice(&key.sign(&message).to_bytes());
    section(&mut out, 255, &sig);
    out
}

fn field(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&(v.len() as u16).to_le_bytes());
    out.extend_from_slice(v);
    out
}

/// The dice manifest's fields, to take apart.
fn fields() -> Vec<Vec<u8>> {
    vec![
        field(1, b"org.example.dice"),
        field(2, b"Dice"),
        field(3, &3u32.to_le_bytes()),
        field(5, &[1]),
        field(6, &1u16.to_le_bytes()),
        field(9, &4u32.to_le_bytes()),
        field(10, &128u32.to_le_bytes()),
        field(11, &[1]),
    ]
}

fn read_fields(fields: &[Vec<u8>]) -> Result<Manifest, Error> {
    let bytes = sign_raw(&fields.concat(), CODE, None, &key());
    read(&bytes).map(|b| b.manifest)
}

#[test]
fn what_write_makes_read_takes_back() {
    let bundle = write(&dice(), CODE, Some(&icon()), &key()).unwrap();
    let b = read(&bundle).unwrap();
    assert_eq!(b.manifest, dice());
    assert_eq!(b.code, CODE);
    assert_eq!(b.icon, Some(icon()));
    assert_eq!(&b.developer, key().verifying_key().as_bytes());
    assert_eq!(b.hash, <[u8; 32]>::from(Sha256::digest(&bundle)));
    assert!(b.manifest.wants(Permission::Keys) && !b.manifest.wants(Permission::Keyboard));

    let plain = write(
        &Manifest { permissions: vec![], label: String::new(), description: String::new(), ..dice() },
        CODE,
        None,
        &key(),
    )
    .unwrap();
    assert_eq!(read(&plain).unwrap().icon, None);
}

#[test]
fn every_changed_byte_is_refused() {
    let bundle = write(&dice(), CODE, Some(&icon()), &key()).unwrap();
    for i in 0..bundle.len() {
        for flip in [0x01u8, 0x80] {
            let mut b = bundle.clone();
            b[i] ^= flip;
            assert!(read(&b).is_err(), "byte {i} ^ {flip:#x} was accepted");
        }
    }
}

#[test]
fn every_cut_and_any_addition_is_refused() {
    let bundle = write(&dice(), CODE, None, &key()).unwrap();
    for len in 0..bundle.len() {
        assert!(read(&bundle[..len]).is_err(), "cut to {len} was accepted");
    }
    let mut longer = bundle.clone();
    longer.push(0);
    assert_eq!(read(&longer).unwrap_err(), Error::Sections);
}

#[test]
fn someone_elses_signature_is_refused() {
    let mut bundle = write(&dice(), CODE, None, &key()).unwrap();
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let n = bundle.len();
    // their key, our signature
    bundle[n - 96..n - 64].copy_from_slice(other.verifying_key().as_bytes());
    assert_eq!(read(&bundle).unwrap_err(), Error::Signature);
}

#[test]
fn framing_errors_say_what_they_are() {
    assert_eq!(read(b"PK\x03\x04 zip").unwrap_err(), Error::NotABundle);
    assert_eq!(read(b"MAKI\x02....").unwrap_err(), Error::Format(2));
    assert_eq!(read(&vec![0u8; MAX_BUNDLE + 1]).unwrap_err(), Error::TooBig);
    let short_icon = sign_raw(&fields().concat(), CODE, Some(&[0u8; 511]), &key());
    assert_eq!(read(&short_icon).unwrap_err(), Error::Icon);
    let no_code = sign_raw(&fields().concat(), b"", None, &key());
    assert_eq!(read(&no_code).unwrap_err(), Error::Sections);
    // the icon before the code
    let mut swapped = b"MAKI\x01".to_vec();
    swapped.extend_from_slice(&[1]);
    assert_eq!(read(&swapped).unwrap_err(), Error::Truncated);
}

#[test]
fn the_plain_manifest_reads() {
    let m = read_fields(&fields()).unwrap();
    assert_eq!((m.id.as_str(), m.name.as_str(), m.version, m.api), ("org.example.dice", "Dice", 3, 1));
    assert!(m.permissions.is_empty() && m.label.is_empty() && m.backup);
}

#[test]
fn manifest_fields_are_strict() {
    let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("unknown field", {
            let mut f = fields();
            f.push(field(13, b"x"));
            f
        }),
        ("repeated", {
            let mut f = fields();
            f.insert(1, field(1, b"org.example.dice"));
            f
        }),
        ("out of order", {
            let mut f = fields();
            f.swap(0, 1);
            f
        }),
        ("no id", fields()[1..].to_vec()),
        ("no backup", fields()[..7].to_vec()),
        ("upper-case id", {
            let mut f = fields();
            f[0] = field(1, b"org.Example.dice");
            f
        }),
        ("id without a dot", {
            let mut f = fields();
            f[0] = field(1, b"dice");
            f
        }),
        ("id with an empty part", {
            let mut f = fields();
            f[0] = field(1, b"org..dice");
            f
        }),
        ("id too long", {
            let mut f = fields();
            f[0] = field(1, format!("org.{}", "a".repeat(61)).as_bytes());
            f
        }),
        ("name with a newline", {
            let mut f = fields();
            f[1] = field(2, b"Di\nce");
            f
        }),
        ("name of spaces", {
            let mut f = fields();
            f[1] = field(2, b"   ");
            f
        }),
        ("name too long", {
            let mut f = fields();
            f[1] = field(2, "D".repeat(25).as_bytes());
            f
        }),
        ("name not UTF-8", {
            let mut f = fields();
            f[1] = field(2, b"\xff");
            f
        }),
        ("version 0", {
            let mut f = fields();
            f[2] = field(3, &0u32.to_le_bytes());
            f
        }),
        ("version too short", {
            let mut f = fields();
            f[2] = field(3, &[3, 0]);
            f
        }),
        ("kind 3", {
            let mut f = fields();
            f[3] = field(5, &[3]);
            f
        }),
        ("api 0", {
            let mut f = fields();
            f[4] = field(6, &0u16.to_le_bytes());
            f
        }),
        ("wasm with firmware", {
            let mut f = fields();
            f.insert(5, field(7, b"0.9"));
            f
        }),
        ("native with an api", {
            let mut f = fields();
            f[3] = field(5, &[2]);
            f
        }),
        ("memory 0", {
            let mut f = fields();
            f[6] = field(10, &0u32.to_le_bytes());
            f
        }),
        ("storage too big", {
            let mut f = fields();
            f[5] = field(9, &(MAX_STORAGE_KIB + 1).to_le_bytes());
            f
        }),
        ("backup 2", {
            let mut f = fields();
            f[7] = field(11, &[2]);
            f
        }),
        ("unknown permission", {
            let mut f = fields();
            f.insert(5, field(8, &[9]));
            f
        }),
        ("empty permission", {
            let mut f = fields();
            f.insert(5, field(8, &[]));
            f
        }),
        ("permissions out of order", {
            let mut f = fields();
            f.insert(5, field(8, &[3]));
            f.insert(6, field(8, &[1]));
            f
        }),
        ("permission twice", {
            let mut f = fields();
            f.insert(5, field(8, &[3]));
            f.insert(6, field(8, &[3]));
            f
        }),
        ("reason too long", {
            let mut f = fields();
            let mut v = vec![3];
            v.extend(std::iter::repeat_n(b'a', 101));
            f.insert(5, field(8, &v));
            f
        }),
        ("field cut short", {
            let mut f = fields();
            f[7] = vec![11, 5, 0, 1];
            f
        }),
    ];
    for (what, f) in cases {
        assert!(
            matches!(read_fields(&f), Err(Error::Manifest(_)) | Err(Error::Truncated)),
            "{what} was accepted"
        );
    }
}

#[test]
fn native_bundles_read_for_the_host_to_refuse() {
    let mut f = fields();
    f[3] = field(5, &[2]);
    f[4] = field(7, b"maki 0.11 xous 0.9.70");
    let m = read_fields(&f).unwrap();
    assert_eq!((m.kind, m.api, m.firmware.as_str()), (Kind::Native, 0, "maki 0.11 xous 0.9.70"));
}

#[test]
fn write_refuses_what_read_would() {
    let bad = Manifest { id: "Dice".into(), ..dice() };
    assert!(write(&bad, CODE, None, &key()).is_err());
    let unsorted = Manifest {
        permissions: vec![(Permission::Motion, String::new()), (Permission::Ask, String::new())],
        ..dice()
    };
    assert!(write(&unsorted, CODE, None, &key()).is_err());
}

#[test]
fn fingerprints_are_six_groups_of_four() {
    let f = fingerprint(key().verifying_key().as_bytes());
    assert_eq!(f.len(), 29);
    let groups: Vec<&str> = f.split(' ').collect();
    assert_eq!(groups.len(), 6);
    assert!(groups.iter().all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_hexdigit())));
    assert_ne!(f, fingerprint(SigningKey::from_bytes(&[8u8; 32]).verifying_key().as_bytes()));
}

#[test]
fn permissions_know_their_names() {
    for p in Permission::ALL {
        assert_eq!(Permission::from_name(p.name()), Some(p));
        assert_eq!(Permission::from_u8(p as u8), Some(p));
        assert!(!p.title().is_empty() && p.warning().ends_with('.'));
    }
    assert_eq!(Permission::from_u8(0), None);
    // no permission gives an app the recovery phrase, or the PIN
    assert_eq!(Permission::from_name("phrase"), None);
    assert_eq!(Permission::from_name("pin"), None);
    assert_eq!(Permission::from_u8(8), None);
}

#[test]
fn only_the_developer_updates_and_only_forwards() {
    let v3 = write(&dice(), CODE, None, &key()).unwrap();
    let b = read(&v3).unwrap();
    let mine = *key().verifying_key().as_bytes();
    assert!(may_update(&mine, 2, &b).is_ok());
    assert!(may_update(&mine, 3, &b).unwrap_err().contains("version 3 is installed"));
    assert!(may_update(&mine, 9, &b).is_err());
    let theirs = *SigningKey::from_bytes(&[8u8; 32]).verifying_key().as_bytes();
    assert!(may_update(&theirs, 1, &b).unwrap_err().contains("different developer"));
}

#[test]
fn stored_bundles_read_without_the_signature_check() {
    let mut bundle = write(&dice(), CODE, None, &key()).unwrap();
    assert_eq!(read_stored(&bundle).unwrap().manifest, dice());
    // a changed signature: `read` notices, `read_stored` (for maki's own storage) doesn't look
    let n = bundle.len();
    bundle[n - 1] ^= 1;
    assert_eq!(read(&bundle).unwrap_err(), Error::Signature);
    assert!(read_stored(&bundle).is_ok());
    // but everything else is still checked
    assert!(read_stored(&bundle[..n - 1]).is_err());
}
