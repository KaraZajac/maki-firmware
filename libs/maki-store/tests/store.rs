//! The store's records, and the checks maki makes of them.

use ed25519_dalek::SigningKey;
use maki_bundle::{Kind, Manifest, Permission};
use maki_store::*;

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

fn public(k: &SigningKey) -> [u8; 32] { k.verifying_key().to_bytes() }

const NOW: u64 = 1_790_000_000;

/// Root keys 1, 2 and 3, two to sign; catalogue key 10.
fn root(version: u32) -> Root {
    Root {
        version,
        threshold: 2,
        keys: vec![public(&key(1)), public(&key(2)), public(&key(3))],
        catalogue: public(&key(10)),
        catalogue_expires: NOW + 365 * 86400,
    }
}

#[test]
fn a_root_needs_its_threshold_of_its_own_keys() {
    let signed = SignedRoot::sign(root(1), &[&key(1), &key(3)]);
    assert_eq!(signed.trust_first().unwrap(), &root(1));
    // one isn't enough, nor two signatures by the same key, nor someone else's
    assert_eq!(SignedRoot::sign(root(1), &[&key(1)]).trust_first(), Err(Error::Signature));
    assert_eq!(SignedRoot::sign(root(1), &[&key(1), &key(1)]).trust_first(), Err(Error::Signature));
    assert_eq!(SignedRoot::sign(root(1), &[&key(1), &key(9)]).trust_first(), Err(Error::Signature));
    // a threshold nobody can meet, or none at all, or a key listed twice
    for bad in [
        Root { threshold: 4, ..root(1) },
        Root { threshold: 0, ..root(1) },
        Root { keys: vec![public(&key(1)); 3], ..root(1) },
    ] {
        assert_eq!(SignedRoot::sign(bad, &[&key(1), &key(2), &key(3)]).trust_first(), Err(Error::Malformed));
    }
    // through bytes and back
    assert_eq!(SignedRoot::decode(&signed.encode()).unwrap(), signed);
}

#[test]
fn a_new_root_needs_the_old_keys_and_its_own() {
    let current = root(1);
    // new root keys 4, 5 and 6, and a new catalogue key
    let next = Root {
        version: 2,
        keys: vec![public(&key(4)), public(&key(5)), public(&key(6))],
        catalogue: public(&key(11)),
        ..root(2)
    };
    let both = SignedRoot::sign(next.clone(), &[&key(1), &key(2), &key(4), &key(5)]);
    assert_eq!(both.replaces(&current).unwrap(), &next);
    // only the new keys: anyone could make a root of their own
    assert_eq!(SignedRoot::sign(next.clone(), &[&key(4), &key(5)]).replaces(&current), Err(Error::Signature));
    // only the old: the new keys' holders never agreed
    assert_eq!(SignedRoot::sign(next.clone(), &[&key(1), &key(2)]).replaces(&current), Err(Error::Signature));
    // not newer
    let same = SignedRoot::sign(root(1), &[&key(1), &key(2)]);
    assert_eq!(same.replaces(&current), Err(Error::Rollback));
    // changed after signing
    let mut tampered = both.clone();
    tampered.root.catalogue_expires += 1;
    assert_eq!(tampered.replaces(&current), Err(Error::Signature));
}

fn manifest(version: u32, permissions: Vec<(Permission, String)>) -> Manifest {
    Manifest {
        id: "com.example.ssh".into(),
        name: "SSH".into(),
        version,
        label: String::new(),
        kind: Kind::Wasm,
        api: 1,
        firmware: String::new(),
        permissions,
        storage_kib: 1,
        memory_kib: 64,
        backup: false,
        description: String::new(),
        wallet: None,
    }
}

fn bundle(version: u32, permissions: Vec<(Permission, String)>) -> Vec<u8> {
    let code = b"\0asm\x01\0\0\0";
    maki_bundle::write(&manifest(version, permissions), code, None, &key(20)).unwrap()
}

#[test]
fn a_stamp_makes_exactly_its_bundle_a_store_app() {
    let r = root(1);
    let plain = bundle(3, vec![(Permission::Keys, "a key".into())]);
    let b = maki_bundle::read(&plain).unwrap();
    assert_eq!(b.stamp, None);
    let stamp = SignedStamp::sign(Stamp::of(&b, NOW), &key(10));
    let stamped = maki_bundle::with_stamp(&plain, &stamp.encode()).unwrap();

    let sb = maki_bundle::read(&stamped).unwrap();
    // the developer's bundle, as they signed it: the stamp isn't in its hash
    assert_eq!(sb.hash, b.hash);
    let read_back = SignedStamp::decode(sb.stamp.unwrap()).unwrap();
    assert_eq!(read_back, stamp);
    read_back.check(&r, Some(NOW), &sb).unwrap();

    // not without verified time, nor once the catalogue key has expired
    assert_eq!(read_back.check(&r, None, &sb), Err(Error::TimeUnverified));
    assert_eq!(read_back.check(&r, Some(r.catalogue_expires), &sb), Err(Error::Expired));
    // signed by another key
    let forged = SignedStamp::sign(Stamp::of(&b, NOW), &key(11));
    assert_eq!(forged.check(&r, Some(NOW), &sb), Err(Error::Signature));
    // for another bundle: another version, other permissions, other contents, another developer
    let other = |plain: Vec<u8>| {
        let b2 = maki_bundle::read(&plain).unwrap();
        let b2 = maki_bundle::Bundle { stamp: None, ..b2 };
        stamp.check(&r, Some(NOW), &b2)
    };
    assert_eq!(other(bundle(4, vec![(Permission::Keys, "a key".into())])), Err(Error::Mismatch("version")));
    assert_eq!(
        other(bundle(3, vec![(Permission::Keys, "a key".into()), (Permission::Keyboard, "typing".into())])),
        Err(Error::Mismatch("permissions"))
    );
    // the same fields, but the developer wrote something else: the hash differs
    let mut m = manifest(3, vec![(Permission::Keys, "another reason".into())]);
    m.description = "changed".into();
    let changed = maki_bundle::write(&m, b"\0asm\x01\0\0\0", None, &key(20)).unwrap();
    assert_eq!(other(changed), Err(Error::Mismatch("contents")));
    let by_another = maki_bundle::write(
        &manifest(3, vec![(Permission::Keys, "a key".into())]),
        b"\0asm\x01\0\0\0",
        None,
        &key(21),
    )
    .unwrap();
    assert_eq!(other(by_another), Err(Error::Mismatch("developer")));

    // restamping replaces the stamp, it doesn't pile them up
    let again = maki_bundle::with_stamp(&stamped, &stamp.encode()).unwrap();
    assert_eq!(again, stamped);
}

#[test]
fn revocations_are_signed_newer_and_say_why() {
    let r = root(1);
    let list = Revocations {
        version: 7,
        expires: NOW + 30 * 86400,
        entries: vec![
            (Revoked::App("com.example.bad".into()), "steals codes".into()),
            (Revoked::UpTo("com.example.ssh".into(), 2), "a bug in signing".into()),
            (Revoked::Developer(public(&key(30))), "a stolen key".into()),
        ],
    };
    let signed = SignedRevocations::sign(list.clone(), &key(10));
    assert_eq!(SignedRevocations::decode(&signed.encode()).unwrap(), signed);
    assert_eq!(signed.replaces(&r, Some(NOW), None).unwrap(), &list);
    let seven = SignedRevocations::sign(Revocations { version: 7, ..list.clone() }, &key(10));
    assert_eq!(signed.replaces(&r, Some(NOW), Some(&seven)), Err(Error::Rollback));
    let six = SignedRevocations::sign(Revocations { version: 6, ..list.clone() }, &key(10));
    assert_eq!(signed.replaces(&r, Some(NOW), Some(&six)).unwrap(), &list);
    assert_eq!(
        SignedRevocations::sign(list.clone(), &key(11)).replaces(&r, Some(NOW), None),
        Err(Error::Signature)
    );
    // the catalogue key signs nothing new without verified time, nor once it's expired
    assert_eq!(signed.replaces(&r, None, None), Err(Error::TimeUnverified));
    assert_eq!(signed.replaces(&r, Some(r.catalogue_expires), None), Err(Error::Expired));
    // a new root's catalogue key: its lists replace the old key's, whatever their version, so a
    // stolen old key's huge version doesn't stop them
    let stolen = SignedRevocations::sign(Revocations { version: u32::MAX, ..list.clone() }, &key(10));
    let r2 = Root { version: 2, catalogue: public(&key(11)), ..root(2) };
    let fresh = SignedRevocations::sign(Revocations { version: 1, ..list.clone() }, &key(11));
    assert_eq!(fresh.replaces(&r2, Some(NOW), Some(&stolen)).unwrap().version, 1);
    assert_eq!(stolen.replaces(&r2, Some(NOW), Some(&fresh)), Err(Error::Signature));

    let dev = public(&key(20));
    assert_eq!(list.check("com.example.bad", 9, &dev), Some("steals codes"));
    assert_eq!(list.check("com.example.ssh", 2, &dev), Some("a bug in signing"));
    assert_eq!(list.check("com.example.ssh", 3, &dev), None);
    assert_eq!(list.check("com.example.anything", 1, &public(&key(30))), Some("a stolen key"));
}

#[test]
fn garbage_isnt_a_record() {
    assert_eq!(SignedRoot::decode(b"MAKIROOT"), Err(Error::Malformed));
    assert_eq!(SignedRoot::decode(b"MAKIROOT\x02"), Err(Error::Format(2)));
    assert_eq!(SignedStamp::decode(b"not a stamp at all"), Err(Error::Malformed));
    let list = SignedRevocations::sign(Revocations { version: 1, expires: NOW, entries: vec![] }, &key(10));
    let mut bytes = list.encode();
    bytes.push(0);
    assert_eq!(SignedRevocations::decode(&bytes), Err(Error::Malformed));
}

#[test]
fn the_index_is_signed_by_the_catalogue_key() {
    let r = root(1);
    let index = br#"{"format":1,"version":3,"apps":[]}"#;
    let sig = sign_index(index, &key(10));
    assert!(index_signed(&r, index, &sig));
    assert!(!index_signed(&r, br#"{"format":1,"version":4,"apps":[]}"#, &sig));
    assert!(!index_signed(&r, index, &sign_index(index, &key(1))));
}
