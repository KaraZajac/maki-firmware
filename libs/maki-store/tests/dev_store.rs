//! The development store (dev-store/, made by its make.sh): what the firmware trusts until the
//! real store opens, and what the tests and the emulator's demo use. Checked here as maki and
//! maki desktop check it.

use maki_store::*;

/// After the development store was made, and long before anything in it expires.
const NOW: u64 = 1_790_600_000;

fn file(path: &str) -> Vec<u8> {
    let full = format!("{}/dev-store/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&full).unwrap_or_else(|e| panic!("{full}: {e}"))
}

#[test]
fn the_development_store_checks_out() {
    let root1 = SignedRoot::decode(&file("roots/1.bin")).unwrap().trust_first().unwrap().clone();
    assert_eq!(root1.version, 1);
    // root 2 replaces root 1, and the catalogue key with it
    let root = SignedRoot::decode(&file("roots/2.bin")).unwrap().replaces(&root1).unwrap().clone();
    assert_ne!(root.catalogue, root1.catalogue);

    let index = file("index.json");
    let sig: [u8; 64] = file("index.sig").try_into().unwrap();
    assert!(index_signed(&root, &index, &sig));
    assert!(!index_signed(&root1, &index, &sig));
    let index: serde_json::Value = serde_json::from_slice(&index).unwrap();
    assert_eq!(index["root"], 2);
    let apps = index["apps"].as_array().unwrap();
    assert!(apps.len() >= 4);
    for app in apps {
        let bytes = file(app["path"].as_str().unwrap());
        let b = maki_bundle::read(&bytes).unwrap();
        assert_eq!(app["id"], b.manifest.id.as_str());
        let stamp = SignedStamp::decode(b.stamp.unwrap()).unwrap();
        stamp.check(&root, Some(NOW), &b).unwrap();
        // stamped by the new catalogue key: a maki still on root 1 won't take it
        assert_eq!(stamp.check(&root1, Some(NOW), &b), Err(Error::Signature));
    }

    let list = SignedRevocations::decode(&file("revocations.bin")).unwrap();
    list.replaces(&root, Some(NOW), None).unwrap();
    assert!(list.list.check("com.leviathan.maki.tally", 1, &[0; 32]).is_some());
    assert!(list.list.check("com.leviathan.maki.tally", 2, &[0; 32]).is_none());
}
