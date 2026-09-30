use maki_fido::*;

/// A credential as OpenSK writes one: {0: id, 2: rp, 3: user handle, [8: user name,] 12: [-7, key]}.
fn credential(id: &[u8], rp: &str, user: Option<&str>) -> Vec<u8> {
    let mut c = vec![if user.is_some() { 0xa5 } else { 0xa4 }, 0x00, 0x58, id.len() as u8];
    c.extend(id);
    c.push(0x02);
    c.push(0x60 | rp.len() as u8);
    c.extend(rp.as_bytes());
    c.extend([0x03, 0x41, 0xaa]);
    if let Some(u) = user {
        c.extend([0x08, 0x60 | u.len() as u8]);
        c.extend(u.as_bytes());
    }
    c.extend([0x0c, 0x82, 0x26, 0x58, 0x20]);
    c.extend((100..132u8).collect::<Vec<_>>());
    c
}

#[test]
fn reads_what_opensk_writes() {
    let id: Vec<u8> = (1..=32).collect();
    let c = credential(&id, "example.com", Some("kara"));
    assert_eq!(credential_id(&c), Some(&id[..]));
    assert_eq!(summary(&c), Some(Summary { rp_id: "example.com", user: Some("kara") }));
    let c = credential(&id, "github.com", None);
    assert_eq!(summary(&c), Some(Summary { rp_id: "github.com", user: None }));
}

#[test]
fn finds_its_way_past_nested_items() {
    // key 0 after a nested map, a float and a tag
    let id: Vec<u8> = (1..=16).collect();
    let mut d =
        vec![0xa3, 0x02, 0xa1, 0x01, 0x82, 0xf9, 0x3c, 0x00, 0xc2, 0x41, 0x05, 0x03, 0xf5, 0x00, 0x50];
    d.extend(&id);
    assert_eq!(credential_id(&d), Some(&id[..]));
    // a display name when there's no user name
    let e = [0xa2, 0x02, 0x63, b'a', b'.', b'b', 0x04, 0x62, b'K', b'Z'];
    assert_eq!(summary(&e), Some(Summary { rp_id: "a.b", user: Some("KZ") }));
}

#[test]
fn turns_away_what_isnt_one() {
    let id: Vec<u8> = (1..=32).collect();
    let c = credential(&id, "example.com", Some("kara"));
    assert_eq!(credential_id(&[0xa1, 0x02, 0x01]), None); // no key 0
    assert_eq!(credential_id(&[0x82, 0x00, 0x01]), None); // not a map
    assert_eq!(credential_id(&c[..20]), None); // cut short
    assert_eq!(credential_id(&[0xbf, 0x00, 0x41, 0x01, 0xff]), None); // indefinite length
    assert_eq!(credential_id(&[0xa1, 0x00, 0x61, 0x61]), None); // key 0 not bytes
    assert_eq!(credential_id(&[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), None); // a huge count
    assert_eq!(summary(&[0xa1, 0x02, 0x42, 0xff, 0xfe]), None); // a site that isn't text
    assert_eq!(summary(&[0xa1, 0x02, 0x62, 0xff, 0xfe]), None); // or isn't UTF-8
}

#[test]
fn backs_up_credentials_and_the_counter_only() {
    assert!(backed_up("1700") && backed_up("1849") && backed_up("2047"));
    // CredRandom and the old master keys come from the phrase now; the rest is per device
    for k in ["1850", "2046", "2041", "3", "2045", "x", ""] {
        assert!(!backed_up(k), "{k}");
    }
}
