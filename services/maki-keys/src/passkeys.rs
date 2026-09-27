//! Passkeys in the backup: the resident credentials and signature counter of the vault's FIDO
//! authenticator, read with `maki_fido`.

pub(crate) use maki_fido::{backed_up, credential_id, COUNTER, CREDENTIALS, DICT};

/// The emulator has no USB, so no passkey can be made there. Built with MAKI_DEMO_BACKUP, a
/// backup gets a made-up one (for "demo.maki"), taken out again once the backup is sealed, so
/// the demo's restore has a passkey to bring back. Never in a badge's build.
pub(crate) fn plant_demo(pddb: &pddb::Pddb, basis: &str) -> bool {
    use std::io::Write;
    let slot = CREDENTIALS.start.to_string();
    if pddb.get(DICT, &slot, Some(basis), false, false, None, None::<fn()>).is_ok() {
        return false;
    }
    // {0: id, 2: "demo.maki", 3: user handle, 12: [-7 (ES256), private key]}
    let mut c = vec![0xa4, 0x00, 0x58, 0x20];
    c.extend((0..32u8).map(|i| 0xd0 ^ i));
    c.extend([0x02, 0x69]);
    c.extend(b"demo.maki");
    c.extend([0x03, 0x44, 0x6d, 0x61, 0x6b, 0x69]);
    c.extend([0x0c, 0x82, 0x26, 0x58, 0x20]);
    c.extend((1..=32u8).collect::<Vec<_>>());
    let written = pddb
        .get(DICT, &slot, Some(basis), true, true, Some(c.len()), None::<fn()>)
        .and_then(|mut k| k.write_all(&c))
        .is_ok();
    pddb.sync().ok();
    log::warn!("demo: a made-up passkey for the backup ({})", if written { "planted" } else { "couldn't" });
    written
}

pub(crate) fn unplant_demo(pddb: &pddb::Pddb, basis: &str) {
    pddb.delete_key(DICT, &CREDENTIALS.start.to_string(), Some(basis)).ok();
    pddb.sync().ok();
    log::warn!("demo: the made-up passkey taken out again, for the restore to bring back");
}
