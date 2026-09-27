//! Passkey records are read by the backup and the Passkeys app: any bytes must be read or turned
//! away, never panic.

use std::panic::catch_unwind;

#[test]
fn no_record_panics_the_reader() {
    let mut x: u64 = 0xdead_beef_cafe_f00d;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..100_000 {
        let len = (next() % 80) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        // start most as maps, to get past the first byte
        if next() % 2 == 0 && !b.is_empty() {
            b[0] = 0xa0 | (b[0] & 0x1f);
        }
        let r = catch_unwind(|| {
            let _ = maki_fido::credential_id(&b);
            let _ = maki_fido::summary(&b);
            let _ = maki_fido::backed_up(&String::from_utf8_lossy(&b));
        });
        assert!(r.is_ok(), "panicked on {b:02x?}");
    }
}
