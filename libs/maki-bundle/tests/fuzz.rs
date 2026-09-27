//! maki reads bundles from the computer: any bytes must be read or turned away, never panic.

use std::panic::catch_unwind;

use ed25519_dalek::SigningKey;
use maki_bundle::*;

#[test]
fn no_bundle_panics_the_reader() {
    let mut x: u64 = 0x5eed_0f_5eed_0f;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let good = write(
        &Manifest {
            id: "org.example.fuzz".into(),
            name: "Fuzz".into(),
            version: 1,
            label: String::new(),
            kind: Kind::Wasm,
            api: 1,
            firmware: String::new(),
            permissions: vec![(Permission::Link, "because".into())],
            storage_kib: 1,
            memory_kib: 64,
            backup: false,
            description: String::new(),
        },
        b"\0asm\x01\0\0\0",
        Some(&[0u32; ICON_WORDS]),
        &SigningKey::from_bytes(&[1u8; 32]),
    )
    .unwrap();
    for round in 0..50_000 {
        // mostly the good bundle with a few bytes changed, sometimes noise
        let b: Vec<u8> = if round % 8 == 0 {
            let len = (next() % 700) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if b.len() >= 5 {
                b[..5].copy_from_slice(b"MAKI\x01");
            }
            b
        } else {
            let mut b = good.clone();
            for _ in 0..1 + next() % 4 {
                let i = (next() as usize) % b.len();
                b[i] = next() as u8;
            }
            if next() % 4 == 0 {
                b.truncate((next() as usize) % b.len());
            }
            b
        };
        let r = catch_unwind(|| {
            if let Ok(bundle) = read(&b) {
                let _ = fingerprint(&bundle.developer);
            }
        });
        assert!(r.is_ok(), "panicked on {b:02x?}");
    }
}
