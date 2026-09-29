//! How long spending takes on this computer, for comparison with maki's (MAKI_DEMO_XMR_BENCH in
//! maki-keys): `cargo run --release -p maki-xmr --features keys --example bench`.
use std::time::Instant;

use maki_xmr::sign::{self, Member, Scalar, G};

fn scalar(n: u64) -> Scalar { Scalar::from_bytes_mod_order(maki_xmr::keccak(&n.to_le_bytes())) }

fn time(what: &str, runs: u32, mut f: impl FnMut(u32)) {
    let start = Instant::now();
    for i in 0..runs {
        f(i);
    }
    println!("{what}: {:.3} ms each", start.elapsed().as_secs_f64() * 1000.0 / runs as f64);
}

fn main() {
    time("hash onto the curve", 64, |i| {
        std::hint::black_box(sign::hash_to_point(&i.to_le_bytes()));
    });
    time("scalar multiplication", 64, |i| {
        std::hint::black_box(G * scalar(i as u64));
    });
    let (secret, mask, pseudo_mask, amount) = (scalar(1), scalar(2), scalar(3), 1_234_567_890_000u64);
    let ring: Vec<Member> = (0..16u64)
        .map(|i| match i {
            7 => Member { key: G * secret, commitment: sign::commit(&mask, amount) },
            _ => Member { key: G * scalar(100 + i), commitment: sign::commit(&scalar(200 + i), i) },
        })
        .collect();
    let pseudo_out = sign::commit(&pseudo_mask, amount);
    time("CLSAG, a ring of 16", 16, |i| {
        sign::clsag(&ring, 7, &secret, &(mask - pseudo_mask), &pseudo_out, &[i as u8; 32], &[0; 32]).unwrap();
    });
}
