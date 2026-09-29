//! How long spending takes on this computer, for comparison with maki's (MAKI_DEMO_XMR_BENCH in
//! maki-keys): `cargo run --release -p maki-xmr --features keys --example bench`.
use std::time::Instant;

use maki_xmr::bulletproof::{self, Generators};
use maki_xmr::sign::{self, Member, Scalar, G};
use maki_xmr::{request, spend, Keys, Network};

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
    let mut generators = Generators::new();
    let outputs = [(1_000_000u64, scalar(5)), (2_000_000u64, scalar(6))];
    time("range proof, two outputs, generators made", 1, |_| {
        std::hint::black_box(bulletproof::prove(&mut generators, &outputs, &mut || scalar(7)));
    });
    time("range proof, two outputs", 16, |_| {
        std::hint::black_box(bulletproof::prove(&mut generators, &outputs, &mut || scalar(7)));
    });
    let keys = Keys::from_spend(scalar(1000));
    let (spend_key, view_key) = keys.public();
    let (spend_key, view_key) = (sign::point(&spend_key).unwrap(), sign::point(&view_key).unwrap());
    let inputs = (0..2u64)
        .map(|n| {
            let r = scalar(2000 + n);
            let amount = 5_000_000_000 * (n + 1);
            let out = sign::pay(&r, &view_key, &spend_key, 1, amount);
            let ring = (0..16u64)
                .map(|i| request::Member {
                    global: 1000 * n + 10 * i + 1,
                    key: if i == 3 { out.key } else { (G * scalar(3000 + 16 * n + i)).compress().to_bytes() },
                    commitment: if i == 3 { out.commitment } else { sign::commit(&scalar(4000 + i), i).compress().to_bytes() },
                })
                .collect();
            request::Input { amount, tx_key: (G * r).compress().to_bytes(), index: 1, subaddress: 0, real: 3, ring }
        })
        .collect();
    let to = "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn";
    let payment = request::Payment { address: to.into(), amount: 12_000_000_000, destination: request::read_destination(to).unwrap().1 };
    let request = request::Request { network: Network::Mainnet, account: 0, fee: 40_000_000, change: 2_960_000_000, payments: vec![payment], inputs };
    time("a transaction, two inputs, two outputs", 16, |i| {
        spend::sign_with(&keys, &request, &[i as u8; 32], &mut generators).unwrap();
    });
}
