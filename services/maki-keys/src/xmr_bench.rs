//! Built with MAKI_DEMO_XMR_BENCH: how long spending Monero takes maki. Once it has started, on
//! made-up keys, it times the curve work a transaction needs of it (`maki_xmr::sign`), the range
//! proof, and a whole transaction as maki makes and signs one (`maki_xmr::spend`), and logs it
//! (`xmr bench: ...`), in maki's own time: the emulator's, or a badge's.

use maki_xmr::bulletproof::{self, Generators};
use maki_xmr::request::{Input, Member, Payment, Request, read_destination};
use maki_xmr::sign::{self, G, Scalar};
use maki_xmr::{Keys, Network, spend};

fn scalar(n: u64) -> Scalar { Scalar::from_bytes_mod_order(maki_xmr::keccak(&n.to_le_bytes())) }

pub fn spawn() {
    std::thread::spawn(|| {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        // after the rest of startup, so as not to be timed with it
        tt.sleep_ms(20_000).ok();
        let time = |what: &str, runs: u64, f: &mut dyn FnMut(u64)| {
            let start = tt.elapsed_ms();
            for i in 0..runs {
                f(i);
            }
            let ms = tt.elapsed_ms() - start;
            log::warn!(
                "xmr bench: {what}: {}.{:01} ms each ({runs} in {ms} ms)",
                ms / runs,
                ms * 10 / runs % 10
            );
        };
        time("hash onto the curve", 8, &mut |i| {
            core::hint::black_box(sign::hash_to_point(&i.to_le_bytes()));
        });
        time("scalar multiplication", 8, &mut |i| {
            core::hint::black_box(G * scalar(i));
        });
        time("key image", 8, &mut |i| {
            core::hint::black_box(sign::key_image(&scalar(i), &(G * scalar(i + 100))));
        });
        // a ring of 16, as Monero's are, signed for its eighth member
        let (secret, mask, pseudo_mask, amount) = (scalar(1), scalar(2), scalar(3), 1_234_567_890_000u64);
        let ring: Vec<sign::Member> = (0..16u64)
            .map(|i| {
                if i == 7 {
                    sign::Member { key: G * secret, commitment: sign::commit(&mask, amount) }
                } else {
                    sign::Member { key: G * scalar(100 + i), commitment: sign::commit(&scalar(200 + i), i) }
                }
            })
            .collect();
        let pseudo_out = sign::commit(&pseudo_mask, amount);
        time("CLSAG, a ring of 16", 2, &mut |i| {
            let signed =
                sign::clsag(&ring, 7, &secret, &(mask - pseudo_mask), &pseudo_out, &[i as u8; 32], &[0; 32]);
            if signed.is_err() {
                log::warn!("xmr bench: CLSAG refused: {signed:?}");
            }
        });
        // the range proof for two outputs: making its 256 generators the first time, then kept
        let mut generators = Generators::new();
        let outputs = [(1_000_000u64, scalar(5)), (2_000_000u64, scalar(6))];
        time("range proof, two outputs, generators made", 1, &mut |_| {
            core::hint::black_box(bulletproof::prove(&mut generators, &outputs, &mut || scalar(7)));
        });
        time("range proof, two outputs", 1, &mut |_| {
            core::hint::black_box(bulletproof::prove(&mut generators, &outputs, &mut || scalar(7)));
        });
        // a whole transaction, as maki signs one: two inputs, a payment and change
        let (keys, request) = transaction();
        time("a transaction, two inputs, two outputs", 1, &mut |i| match spend::sign_with(
            &keys,
            &request,
            &[i as u8; 32],
            &mut generators,
        ) {
            Ok(signed) => log::warn!("xmr bench: signed {} bytes", signed.transaction.len()),
            Err(e) => log::warn!("xmr bench: not signed: {e}"),
        });
    });
}

/// Made-up keys, and a request spending two outputs paid to them (each in a ring of 16).
fn transaction() -> (Keys, Request) {
    let keys = Keys::from_spend(scalar(1000));
    let (spend, view) = keys.public();
    let (spend, view) = (sign::point(&spend).unwrap(), sign::point(&view).unwrap());
    let inputs = (0..2u64)
        .map(|n| {
            let r = scalar(2000 + n);
            let amount = 5_000_000_000 * (n + 1);
            let out = sign::pay(&r, &view, &spend, 1, amount);
            let ring = (0..16u64)
                .map(|i| Member {
                    global: 1000 * n + 10 * i + 1,
                    key: if i == 3 { out.key } else { (G * scalar(3000 + 16 * n + i)).compress().to_bytes() },
                    commitment: if i == 3 {
                        out.commitment
                    } else {
                        sign::commit(&scalar(4000 + i), i).compress().to_bytes()
                    },
                })
                .collect();
            Input { amount, tx_key: (G * r).compress().to_bytes(), index: 1, subaddress: 0, real: 3, ring }
        })
        .collect();
    let to =
        "49vDbkSo7eve3J41sBdjvjaBUyz8qHohsQcGtRf63qEUTMBvmA45fpp5pSacMdSg7A3b71RejLzB8EkGbfjp5PELVF2N4Zn";
    let payment =
        Payment { address: to.into(), amount: 12_000_000_000, destination: read_destination(to).unwrap().1 };
    let request = Request {
        network: Network::Mainnet,
        account: 0,
        fee: 40_000_000,
        change: 2_960_000_000,
        payments: vec![payment],
        inputs,
    };
    (keys, request)
}
