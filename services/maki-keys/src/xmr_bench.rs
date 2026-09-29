//! Built with MAKI_DEMO_XMR_BENCH: how long spending Monero takes maki. Once it has started, on
//! made-up keys, it times the curve work a transaction needs of it (`maki_xmr::sign`) and logs
//! it (`xmr bench: ...`), in maki's own time: the emulator's, or a badge's.

use maki_xmr::sign::{self, Member, Scalar, G};

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
            log::warn!("xmr bench: {what}: {}.{:01} ms each ({runs} in {ms} ms)", ms / runs, ms * 10 / runs % 10);
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
        let ring: Vec<Member> = (0..16u64)
            .map(|i| {
                if i == 7 {
                    Member { key: G * secret, commitment: sign::commit(&mask, amount) }
                } else {
                    Member { key: G * scalar(100 + i), commitment: sign::commit(&scalar(200 + i), i) }
                }
            })
            .collect();
        let pseudo_out = sign::commit(&pseudo_mask, amount);
        time("CLSAG, a ring of 16", 2, &mut |i| {
            let signed = sign::clsag(&ring, 7, &secret, &(mask - pseudo_mask), &pseudo_out, &[i as u8; 32], &[0; 32]);
            if signed.is_err() {
                log::warn!("xmr bench: CLSAG refused: {signed:?}");
            }
        });
    });
}
