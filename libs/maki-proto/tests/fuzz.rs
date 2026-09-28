//! Every byte from the host goes through the deframer and the device logic on maki: anything,
//! however broken, must get an error reply or be dropped, never a panic.

use std::panic::{catch_unwind, AssertUnwindSafe};

use maki_proto::device::{Device, Platform, TimeState};
use maki_proto::frame::{self, Deframer, Packet};
use maki_proto::kind;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize { (self.next() % n.max(1) as u64) as usize }
}

struct Host;
impl Platform for Host {
    fn fill_random(&mut self, buf: &mut [u8]) { buf.fill(7) }
    fn uptime_ms(&self) -> u64 { 1_000 }
    fn utc_ms(&self) -> Option<u64> { None }
    fn set_time(&mut self, _: u64, _: i32) {}
    fn time_state_changed(&mut self, _: TimeState) {}
}

const KINDS: [u8; 24] = [
    kind::HELLO,
    kind::STATUS,
    kind::TIME_CHALLENGE,
    kind::TIME_PROOF,
    kind::TIME_UNVERIFIED,
    kind::GET_LOGIN,
    kind::GET_TOTP,
    kind::SAVE_LOGIN,
    kind::BACKUP_GET,
    kind::BACKUP_PUT,
    kind::BTC_ACCOUNT,
    kind::BTC_ADDRESS,
    kind::BTC_SIGN,
    kind::BTC_SIGNED,
    kind::ETH_ACCOUNT,
    kind::ETH_SIGN_TX,
    kind::ETH_SIGNED,
    kind::ETH_SIGN_MESSAGE,
    kind::ETH_SIGN_TYPED,
    kind::APP_LIST,
    kind::APP_INSTALL,
    kind::APP_REMOVE,
    kind::APP_MESSAGE,
    kind::STORE_UPDATE,
];

#[test]
fn nothing_the_host_sends_panics_maki() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut device = Device::new(Host, "maki", "test".into());
    let mut deframer = Deframer::default();
    for i in 0..50_000 {
        // a message body for a real kind, random or shaped like one (a site, then numbers)
        let kind = KINDS[rng.below(KINDS.len())];
        let mut body: Vec<u8> = (0..rng.below(64)).map(|_| rng.next() as u8).collect();
        if i % 2 == 0 {
            let site = b"example.com";
            let mut shaped = vec![site.len() as u8];
            shaped.extend(site);
            shaped.extend(body);
            body = shaped;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _ = device.handle(&Packet { kind, id: i as u16, body: body.clone() });
            // and the same as bytes on the wire, sometimes damaged
            let mut wire = frame::encode(kind, i as u16, &body);
            if i % 3 == 0 && !wire.is_empty() {
                let at = rng.below(wire.len());
                wire[at] ^= 1 << rng.below(8);
            }
            for p in deframer.push(&wire).into_iter().flatten() {
                let _ = device.handle(&p);
            }
            // and plain noise
            let noise: Vec<u8> = (0..rng.below(40)).map(|_| rng.next() as u8).collect();
            let _ = deframer.push(&noise);
        }));
        assert!(outcome.is_ok(), "panicked on kind 0x{kind:02x} body {body:02x?}");
    }
}
