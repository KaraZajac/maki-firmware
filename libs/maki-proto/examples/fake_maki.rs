//! A host stand-in for maki: the real protocol logic behind a TCP socket.
//!
//!     cargo run -p maki-proto --example fake_maki [ADDR]      # default 127.0.0.1:7878
//!
//! The desktop app connects to it as if it were a badge. Everything maki-link does on the device
//! happens here too, except the USB hop and the Xous clock. State survives reconnects, like a badge
//! that stays plugged in.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use maki_proto::device::{Device, Platform, TimeState};
use maki_proto::frame::{self, Deframer};

struct Host {
    start: Instant,
    clock: Option<(u64, Instant)>,
}

fn host_utc_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }

impl Platform for Host {
    fn fill_random(&mut self, buf: &mut [u8]) {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("no /dev/urandom");
    }

    fn uptime_ms(&self) -> u64 { self.start.elapsed().as_millis() as u64 }

    fn utc_ms(&self) -> Option<u64> { self.clock.map(|(t, at)| t + at.elapsed().as_millis() as u64) }

    fn set_time(&mut self, utc_ms: u64, tz_offset_s: i32) {
        let drift = utc_ms as i64 - host_utc_ms() as i64;
        println!("  clock set: {utc_ms} ms UTC, tz {tz_offset_s:+} s ({drift:+} ms from this computer)");
        self.clock = Some((utc_ms, Instant::now()));
    }

    fn time_state_changed(&mut self, state: TimeState) { println!("  time is now {state:?}"); }
}

fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:7878".into());
    let listener = TcpListener::bind(&addr).expect("bind");
    // print the bound address, so a caller that asked for port 0 learns the real one
    println!("fake maki listening on {}", listener.local_addr().unwrap());
    let mut device = Device::new(Host { start: Instant::now(), clock: None }, "maki", "0.1.0-fake".into());
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        println!("connected: {:?}", stream.peer_addr());
        let mut deframer = Deframer::default();
        let mut buf = [0u8; 4096];
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for packet in deframer.push(&buf[..n]) {
                match packet {
                    Ok(packet) => {
                        let (kind, body) = device.handle(&packet);
                        println!("  0x{:02x} ({} bytes) -> 0x{:02x} ({} bytes)", packet.kind, packet.body.len(), kind, body.len());
                        if stream.write_all(&frame::encode(kind, &body)).is_err() {
                            break;
                        }
                    }
                    Err(e) => println!("  bad frame: {e:?}"),
                }
            }
        }
        println!("disconnected");
    }
}
