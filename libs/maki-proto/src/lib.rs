//! maki's serial protocol: framing, messages, and the device-side logic.
//!
//! Shared by the firmware service (`services/maki-link`) and `examples/fake_maki.rs`, a host
//! stand-in the desktop app can reach over TCP. The wire format is specified in `PROTOCOL.md`
//! beside this crate; keep the two in step.

pub mod device;
pub mod frame;
pub mod wire;

/// Message kinds. Replies set the top bit of the request they answer.
pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const STATUS: u8 = 0x02;
    pub const TIME_CHALLENGE: u8 = 0x03;
    pub const TIME_PROOF: u8 = 0x04;
    pub const TIME_UNVERIFIED: u8 = 0x05;
    pub const REPLY: u8 = 0x80;
    pub const ERROR: u8 = 0x7f;
}
