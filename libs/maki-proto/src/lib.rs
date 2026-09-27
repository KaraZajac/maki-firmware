//! maki's serial protocol: framing, messages, and the device-side logic.
//!
//! Shared by the firmware service (`services/maki-link`) and `examples/fake_maki.rs`, a host
//! stand-in the desktop app can reach over TCP. The wire format is specified in `PROTOCOL.md`
//! beside this crate; keep the two in step.

pub mod device;
pub mod frame;
pub mod site;
pub mod wire;

/// Message kinds. Replies set the top bit of the request they answer.
pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const STATUS: u8 = 0x02;
    pub const TIME_CHALLENGE: u8 = 0x03;
    pub const TIME_PROOF: u8 = 0x04;
    pub const TIME_UNVERIFIED: u8 = 0x05;
    /// Answered only after the owner approves on maki's screen.
    pub const GET_LOGIN: u8 = 0x10;
    pub const GET_TOTP: u8 = 0x11;
    pub const SAVE_LOGIN: u8 = 0x12;
    /// A piece of maki's backup (encrypted with a key from the recovery phrase).
    pub const BACKUP_GET: u8 = 0x20;
    /// A piece of a backup to restore; the last is answered once the owner decides.
    pub const BACKUP_PUT: u8 = 0x21;
    /// The Bitcoin account for wallet software, once the owner agrees.
    pub const BTC_ACCOUNT: u8 = 0x30;
    /// An address, put on maki's screen for the owner to compare.
    pub const BTC_ADDRESS: u8 = 0x31;
    /// A piece of a PSBT to sign; the last is answered once the owner decides.
    pub const BTC_SIGN: u8 = 0x32;
    /// A piece of the PSBT maki signed.
    pub const BTC_SIGNED: u8 = 0x33;
    /// The Ethereum account's address, once the owner lets the site connect.
    pub const ETH_ACCOUNT: u8 = 0x40;
    /// A piece of an Ethereum transaction to sign; the last is answered once the owner decides.
    pub const ETH_SIGN_TX: u8 = 0x41;
    /// A piece of the transaction maki signed.
    pub const ETH_SIGNED: u8 = 0x42;
    /// A message to sign (EIP-191 personal_sign), answered once the owner decides.
    pub const ETH_SIGN_MESSAGE: u8 = 0x43;
    pub const REPLY: u8 = 0x80;
    pub const ERROR: u8 = 0x7f;
}
