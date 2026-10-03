//! maki's serial protocol: framing, messages, and the device-side logic.
//!
//! Shared by the firmware service (`services/maki-link`) and `examples/fake_maki.rs`, a host
//! stand-in the desktop app can reach over TCP. The wire format is specified in `PROTOCOL.md`
//! beside this crate; keep the two in step.

pub mod device;
pub mod frame;
pub mod import;
pub mod names;
pub mod site;
pub mod wire;

/// Message kinds. Replies set the top bit of the request they answer.
pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const STATUS: u8 = 0x02;
    pub const TIME_CHALLENGE: u8 = 0x03;
    pub const TIME_PROOF: u8 = 0x04;
    pub const TIME_UNVERIFIED: u8 = 0x05;
    /// Restart maki into its boot stage's update mode, where maki desktop puts new firmware on
    /// it; answered once the owner decides, and on a yes, maki restarts.
    pub const UPDATE_MODE: u8 = 0x06;
    /// Which wallet maki's wallet apps have: none (maki is locked), the recovery phrase's own, or
    /// a passphrase wallet, and its master key's fingerprint, so maki desktop keeps each wallet's
    /// accounts apart.
    pub const WALLET_STATUS: u8 = 0x07;
    /// Answered only after the owner approves on maki's screen.
    pub const GET_LOGIN: u8 = 0x10;
    pub const GET_TOTP: u8 = 0x11;
    pub const SAVE_LOGIN: u8 = 0x12;
    /// How many logins, codes and passkeys the vault holds, and how many of the passkeys were
    /// imported. Nothing is asked.
    pub const VAULT_STATUS: u8 = 0x13;
    /// A piece of maki's backup (encrypted with a key from the recovery phrase).
    pub const BACKUP_GET: u8 = 0x20;
    /// A piece of a backup to restore; the last is answered once the owner decides.
    pub const BACKUP_PUT: u8 = 0x21;
    /// A piece of an import from another password manager (`import`); the last is answered once
    /// maki has checked every record and the owner decides.
    pub const IMPORT_PUT: u8 = 0x22;
    /// The apps installed on maki, one per request.
    pub const APP_LIST: u8 = 0x50;
    /// A piece of a `.maki` bundle to install; the last is answered once the owner decides.
    pub const APP_INSTALL: u8 = 0x51;
    /// An app to remove, answered once the owner decides.
    pub const APP_REMOVE: u8 = 0x52;
    /// A message for an app with the link permission, answered with the app's reply.
    pub const APP_MESSAGE: u8 = 0x53;
    /// A piece of a maki store record (a new root, a revocation list), checked and kept by
    /// maki; or, with nothing, what maki has.
    pub const STORE_UPDATE: u8 = 0x54;
    /// How much of maki's room for apps is taken, and how many more apps it has room for.
    pub const APP_SPACE: u8 = 0x55;
    pub const REPLY: u8 = 0x80;
    pub const ERROR: u8 = 0x7f;
}
