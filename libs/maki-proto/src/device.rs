//! The device side: what maki does with each message, independent of how bytes arrive or how
//! the clock gets set. `services/maki-link` supplies a Xous `Platform`; the fake supplies a host one.

use roughtime::REQUEST_LEN;

use crate::frame::Packet;
use crate::kind;
use crate::wire::{Reader, Truncated, Writer};

/// A Roughtime server maki trusts. The key is pinned here, never supplied by the host: the host
/// only carries packets, and a key it chose would let it choose the time.
pub struct Server {
    pub id: u8,
    pub host: &'static str,
    pub port: u16,
    pub key: [u8; 32],
}

/// Keys fetched from each server's DNS TXT record and checked against live answers, 2026-09-26.
pub const SERVERS: [Server; 3] = [
    Server {
        id: 0,
        host: "time.txryan.com",
        port: 2002,
        key: [
            0x88, 0x15, 0x63, 0xc6, 0x0f, 0xf5, 0x8f, 0xbc, 0xb5, 0xfa, 0x44, 0x14, 0x4c, 0x16, 0x1d, 0x4d,
            0xa6, 0xf1, 0x0a, 0x9a, 0x5e, 0xb1, 0x4f, 0xf4, 0xec, 0x3e, 0x0f, 0x30, 0x32, 0x64, 0xd9, 0x60,
        ],
    },
    Server {
        id: 1,
        host: "roughtime.se",
        port: 2002,
        key: [
            0x4b, 0x70, 0x33, 0x7d, 0x92, 0x79, 0x0a, 0x34, 0x9d, 0x90, 0x9d, 0xb5, 0x64, 0x91, 0x9b, 0xc6,
            0xa7, 0x58, 0x3f, 0xf4, 0xa8, 0x13, 0xc7, 0xd7, 0x29, 0x8d, 0x3e, 0x6a, 0x27, 0x2c, 0x7a, 0x12,
        ],
    },
    Server {
        id: 2,
        host: "roughtime.int08h.com",
        port: 2002,
        key: [
            0x01, 0x6e, 0x6e, 0x02, 0x84, 0xd2, 0x4c, 0x37, 0xc6, 0xe4, 0xd7, 0xd8, 0xd5, 0xb4, 0xe1, 0xd3,
            0xc1, 0x94, 0x9c, 0xea, 0xa5, 0x45, 0xbf, 0x87, 0x56, 0x16, 0xc9, 0xdc, 0xe0, 0xc9, 0xbe, 0xc1,
        ],
    },
];

/// A proof must arrive this soon after its challenge.
pub const CHALLENGE_TTL_MS: u64 = 30_000;
/// Verified answers needed before maki believes a time: one server alone can't set the clock.
pub const MIN_AGREEING: usize = 2;
/// Answers claiming worse accuracy than this are not used.
pub const MAX_RADIUS_S: u32 = 10;
/// UTC offsets run from -12:00 to +14:00.
pub const TZ_RANGE_S: core::ops::RangeInclusive<i32> = -12 * 3600..=14 * 3600;
/// No honest clock reads earlier than this (2026-01-01); rejects zeroed or garbage times.
pub const EARLIEST_UTC_MS: u64 = 1_767_225_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeState {
    Unset = 0,
    /// Set from the host's own clock: displayed, but not trusted.
    Unverified = 1,
    /// Set from agreeing, signed Roughtime answers.
    Verified = 2,
}

/// Outcome of a `TIME_PROOF`, first byte of its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofStatus {
    Set = 0,
    TooFewVerified = 1,
    Disagree = 2,
}

/// Per-answer result in a `TIME_PROOF` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnswerStatus {
    Verified = 0,
    UnknownServer = 1,
    Duplicate = 2,
    Invalid = 3,
    TooImprecise = 4,
}

/// Codes carried by an `ERROR` reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    Malformed = 1,
    UnknownKind = 2,
    NoChallenge = 3,
    ChallengeExpired = 4,
    BadArgument = 5,
}

/// What `Device::handle` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    /// Answer now, with this kind and body.
    Reply(u8, Vec<u8>),
    /// Needs the owner. The glue asks the vault, which shows the request on maki's screen, and
    /// answers later with the matching builder in [`reply`], echoing the request's id.
    Ask(Ask),
    /// A piece of the backup, either way: the glue passes it to maki-keys and answers with
    /// [`reply::backup_piece`] or [`reply::restore_piece`].
    Backup(Backup),
    /// The Bitcoin wallet: the glue passes it to maki-keys, which asks the owner where it must,
    /// and answers with the matching `reply::btc_*`.
    Bitcoin(Bitcoin),
    /// The Ethereum account, the same way, with `reply::eth_*`.
    Ethereum(Ethereum),
    /// Installed apps: the glue passes these to maki's app host, which checks bundles and asks
    /// the owner, and answers with `reply::app_*`.
    Apps(Apps),
}

/// Installed apps (ARCHITECTURE.md, "Apps you can install").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Apps {
    List { index: u32 },
    Install { total: u32, offset: u32, data: Vec<u8> },
    Remove { id: String },
    Message { id: String, message: Vec<u8> },
    /// `total` 0: just what maki has.
    StoreUpdate { total: u32, offset: u32, data: Vec<u8> },
    Space,
}

/// Pieces of a bundle are at most this big.
pub const APP_PIECE: usize = 4096;
/// The biggest bundle maki takes (`maki_bundle::MAX_BUNDLE`).
pub const MAX_APP: u32 = 512 * 1024;
/// The biggest message to or from an app (`maki_wasm::MAX_MESSAGE`).
pub const MAX_APP_MESSAGE: usize = 4096;
/// Pieces of a store record are at most this big.
pub const STORE_PIECE: usize = 4096;
/// The biggest store record maki takes (`maki_app_host_api::MAX_STORE_RECORD`).
pub const MAX_STORE_RECORD: u32 = 64 * 1024;

/// What maki has of the maki store, as STORE_UPDATE's reply says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreState {
    /// The version of the store root maki trusts.
    pub root: u32,
    /// The version of the newest revocation list it took, 0 for none.
    pub revocations: u32,
    /// When that list goes stale, unix seconds (0 for none).
    pub revocations_expires: u64,
}

/// An installed app, as APP_LIST describes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppEntry {
    /// Reverse-DNS: `com.example.dice`.
    pub id: String,
    pub name: String,
    pub version: u32,
    /// The version as people write it; may be empty.
    pub label: String,
    /// The developer's Ed25519 key, 32 bytes.
    pub developer: Vec<u8>,
    /// Reviewed and stamped by the maki store; otherwise sideloaded.
    pub from_store: bool,
    /// Whether its data goes in maki's backup: the owner's choice.
    pub backup: bool,
    /// Bytes of storage it uses.
    pub used: u32,
    /// 64x64 in `maki_icons` form as little-endian words (512 bytes), or empty.
    pub icon: Vec<u8>,
    /// Bytes its bundle takes on maki.
    pub bundle: u32,
    /// Bytes of storage its manifest asks for: what it may use, kept for it.
    pub storage: u32,
}

/// maki's room for apps: its bundles and the storage each asks for, within `space` bytes, and
/// at most `max_apps` of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AppSpace {
    pub apps: u32,
    pub max_apps: u32,
    pub space: u32,
    /// What the apps installed take: their bundles and the storage each asks for.
    pub taken: u32,
}

/// Whether `id` is an app ID as bundles have them: reverse-DNS, lower case.
pub fn app_id_valid(id: &str) -> bool {
    id.len() >= 3
        && id.len() <= 64
        && id.contains('.')
        && id.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Ethereum requests come from a site (the browser extension's EIP-1193 provider), which maki
/// shows the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ethereum {
    Account { site: String, index: u32 },
    Sign { site: String, index: u32, total: u32, offset: u32, data: Vec<u8> },
    Signed { offset: u32 },
    Message { site: String, index: u32, message: Vec<u8> },
    /// A piece of typed data (EIP-712, as JSON) to sign.
    Typed { site: String, index: u32, total: u32, offset: u32, data: Vec<u8> },
}

/// Pieces of an Ethereum transaction are at most this big, either way.
pub const TX_PIECE: usize = 4096;
/// The biggest transaction maki takes in: room for the largest contract a deployment may carry.
pub const MAX_TX: u32 = 128 * 1024;
/// The longest message maki signs, in one piece.
pub const MAX_MESSAGE: usize = 4096;
/// The most typed data maki takes in, in pieces of `TX_PIECE` (`maki_eth::typed::MAX_TYPED`).
pub const MAX_TYPED: u32 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bitcoin {
    Account { network: u8, account: u8 },
    Address { network: u8, change: bool, index: u32, account: u8 },
    Sign { network: u8, total: u32, offset: u32, data: Vec<u8> },
    Signed { offset: u32 },
}

/// `network` in Bitcoin requests: bitcoin itself, or the test networks (testnet and signet share
/// addresses and keys).
pub const NETWORK_BITCOIN: u8 = 0;
pub const NETWORK_TESTNET: u8 = 1;
/// `account` in Bitcoin requests: native SegWit (BIP84), or taproot (BIP86).
pub const ACCOUNT_SEGWIT: u8 = 0;
pub const ACCOUNT_TAPROOT: u8 = 1;
/// Pieces of a PSBT are at most this big, either way.
pub const PSBT_PIECE: usize = 4096;
/// The biggest PSBT maki takes in.
pub const MAX_PSBT: u32 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backup {
    Get { offset: u32 },
    Put { total: u32, offset: u32, data: Vec<u8> },
}

/// Pieces of a backup are at most this big.
pub const BACKUP_PIECE: usize = 4096;
/// The biggest backup a restore takes in.
pub const MAX_BACKUP: u32 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    Login { site: String },
    Totp { site: String },
    SaveLogin { site: String, username: String, password: String },
}

/// First byte of every approval reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Approval {
    Approved = 0,
    Denied = 1,
    /// Nothing saved for this site; the owner was not asked.
    NoMatch = 2,
    /// The owner didn't answer in time.
    TimedOut = 3,
    /// The vault couldn't be reached or its storage isn't ready.
    Unavailable = 4,
    /// A code needs a clock verified by Roughtime. The host's word isn't enough: a host that
    /// could set the clock could collect codes for times still to come.
    ClockNotVerified = 5,
    /// maki is waiting for its PIN; nothing is asked before then.
    Locked = 6,
    /// A backup this maki's recovery phrase can't open: another maki's, or damaged.
    NotYours = 7,
    /// No recovery phrase yet: nothing to back up with, or open a backup with.
    NoPhrase = 8,
    /// A PSBT maki won't sign: not this wallet's, or without what it needs to check it. The
    /// reply says why; the owner wasn't asked.
    Refused = 9,
}

impl Approval {
    pub fn from_u8(v: u8) -> Option<Approval> {
        Some(match v {
            0 => Approval::Approved,
            1 => Approval::Denied,
            2 => Approval::NoMatch,
            3 => Approval::TimedOut,
            4 => Approval::Unavailable,
            5 => Approval::ClockNotVerified,
            6 => Approval::Locked,
            7 => Approval::NotYours,
            8 => Approval::NoPhrase,
            9 => Approval::Refused,
            _ => return None,
        })
    }
}

/// Reply bodies for [`Ask`] outcomes, so the device glue and the fake build them identically.
pub mod reply {
    use super::Approval;
    use crate::kind;
    use crate::wire::Writer;

    pub fn login(approval: Approval, username: &str, password: &str) -> (u8, Vec<u8>) {
        let (u, p) = if approval == Approval::Approved { (username, password) } else { ("", "") };
        (kind::GET_LOGIN | kind::REPLY, Writer::new().u8(approval as u8).str8(u).str8(p).finish())
    }

    pub fn totp(approval: Approval, code: &str, valid_for_s: u8) -> (u8, Vec<u8>) {
        let (c, v) = if approval == Approval::Approved { (code, valid_for_s) } else { ("", 0) };
        (kind::GET_TOTP | kind::REPLY, Writer::new().u8(approval as u8).str8(c).u8(v).finish())
    }

    pub fn save(approval: Approval) -> (u8, Vec<u8>) {
        (kind::SAVE_LOGIN | kind::REPLY, Writer::new().u8(approval as u8).finish())
    }

    /// A piece of the backup: `status` is `Approved` with the piece, or why not (`Locked`,
    /// `NoPhrase`, `Unavailable`) with nothing.
    pub fn backup_piece(status: Approval, total: u32, offset: u32, data: &[u8]) -> (u8, Vec<u8>) {
        let data = if status == Approval::Approved { data } else { &[] };
        (kind::BACKUP_GET | kind::REPLY, Writer::new().u8(status as u8).u32(total).u32(offset).bytes16(data).finish())
    }

    /// The Ethereum account's address (EIP-55), when the owner let the site connect.
    pub fn eth_account(approval: Approval, address: &str) -> (u8, Vec<u8>) {
        let a = if approval == Approval::Approved { address } else { "" };
        (kind::ETH_ACCOUNT | kind::REPLY, Writer::new().u8(approval as u8).str8(a).finish())
    }

    /// A transaction piece taken in (`done` false), or the outcome (`done` true): approved with
    /// the signed transaction's size, to fetch with ETH_SIGNED, or refused with the reason.
    pub fn eth_sign(done: bool, approval: Approval, signed_total: u32, reason: &str) -> (u8, Vec<u8>) {
        let total = if approval == Approval::Approved { signed_total } else { 0 };
        let reason = if approval == Approval::Refused { reason } else { "" };
        (kind::ETH_SIGN_TX | kind::REPLY, Writer::new().u8(done as u8).u8(approval as u8).u32(total).str8(reason).finish())
    }

    /// A piece of the signed transaction, ready for `eth_sendRawTransaction`.
    pub fn eth_signed(status: Approval, total: u32, offset: u32, data: &[u8]) -> (u8, Vec<u8>) {
        let data = if status == Approval::Approved { data } else { &[] };
        (kind::ETH_SIGNED | kind::REPLY, Writer::new().u8(status as u8).u32(total).u32(offset).bytes16(data).finish())
    }

    /// A piece of typed data taken in (`done` false), or the outcome (`done` true): approved with
    /// the signature (r, s, v: 65 bytes), or refused with the reason.
    pub fn eth_typed(done: bool, approval: Approval, signature: &[u8], reason: &str) -> (u8, Vec<u8>) {
        let s = if approval == Approval::Approved { signature } else { &[] };
        let reason = if approval == Approval::Refused { reason } else { "" };
        (kind::ETH_SIGN_TYPED | kind::REPLY, Writer::new().u8(done as u8).u8(approval as u8).bytes16(s).str8(reason).finish())
    }

    /// A message's signature: r, s, v (65 bytes), when approved.
    pub fn eth_message(approval: Approval, signature: &[u8]) -> (u8, Vec<u8>) {
        let s = if approval == Approval::Approved { signature } else { &[] };
        (kind::ETH_SIGN_MESSAGE | kind::REPLY, Writer::new().u8(approval as u8).bytes16(s).finish())
    }

    /// The account for wallet software: its zpub (vpub on test networks) and output descriptor.
    pub fn btc_account(approval: Approval, zpub: &str, descriptor: &str) -> (u8, Vec<u8>) {
        let (z, d) = if approval == Approval::Approved { (zpub, descriptor) } else { ("", "") };
        (kind::BTC_ACCOUNT | kind::REPLY, Writer::new().u8(approval as u8).str8(z).str8(d).finish())
    }

    /// The address maki showed, and whether the owner said it matched (`Approved`) or not
    /// (`Denied`). Empty when maki couldn't show one.
    pub fn btc_address(approval: Approval, address: &str) -> (u8, Vec<u8>) {
        let a = if matches!(approval, Approval::Approved | Approval::Denied) { address } else { "" };
        (kind::BTC_ADDRESS | kind::REPLY, Writer::new().u8(approval as u8).str8(a).finish())
    }

    /// A PSBT piece taken in (`done` false), or the outcome (`done` true): approved with the
    /// signed PSBT's size, to fetch with BTC_SIGNED, or refused with the reason.
    pub fn btc_sign(done: bool, approval: Approval, signed_total: u32, reason: &str) -> (u8, Vec<u8>) {
        let total = if approval == Approval::Approved { signed_total } else { 0 };
        let reason = if approval == Approval::Refused { reason } else { "" };
        (kind::BTC_SIGN | kind::REPLY, Writer::new().u8(done as u8).u8(approval as u8).u32(total).str8(reason).finish())
    }

    /// A piece of the signed PSBT: `Approved` with the piece, or `Unavailable` with nothing (no
    /// PSBT signed since maki was plugged in).
    pub fn btc_signed(status: Approval, total: u32, offset: u32, data: &[u8]) -> (u8, Vec<u8>) {
        let data = if status == Approval::Approved { data } else { &[] };
        (kind::BTC_SIGNED | kind::REPLY, Writer::new().u8(status as u8).u32(total).u32(offset).bytes16(data).finish())
    }

    /// A restore piece taken in (`done` false), or the restore's outcome (`done` true): the
    /// approval, and what it added.
    pub fn restore_piece(done: bool, status: Approval, logins: u16, codes: u16, passkeys: u16) -> (u8, Vec<u8>) {
        let (logins, codes, passkeys) = if status == Approval::Approved { (logins, codes, passkeys) } else { (0, 0, 0) };
        let body = Writer::new().u8(done as u8).u8(status as u8).u16(logins).u16(codes).u16(passkeys).finish();
        (kind::BACKUP_PUT | kind::REPLY, body)
    }

    /// How many apps are installed, and the one asked for if there's one at that index;
    /// `status` is `Approved`, or why not (`Locked`, `Unavailable`) with nothing.
    pub fn app_list(status: Approval, count: u32, entry: Option<&super::AppEntry>) -> (u8, Vec<u8>) {
        let ok = status == Approval::Approved;
        let entry = entry.filter(|_| ok);
        let mut w = Writer::new().u8(status as u8).u32(if ok { count } else { 0 }).u8(entry.is_some() as u8);
        if let Some(e) = entry {
            w = w
                .str8(&e.id)
                .str8(&e.name)
                .u32(e.version)
                .str8(&e.label)
                .bytes16(&e.developer)
                .u8(e.from_store as u8)
                .u8(e.backup as u8)
                .u32(e.used)
                .bytes16(&e.icon)
                .u32(e.bundle)
                .u32(e.storage);
        }
        (kind::APP_LIST | kind::REPLY, w.finish())
    }

    /// maki's room for apps; `status` is `Approved`, or why not (`Locked`, `Unavailable`)
    /// with nothing.
    pub fn app_space(status: Approval, space: &super::AppSpace) -> (u8, Vec<u8>) {
        let s = if status == Approval::Approved { *space } else { super::AppSpace::default() };
        let body = Writer::new().u8(status as u8).u32(s.apps).u32(s.max_apps).u32(s.space).u32(s.taken).finish();
        (kind::APP_SPACE | kind::REPLY, body)
    }

    /// A piece of a bundle taken (`done` false, `Approved`), or the outcome once the owner
    /// decided or maki refused it, with the reason (at most 255 bytes, cut at a character).
    pub fn app_install(done: bool, approval: Approval, reason: &str) -> (u8, Vec<u8>) {
        let reason = if approval == Approval::Refused { reason } else { "" };
        let mut end = reason.len().min(255);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        (kind::APP_INSTALL | kind::REPLY, Writer::new().u8(done as u8).u8(approval as u8).str8(&reason[..end]).finish())
    }

    pub fn app_remove(approval: Approval) -> (u8, Vec<u8>) {
        (kind::APP_REMOVE | kind::REPLY, Writer::new().u8(approval as u8).finish())
    }

    /// The app's answer (`Approved`), or why there's none, with nothing.
    pub fn app_message(status: Approval, answer: &[u8]) -> (u8, Vec<u8>) {
        let answer = if status == Approval::Approved { &answer[..answer.len().min(super::MAX_APP_MESSAGE)] } else { &[] };
        (kind::APP_MESSAGE | kind::REPLY, Writer::new().u8(status as u8).bytes16(answer).finish())
    }

    /// A piece of a store record taken (`done` false), or the outcome: taken (`Approved`), or
    /// `Refused` with maki's reason (at most 255 bytes, cut at a character); and what maki has
    /// now, unless it's `Locked` or `Unavailable`.
    pub fn store_update(done: bool, status: Approval, state: super::StoreState, reason: &str) -> (u8, Vec<u8>) {
        let state = if matches!(status, Approval::Approved | Approval::Refused) { state } else { super::StoreState::default() };
        let reason = if status == Approval::Refused { reason } else { "" };
        let mut end = reason.len().min(255);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let body = Writer::new()
            .u8(done as u8)
            .u8(status as u8)
            .u32(state.root)
            .u32(state.revocations)
            .u64(state.revocations_expires)
            .str8(&reason[..end])
            .finish();
        (kind::STORE_UPDATE | kind::REPLY, body)
    }
}

pub trait Platform {
    /// Cryptographically secure random bytes (the TRNG on the badge).
    fn fill_random(&mut self, buf: &mut [u8]);
    /// Monotonic milliseconds; only differences matter.
    fn uptime_ms(&self) -> u64;
    /// Current UTC in milliseconds, if the clock has been set.
    fn utc_ms(&self) -> Option<u64>;
    fn set_time(&mut self, utc_ms: u64, tz_offset_s: i32);
    /// Called after every change, for anything that displays the time (the launcher's clock).
    fn time_state_changed(&mut self, _state: TimeState) {}
}

struct Challenge {
    issued_ms: u64,
    requests: Vec<(u8, [u8; REQUEST_LEN])>,
}

pub struct Device<P: Platform> {
    platform: P,
    name: &'static str,
    version: String,
    challenge: Option<Challenge>,
    state: TimeState,
    tz_offset_s: i32,
}

type Reply = (u8, Vec<u8>);

fn error(code: ErrorCode, detail: &str) -> Reply {
    (kind::ERROR, Writer::new().u8(code as u8).str8(detail).finish())
}

fn malformed(_: Truncated) -> Reply { error(ErrorCode::Malformed, "malformed message") }

impl<P: Platform> Device<P> {
    pub fn new(platform: P, name: &'static str, version: String) -> Self {
        Device { platform, name, version, challenge: None, state: TimeState::Unset, tz_offset_s: 0 }
    }

    pub fn state(&self) -> TimeState { self.state }

    pub fn platform(&self) -> &P { &self.platform }

    /// For the fake maki only: take the platform's clock (the host's own) as verified, so codes
    /// work without reaching the Roughtime servers.
    #[cfg(feature = "fake")]
    pub fn trust_platform_clock(&mut self, tz_offset_s: i32) {
        self.tz_offset_s = tz_offset_s;
        self.state = TimeState::Verified;
        self.platform.time_state_changed(self.state);
    }

    /// Handle one packet: answer it now, or hand back what to ask the owner.
    pub fn handle(&mut self, packet: &Packet) -> Handled {
        let body = &packet.body;
        let result = match packet.kind {
            kind::HELLO => self.hello(body),
            kind::STATUS => self.status(body),
            kind::TIME_CHALLENGE => self.time_challenge(body),
            kind::TIME_PROOF => self.time_proof(body),
            kind::TIME_UNVERIFIED => self.time_unverified(body),
            kind::GET_LOGIN | kind::GET_TOTP | kind::SAVE_LOGIN => return self.ask(packet.kind, body),
            kind::BACKUP_GET | kind::BACKUP_PUT => return Self::backup(packet.kind, body),
            kind::BTC_ACCOUNT | kind::BTC_ADDRESS | kind::BTC_SIGN | kind::BTC_SIGNED => {
                return Self::bitcoin(packet.kind, body)
            }
            kind::ETH_ACCOUNT | kind::ETH_SIGN_TX | kind::ETH_SIGNED | kind::ETH_SIGN_MESSAGE | kind::ETH_SIGN_TYPED => {
                return Self::ethereum(packet.kind, body)
            }
            kind::APP_LIST | kind::APP_INSTALL | kind::APP_REMOVE | kind::APP_MESSAGE | kind::STORE_UPDATE | kind::APP_SPACE => {
                return Self::apps(packet.kind, body)
            }
            _ => Ok(error(ErrorCode::UnknownKind, "unknown message kind")),
        };
        let (kind, body) = result.unwrap_or_else(malformed);
        Handled::Reply(kind, body)
    }

    fn ask(&self, kind: u8, body: &[u8]) -> Handled {
        let parsed = (|| {
            let mut r = Reader::new(body);
            let site = r.str8()?.to_string();
            let ask = match kind {
                kind::GET_LOGIN => Ask::Login { site: site.clone() },
                kind::GET_TOTP => Ask::Totp { site: site.clone() },
                _ => Ask::SaveLogin { site: site.clone(), username: r.str8()?.into(), password: r.str8()?.into() },
            };
            r.end()?;
            Ok::<_, Truncated>((site, ask))
        })();
        match parsed {
            Err(t) => {
                let (k, b) = malformed(t);
                Handled::Reply(k, b)
            }
            Ok((site, _)) if !crate::site::valid(&site) => {
                let (k, b) = error(ErrorCode::BadArgument, "site must be a lowercase ASCII hostname");
                Handled::Reply(k, b)
            }
            Ok((_, Ask::SaveLogin { username, password, .. })) if username.is_empty() || password.is_empty() => {
                let (k, b) = error(ErrorCode::BadArgument, "username or password is empty");
                Handled::Reply(k, b)
            }
            // the vault keeps a record as lines of text; and nothing shown on screen should
            // be able to move the cursor
            Ok((_, Ask::SaveLogin { username, password, .. }))
                if username.chars().chain(password.chars()).any(char::is_control) =>
            {
                let (k, b) = error(ErrorCode::BadArgument, "control characters in username or password");
                Handled::Reply(k, b)
            }
            Ok((_, Ask::Totp { .. })) if self.state != TimeState::Verified => {
                let (k, b) = reply::totp(Approval::ClockNotVerified, "", 0);
                Handled::Reply(k, b)
            }
            Ok((_, ask)) => Handled::Ask(ask),
        }
    }

    fn apps(kind: u8, body: &[u8]) -> Handled {
        let parsed = (|| {
            let mut r = Reader::new(body);
            let request = match kind {
                kind::APP_LIST => Apps::List { index: r.u32()? },
                kind::APP_INSTALL => Apps::Install { total: r.u32()?, offset: r.u32()?, data: r.bytes16()?.to_vec() },
                kind::APP_MESSAGE => Apps::Message { id: r.str8()?.to_string(), message: r.bytes16()?.to_vec() },
                kind::STORE_UPDATE => Apps::StoreUpdate { total: r.u32()?, offset: r.u32()?, data: r.bytes16()?.to_vec() },
                kind::APP_SPACE => Apps::Space,
                _ => Apps::Remove { id: r.str8()?.to_string() },
            };
            r.end()?;
            Ok::<_, Truncated>(request)
        })();
        let bad = |why: &str| {
            let (k, b) = error(ErrorCode::BadArgument, why);
            Handled::Reply(k, b)
        };
        match parsed {
            Err(t) => {
                let (k, b) = malformed(t);
                Handled::Reply(k, b)
            }
            Ok(Apps::Install { total, offset, ref data })
                if total == 0
                    || total > MAX_APP
                    || data.len() > APP_PIECE
                    || offset as u64 + data.len() as u64 > total as u64 =>
            {
                bad("bundle piece out of range")
            }
            Ok(Apps::Remove { ref id } | Apps::Message { ref id, .. }) if !app_id_valid(id) => bad("not an app ID"),
            Ok(Apps::Message { ref message, .. }) if message.len() > MAX_APP_MESSAGE => bad("message too big"),
            Ok(Apps::StoreUpdate { total: 0, offset, ref data }) if offset != 0 || !data.is_empty() => {
                bad("a store status request carries nothing")
            }
            Ok(Apps::StoreUpdate { total, offset, ref data })
                if total > MAX_STORE_RECORD
                    || data.len() > STORE_PIECE
                    || offset as u64 + data.len() as u64 > total as u64 =>
            {
                bad("store record piece out of range")
            }
            Ok(request) => Handled::Apps(request),
        }
    }

    fn backup(kind: u8, body: &[u8]) -> Handled {
        let parsed = (|| {
            let mut r = Reader::new(body);
            let request = if kind == kind::BACKUP_GET {
                Backup::Get { offset: r.u32()? }
            } else {
                Backup::Put { total: r.u32()?, offset: r.u32()?, data: r.bytes16()?.to_vec() }
            };
            r.end()?;
            Ok::<_, Truncated>(request)
        })();
        match parsed {
            Err(t) => {
                let (k, b) = malformed(t);
                Handled::Reply(k, b)
            }
            Ok(Backup::Put { total, offset, ref data })
                if total > MAX_BACKUP || data.len() > BACKUP_PIECE || offset as u64 + data.len() as u64 > total as u64 =>
            {
                let (k, b) = error(ErrorCode::BadArgument, "restore piece out of range");
                Handled::Reply(k, b)
            }
            Ok(request) => Handled::Backup(request),
        }
    }

    fn bitcoin(kind: u8, body: &[u8]) -> Handled {
        let parsed = (|| {
            let mut r = Reader::new(body);
            let request = match kind {
                kind::BTC_ACCOUNT => Bitcoin::Account { network: r.u8()?, account: r.u8()? },
                kind::BTC_ADDRESS => {
                    Bitcoin::Address { network: r.u8()?, change: r.u8()? != 0, index: r.u32()?, account: r.u8()? }
                }
                kind::BTC_SIGN => {
                    Bitcoin::Sign { network: r.u8()?, total: r.u32()?, offset: r.u32()?, data: r.bytes16()?.to_vec() }
                }
                _ => Bitcoin::Signed { offset: r.u32()? },
            };
            r.end()?;
            Ok::<_, Truncated>(request)
        })();
        let bad = |why: &str| {
            let (k, b) = error(ErrorCode::BadArgument, why);
            Handled::Reply(k, b)
        };
        match parsed {
            Err(t) => {
                let (k, b) = malformed(t);
                Handled::Reply(k, b)
            }
            Ok(Bitcoin::Account { network, .. } | Bitcoin::Address { network, .. } | Bitcoin::Sign { network, .. })
                if network > NETWORK_TESTNET =>
            {
                bad("unknown network")
            }
            Ok(Bitcoin::Account { account, .. } | Bitcoin::Address { account, .. }) if account > ACCOUNT_TAPROOT => {
                bad("unknown account")
            }
            Ok(Bitcoin::Address { index, .. }) if index >= 0x8000_0000 => bad("address index out of range"),
            // the byte after the network
            Ok(Bitcoin::Address { .. }) if body[1] > 1 => bad("change is 0 or 1"),
            Ok(Bitcoin::Sign { total, offset, ref data, .. })
                if total == 0
                    || total > MAX_PSBT
                    || data.len() > PSBT_PIECE
                    || offset as u64 + data.len() as u64 > total as u64 =>
            {
                bad("PSBT piece out of range")
            }
            Ok(request) => Handled::Bitcoin(request),
        }
    }

    fn ethereum(kind: u8, body: &[u8]) -> Handled {
        let parsed = (|| {
            let mut r = Reader::new(body);
            let request = match kind {
                kind::ETH_ACCOUNT => Ethereum::Account { site: r.str8()?.into(), index: r.u32()? },
                kind::ETH_SIGN_TX => Ethereum::Sign {
                    site: r.str8()?.into(),
                    index: r.u32()?,
                    total: r.u32()?,
                    offset: r.u32()?,
                    data: r.bytes16()?.to_vec(),
                },
                kind::ETH_SIGN_MESSAGE => {
                    Ethereum::Message { site: r.str8()?.into(), index: r.u32()?, message: r.bytes16()?.to_vec() }
                }
                kind::ETH_SIGN_TYPED => Ethereum::Typed {
                    site: r.str8()?.into(),
                    index: r.u32()?,
                    total: r.u32()?,
                    offset: r.u32()?,
                    data: r.bytes16()?.to_vec(),
                },
                _ => Ethereum::Signed { offset: r.u32()? },
            };
            r.end()?;
            Ok::<_, Truncated>(request)
        })();
        let bad = |why: &str| {
            let (k, b) = error(ErrorCode::BadArgument, why);
            Handled::Reply(k, b)
        };
        match parsed {
            Err(t) => {
                let (k, b) = malformed(t);
                Handled::Reply(k, b)
            }
            Ok(
                Ethereum::Account { ref site, .. }
                | Ethereum::Sign { ref site, .. }
                | Ethereum::Message { ref site, .. }
                | Ethereum::Typed { ref site, .. },
            ) if !crate::site::valid(site) => bad("site must be a lowercase ASCII hostname"),
            Ok(
                Ethereum::Account { index, .. }
                | Ethereum::Sign { index, .. }
                | Ethereum::Message { index, .. }
                | Ethereum::Typed { index, .. },
            ) if index >= 0x8000_0000 => bad("account index out of range"),
            Ok(Ethereum::Sign { total, offset, ref data, .. })
                if total == 0
                    || total > MAX_TX
                    || data.len() > TX_PIECE
                    || offset as u64 + data.len() as u64 > total as u64 =>
            {
                bad("transaction piece out of range")
            }
            Ok(Ethereum::Message { ref message, .. }) if message.len() > MAX_MESSAGE => bad("message too long"),
            Ok(Ethereum::Typed { total, offset, ref data, .. })
                if total == 0
                    || total > MAX_TYPED
                    || data.len() > TX_PIECE
                    || offset as u64 + data.len() as u64 > total as u64 =>
            {
                bad("typed data piece out of range")
            }
            Ok(request) => Handled::Ethereum(request),
        }
    }

    fn hello(&mut self, body: &[u8]) -> Result<Reply, Truncated> {
        Reader::new(body).end()?;
        let reply = Writer::new().u8(crate::frame::PROTOCOL_VERSION).str8(self.name).str8(&self.version).finish();
        Ok((kind::HELLO | kind::REPLY, reply))
    }

    fn status(&mut self, body: &[u8]) -> Result<Reply, Truncated> {
        Reader::new(body).end()?;
        let reply = Writer::new()
            .u8(self.state as u8)
            .u64(self.platform.utc_ms().unwrap_or(0))
            .i32(self.tz_offset_s)
            .finish();
        Ok((kind::STATUS | kind::REPLY, reply))
    }

    fn time_challenge(&mut self, body: &[u8]) -> Result<Reply, Truncated> {
        Reader::new(body).end()?;
        let mut requests = Vec::with_capacity(SERVERS.len());
        let mut reply = Writer::new().u8(SERVERS.len() as u8);
        for server in &SERVERS {
            let mut nonce = [0u8; 32];
            self.platform.fill_random(&mut nonce);
            let request = roughtime::request(&nonce);
            reply = reply.u8(server.id).str8(server.host).u16(server.port).bytes16(&request);
            requests.push((server.id, request));
        }
        // a new challenge replaces any old one, so each nonce is used for exactly one proof
        self.challenge = Some(Challenge { issued_ms: self.platform.uptime_ms(), requests });
        Ok((kind::TIME_CHALLENGE | kind::REPLY, reply.finish()))
    }

    fn time_proof(&mut self, body: &[u8]) -> Result<Reply, Truncated> {
        let mut r = Reader::new(body);
        let tz_offset_s = r.i32()?;
        let count = r.u8()? as usize;
        let mut answers = Vec::with_capacity(count);
        for _ in 0..count {
            answers.push((r.u8()?, r.bytes16()?));
        }
        r.end()?;
        if !TZ_RANGE_S.contains(&tz_offset_s) {
            return Ok(error(ErrorCode::BadArgument, "timezone offset out of range"));
        }
        let Some(challenge) = self.challenge.take() else {
            return Ok(error(ErrorCode::NoChallenge, "no outstanding challenge"));
        };
        let elapsed_ms = self.platform.uptime_ms().saturating_sub(challenge.issued_ms);
        if elapsed_ms > CHALLENGE_TTL_MS {
            return Ok(error(ErrorCode::ChallengeExpired, "challenge expired"));
        }

        let mut verified: Vec<roughtime::Verified> = Vec::new();
        let mut seen: Vec<u8> = Vec::new();
        let mut results = Writer::new().u8(answers.len() as u8);
        for (id, response) in answers {
            let status = match (challenge.requests.iter().find(|(i, _)| *i == id), SERVERS.iter().find(|s| s.id == id)) {
                _ if seen.contains(&id) => AnswerStatus::Duplicate,
                (Some((_, request)), Some(server)) => match roughtime::verify(request, response, &server.key) {
                    Ok(v) if v.radius <= MAX_RADIUS_S => {
                        verified.push(v);
                        AnswerStatus::Verified
                    }
                    Ok(_) => AnswerStatus::TooImprecise,
                    Err(_) => AnswerStatus::Invalid,
                },
                _ => AnswerStatus::UnknownServer,
            };
            seen.push(id);
            results = results.u8(id).u8(status as u8);
        }
        let results = results.finish();

        let reply = |status: ProofStatus, utc_ms: u64| {
            let mut body = Writer::new().u8(status as u8).u8(verified.len() as u8).u64(utc_ms).finish();
            body.extend_from_slice(&results);
            (kind::TIME_PROOF | kind::REPLY, body)
        };
        if verified.len() < MIN_AGREEING {
            return Ok(reply(ProofStatus::TooFewVerified, 0));
        }
        // every server processed our request between the challenge and now, so honest answers
        // differ by at most the round trip plus their stated radii
        let lo = verified.iter().map(|v| v.midpoint).min().unwrap();
        let hi = verified.iter().map(|v| v.midpoint).max().unwrap();
        let slack_s = verified.iter().map(|v| v.radius as u64).max().unwrap() + elapsed_ms / 1000 + 2;
        if hi - lo > slack_s {
            return Ok(reply(ProofStatus::Disagree, 0));
        }
        let mut midpoints: Vec<u64> = verified.iter().map(|v| v.midpoint).collect();
        midpoints.sort_unstable();
        // the servers answered somewhere inside the round trip; assume its middle
        let utc_ms = midpoints[midpoints.len() / 2] * 1000 + elapsed_ms / 2;

        self.platform.set_time(utc_ms, tz_offset_s);
        self.tz_offset_s = tz_offset_s;
        self.state = TimeState::Verified;
        self.platform.time_state_changed(self.state);
        Ok(reply(ProofStatus::Set, utc_ms))
    }

    fn time_unverified(&mut self, body: &[u8]) -> Result<Reply, Truncated> {
        let mut r = Reader::new(body);
        let utc_ms = r.u64()?;
        let tz_offset_s = r.i32()?;
        r.end()?;
        if !TZ_RANGE_S.contains(&tz_offset_s) || utc_ms < EARLIEST_UTC_MS {
            return Ok(error(ErrorCode::BadArgument, "time or timezone out of range"));
        }
        // a verified clock is never overwritten by the host's word
        let accepted = self.state != TimeState::Verified;
        if accepted {
            self.platform.set_time(utc_ms, tz_offset_s);
            self.tz_offset_s = tz_offset_s;
            self.state = TimeState::Unverified;
            self.platform.time_state_changed(self.state);
        }
        Ok((kind::TIME_UNVERIFIED | kind::REPLY, Writer::new().u8(if accepted { 0 } else { 1 }).finish()))
    }
}
