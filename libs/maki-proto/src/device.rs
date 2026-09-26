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
}

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

    /// Handle one packet: answer it now, or hand back what to ask the owner.
    pub fn handle(&mut self, packet: &Packet) -> Handled {
        let body = &packet.body;
        let result = match packet.kind {
            kind::HELLO => self.hello(body),
            kind::STATUS => self.status(body),
            kind::TIME_CHALLENGE => self.time_challenge(body),
            kind::TIME_PROOF => self.time_proof(body),
            kind::TIME_UNVERIFIED => self.time_unverified(body),
            kind::GET_LOGIN | kind::GET_TOTP | kind::SAVE_LOGIN => return Self::ask(packet.kind, body),
            _ => Ok(error(ErrorCode::UnknownKind, "unknown message kind")),
        };
        let (kind, body) = result.unwrap_or_else(malformed);
        Handled::Reply(kind, body)
    }

    fn ask(kind: u8, body: &[u8]) -> Handled {
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
            Ok((_, Ask::SaveLogin { username, .. })) if username.is_empty() => {
                let (k, b) = error(ErrorCode::BadArgument, "username is empty");
                Handled::Reply(k, b)
            }
            Ok((_, ask)) => Handled::Ask(ask),
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
