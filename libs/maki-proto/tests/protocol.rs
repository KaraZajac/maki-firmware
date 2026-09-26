//! Framing, and the device logic driven with real Roughtime answers captured 2026-09-26.

use std::cell::Cell;

use maki_proto::device::*;
use maki_proto::frame::{self, Deframer, FrameError, Packet};
use maki_proto::site;
use maki_proto::kind;
use maki_proto::wire::{Reader, Writer};

const MIDPOINT_MS: u64 = 1_790_399_658_000; // 2026-09-26 05:14:18 UTC, from all three servers
const VECTORS: [&str; 3] = ["time_txryan_com", "roughtime_se", "roughtime_int08h_com"]; // ids 0, 1, 2

fn vector(name: &str) -> (Vec<u8>, Vec<u8>) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../roughtime/tests/vectors/");
    (std::fs::read(format!("{dir}{name}.req")).unwrap(), std::fs::read(format!("{dir}{name}.resp")).unwrap())
}

/// A platform whose "random" nonces are the ones the captured requests used, so the device
/// rebuilds exactly the requests those servers answered.
struct Replay {
    nonces: Vec<[u8; 32]>,
    next: usize,
    uptime: Cell<u64>,
    clock: Option<(u64, i32)>,
    states: Vec<TimeState>,
}

impl Replay {
    fn new() -> Self {
        let nonces = VECTORS.iter().map(|v| vector(v).0[12 + 36..12 + 68].try_into().unwrap()).collect();
        Replay { nonces, next: 0, uptime: Cell::new(1_000), clock: None, states: vec![] }
    }
}

impl Platform for Replay {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.nonces[self.next % self.nonces.len()]);
        self.next += 1;
    }

    fn uptime_ms(&self) -> u64 { self.uptime.get() }

    fn utc_ms(&self) -> Option<u64> { self.clock.map(|(t, _)| t) }

    fn set_time(&mut self, utc_ms: u64, tz_offset_s: i32) { self.clock = Some((utc_ms, tz_offset_s)); }

    fn time_state_changed(&mut self, state: TimeState) { self.states.push(state); }
}

fn device() -> Device<Replay> { Device::new(Replay::new(), "maki", "0.1.0".into()) }

fn ask(d: &mut Device<Replay>, kind: u8, body: Vec<u8>) -> (u8, Vec<u8>) {
    match d.handle(&Packet { kind, id: 7, body }) {
        Handled::Reply(k, b) => (k, b),
        other => panic!("expected an immediate reply, got {other:?}"),
    }
}

fn challenge(d: &mut Device<Replay>) -> Vec<(u8, Vec<u8>)> {
    let (k, body) = ask(d, kind::TIME_CHALLENGE, vec![]);
    assert_eq!(k, kind::TIME_CHALLENGE | kind::REPLY);
    let mut r = Reader::new(&body);
    let n = r.u8().unwrap();
    let out = (0..n)
        .map(|_| {
            let id = r.u8().unwrap();
            let _host = r.str8().unwrap();
            let _port = r.u16().unwrap();
            (id, r.bytes16().unwrap().to_vec())
        })
        .collect();
    r.end().unwrap();
    out
}

fn proof(d: &mut Device<Replay>, tz: i32, answers: &[(u8, Vec<u8>)]) -> (u8, Vec<u8>) {
    let mut w = Writer::new().i32(tz).u8(answers.len() as u8);
    for (id, resp) in answers {
        w = w.u8(*id).bytes16(resp);
    }
    ask(d, kind::TIME_PROOF, w.finish())
}

/// (status, verified count, utc, per-answer statuses)
fn proof_reply(body: &[u8]) -> (u8, u8, u64, Vec<(u8, u8)>) {
    let mut r = Reader::new(body);
    let (status, verified, utc) = (r.u8().unwrap(), r.u8().unwrap(), r.u64().unwrap());
    let n = r.u8().unwrap();
    let results = (0..n).map(|_| (r.u8().unwrap(), r.u8().unwrap())).collect();
    r.end().unwrap();
    (status, verified, utc, results)
}

fn answers(tamper: &[usize]) -> Vec<(u8, Vec<u8>)> {
    VECTORS
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mut resp = vector(v).1;
            if tamper.contains(&i) {
                let mid = resp.len() / 2;
                resp[mid] ^= 1;
            }
            (i as u8, resp)
        })
        .collect()
}

fn error_code(reply: &(u8, Vec<u8>)) -> u8 {
    assert_eq!(reply.0, kind::ERROR);
    reply.1[0]
}

// ---- framing ----

#[test]
fn crc_is_the_standard_one() {
    assert_eq!(frame::crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn frames_round_trip_whatever_the_payload() {
    for body in [vec![], vec![0u8; 1], vec![0u8; 1024], (0..=255u8).cycle().take(700).collect::<Vec<_>>()] {
        let wire = frame::encode(0x42, 0xbeef, &body);
        assert_eq!(wire.iter().filter(|&&b| b == 0).count(), 1, "only the delimiter is zero");
        let got = frame::decode(&wire[..wire.len() - 1]).unwrap();
        assert_eq!(got, Packet { kind: 0x42, id: 0xbeef, body });
    }
}

#[test]
fn deframer_copes_with_dribbles_and_garbage() {
    let a = frame::encode(1, 1, b"first");
    let b = frame::encode(2, 2, &[0u8; 300]);
    let mut stream = b"\x07\x07junk".to_vec();
    stream.push(0);
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&b);
    let mut d = Deframer::default();
    let mut got = vec![];
    for byte in stream {
        got.extend(d.push(&[byte]));
    }
    assert_eq!(got.len(), 3);
    assert!(got[0].is_err(), "the garbage is reported, not swallowed");
    assert_eq!(got[1].as_ref().unwrap().kind, 1);
    assert_eq!(got[2].as_ref().unwrap().body, vec![0u8; 300]);
}

#[test]
fn corrupted_frames_are_rejected() {
    let mut wire = frame::encode(1, 1, b"hello");
    wire[3] ^= 0x10;
    assert_eq!(frame::decode(&wire[..wire.len() - 1]), Err(FrameError::Crc));
}

// ---- device ----

#[test]
fn hello_names_the_firmware() {
    let mut d = device();
    let (k, body) = ask(&mut d, kind::HELLO, vec![]);
    assert_eq!(k, kind::HELLO | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap(), r.str8().unwrap()), (2, "maki", "0.1.0"));
}

#[test]
fn challenge_asks_every_pinned_server_with_a_fresh_nonce() {
    let mut d = device();
    let c = challenge(&mut d);
    assert_eq!(c.iter().map(|(id, _)| *id).collect::<Vec<_>>(), vec![0, 1, 2]);
    for (i, (_, req)) in c.iter().enumerate() {
        assert_eq!(req, &vector(VECTORS[i]).0, "rebuilt exactly the request server {i} answered");
    }
}

#[test]
fn three_agreeing_signed_answers_set_a_verified_clock() {
    let mut d = device();
    challenge(&mut d);
    d.platform().uptime.set(1_500); // half a second in flight
    let (k, body) = proof(&mut d, 3600, &answers(&[]));
    assert_eq!(k, kind::TIME_PROOF | kind::REPLY);
    let (status, verified, utc, results) = proof_reply(&body);
    assert_eq!((status, verified), (ProofStatus::Set as u8, 3));
    assert_eq!(utc, MIDPOINT_MS + 250, "midpoint plus half the round trip");
    assert!(results.iter().all(|&(_, s)| s == AnswerStatus::Verified as u8));
    assert_eq!(d.platform().clock, Some((MIDPOINT_MS + 250, 3600)));
    assert_eq!(d.state(), TimeState::Verified);
}

#[test]
fn one_bad_answer_is_outvoted() {
    let mut d = device();
    challenge(&mut d);
    let (status, verified, _, results) = proof_reply(&proof(&mut d, 0, &answers(&[1])).1);
    assert_eq!((status, verified), (ProofStatus::Set as u8, 2));
    assert_eq!(results[1], (1, AnswerStatus::Invalid as u8));
}

#[test]
fn a_single_server_cannot_set_the_clock() {
    let mut d = device();
    challenge(&mut d);
    let (status, verified, _, _) = proof_reply(&proof(&mut d, 0, &answers(&[0, 2])).1);
    assert_eq!((status, verified), (ProofStatus::TooFewVerified as u8, 1));
    assert_eq!(d.platform().clock, None);
    assert_eq!(d.state(), TimeState::Unset);
}

#[test]
fn replaying_one_server_twice_counts_once() {
    let mut d = device();
    challenge(&mut d);
    let a = answers(&[]);
    let (status, verified, _, results) = proof_reply(&proof(&mut d, 0, &[a[0].clone(), a[0].clone()]).1);
    assert_eq!((status, verified), (ProofStatus::TooFewVerified as u8, 1));
    assert_eq!(results[1], (0, AnswerStatus::Duplicate as u8));
}

#[test]
fn proofs_need_a_live_challenge_and_use_it_up() {
    let mut d = device();
    assert_eq!(error_code(&proof(&mut d, 0, &answers(&[]))), ErrorCode::NoChallenge as u8);

    challenge(&mut d);
    d.platform().uptime.set(1_000 + CHALLENGE_TTL_MS + 1);
    assert_eq!(error_code(&proof(&mut d, 0, &answers(&[]))), ErrorCode::ChallengeExpired as u8);

    challenge(&mut d);
    proof(&mut d, 0, &answers(&[]));
    assert_eq!(error_code(&proof(&mut d, 0, &answers(&[]))), ErrorCode::NoChallenge as u8, "no replay");
}

#[test]
fn the_hosts_word_is_accepted_but_never_over_a_verified_clock() {
    let mut d = device();
    let set = |d: &mut Device<Replay>, t: u64| ask(d, kind::TIME_UNVERIFIED, Writer::new().u64(t).i32(-18_000).finish());

    let (k, body) = set(&mut d, MIDPOINT_MS);
    assert_eq!((k, body[0]), (kind::TIME_UNVERIFIED | kind::REPLY, 0));
    assert_eq!(d.state(), TimeState::Unverified);

    challenge(&mut d);
    proof(&mut d, 0, &answers(&[]));
    let before = d.platform().clock;
    let (_, body) = set(&mut d, MIDPOINT_MS + 3_600_000);
    assert_eq!(body[0], 1, "refused");
    assert_eq!(d.platform().clock, before);
    assert_eq!(d.platform().states, vec![TimeState::Unverified, TimeState::Verified]);
}

#[test]
fn nonsense_arguments_and_messages_are_refused() {
    let mut d = device();
    let early = ask(&mut d, kind::TIME_UNVERIFIED, Writer::new().u64(0).i32(0).finish());
    assert_eq!(error_code(&early), ErrorCode::BadArgument as u8);
    let tz = ask(&mut d, kind::TIME_UNVERIFIED, Writer::new().u64(MIDPOINT_MS).i32(15 * 3600).finish());
    assert_eq!(error_code(&tz), ErrorCode::BadArgument as u8);
    assert_eq!(error_code(&ask(&mut d, kind::HELLO, vec![1])), ErrorCode::Malformed as u8);
    assert_eq!(error_code(&ask(&mut d, 0x55, vec![])), ErrorCode::UnknownKind as u8);
    let (k, body) = ask(&mut d, kind::STATUS, vec![]);
    assert_eq!((k, body[0]), (kind::STATUS | kind::REPLY, TimeState::Unset as u8));
}

// ---- asks: requests the owner approves on maki ----

fn handled(d: &mut Device<Replay>, kind: u8, body: Vec<u8>) -> Handled { d.handle(&Packet { kind, id: 9, body }) }

#[test]
fn login_and_totp_requests_become_asks() {
    let mut d = device();
    assert_eq!(
        handled(&mut d, kind::GET_LOGIN, Writer::new().str8("github.com").finish()),
        Handled::Ask(Ask::Login { site: "github.com".into() })
    );
    assert_eq!(
        handled(&mut d, kind::GET_TOTP, Writer::new().str8("xn--80ak6aa92e.com").finish()),
        Handled::Ask(Ask::Totp { site: "xn--80ak6aa92e.com".into() }),
        "punycode is fine: it is shown as punycode"
    );
    assert_eq!(
        handled(&mut d, kind::SAVE_LOGIN, Writer::new().str8("example.org").str8("kara").str8("hunter2").finish()),
        Handled::Ask(Ask::SaveLogin { site: "example.org".into(), username: "kara".into(), password: "hunter2".into() })
    );
}

#[test]
fn sites_that_could_mislead_on_screen_are_refused() {
    let mut d = device();
    for bad in ["", "GitHub.com", "аpple.com", "github.com/login", ".github.com", "git hub.com", "a..b"] {
        let reply = ask(&mut d, kind::GET_LOGIN, Writer::new().str8(bad).finish());
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "{bad:?} was accepted");
    }
    let no_user = ask(&mut d, kind::SAVE_LOGIN, Writer::new().str8("example.org").str8("").str8("pw").finish());
    assert_eq!(error_code(&no_user), ErrorCode::BadArgument as u8);
}

#[test]
fn saved_entries_cover_their_own_site_and_subdomains_only() {
    assert!(site::covers("github.com", "github.com"));
    assert!(site::covers("https://www.github.com/login", "gist.github.com"));
    assert!(site::covers("GitHub.com", "github.com"));
    assert!(!site::covers("github.com", "evilgithub.com"));
    assert!(!site::covers("github.com", "github.com.evil.net"));
    assert!(!site::covers("", "github.com"));
}

#[test]
fn a_refusal_never_carries_the_secret() {
    let (k, body) = reply::login(Approval::Denied, "kara", "hunter2");
    assert_eq!(k, kind::GET_LOGIN | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap(), r.str8().unwrap()), (Approval::Denied as u8, "", ""));
    let (_, body) = reply::totp(Approval::TimedOut, "123456", 20);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap(), r.u8().unwrap()), (Approval::TimedOut as u8, "", 0));
}
