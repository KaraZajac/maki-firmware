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

/// A device whose clock three pinned servers have verified.
fn verified_device() -> Device<Replay> {
    let mut d = device();
    challenge(&mut d);
    proof(&mut d, 0, &answers(&[]));
    assert_eq!(d.state(), TimeState::Verified);
    d
}

#[test]
fn login_and_totp_requests_become_asks() {
    let mut d = verified_device();
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
    let no_password = ask(&mut d, kind::SAVE_LOGIN, Writer::new().str8("example.org").str8("kara").str8("").finish());
    assert_eq!(error_code(&no_password), ErrorCode::BadArgument as u8);
}

#[test]
fn a_saved_login_cannot_smuggle_lines_into_the_vault() {
    let mut d = device();
    for (user, pass) in [("kara\ndescription:bank.com", "pw"), ("kara", "pw\npassword:x"), ("kara\r", "pw"), ("ka\u{1b}[2Jra", "pw")] {
        let reply = ask(&mut d, kind::SAVE_LOGIN, Writer::new().str8("example.org").str8(user).str8(pass).finish());
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "{user:?}/{pass:?} was accepted");
    }
}

#[test]
fn codes_wait_for_a_verified_clock() {
    let totp = |d: &mut Device<Replay>| d.handle(&Packet { kind: kind::GET_TOTP, id: 3, body: Writer::new().str8("github.com").finish() });
    let refused = Handled::Reply(kind::GET_TOTP | kind::REPLY, reply::totp(Approval::ClockNotVerified, "", 0).1);
    let mut d = device();
    assert_eq!(totp(&mut d), refused, "no clock at all");
    // the host's word sets the clock, but a host that could choose the time could collect codes
    // for times still to come
    let (k, _) = ask(&mut d, kind::TIME_UNVERIFIED, Writer::new().u64(1_790_000_000_000).i32(0).finish());
    assert_eq!(k, kind::TIME_UNVERIFIED | kind::REPLY);
    assert_eq!(totp(&mut d), refused, "the host's clock");
    let mut d = verified_device();
    assert_eq!(totp(&mut d), Handled::Ask(Ask::Totp { site: "github.com".into() }));
    // logins don't depend on the clock
    let mut d = device();
    assert!(matches!(d.handle(&Packet { kind: kind::GET_LOGIN, id: 4, body: Writer::new().str8("github.com").finish() }), Handled::Ask(_)));
}

#[test]
fn saved_entries_cover_their_own_site_and_subdomains_only() {
    assert!(site::covers("github.com", "github.com"));
    assert!(site::covers("https://www.github.com/login", "gist.github.com"));
    assert!(site::covers("GitHub.com", "github.com"));
    assert!(!site::covers("github.com", "evilgithub.com"));
    assert!(!site::covers("github.com", "github.com.evil.net"));
    assert!(!site::covers("", "github.com"));
    // entries that aren't hostnames match nothing, rather than whole top-level domains
    assert!(!site::covers("Bank", "evil.bank"));
    assert!(!site::covers("my bank", "bank"));
    assert!(!site::covers("com", "github.com"));
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

#[test]
fn sites_on_screen_break_at_dots_and_always_show_their_end() {
    assert_eq!(site::lines("github.com", 17, 3), ["github.com"]);
    assert_eq!(site::lines("login.accounts.example.com", 17, 3), ["login.accounts.", "example.com"]);
    // a label too long for a line is broken where it has to be
    assert_eq!(site::lines("averyveryverylonglabel.com", 17, 3), ["averyveryverylong", "label.com"]);
    // too long to show whole: the start goes, the end stays
    let long = format!("{}.github.com.evil.example", "x".repeat(80));
    let shown = site::lines(&long, 17, 3);
    assert_eq!(shown.len(), 3);
    assert!(shown.iter().all(|l| l.chars().count() <= 17), "{shown:?}");
    assert!(shown[0].starts_with('…'));
    assert!(shown.concat().ends_with(".github.com.evil.example"), "{shown:?}");
    // a cut that lands on a dot starts the shown part at the next label
    assert_eq!(
        site::lines("accounts.a-rather-long-subdomain.login.example.co.uk", 15, 3).concat(),
        "…a-rather-long-subdomain.login.example.co.uk"
    );
    // never more lines than asked for, even when breaking at dots would need them
    let dotty = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y";
    assert!(site::lines(dotty, 17, 3).len() <= 3);
    assert_eq!(site::lines(dotty, 17, 3).concat(), dotty);
}

#[test]
fn backup_pieces_are_asked_for_by_offset() {
    let mut d = device();
    assert_eq!(
        d.handle(&Packet { kind: kind::BACKUP_GET, id: 1, body: Writer::new().u32(4096).finish() }),
        Handled::Backup(Backup::Get { offset: 4096 })
    );
    let piece = vec![7u8; 100];
    assert_eq!(
        d.handle(&Packet { kind: kind::BACKUP_PUT, id: 2, body: Writer::new().u32(300).u32(200).bytes16(&piece).finish() }),
        Handled::Backup(Backup::Put { total: 300, offset: 200, data: piece.clone() })
    );
    // pieces that can't be part of a backup maki would take
    for (total, offset, len) in [(100, 50, 100), (MAX_BACKUP + 1, 0, 10), (10_000, 0, BACKUP_PIECE + 1)] {
        let body = Writer::new().u32(total).u32(offset).bytes16(&vec![0; len]).finish();
        let reply = ask(&mut d, kind::BACKUP_PUT, body);
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "{total} {offset} {len}");
    }
}

#[test]
fn backup_replies_carry_nothing_unless_approved() {
    let (k, body) = reply::backup_piece(Approval::Locked, 999, 0, &[1, 2, 3]);
    assert_eq!(k, kind::BACKUP_GET | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u32().unwrap(), r.u32().unwrap(), r.bytes16().unwrap()), (Approval::Locked as u8, 999, 0, &[][..]));
    let (_, body) = reply::restore_piece(true, Approval::Denied, 5, 6, 7);
    let mut r = Reader::new(&body);
    assert_eq!(
        (r.u8().unwrap(), r.u8().unwrap(), r.u16().unwrap(), r.u16().unwrap(), r.u16().unwrap()),
        (1, Approval::Denied as u8, 0, 0, 0)
    );
    r.end().unwrap();
    let (_, body) = reply::restore_piece(true, Approval::Approved, 5, 6, 7);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u8().unwrap(), r.u16().unwrap(), r.u16().unwrap(), r.u16().unwrap()), (1, 0, 5, 6, 7));
}

#[test]
fn bitcoin_requests_go_to_the_wallet() {
    let mut d = device();
    assert_eq!(
        handled(&mut d, kind::BTC_ACCOUNT, Writer::new().u8(NETWORK_TESTNET).finish()),
        Handled::Bitcoin(Bitcoin::Account { network: NETWORK_TESTNET })
    );
    assert_eq!(
        handled(&mut d, kind::BTC_ADDRESS, Writer::new().u8(NETWORK_BITCOIN).u8(1).u32(42).finish()),
        Handled::Bitcoin(Bitcoin::Address { network: NETWORK_BITCOIN, change: true, index: 42 })
    );
    let piece = vec![0x70u8; 64];
    assert_eq!(
        handled(&mut d, kind::BTC_SIGN, Writer::new().u8(0).u32(100).u32(36).bytes16(&piece).finish()),
        Handled::Bitcoin(Bitcoin::Sign { network: 0, total: 100, offset: 36, data: piece })
    );
    assert_eq!(
        handled(&mut d, kind::BTC_SIGNED, Writer::new().u32(8192).finish()),
        Handled::Bitcoin(Bitcoin::Signed { offset: 8192 })
    );
}

#[test]
fn bitcoin_requests_out_of_range_are_refused() {
    let mut d = device();
    let bad = [
        (kind::BTC_ACCOUNT, Writer::new().u8(2).finish()),
        (kind::BTC_ADDRESS, Writer::new().u8(0).u8(2).u32(0).finish()),
        (kind::BTC_ADDRESS, Writer::new().u8(0).u8(0).u32(0x8000_0000).finish()),
        (kind::BTC_SIGN, Writer::new().u8(0).u32(0).u32(0).bytes16(&[]).finish()),
        (kind::BTC_SIGN, Writer::new().u8(0).u32(MAX_PSBT + 1).u32(0).bytes16(&[1]).finish()),
        (kind::BTC_SIGN, Writer::new().u8(0).u32(100).u32(90).bytes16(&[0; 20]).finish()),
        (kind::BTC_SIGN, Writer::new().u8(0).u32(10_000).u32(0).bytes16(&vec![0; PSBT_PIECE + 1]).finish()),
    ];
    for (k, body) in bad {
        let reply = ask(&mut d, k, body.clone());
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "0x{k:02x} {body:?}");
    }
    let reply = ask(&mut d, kind::BTC_ACCOUNT, Writer::new().u8(0).u8(0).finish());
    assert_eq!(error_code(&reply), ErrorCode::Malformed as u8);
}

#[test]
fn bitcoin_replies_carry_only_what_the_answer_allows() {
    let (k, body) = reply::btc_account(Approval::Denied, "zpub…", "wpkh(…)");
    assert_eq!(k, kind::BTC_ACCOUNT | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap(), r.str8().unwrap()), (Approval::Denied as u8, "", ""));

    // the address maki showed comes back whether or not it matched: it's maki's word either way
    let (_, body) = reply::btc_address(Approval::Denied, "bc1q…");
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap()), (Approval::Denied as u8, "bc1q…"));
    let (_, body) = reply::btc_address(Approval::Locked, "bc1q…");
    assert_eq!(Reader::new(&body).u8().unwrap(), Approval::Locked as u8);
    assert_eq!(body.len(), 2);

    let (_, body) = reply::btc_sign(true, Approval::Refused, 500, "input 0 isn't this wallet's");
    let mut r = Reader::new(&body);
    assert_eq!(
        (r.u8().unwrap(), r.u8().unwrap(), r.u32().unwrap(), r.str8().unwrap()),
        (1, Approval::Refused as u8, 0, "input 0 isn't this wallet's")
    );
    let (_, body) = reply::btc_sign(true, Approval::Approved, 500, "ignored");
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u8().unwrap(), r.u32().unwrap(), r.str8().unwrap()), (1, 0, 500, ""));

    let (k, body) = reply::btc_signed(Approval::Unavailable, 10, 0, &[1, 2]);
    assert_eq!(k, kind::BTC_SIGNED | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u32().unwrap(), r.u32().unwrap(), r.bytes16().unwrap()), (Approval::Unavailable as u8, 10, 0, &[][..]));
    assert_eq!(Approval::from_u8(9), Some(Approval::Refused));
}

#[test]
fn ethereum_requests_go_to_the_account() {
    let mut d = device();
    assert_eq!(
        handled(&mut d, kind::ETH_ACCOUNT, Writer::new().str8("app.uniswap.org").u32(0).finish()),
        Handled::Ethereum(Ethereum::Account { site: "app.uniswap.org".into(), index: 0 })
    );
    let piece = vec![0x02u8, 0xc0];
    assert_eq!(
        handled(&mut d, kind::ETH_SIGN_TX, Writer::new().str8("example.com").u32(1).u32(2).u32(0).bytes16(&piece).finish()),
        Handled::Ethereum(Ethereum::Sign { site: "example.com".into(), index: 1, total: 2, offset: 0, data: piece })
    );
    assert_eq!(
        handled(&mut d, kind::ETH_SIGNED, Writer::new().u32(4096).finish()),
        Handled::Ethereum(Ethereum::Signed { offset: 4096 })
    );
    assert_eq!(
        handled(&mut d, kind::ETH_SIGN_MESSAGE, Writer::new().str8("example.com").u32(0).bytes16(b"hi").finish()),
        Handled::Ethereum(Ethereum::Message { site: "example.com".into(), index: 0, message: b"hi".to_vec() })
    );
}

#[test]
fn ethereum_requests_out_of_range_are_refused() {
    let mut d = device();
    let bad = [
        (kind::ETH_ACCOUNT, Writer::new().str8("Example.COM").u32(0).finish()),
        (kind::ETH_ACCOUNT, Writer::new().str8("example.com").u32(0x8000_0000).finish()),
        (kind::ETH_SIGN_TX, Writer::new().str8("example.com").u32(0).u32(0).u32(0).bytes16(&[]).finish()),
        (kind::ETH_SIGN_TX, Writer::new().str8("example.com").u32(0).u32(MAX_TX + 1).u32(0).bytes16(&[1]).finish()),
        (kind::ETH_SIGN_TX, Writer::new().str8("example.com").u32(0).u32(10).u32(5).bytes16(&[0; 6]).finish()),
        (kind::ETH_SIGN_MESSAGE, Writer::new().str8("example.com").u32(0).bytes16(&vec![0; MAX_MESSAGE + 1]).finish()),
    ];
    for (k, body) in bad {
        let reply = ask(&mut d, k, body);
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "0x{k:02x}");
    }
}

#[test]
fn ethereum_replies_carry_only_what_the_answer_allows() {
    let (k, body) = reply::eth_account(Approval::Denied, "0xabc");
    assert_eq!(k, kind::ETH_ACCOUNT | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.str8().unwrap()), (Approval::Denied as u8, ""));
    let (_, body) = reply::eth_message(Approval::TimedOut, &[1; 65]);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.bytes16().unwrap()), (Approval::TimedOut as u8, &[][..]));
    let (_, body) = reply::eth_message(Approval::Approved, &[1; 65]);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.bytes16().unwrap().len()), (0, 65));
    let (_, body) = reply::eth_sign(true, Approval::Refused, 99, "maki doesn't sign blob transactions");
    let mut r = Reader::new(&body);
    assert_eq!(
        (r.u8().unwrap(), r.u8().unwrap(), r.u32().unwrap(), r.str8().unwrap()),
        (1, Approval::Refused as u8, 0, "maki doesn't sign blob transactions")
    );
}

#[test]
fn app_requests_go_to_the_host() {
    let mut d = device();
    assert_eq!(handled(&mut d, kind::APP_LIST, Writer::new().u32(2).finish()), Handled::Apps(Apps::List { index: 2 }));
    let piece = vec![b'M', b'A', b'K', b'I'];
    assert_eq!(
        handled(&mut d, kind::APP_INSTALL, Writer::new().u32(9000).u32(4096).bytes16(&piece).finish()),
        Handled::Apps(Apps::Install { total: 9000, offset: 4096, data: piece })
    );
    assert_eq!(
        handled(&mut d, kind::APP_REMOVE, Writer::new().str8("com.leviathan.maki.dice").finish()),
        Handled::Apps(Apps::Remove { id: "com.leviathan.maki.dice".into() })
    );
    assert_eq!(
        handled(&mut d, kind::APP_MESSAGE, Writer::new().str8("com.leviathan.maki.ssh").bytes16(b"list").finish()),
        Handled::Apps(Apps::Message { id: "com.leviathan.maki.ssh".into(), message: b"list".to_vec() })
    );
}

#[test]
fn app_requests_out_of_range_are_refused() {
    let mut d = device();
    let bad = [
        (kind::APP_INSTALL, Writer::new().u32(0).u32(0).bytes16(&[]).finish()),
        (kind::APP_INSTALL, Writer::new().u32(MAX_APP + 1).u32(0).bytes16(&[1]).finish()),
        (kind::APP_INSTALL, Writer::new().u32(10).u32(5).bytes16(&[0; 6]).finish()),
        (kind::APP_INSTALL, Writer::new().u32(MAX_APP).u32(0).bytes16(&vec![0; APP_PIECE + 1]).finish()),
        (kind::APP_REMOVE, Writer::new().str8("Dice").finish()),
        (kind::APP_REMOVE, Writer::new().str8("com..dice").finish()),
        (kind::APP_REMOVE, Writer::new().str8("").finish()),
        (kind::APP_MESSAGE, Writer::new().str8("SSH").bytes16(b"list").finish()),
        (kind::APP_MESSAGE, Writer::new().str8("com.leviathan.maki.ssh").bytes16(&vec![0; MAX_APP_MESSAGE + 1]).finish()),
    ];
    for (k, body) in bad {
        let reply = ask(&mut d, k, body.clone());
        assert_eq!(error_code(&reply), ErrorCode::BadArgument as u8, "0x{k:02x} {body:02x?}");
    }
    let reply = ask(&mut d, kind::APP_LIST, Writer::new().u32(1).u8(0).finish());
    assert_eq!(error_code(&reply), ErrorCode::Malformed as u8);
}

#[test]
fn app_replies_carry_only_what_the_answer_allows() {
    let entry = AppEntry {
        id: "com.leviathan.maki.dice".into(),
        name: "Dice".into(),
        version: 3,
        label: "1.2".into(),
        developer: vec![7; 32],
        from_store: false,
        backup: true,
        used: 4,
        icon: vec![0xff; 512],
    };
    let (k, body) = reply::app_list(Approval::Approved, 2, Some(&entry));
    assert_eq!(k, kind::APP_LIST | kind::REPLY);
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u32().unwrap(), r.u8().unwrap()), (0, 2, 1));
    assert_eq!((r.str8().unwrap(), r.str8().unwrap(), r.u32().unwrap(), r.str8().unwrap()), ("com.leviathan.maki.dice", "Dice", 3, "1.2"));
    assert_eq!((r.bytes16().unwrap(), r.u8().unwrap(), r.u8().unwrap(), r.u32().unwrap()), (&[7u8; 32][..], 0, 1, 4));
    assert_eq!(r.bytes16().unwrap().len(), 512);
    r.end().unwrap();
    // past the end: the count, no app
    let (_, body) = reply::app_list(Approval::Approved, 2, None);
    assert_eq!(body, [0, 2, 0, 0, 0, 0]);
    // locked: nothing, not even the count
    let (_, body) = reply::app_list(Approval::Locked, 2, Some(&entry));
    assert_eq!(body, [Approval::Locked as u8, 0, 0, 0, 0, 0]);

    let (k, body) = reply::app_install(false, Approval::Approved, "ignored");
    assert_eq!((k, body), (kind::APP_INSTALL | kind::REPLY, vec![0, 0, 0]));
    let (_, body) = reply::app_install(true, Approval::Refused, &"é".repeat(200));
    let mut r = Reader::new(&body);
    assert_eq!((r.u8().unwrap(), r.u8().unwrap()), (1, Approval::Refused as u8));
    // cut at a character, never inside one
    assert_eq!(r.str8().unwrap(), "é".repeat(127));
    let (k, body) = reply::app_remove(Approval::Denied);
    assert_eq!((k, body), (kind::APP_REMOVE | kind::REPLY, vec![Approval::Denied as u8]));

    let (k, body) = reply::app_message(Approval::Approved, b"ok");
    assert_eq!((k, body), (kind::APP_MESSAGE | kind::REPLY, vec![0, 2, 0, b'o', b'k']));
    // no answer: nothing of one
    let (_, body) = reply::app_message(Approval::Unavailable, b"ok");
    assert_eq!(body, [Approval::Unavailable as u8, 0, 0]);
}
