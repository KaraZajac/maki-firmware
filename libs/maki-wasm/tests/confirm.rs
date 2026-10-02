//! The Confirm example (sdk/examples/confirm), as `maki build` packed it and maki runs it: its key
//! for `maki-confirm` to keep, each request shown whole on maki's review screen (the question,
//! more about it, who asked where), signed once the owner says yes (the request and all it showed,
//! with the app's key), and what it can't read or show whole refused before anything's shown.
//! Rebuild the fixture after changing the app: `maki build sdk/examples/confirm`, then copy
//! `sdk/target/maki/com.leviathan.maki.confirm.maki` to `tests/fixtures/confirm.maki`.

mod harness;

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use harness::*;
use maki_wasm::*;

/// What a yes is a signature of: this, then the request.
const SIGNED: &[u8] = b"maki confirm approval\0";

/// The app's key: the harness gives every label the same secret, the key's seed.
fn key() -> VerifyingKey { SigningKey::from_bytes(&[7; 32]).verifying_key() }

/// A request as `maki-confirm` sends one (the app's `Request`), its parts to change.
#[derive(Clone)]
struct Req {
    nonce: u8,
    timeout: u16,
    question: Vec<u8>,
    detail: Vec<u8>,
    user: Vec<u8>,
    host: Vec<u8>,
    cwd: Vec<u8>,
    program: Vec<Vec<u8>>,
    more: u8,
}

fn req(question: &str) -> Req {
    Req {
        nonce: 1,
        timeout: 120,
        question: question.into(),
        detail: Vec::new(),
        user: b"kara".to_vec(),
        host: b"laptop".to_vec(),
        cwd: b"/home/kara/site".to_vec(),
        program: vec![b"bash".to_vec(), b"./deploy.sh".to_vec(), b"production".to_vec()],
        more: 0,
    }
}

impl Req {
    /// Everything after the `C`.
    fn body(&self) -> Vec<u8> {
        let s8 = |out: &mut Vec<u8>, b: &[u8]| {
            out.push(b.len() as u8);
            out.extend(b);
        };
        let s16 = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend((b.len() as u16).to_le_bytes());
            out.extend(b);
        };
        let mut out = vec![self.nonce; 32];
        out.extend(self.timeout.to_le_bytes());
        s8(&mut out, &self.question);
        s16(&mut out, &self.detail);
        s8(&mut out, &self.user);
        s8(&mut out, &self.host);
        s16(&mut out, &self.cwd);
        out.push(self.program.len() as u8);
        for word in &self.program {
            s16(&mut out, word);
        }
        out.push(self.more);
        out
    }

    fn message(&self) -> Vec<u8> { [&b"C"[..], &self.body()].concat() }
}

/// The app run on these messages, the owner answering as `answers` say, from `storage`.
fn asked(messages: &[Vec<u8>], answers: &[Answer], storage: BTreeMap<String, Vec<u8>>) -> Record {
    let (stop, record) = run_record(
        "confirm",
        Record {
            events: messages.iter().map(|_| Event::Message).collect(),
            inbox: messages.iter().cloned().collect(),
            answers: answers.iter().copied().collect(),
            storage,
            ..Default::default()
        },
    );
    assert_eq!(stop, Stop::Finished);
    record
}

fn verifies(reply: &[u8], body: &[u8]) -> bool {
    reply.len() == 65
        && reply[0] == 0
        && key().verify(&[SIGNED, body].concat(), &Signature::from_slice(&reply[1..]).unwrap()).is_ok()
}

/// Whether `frame` has `text` across the middle at `y`, and nothing else in its rows.
fn line(frame: &Canvas, y: i32, text: &str, style: Style) -> bool {
    let mut want = Canvas::default();
    want.text((WIDTH as i32 - Canvas::text_width(text, style)) / 2, y, text, style, Color::Light);
    (y..y + style.height()).all(|row| (0..WIDTH as i32).all(|x| frame.get(x, row) == want.get(x, row)))
}

#[test]
fn confirm_gives_its_key_and_signs_a_request_it_showed_whole_once_the_owner_says_yes() {
    let bundle =
        std::fs::read(format!("{}/tests/fixtures/confirm.maki", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let bundle = maki_bundle::read(&bundle).unwrap();
    assert_eq!((bundle.manifest.api, bundle.manifest.backup), (7, false));

    // its key, for maki-confirm's key file
    let got = asked(&[b"P".to_vec()], &[], BTreeMap::new());
    assert_eq!(got.replies, [[&[0u8][..], key().as_bytes()].concat()]);
    assert!(got.reviews.is_empty());

    // a request: the details, then who asked where, then the question
    let mut deploy = req("Deploy to production?");
    deploy.detail = b"web-1, web-2\nrelease 2.4.1".to_vec();
    let got = asked(&[deploy.message()], &[Answer::Yes], BTreeMap::new());
    assert_eq!(got.menu, ["Show the key"]);
    let review = &got.reviews[0];
    assert_eq!(
        (review.question.as_str(), review.detail.as_str()),
        ("Deploy to production?", "kara on laptop")
    );
    assert_eq!((review.yes.as_str(), review.no.as_str(), review.timeout_s), ("yes", "no", 120));
    assert_eq!(
        review.pages,
        [
            Page { heading: "Details".into(), mono: "web-1, web-2\nrelease 2.4.1".into(), ..Page::default() },
            Page {
                heading: "Asked by".into(),
                value: "kara".into(),
                mono: "bash ./deploy.sh production".into(),
                prose: "on laptop, in /home/kara/site".into(),
            },
        ]
    );
    // signed: the request, everything after the C, behind the app's own words
    assert!(verifies(&got.replies[0], &deploy.body()), "{:?}", got.replies);
    // and only that request: another nonce, or another question, isn't what was signed
    let mut again = deploy.clone();
    again.nonce = 2;
    assert!(!verifies(&got.replies[0], &again.body()));
    let mut other = deploy.clone();
    other.question = b"Deploy to staging?".to_vec();
    assert!(!verifies(&got.replies[0], &other.body()));
    // kept: what it asked, and that the owner said yes
    assert_eq!(got.storage["last"], b"\0Deploy to production?");

    // the time it gives the owner is the request's, and no details is no page for them
    let mut quick = req("Force-push main?");
    quick.timeout = 10;
    quick.program = Vec::new();
    quick.cwd = Vec::new();
    let got = asked(&[quick.message()], &[Answer::Yes], BTreeMap::new());
    assert_eq!(got.reviews[0].timeout_s, 10);
    assert_eq!(
        got.reviews[0].pages,
        [Page {
            heading: "Asked by".into(),
            value: "kara".into(),
            prose: "on laptop".into(),
            ..Page::default()
        }]
    );
    assert!(verifies(&got.replies[0], &quick.body()));
}

#[test]
fn confirm_says_no_and_no_answer_and_signs_nothing_then() {
    let (no, quiet) = (req("Drop the users table?"), req("Run the migration?"));
    let got = asked(&[no.message(), quiet.message()], &[Answer::No, Answer::NoAnswer], BTreeMap::new());
    assert_eq!(got.reviews.len(), 2);
    assert_eq!(got.replies, [vec![1], vec![2]]);
    assert_eq!(got.storage["last"], b"\x02Run the migration?");
}

#[test]
fn confirm_shows_what_isnt_plain_as_escapes_and_a_command_line_as_a_shell_takes_it() {
    let mut odd = req("D\u{e9}ployer ?");
    odd.detail = b"a\tb\\c\r\nnext line".to_vec();
    odd.user = b"k\x1bara".to_vec();
    odd.cwd = b"/tmp/new\nline".to_vec();
    odd.program =
        vec![b"/bin/sh".to_vec(), b"-c".to_vec(), b"echo 'hi' there".to_vec(), b"a\nb".to_vec(), Vec::new()];
    odd.more = 3;
    let got = asked(&[odd.message()], &[Answer::Yes], BTreeMap::new());
    let review = &got.reviews[0];
    // nothing hides, or looks like something it isn't: bytes beyond printable ASCII as escapes,
    // and a backslash doubled so an escape can't be faked; new lines in the details kept
    assert_eq!(review.question, r"D\xc3\xa9ployer ?");
    assert_eq!(review.detail, r"k\x1bara on laptop");
    assert_eq!(review.pages[0].mono, "a\\x09b\\\\c\\x0d\nnext line");
    assert_eq!(review.pages[1].value, r"k\x1bara");
    // each word of the command line quoted as a shell would take it back, and the words left out
    // said to be
    assert_eq!(review.pages[1].mono, r#"/bin/sh -c 'echo '\''hi'\'' there' $'a\nb' ''"#);
    assert_eq!(
        review.pages[1].prose,
        r"on laptop, in /tmp/new\x0aline. Its command line has 3 more words, left out."
    );
    assert!(verifies(&got.replies[0], &odd.body()));
    let mut one = req("Go?");
    one.more = 1;
    let got = asked(&[one.message()], &[Answer::Yes], BTreeMap::new());
    assert!(got.reviews[0].pages[0].prose.ends_with("Its command line has 1 more word, left out."));
}

#[test]
fn confirm_refuses_what_it_cannot_read_or_show_whole_without_asking() {
    let plain = req("Deploy?");
    let body = plain.body();
    let mut bad: Vec<Vec<u8>> = Vec::new();
    // not a request: cut short, or with more after it
    bad.push([&b"C"[..], &body[..body.len() - 1]].concat());
    bad.push([&b"C"[..], &body, &[0]].concat());
    bad.push([&b"C"[..], &body[..20]].concat());
    // a time the owner can't be given
    for timeout in [0, 9, 301, u16::MAX] {
        let mut r = plain.clone();
        r.timeout = timeout;
        bad.push(r.message());
    }
    // no question, or nobody asking from nowhere
    for (question, user, host) in
        [("", "kara", "laptop"), ("   ", "kara", "laptop"), ("Go?", "", "laptop"), ("Go?", "kara", "")]
    {
        let mut r = req(question);
        (r.user, r.host) = (user.into(), host.into());
        bad.push(r.message());
    }
    // too long to show whole: a question past maki's 64 (an escape counting as the four it shows),
    // details past 1024, a name past 64, a directory or a command line past 512
    let mut r = req(&"q".repeat(65));
    bad.push(r.message());
    r.question = [&b"q".repeat(61)[..], b"\xff"].concat();
    bad.push(r.message());
    let mut r = plain.clone();
    r.detail = vec![b'd'; 1025];
    bad.push(r.message());
    let mut r = plain.clone();
    r.detail = vec![0; 257];
    bad.push(r.message());
    let mut r = plain.clone();
    r.user = vec![b'u'; 65];
    bad.push(r.message());
    let mut r = plain.clone();
    r.host = vec![b'h'; 65];
    bad.push(r.message());
    let mut r = plain.clone();
    r.cwd = vec![b'c'; 513];
    bad.push(r.message());
    let mut r = plain.clone();
    r.program = vec![vec![b'p'; 400], vec![b'p'; 112]];
    bad.push(r.message());
    // what isn't a message of its own
    for m in [&b""[..], b"Q", b"PP", b"c"] {
        bad.push(m.to_vec());
    }
    let n = bad.len();
    let got = asked(&bad, &vec![Answer::Yes; n], BTreeMap::new());
    assert!(got.reviews.is_empty(), "{:?}", got.reviews);
    assert_eq!(got.replies, vec![vec![4]; n]);

    // just inside each limit, it asks
    let mut r = req(&"q".repeat(64));
    r.detail = vec![b'd'; 1024];
    (r.user, r.host, r.cwd) = (vec![b'u'; 64], vec![b'h'; 64], vec![b'c'; 512]);
    r.program = vec![vec![b'p'; 400], vec![b'p'; 110]];
    let got = asked(&[r.message()], &[Answer::Yes], BTreeMap::new());
    assert_eq!(got.reviews.len(), 1);
    assert!(verifies(&got.replies[0], &r.body()));
    // the line under the question is cut to maki's 128, and said to be; the page has it whole
    assert_eq!(got.reviews[0].detail, format!("{} on {}...", "u".repeat(64), "h".repeat(57)));
    assert!(got.reviews[0].pages[1].prose.starts_with(&format!("on {}, in ", "h".repeat(64))));
}

#[test]
fn confirm_shows_the_last_question_and_what_was_said_and_its_key_from_the_menu() {
    // nothing asked yet
    let (_, fresh) = run_fixture("confirm", &[], BTreeMap::new());
    let first = &fresh.frames[0];
    assert!(line(first, 8, "Confirm", Style::Bold));
    assert!(line(first, 28, "Scripts ask you here", Style::Small));
    assert!(line(first, 62, "nothing asked yet", Style::Small));
    assert!(line(first, 94, "menu: show the key", Style::Small));

    // a yes, then the question and what was said, kept for when it's opened again
    let got = asked(&[req("Deploy to production?").message()], &[Answer::Yes], BTreeMap::new());
    let after = got.frames.last().unwrap();
    assert!(line(after, 58, "Deploy to production?", Style::Small));
    assert!(line(after, 72, "you said yes", Style::Regular));
    let (_, opened) = run_fixture("confirm", &[], got.storage.clone());
    assert_eq!(&opened.frames[0], after);
    // a no, no answer, and one too long to show, each said
    for (answer, said) in [(Answer::No, "you said no"), (Answer::NoAnswer, "no answer")] {
        let got = asked(&[req("Go?").message()], &[answer], BTreeMap::new());
        assert!(line(got.frames.last().unwrap(), 72, said, Style::Regular), "{said}");
    }
    let got = asked(&[req(&"q".repeat(70)).message()], &[], BTreeMap::new());
    assert!(line(got.frames.last().unwrap(), 72, "too long to show", Style::Regular));
    assert_eq!(got.storage["last"], [&[4u8][..], &b"q".repeat(61), b"..."].concat());
    let got = asked(&[b"Cx".to_vec()], &[], BTreeMap::new());
    assert!(line(got.frames.last().unwrap(), 58, "a request it couldn't read", Style::Small));
    assert!(line(got.frames.last().unwrap(), 72, "turned down", Style::Regular));
    // a long question cut to the screen's width, and said to be
    let long = "Run the database migration on every shard?";
    let got = asked(&[req(long).message()], &[Answer::Yes], BTreeMap::new());
    let frame = got.frames.last().unwrap();
    assert!(!line(frame, 58, long, Style::Small));
    let cut = (1..long.len())
        .rev()
        .map(|n| format!("{}...", &long[..n]))
        .find(|s| Canvas::text_width(s, Style::Small) <= 124);
    assert!(line(frame, 58, &cut.unwrap(), Style::Small));

    // what an older version left, or anything else, isn't read as what was said
    for kept in [vec![9u8, b'x'], vec![0u8, 0xff], vec![0u8; 80]] {
        let (_, r) = run_fixture("confirm", &[], BTreeMap::from([("last".to_string(), kept)]));
        assert_eq!(r.frames[0], *first);
    }

    // its key, from the menu, as maki desktop and maki-confirm show it: four lines of hex; any
    // press goes back
    let (_, r) = run_fixture("confirm", &[Event::Menu(0), Event::Centre], BTreeMap::new());
    let mut want = Canvas::default();
    want.text(2, 2, "Confirm's key", Style::Small, Color::Light);
    for (row, part) in key().as_bytes().chunks(8).enumerate() {
        let hex: String = part.iter().map(|b| format!("{b:02x}")).collect();
        want.text(8, 22 + row as i32 * 18, &hex, Style::Mono, Color::Light);
    }
    assert_eq!(r.frames[1], want);
    assert_eq!(r.frames[2], *first);
}
