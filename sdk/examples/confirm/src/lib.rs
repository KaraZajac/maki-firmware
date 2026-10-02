//! Confirm: a script or program on the computer asks here before it goes ahead with something
//! that matters (a deploy, `terraform apply`, a force push, a database migration), and goes ahead
//! only on the owner's yes. maki desktop's `maki-confirm` asks over the link with the question,
//! more about it, and who asked where: the user, the computer, the directory and the program. The
//! app shows all of it on maki's review screen (host API 7's `AskPages`), then the question, and
//! on a yes signs the request (a fresh nonce of the caller's, and everything it showed) with its
//! key, the keys permission's Ed25519 key, which maki holds. A caller that keeps the key checks the
//! signature: nothing on the computer can make one, nor use one again for another request. Opened,
//! it shows the last question and what the owner said; from its menu, its key, to compare with the
//! one the caller keeps.
//!
//! The link's messages, a byte saying what first:
//! - `P`: the public key: `0` and its 32 bytes.
//! - `C`: a request to confirm (its layout is `Request`'s). Answered `0` and an Ed25519 signature (64 bytes)
//!   of `SIGNED` followed by the request (everything after the `C`); or `1` the owner said no, `2` no answer,
//!   `3` maki is locked, `4` not a request it takes (or too long to show whole).

#![no_std]

use core::cell::UnsafeCell;
use core::fmt::Write;

use maki_app::*;

const LABEL: &str = "confirm";
/// What a caller checks a signature of: this, then the request.
const SIGNED: &[u8] = b"maki confirm approval\0";

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;

/// The time a request may give the owner to answer, in seconds (maki's review takes 5 to 300).
const SOONEST_S: u16 = 10;
const LATEST_S: u16 = 300;
/// The most a message can be, and room before it for `SIGNED`, to sign it where it lies.
const MOST: usize = 4096;
const ROOM: usize = SIGNED.len() + MOST;

/// The most of each part the owner is shown, in bytes as maki shows them (`shown`): the question
/// is maki's own limit for one, and the rest keep a request to a few screens. A request with more
/// is refused, not cut.
const QUESTION: usize = 64;
const DETAIL: usize = 1024;
const NAME: usize = 64;
const CWD: usize = 512;
const PROGRAM: usize = 512;

/// What's too big for an app's 16 KiB stack, kept here instead. The app has one thread, and takes
/// each once for each message.
struct Scratch<T>(UnsafeCell<T>);

// SAFETY: an app runs on one thread.
unsafe impl<T> Sync for Scratch<T> {}

impl<T> Scratch<T> {
    const fn new(t: T) -> Self { Scratch(UnsafeCell::new(t)) }

    /// SAFETY: nothing else has it.
    #[allow(clippy::mut_from_ref)]
    unsafe fn take(&self) -> &mut T { &mut *self.0.get() }
}

static MESSAGE: Scratch<[u8; ROOM]> = Scratch::new([0; ROOM]);

/// What the owner reads of a request, as it's put together: each part a byte bigger than it may
/// be shown, to tell one that fits from one that doesn't.
struct Shown {
    question: Buf<{ QUESTION + 1 }>,
    detail: Buf<{ DETAIL + 1 }>,
    user: Buf<{ NAME + 1 }>,
    host: Buf<{ NAME + 1 }>,
    cwd: Buf<{ CWD + 1 }>,
    program: Buf<{ PROGRAM + 1 }>,
}

static SHOWN: Scratch<Shown> = Scratch::new(Shown {
    question: Buf::new(),
    detail: Buf::new(),
    user: Buf::new(),
    host: Buf::new(),
    cwd: Buf::new(),
    program: Buf::new(),
});
/// The review's text: all of that, and room.
static REVIEW: Scratch<[u8; 4096]> = Scratch::new([0; 4096]);

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }

    fn byte(&mut self) -> Option<u8> { Some(self.take(1)?[0]) }

    fn u16(&mut self) -> Option<u16> { Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?)) }

    fn str8(&mut self) -> Option<&'a [u8]> {
        let n = self.byte()? as usize;
        self.take(n)
    }

    fn str16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    /// A count, then that many `str16`s: the whole list, checked, and how many.
    fn list(&mut self) -> Option<List<'a>> {
        let count = self.byte()? as usize;
        let start = self.0;
        for _ in 0..count {
            self.str16()?;
        }
        Some(List { bytes: &start[..start.len() - self.0.len()], count })
    }
}

#[derive(Clone, Copy)]
struct List<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> List<'a> {
    fn iter(&self) -> impl Iterator<Item = &'a [u8]> {
        let mut r = Reader(self.bytes);
        (0..self.count).map(move |_| r.str16().unwrap_or(&[]))
    }
}

/// A request to confirm, as `maki-confirm` sends it: none of it need be UTF-8.
///
/// ```text
/// nonce      32 bytes  fresh for each, the caller's
/// timeout    u16       the seconds the owner has to answer, 10 to 300
/// question   str8      what's asked ("Deploy to production?")
/// detail     str16     more about it, in lines (else empty)
/// user       str8      who asked
/// host       str8      the computer's name
/// cwd        str16     the directory it was asked from (else empty)
/// program    list      the program that asked: its command line, a word each (else none)
/// more       u8        how many more words its command line has, left out (else 0)
/// ```
///
/// `str8` is a byte's length then the bytes, `str16` a u16's (little-endian); a list is a byte's
/// count, then that many `str16`s.
struct Request<'a> {
    timeout: u16,
    question: &'a [u8],
    detail: &'a [u8],
    user: &'a [u8],
    host: &'a [u8],
    cwd: &'a [u8],
    program: List<'a>,
    more: u8,
}

impl<'a> Request<'a> {
    fn parse(body: &'a [u8]) -> Option<Request<'a>> {
        let mut r = Reader(body);
        r.take(32)?;
        let request = Request {
            timeout: r.u16()?,
            question: r.str8()?,
            detail: r.str16()?,
            user: r.str8()?,
            host: r.str8()?,
            cwd: r.str16()?,
            program: r.list()?,
            more: r.byte()?,
        };
        let known = r.0.is_empty()
            && (SOONEST_S..=LATEST_S).contains(&request.timeout)
            && request.question.iter().any(|&c| c != b' ')
            && !request.user.is_empty()
            && !request.host.is_empty();
        known.then_some(request)
    }
}

/// Bytes as the owner reads them: printable ASCII as it is (a backslash doubled), anything else as
/// `\xNN`, so nothing hides or looks like something it isn't; new lines kept, if `lines`.
fn shown(out: &mut impl Write, b: &[u8], lines: bool) {
    for &c in b {
        let _ = match c {
            b'\\' => out.write_str("\\\\"),
            b'\n' if lines => out.write_char('\n'),
            0x20..=0x7e => out.write_char(c as char),
            _ => write!(out, "\\x{c:02x}"),
        };
    }
}

/// A word of a command line as a shell takes it back: bare if nothing in it is special, in single
/// quotes if it's printable, else in `$'...'` with every other byte escaped.
fn word(out: &mut impl Write, b: &[u8]) {
    let bare = |c: u8| c.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&c);
    let printable = |c: u8| (0x20..=0x7e).contains(&c);
    if !b.is_empty() && b.iter().all(|&c| bare(c)) {
        shown(out, b, false);
    } else if b.iter().all(|&c| printable(c)) {
        let _ = out.write_char('\'');
        for &c in b {
            let _ = if c == b'\'' { out.write_str("'\\''") } else { out.write_char(c as char) };
        }
        let _ = out.write_char('\'');
    } else {
        let _ = out.write_str("$'");
        for &c in b {
            let _ = match c {
                b'\\' => out.write_str("\\\\"),
                b'\'' => out.write_str("\\'"),
                b'\n' => out.write_str("\\n"),
                b'\t' => out.write_str("\\t"),
                b'\r' => out.write_str("\\r"),
                0x20..=0x7e => out.write_char(c as char),
                _ => write!(out, "\\x{c:02x}"),
            };
        }
        let _ = out.write_char('\'');
    }
}

/// Whether all of `write` fit in `out`, a byte bigger than may be shown: a `Buf` drops what
/// doesn't fit, and all of it is ASCII.
fn fits<const N: usize>(out: &mut Buf<N>, write: impl FnOnce(&mut Buf<N>)) -> bool {
    out.clear();
    write(out);
    out.len() < N
}

/// ASCII `s` into `out`, cut to `most` bytes with "..." if it's longer.
fn cut<const N: usize>(out: &mut Buf<N>, s: &str, most: usize) {
    if s.len() <= most {
        let _ = out.write_str(s);
    } else {
        let _ = out.write_str(s.get(..most.saturating_sub(3)).unwrap_or(""));
        let _ = out.write_str("...");
    }
}

/// `s` cut to fit `width` pixels in `style`, with "..." if it had to be.
fn fitted(s: &str, style: Style, width: i32) -> Buf<{ QUESTION + 1 }> {
    let mut line = Buf::new();
    let _ = line.write_str(s);
    let mut keep = s.len();
    while keep > 0 && screen::text_width(line.as_str(), style) > width {
        keep -= 1;
        line.clear();
        cut(&mut line, s, keep);
    }
    line
}

/// An answer's bytes: what fits.
struct Reply {
    bytes: [u8; 80],
    len: usize,
}

impl Reply {
    fn push(&mut self, b: u8) { self.extend(&[b]) }

    fn extend(&mut self, b: &[u8]) {
        let n = b.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
    }
}

struct App {
    /// The last request's question, as it was shown (cut, if it was too long to show), and what
    /// came of it: an answer's first byte.
    last: Buf<{ QUESTION + 1 }>,
    said: Option<u8>,
    showing_key: bool,
}

impl App {
    /// As it was left: the last request, kept as what came of it and then its question.
    fn load() -> App {
        let mut app = App { last: Buf::new(), said: None, showing_key: false };
        let mut record = [0u8; QUESTION + 1];
        let Some(n) = storage::get("last", &mut record) else { return app };
        let (Some(&said), Some(question)) = (record.first(), record.get(1..n)) else { return app };
        // what this version keeps (the question as it was shown, so printable ASCII), and nothing
        // else
        let question = core::str::from_utf8(question).unwrap_or("\n");
        if matches!(said, OK | DENIED | NO_ANSWER | BAD)
            && question.bytes().all(|c| (0x20..=0x7e).contains(&c))
        {
            let _ = app.last.write_str(question);
            app.said = Some(said);
        }
        app
    }

    /// What came of a request, kept to show when the app's opened.
    fn keep(&mut self, said: u8, question: &str) {
        self.last.clear();
        cut(&mut self.last, question, QUESTION);
        self.said = Some(said);
        let mut record = [0u8; QUESTION + 1];
        record[0] = said;
        let q = self.last.as_str().as_bytes();
        record[1..1 + q.len()].copy_from_slice(q);
        let _ = storage::set("last", &record[..1 + q.len()]);
    }

    /// A message from `maki-confirm`, and the answer, into `answer`.
    fn handle(&mut self, message: &mut [u8; ROOM], n: usize, answer: &mut Reply) {
        let Ok(public) = keys::public_key(LABEL) else {
            answer.push(LOCKED);
            return;
        };
        // the message lies after room for SIGNED, to be signed where it is
        let at = SIGNED.len() - 1;
        match message[at] {
            b'P' if n == 1 => {
                answer.push(OK);
                answer.extend(&public);
            }
            b'C' => {
                let said = self.confirm(&message[at + 1..at + n]);
                if said != OK {
                    answer.push(said);
                    return;
                }
                message[..SIGNED.len()].copy_from_slice(SIGNED);
                match keys::sign(LABEL, &message[..at + n]) {
                    Ok(signature) => {
                        answer.push(OK);
                        answer.extend(&signature);
                    }
                    Err(_) => answer.push(LOCKED),
                }
            }
            _ => answer.push(BAD),
        }
    }

    /// Shows the owner a request and asks: OK for a yes.
    fn confirm(&mut self, body: &[u8]) -> u8 {
        let Some(r) = Request::parse(body) else {
            self.keep(BAD, "");
            return BAD;
        };
        // SAFETY: taken once, for this message
        let (shown_, text) = unsafe { (SHOWN.take(), REVIEW.take()) };
        let whole = fits(&mut shown_.question, |out| shown(out, r.question, false))
            && fits(&mut shown_.detail, |out| shown(out, r.detail, true))
            && fits(&mut shown_.user, |out| shown(out, r.user, false))
            && fits(&mut shown_.host, |out| shown(out, r.host, false))
            && fits(&mut shown_.cwd, |out| shown(out, r.cwd, false))
            && fits(&mut shown_.program, |out| {
                for (i, w) in r.program.iter().enumerate() {
                    if i > 0 {
                        let _ = out.write_char(' ');
                    }
                    word(out, w);
                }
            });
        if !whole {
            // what can be shown of the question, for the owner to know what was turned down
            let mut question = Buf::<{ QUESTION + 1 }>::new();
            let mut all = Buf::<{ 4 * 255 }>::new();
            shown(&mut all, r.question, false);
            cut(&mut question, all.as_str(), QUESTION);
            self.keep(BAD, question.as_str());
            return BAD;
        }

        // under the question, who asked on which computer; on the last page, all of where
        let mut who = Buf::<{ 2 * NAME + 4 }>::new();
        let _ = write!(who, "{} on {}", shown_.user.as_str(), shown_.host.as_str());
        let mut line = Buf::<128>::new();
        cut(&mut line, who.as_str(), 128);
        let mut place = Buf::<{ NAME + CWD + 80 }>::new();
        let _ = write!(place, "on {}", shown_.host.as_str());
        if !shown_.cwd.is_empty() {
            let _ = write!(place, ", in {}", shown_.cwd.as_str());
        }
        if r.more > 0 {
            let words = if r.more == 1 { "word" } else { "words" };
            let _ = write!(place, ". Its command line has {} more {words}, left out.", r.more);
        }

        let mut review = AskPages::new(text, shown_.question.as_str(), line.as_str(), "yes", "no");
        if !shown_.detail.is_empty() {
            review.page("Details", "", shown_.detail.as_str(), "");
        }
        review.page("Asked by", shown_.user.as_str(), shown_.program.as_str(), place.as_str());
        let said = match review.timeout(u32::from(r.timeout)).show() {
            Ok(Answer::Yes) => OK,
            Ok(Answer::No) => DENIED,
            Ok(Answer::NoAnswer) => NO_ANSWER,
            // maki wouldn't show it
            Err(_) => BAD,
        };
        self.keep(said, shown_.question.as_str());
        said
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match keys::public_key(LABEL) {
            Err(_) => {
                screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                screen::text_centred(45, "answer scripts", Style::Regular, Color::Light);
            }
            Ok(public) if self.showing_key => {
                // as maki-confirm --public-key and maki desktop show it
                screen::text(2, 2, "Confirm's key", Style::Small, Color::Light);
                for (row, part) in public.chunks(8).enumerate() {
                    let mut line = Buf::<16>::new();
                    for b in part {
                        let _ = write!(line, "{b:02x}");
                    }
                    screen::text(8, 22 + row as i32 * 18, line.as_str(), Style::Mono, Color::Light);
                }
            }
            Ok(_) => {
                screen::text_centred(8, "Confirm", Style::Bold, Color::Light);
                screen::text_centred(28, "Scripts ask you here", Style::Small, Color::Light);
                screen::text_centred(40, "before they go ahead", Style::Small, Color::Light);
                match self.said {
                    None => screen::text_centred(62, "nothing asked yet", Style::Small, Color::Light),
                    Some(said) => {
                        let unread = self.last.is_empty();
                        let question = if unread { "a request it couldn't read" } else { self.last.as_str() };
                        let line = fitted(question, Style::Small, WIDTH - 4);
                        screen::text_centred(58, line.as_str(), Style::Small, Color::Light);
                        let what = match said {
                            OK => "you said yes",
                            DENIED => "you said no",
                            NO_ANSWER => "no answer",
                            _ if unread => "turned down",
                            _ => "too long to show",
                        };
                        screen::text_centred(72, what, Style::Regular, Color::Light);
                    }
                }
                screen::text_centred(94, "menu: show the key", Style::Small, Color::Light);
            }
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&["Show the key"]);
    let mut app = App::load();
    loop {
        app.draw();
        match wait(None) {
            Event::Message => {
                // SAFETY: taken once, for this message
                let message = unsafe { MESSAGE.take() };
                let mut answer = Reply { bytes: [0; 80], len: 0 };
                let at = SIGNED.len() - 1;
                match link::read(&mut message[at..]) {
                    Some(n) if (1..=MOST).contains(&n) => app.handle(message, n, &mut answer),
                    _ => answer.push(BAD),
                }
                let _ = link::reply(&answer.bytes[..answer.len]);
            }
            Event::Menu(0) => app.showing_key = !app.showing_key,
            Event::Centre | Event::Left | Event::Right if app.showing_key => app.showing_key = false,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
