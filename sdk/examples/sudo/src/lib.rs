//! Sudo: each command sudo runs waits for the owner's yes on maki. maki desktop's sudo plugin, an
//! approval plugin (sudo_plugin(5)), asks here over the link once sudoers has said yes, with the
//! whole command; the app shows it on maki's review screen (host API 7's `ask_review`): the
//! command line, what it's given to run with beyond what every command gets, and who asked,
//! where. Once the owner says yes, it signs the request (a fresh nonce of the plugin's, and all it
//! showed) with its key, the keys permission's Ed25519 key, which maki holds. The plugin checks
//! the signature against the key it was set up with, which root keeps, so nothing on the computer
//! can say yes for maki: not with the user's password, nor sudo's remembered one. Opened, it
//! shows how many commands it has approved; from its menu, its key, to check against the one the
//! plugin was set up with.
//!
//! The link's messages, a byte saying what first:
//! - `P`: the public key: `0` and its 32 bytes.
//! - `R`: a command to approve (its layout is `Request`'s). Answered `0` and an Ed25519 signature
//!   (64 bytes) of `SIGNED` followed by the request (everything after the `R`); or `1` the owner
//!   said no, `2` no answer, `3` maki is locked, `4` not a request it takes (or too long to show
//!   whole).

#![no_std]

use core::cell::UnsafeCell;
use core::fmt::Write;

use maki_app::*;

const LABEL: &str = "sudo";
/// What the plugin checks a signature of: this, then the request.
const SIGNED: &[u8] = b"maki sudo approval\0";

const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;

/// How long the owner has to read it and say.
const TIMEOUT_S: u32 = 60;
/// The most a message can be, and room before it for `SIGNED`, to sign it where it lies.
const MOST: usize = 4096;
const ROOM: usize = SIGNED.len() + MOST;

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

/// What the owner reads of a request, as it's put together.
struct Shown {
    /// the command line (for sudoedit, the files)
    command: Buf<4096>,
    /// what it's told it's called, if that isn't its name
    called: Buf<256>,
    environment: Buf<2048>,
    /// where it was asked from, and runs
    place: Buf<1024>,
}

static SHOWN: Scratch<Shown> =
    Scratch::new(Shown { command: Buf::new(), called: Buf::new(), environment: Buf::new(), place: Buf::new() });
/// The review's text: all of that, and room.
static REVIEW: Scratch<[u8; 8192]> = Scratch::new([0; 8192]);

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = b;
        Some(a)
    }

    fn byte(&mut self) -> Option<u8> { Some(self.take(1)?[0]) }

    fn str8(&mut self) -> Option<&'a [u8]> {
        let n = self.byte()? as usize;
        self.take(n)
    }

    fn str16(&mut self) -> Option<&'a [u8]> {
        let n = u16::from_le_bytes(self.take(2)?.try_into().ok()?) as usize;
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

/// A command sudo would run, as the plugin sends it: none of it need be UTF-8.
///
/// ```text
/// nonce         32 bytes, fresh for each
/// host          str8    the computer's name
/// user          str8    who asked
/// runas_user    str8    who it runs as
/// runas_group   str8    the group it runs with, if not that user's own (else empty)
/// cwd           str16   the directory it runs in
/// chroot        str16   the root directory it runs in, if not / (else empty)
/// tty           str8    the terminal it was asked from (else empty)
/// flags         u8      1: sudoedit, which copies files to edit as the user and back
/// edit_files    u8      for sudoedit, how many of the arguments, at the end, are its files
/// command       str16   its full path
/// argv          list    what it's told it was run as (argv[0]), then its arguments
/// env           list    "NAME=value" for what it's given beyond what every command gets
/// ```
///
/// `str8` is a byte's length then the bytes, `str16` a u16's (little-endian); a list is a byte's
/// count, then that many `str16`s.
struct Request<'a> {
    host: &'a [u8],
    user: &'a [u8],
    runas_user: &'a [u8],
    runas_group: &'a [u8],
    cwd: &'a [u8],
    chroot: &'a [u8],
    tty: &'a [u8],
    sudoedit: bool,
    edit_files: usize,
    command: &'a [u8],
    argv: List<'a>,
    env: List<'a>,
}

impl<'a> Request<'a> {
    fn parse(body: &'a [u8]) -> Option<Request<'a>> {
        let mut r = Reader(body);
        r.take(32)?;
        let request = Request {
            host: r.str8()?,
            user: r.str8()?,
            runas_user: r.str8()?,
            runas_group: r.str8()?,
            cwd: r.str16()?,
            chroot: r.str16()?,
            tty: r.str8()?,
            sudoedit: r.byte()? & 1 != 0,
            edit_files: r.byte()? as usize,
            command: r.str16()?,
            argv: r.list()?,
            env: r.list()?,
        };
        let known = r.0.is_empty() && !request.command.is_empty() && request.argv.count > 0;
        (known && request.edit_files < request.argv.count && !request.runas_user.is_empty()).then_some(request)
    }

    /// The command's own name: its path's last part.
    fn name(&self) -> &'a [u8] { self.command.rsplit(|&b| b == b'/').next().unwrap_or(self.command) }
}

/// Bytes as the owner reads them: printable ASCII as it is (a backslash doubled), anything else as
/// `\xNN`, so nothing hides or looks like something it isn't.
fn plain(out: &mut impl Write, b: &[u8]) {
    for &c in b {
        let _ = match c {
            b'\\' => out.write_str("\\\\"),
            0x20..=0x7e => out.write_char(c as char),
            _ => write!(out, "\\x{c:02x}"),
        };
    }
}

/// `plain`, cut to `most` bytes with "..." if it's longer.
fn plain_cut<const N: usize>(out: &mut Buf<N>, b: &[u8], most: usize) {
    let mut all = Buf::<512>::new();
    plain(&mut all, b);
    if all.len() <= most && all.len() < 512 {
        let _ = out.write_str(all.as_str());
    } else {
        let _ = out.write_str(&all.as_str()[..most.saturating_sub(3).min(all.len())]);
        let _ = out.write_str("...");
    }
}

/// A word of a command line as a shell takes it back: bare if nothing in it is special, in single
/// quotes if it's printable, else in `$'...'` with every other byte escaped.
fn word(out: &mut impl Write, b: &[u8]) {
    let bare = |c: u8| c.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&c);
    let printable = |c: u8| (0x20..=0x7e).contains(&c);
    if !b.is_empty() && b.iter().all(|&c| bare(c)) {
        plain(out, b);
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

/// Whether all of `write` fit in `out`: a `Buf` drops what doesn't.
fn fits<const N: usize>(out: &mut Buf<N>, write: impl FnOnce(&mut Buf<N>)) -> bool {
    out.clear();
    write(out);
    out.len() < N
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
    approved: u32,
    status: Buf<48>,
    showing_key: bool,
}

impl App {
    fn note(&mut self, what: &str) {
        self.status.clear();
        let _ = self.status.write_str(what);
    }

    /// A message from the plugin, and the answer, into `answer`.
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
            b'R' => {
                let code = self.approve(&message[at + 1..at + n]);
                if code != OK {
                    answer.push(code);
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
    fn approve(&mut self, body: &[u8]) -> u8 {
        let Some(r) = Request::parse(body) else { return BAD };
        // SAFETY: taken once, for this message
        let (shown, text) = unsafe { (SHOWN.take(), REVIEW.take()) };
        let files = r.argv.count - r.edit_files;
        let argv0 = r.argv.iter().next().unwrap_or(&[]);
        let whole = fits(&mut shown.command, |out| {
            if r.sudoedit {
                // the files, one to a line: the editor runs as the owner, not as root
                for (i, file) in r.argv.iter().skip(files).enumerate() {
                    if i > 0 {
                        let _ = out.write_char('\n');
                    }
                    word(out, file);
                }
            } else {
                word(out, r.command);
                for arg in r.argv.iter().skip(1) {
                    let _ = out.write_char(' ');
                    word(out, arg);
                }
            }
        }) && fits(&mut shown.environment, |out| {
            for (i, var) in r.env.iter().enumerate() {
                if i > 0 {
                    let _ = out.write_char('\n');
                }
                plain(out, var);
            }
        }) && fits(&mut shown.called, |out| {
            // a login shell's "-bash", say
            if !r.sudoedit && argv0 != r.name() && argv0 != r.command {
                let _ = out.write_str("It's told it's called ");
                word(out, argv0);
                let _ = out.write_char('.');
            }
        }) && fits(&mut shown.place, |out| {
            let _ = out.write_str("on ");
            plain(out, r.host);
            let _ = out.write_str(", in ");
            plain(out, r.cwd);
            if !r.tty.is_empty() {
                let _ = out.write_str(", at ");
                plain(out, r.tty);
            }
            if !r.runas_group.is_empty() {
                let _ = out.write_str("; with the group ");
                plain(out, r.runas_group);
            }
            if !r.chroot.is_empty() {
                let _ = out.write_str("; in the chroot ");
                plain(out, r.chroot);
            }
        });
        if !whole || (r.sudoedit && r.edit_files == 0) {
            self.note("too long to show: denied");
            return BAD;
        }

        let mut question = Buf::<64>::new();
        let _ = question.write_str(if r.sudoedit { "Edit as " } else { "Run it as " });
        plain_cut(&mut question, r.runas_user, 64 - 11 - 1);
        let _ = question.write_char('?');
        let mut detail = Buf::<128>::new();
        let _ = detail.write_str("sudo on ");
        plain_cut(&mut detail, r.host, 120);
        let mut name = Buf::<128>::new();
        plain_cut(&mut name, r.name(), 128);
        let mut who = Buf::<128>::new();
        plain_cut(&mut who, r.user, 128);

        let (yes, heading) = if r.sudoedit { ("edit", "Edit") } else { ("run", "Command") };
        let mut review = AskPages::new(text, question.as_str(), detail.as_str(), yes, "deny");
        if r.sudoedit {
            let mut editor = Buf::<128>::new();
            plain_cut(&mut editor, argv0, 100);
            let mut prose = Buf::<160>::new();
            let _ = write!(prose, "Copied for {} to edit with {}, then back.", who.as_str(), editor.as_str());
            review.page(heading, "", shown.command.as_str(), prose.as_str());
        } else {
            review.page(heading, name.as_str(), shown.command.as_str(), shown.called.as_str());
        }
        if !shown.environment.is_empty() {
            review.page("Given", "", shown.environment.as_str(), "set for it, beyond what every command gets");
        }
        review.page("Asked by", who.as_str(), "", shown.place.as_str());
        match review.timeout(TIMEOUT_S).show() {
            Ok(Answer::Yes) => {
                self.approved += 1;
                let _ = storage::set_u32("approved", self.approved);
                self.note("approved");
                OK
            }
            Ok(Answer::No) => {
                self.note("you said no");
                DENIED
            }
            Ok(Answer::NoAnswer) => {
                self.note("no answer");
                NO_ANSWER
            }
            Err(_) => {
                self.note("couldn't show it: denied");
                BAD
            }
        }
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match keys::public_key(LABEL) {
            Err(_) => {
                screen::text_centred(30, "Unlock maki to", Style::Regular, Color::Light);
                screen::text_centred(45, "approve sudo", Style::Regular, Color::Light);
            }
            Ok(public) if self.showing_key => {
                // as the plugin's key file and maki desktop show it
                screen::text(2, 2, "Sudo's key", Style::Small, Color::Light);
                for (row, part) in public.chunks(8).enumerate() {
                    let mut line = Buf::<16>::new();
                    for b in part {
                        let _ = write!(line, "{b:02x}");
                    }
                    screen::text(8, 22 + row as i32 * 18, line.as_str(), Style::Mono, Color::Light);
                }
            }
            Ok(_) => {
                screen::text_centred(8, "Sudo", Style::Bold, Color::Light);
                screen::text_centred(30, "Each command sudo", Style::Small, Color::Light);
                screen::text_centred(43, "runs asks you here", Style::Small, Color::Light);
                let mut line = Buf::<48>::new();
                if self.status.is_empty() {
                    let _ = write!(line, "approved {}", self.approved);
                } else {
                    let _ = line.write_str(self.status.as_str());
                }
                screen::text_centred(66, line.as_str(), Style::Regular, Color::Light);
                screen::text_centred(94, "menu: show the key", Style::Small, Color::Light);
            }
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&["Show the key"]);
    let mut app = App { approved: storage::get_u32("approved", 0), status: Buf::new(), showing_key: false };
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
