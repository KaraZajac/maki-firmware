//! Solana: maki's Solana account, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). The account is SLIP-10's, `m/44'/501'/i'/0'`, as Phantom and Solflare make it, so the
//! phrase works there too. maki keeps the key (the wallet permission, Ed25519 on `m/44'/501'` and
//! nothing else); this app reads what it's asked to sign with maki's code (`maki-sol`: strictly, as
//! Solana's runtime reads it; SOL and token transfers spelled out, a token's recipient shown as
//! their own address when the transaction proves the token account is theirs; the most the fee can
//! be; anything else flagged, with whether it's given this account's signature), shows it on maki's
//! own review screen after the site that asked, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop (for sites, through the maki extension, and for its own wallet as `desktop.maki`)
//! talks to it over the link. Each message starts with what it is; each answer with a status, then
//! its fields (a reason as a u16 length and the text). `site` is the site asking, as a length byte
//! and the name:
//!
//! - `A` index (u32, little-endian), site: the account's key (32 bytes), once the owner lets the
//!   site connect;
//! - `T` index, site, then a transaction's message: its signature (64 bytes), once the owner has
//!   gone through it;
//! - `M` index, site, then a message: its signature, once the owner has read it.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_sol::{address, display, Key, Message};

const ACCOUNT: u8 = b'A';
const TRANSACTION: u8 = b'T';
const MESSAGE: u8 = b'M';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, or can't show.
const REFUSED: u8 = 5;

const H: u32 = wallet::HARDENED;

/// An answer: the status, then its fields.
struct Answer(Vec<u8>);

impl Answer {
    fn new(status: u8) -> Answer { Answer(vec![status]) }
    fn text(mut self, s: &str) -> Answer {
        self.0.extend_from_slice(&(s.len() as u16).to_le_bytes());
        self.0.extend_from_slice(s.as_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> Answer {
        self.0.extend_from_slice(b);
        self
    }
}

fn refused(why: &str) -> Answer { Answer::new(REFUSED).text(why) }

fn u32_at(b: &[u8], at: usize) -> Option<u32> { b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) }

/// The site at `at` (a length byte, then the name), and where what follows starts.
fn site_at(b: &[u8], at: usize) -> Option<(&str, usize)> {
    let n = *b.get(at)? as usize;
    let site = core::str::from_utf8(b.get(at + 1..at + 1 + n)?).ok()?;
    valid_site(site).then_some((site, at + 1 + n))
}

/// A site maki is willing to show, as for logins (maki-proto's `site::valid`): a plain hostname,
/// lowercase ASCII letters, digits, dots and hyphens. An international domain comes as punycode
/// (`xn--...`) and is shown that way, never as characters that could pass for another site's.
fn valid_site(site: &str) -> bool {
    !site.is_empty()
        && site.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !site.starts_with('.')
        && !site.ends_with('.')
        && !site.contains("..")
}

/// The page every review starts with: who's asking. The browser names the site; maki shows it.
fn site_page(site: &str) -> Page { Page::new("Asked by").mono(site) }

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

/// Account `index`'s path: `m/44'/501'/index'/0'`, as Phantom and Solflare have it.
fn path(index: u32) -> [u32; 4] { [44 | H, 501 | H, index | H, H] }

fn which(index: u32) -> String { if index == 0 { "solana account".into() } else { format!("account #{index}") } }

/// Account `index`'s key, from maki; an answer to send back if maki can't give it.
fn key(index: u32) -> Result<Key, Answer> {
    if index >= H {
        return Err(Answer::new(BAD));
    }
    wallet::ed25519_public(&path(index)).map_err(|e| match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that account"),
    })
}

/// The owner's answer to a review: go on, or the answer to send back.
fn said_yes(asked: Result<maki_app::Answer, Error>) -> Result<(), Answer> {
    match asked {
        Ok(maki_app::Answer::Yes) => Ok(()),
        Ok(maki_app::Answer::No) => Err(Answer::new(DENIED)),
        Ok(maki_app::Answer::NoAnswer) => Err(Answer::new(NO_ANSWER)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("too much to show on maki's screen")),
    }
}

fn signed(index: u32, bytes: &[u8]) -> Result<Answer, Answer> {
    match wallet::sign_ed25519(&path(index), bytes) {
        Ok(signature) => Ok(Answer::new(OK).bytes(&signature)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
}

fn answer(m: &[u8]) -> Answer {
    let result = match m.first() {
        Some(&ACCOUNT) => connect(m),
        Some(&TRANSACTION) => transaction(m),
        Some(&MESSAGE) => message(m),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key, once the owner lets the site connect.
fn connect(m: &[u8]) -> Result<Answer, Answer> {
    let (Some(index), Some((site, _))) = (u32_at(m, 1), site_at(m, 5)) else { return Err(Answer::new(BAD)) };
    let key = key(index)?;
    let asked = Review::new("Connect wallet?").detail(&which(index)).answers("connect", "don't").page(site_page(site)).signatures(0).timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&key))
}

/// `T`: a transaction's message, read strictly, shown (what it sends and to whom, the most the
/// fee can be, whatever maki can't read), and signed on a yes.
fn transaction(m: &[u8]) -> Result<Answer, Answer> {
    let (Some(index), Some((site, at))) = (u32_at(m, 1), site_at(m, 5)) else { return Err(Answer::new(BAD)) };
    let bytes = &m[at..];
    let key = key(index)?;
    let message = Message::parse(bytes).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&message, &key).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).page(site_page(site)).timeout(300);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    signed(index, bytes)
}

/// `M`: a message, signed once the owner has read it: a warning first when it's a sign-in for
/// another site or account. A transaction passed as a message is refused.
fn message(m: &[u8]) -> Result<Answer, Answer> {
    let (Some(index), Some((site, at))) = (u32_at(m, 1), site_at(m, 5)) else { return Err(Answer::new(BAD)) };
    let bytes = &m[at..];
    let key = key(index)?;
    let pages = display::message_pages(site, &key, bytes).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign message?").detail("not a transaction").page(site_page(site)).timeout(120);
    for p in pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    signed(index, bytes)
}

fn draw(index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok(key) = wallet::ed25519_public(&path(index)) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = address(&key);
    if as_text {
        screen::text_centred(2, &which(index), Style::Small, Color::Light);
        for (i, start) in (0..address.len()).step_by(14).enumerate() {
            screen::text_centred(20 + i as i32 * 15, &address[start..(start + 14).min(address.len())], Style::Mono, Color::Light);
        }
    } else {
        let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
        let short = format!("{}…{}", &address[..6], &address[address.len() - 4..]);
        screen::text_centred(97, &short, Style::Small, Color::Light);
    }
    screen::present();
}

fn main() {
    let (mut index, mut as_text, mut shown) = (0u32, false, true);
    loop {
        if shown {
            draw(index, as_text);
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; 4096];
                let n = link::read(&mut m).unwrap_or(0).min(m.len());
                let reply = answer(&m[..n]);
                let _ = link::reply(&reply.0);
            }
            Event::Left => index = index.saturating_sub(1),
            Event::Right => index = (index + 1).min(H - 1),
            Event::Centre => as_text = !as_text,
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
