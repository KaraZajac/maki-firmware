//! Stellar: maki's Stellar account, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). The account is SLIP-10's, `m/44'/148'/i'`, as SEP-5 has it (and Freighter and Ledger's
//! Stellar app make it), so the phrase works there too. maki keeps the key (the wallet permission,
//! Ed25519 on `m/44'/148'` and nothing else); this app reads what it's asked to sign with maki's
//! code (`maki-xlm`: strictly, as stellar-core reads it; payments and their recipients spelled out,
//! assets by their issuer, anything that changes who can sign for the account loudly, the most the
//! fee can be, and what a contract is asked to do flagged as something maki can't read), shows it
//! on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop talks to it over the link. Each message starts with what it is, then the network
//! (0 Stellar's public network, 1 its test network) and the account's index (u32,
//! little-endian); each answer with a status (0 OK, 1 denied, 2 no answer, 3 locked, 4 bad, 5
//! refused and why, as a u16 length and the text), then its fields:
//!
//! - `A` network, index: the account's key (a length byte, 32, and the key) and its address (a u16 length and
//!   the `G…` address), once the owner agrees to share them;
//! - `D` network, index: the address put on maki's screen for the owner to compare with the computer's: the
//!   owner's status (0 matches, 1 doesn't), then the address, either way;
//! - `T` network, index, then a transaction envelope (XDR, unsigned: version 1, version 0, or a fee bump this
//!   account pays): its signature (64 bytes, Ed25519, of the hash the network and the transaction make), once
//!   the owner has gone through it.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_xlm::{Envelope, Key, Network, address, display};

const ACCOUNT: u8 = b'A';
const SHOW: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, not this account's to sign, or too much to
/// show.
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

/// A message's network and account: its second byte, and the u32 after it.
fn head(m: &[u8]) -> Option<(Network, u32)> {
    let network = Network::from_byte(*m.get(1)?)?;
    let index = u32::from_le_bytes(m.get(2..6)?.try_into().ok()?);
    (index < H).then_some((network, index))
}

/// Account `index`'s path: `m/44'/148'/index'`, as SEP-5 has it.
fn path(index: u32) -> [u32; 3] { [44 | H, 148 | H, index | H] }

/// The account as the owner hears of it: `stellar`, `stellar testnet account #2`.
fn which(network: Network, index: u32) -> String {
    let net = if network == Network::Test { "stellar testnet" } else { "stellar" };
    if index == 0 { net.into() } else { format!("{net} account #{index}") }
}

/// Account `index`'s key, from maki; an answer to send back if maki can't give it.
fn key(index: u32) -> Result<Key, Answer> {
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

fn answer(m: &[u8]) -> Answer {
    let result = match m.first() {
        Some(&ACCOUNT) => share(m),
        Some(&SHOW) => compare(m),
        Some(&TRANSACTION) => transaction(m),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key and address, once the owner agrees: nothing secret (all an account
/// does is public on Stellar), but it ties this account to the computer asking.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let (Some((network, index)), 6) = (head(m), m.len()) else { return Err(Answer::new(BAD)) };
    let key = key(index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(network, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[32]).bytes(&key).text(&address(&key)))
}

/// `D`: the address, on maki's screen for the owner to compare with the computer's. maki's
/// address goes back whatever they say.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let (Some((network, index)), 6) = (head(m), m.len()) else { return Err(Answer::new(BAD)) };
    let address = address(&key(index)?);
    let net = if network == Network::Test { "Stellar testnet" } else { "Stellar" };
    let heading = if index == 0 { String::from("Account") } else { format!("Account #{index}") };
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&heading).value(net).mono(&address))
        .signatures(0)
        .show();
    let status = match asked {
        Ok(maki_app::Answer::Yes) => OK,
        Ok(maki_app::Answer::No) => DENIED,
        Err(Error::Locked) => return Err(Answer::new(LOCKED)),
        Ok(maki_app::Answer::NoAnswer) | Err(_) => NO_ANSWER,
    };
    Ok(Answer::new(status).text(&address))
}

/// `T`: a transaction envelope, read strictly, shown (what it does, as which account, the most the
/// fee can be, whatever maki can't read), and signed on a yes: the hash Stellar signs, which the
/// network and the transaction make.
fn transaction(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let key = key(index)?;
    let envelope = Envelope::parse(&m[6..]).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&envelope, &key, network).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose));
    }
    said_yes(asked.show())?;
    match wallet::sign_ed25519(&path(index), &envelope.hash(network)) {
        Ok(signature) => Ok(Answer::new(OK).bytes(&signature)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
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
        let caption = if index == 0 { String::from("stellar account") } else { format!("account #{index}") };
        screen::text_centred(2, &caption, Style::Small, Color::Light);
        for (i, start) in (0..address.len()).step_by(14).enumerate() {
            screen::text_centred(
                20 + i as i32 * 15,
                &address[start..(start + 14).min(address.len())],
                Style::Mono,
                Color::Light,
            );
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
