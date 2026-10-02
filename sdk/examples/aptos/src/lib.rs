//! Aptos: maki's Aptos account, as an app from the maki store (ARCHITECTURE.md, "Wallets are apps").
//! The account is SLIP-10's on Ed25519 at `m/44'/637'/i'/0'/0'`, as Petra, Ledger's Aptos app and
//! Aptos's SDKs make it, so the phrase works there too. maki keeps the key (the wallet permission, on
//! `m/44'/637'` and nothing else); this app reads what it's asked to sign with maki's code
//! (`maki-apt`: strictly, as Aptos reads a transaction's BCS; APT, coins and fungible assets sent and
//! staking with a delegation pool spelled out; an object handed over called out; the most the fee can
//! be; a call it can't read flagged, with its function and arguments; a change of who controls the
//! account refused), shows it on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. Each
//! starts with what it is, the network (0 for Aptos's own, 1 for its test network) and the account
//! (a u32, little-endian: `i` of `m/44'/637'/i'/0'/0'`), and is at most 4096 bytes; each answer starts
//! with a status, then its fields (a string as a u16 length, little-endian, and its UTF-8; REFUSED is
//! followed by why):
//!
//! - `A` network, account: the account's public key, as a length byte (32) and the Ed25519 key (as a
//!   SignedTransaction's authenticator carries it), and its address, once the owner agrees to share them;
//! - `D` network, account: the address, put on maki's screen for the owner to compare with the computer's;
//!   the owner's answer (OK, it matches; DENIED, it doesn't), then maki's address either way;
//! - `T` network, account, then a transaction: the BCS of its `RawTransaction` (the TypeScript SDK's
//!   `rawTransaction.bcsToBytes()`), read, shown and signed on a yes; the signature, 64 bytes, Ed25519 over
//!   the transaction's signing message (the SHA3-256 of `APTOS::RawTransaction`, then the transaction). One
//!   for another network, or not this account's, is refused with why, before anything is shown.
//!
//! The transaction names its network (its chain ID: 1 for Aptos's own, 2 for the test network), and
//! must name the one the message does.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_apt::{Address, Network, Transaction, address, address_of, display, path, signing_message};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, not this account's, or another network's.
const REFUSED: u8 = 5;

/// The most a message can be: maki's link carries 4096 bytes each way.
const MAX_MESSAGE: usize = 4096;
/// A message's head: what it is, the network, the account.
const HEAD: usize = 6;

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

/// The network and account a message's head names.
fn head(m: &[u8]) -> Option<(Network, u32)> {
    let network = Network::from_byte(*m.get(1)?)?;
    let index = u32::from_le_bytes(m.get(2..HEAD)?.try_into().ok()?);
    (index < wallet::HARDENED).then_some((network, index))
}

/// The account, as the owner reads it: `aptos`, `aptos testnet account #2`.
fn which(network: Network, index: u32) -> String {
    let name = network.name().to_lowercase();
    if index == 0 { name } else { format!("{name} account #{index}") }
}

/// Account `index`'s public key and address, from maki; an answer to send back if maki can't give
/// them.
fn account(index: u32) -> Result<([u8; 32], Address), Answer> {
    let key = wallet::ed25519_public(&path(index)).map_err(|e| match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that account"),
    })?;
    Ok((key, address_of(&key)))
}

/// What the owner answered, as an answer's status.
fn status(a: maki_app::Answer) -> u8 {
    match a {
        maki_app::Answer::Yes => OK,
        maki_app::Answer::No => DENIED,
        maki_app::Answer::NoAnswer => NO_ANSWER,
    }
}

/// The owner's answer to a review: go on, or the answer to send back.
fn said_yes(asked: Result<maki_app::Answer, Error>) -> Result<(), Answer> {
    match asked {
        Ok(maki_app::Answer::Yes) => Ok(()),
        Ok(a) => Err(Answer::new(status(a))),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("too much to show on maki's screen")),
    }
}

fn answer(m: &[u8]) -> Answer {
    let result = match m.first() {
        Some(&ACCOUNT) => share(m),
        Some(&ADDRESS) => compare(m),
        Some(&TRANSACTION) => sign(m),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key and address, once the owner agrees: view only, but everything the
/// account does is theirs to see.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m).filter(|_| m.len() == HEAD) else { return Err(Answer::new(BAD)) };
    let (key, a) = account(index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(network, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[key.len() as u8]).bytes(&key).text(&address(&a)))
}

/// `D`: the address, on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m).filter(|_| m.len() == HEAD) else { return Err(Answer::new(BAD)) };
    let (_, a) = account(index)?;
    let a = address(&a);
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new("Address").value(&which(network, index)).mono(&a))
        .signatures(0)
        .show();
    match asked {
        Ok(answer) => Ok(Answer::new(status(answer)).text(&a)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't show it")),
    }
}

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

/// `T`: a transaction's BCS, read strictly (another account's, another network's, or anything Aptos
/// would refuse, refused before anything is shown), shown (the network, what it does, when it
/// expires, the most the fee can be, whatever maki can't read), and signed on a yes.
fn sign(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let raw = &m[HEAD..];
    let (_, me) = account(index)?;
    let tx = Transaction::parse(raw).map_err(|e| refused(&e.to_string()))?;
    // maki's clock, if it has one, for when the transaction expires (whatever the computer said, if
    // Roughtime didn't check it: it's only to warn by)
    let review = display::review(&tx, &me, network, unix_time()).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    match wallet::sign_ed25519(&path(index), &signing_message(raw)) {
        Ok(signature) => Ok(Answer::new(OK).bytes(&signature)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
}

fn draw(index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok((_, a)) = account(index) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = address(&a);
    let caption = if index == 0 { String::from("aptos account") } else { format!("account #{index}") };
    if as_text {
        screen::text_centred(2, &caption, Style::Small, Color::Light);
        // 66 characters: five lines of fourteen at most
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
                let mut m = vec![0u8; MAX_MESSAGE];
                // the whole message's length: one longer than the link carries isn't read at all
                let n = link::read(&mut m).unwrap_or(0);
                let reply = if n > MAX_MESSAGE { Answer::new(BAD) } else { answer(&m[..n]) };
                let _ = link::reply(&reply.0);
            }
            Event::Left => index = index.saturating_sub(1),
            Event::Right => index = (index + 1).min(wallet::HARDENED - 1),
            Event::Centre => as_text = !as_text,
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
