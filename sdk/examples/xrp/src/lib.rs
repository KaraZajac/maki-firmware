//! XRP: maki's XRP Ledger account, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). The account is BIP32's, `m/44'/144'/i'/0/0` on secp256k1, as Ledger, Xaman, Trust
//! Wallet and xrpl.js make it, so the phrase works there too. maki keeps the key (the wallet
//! permission, on `m/44'/144'` and nothing else); this app reads what it's asked to sign with
//! maki's code (`maki-xrp`: strictly, as rippled reads a transaction; XRP and tokens sent spelled
//! out, with the destination tag an exchange needs; a partial payment, which may deliver far less,
//! said loudly, and so is anything that hands the account over or deletes it; anything else
//! flagged), shows it on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. A
//! message starts with what it is, the network (0, the XRP Ledger; 1, its test network) and the
//! account (a u32, little-endian), and is at most 4096 bytes; an answer starts with a status, then
//! its fields (a string as a u16 length, little-endian, and its UTF-8):
//!
//! - `A` network, account: the account's public key (a length byte, 33, then the compressed key, as its
//!   transactions' SigningPubKey) and its classic address, once the owner agrees to share them;
//! - `D` network, account: the owner's answer to the address on maki's screen (OK, it matches; DENIED, it
//!   doesn't), then the address either way;
//! - `T` network, account, then a transaction to sign: the bytes the ledger's tooling makes of it (xrpl.js's
//!   `encode` of the transaction with this account's SigningPubKey and no signature), read, shown and signed
//!   on a yes: its signature (a length byte, then the DER), its TxnSignature. One for another network, or not
//!   this account's, is refused with why, before anything is shown.
//!
//! Neither network is named in a transaction, so the network is what maki desktop says, and maki
//! shows it as that: a test network's transaction is good on the main one too.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_xrp::{Network, Transaction, address, display, sign};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not this account's, another network's, or what the ledger would refuse.
const REFUSED: u8 = 5;

/// The most a message can be.
const MAX_MESSAGE: usize = 4096;

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

    /// Bytes after their length, in a byte.
    fn bytes(mut self, b: &[u8]) -> Answer {
        self.0.push(b.len() as u8);
        self.0.extend_from_slice(b);
        self
    }
}

fn refused(why: &str) -> Answer { Answer::new(REFUSED).text(why) }

/// Account `index`'s path: `m/44'/144'/index'/0/0`, as Ledger and Xaman have it.
fn path(index: u32) -> [u32; 5] { [44 | H, 144 | H, index | H, 0, 0] }

/// The network a message names.
fn network(n: u8) -> Option<Network> {
    match n {
        0 => Some(Network::Main),
        1 => Some(Network::Test),
        _ => None,
    }
}

/// The account, as the owner sees it: `xrp`, `xrp testnet account #2`.
fn which(net: Network, index: u32) -> String {
    if index == 0 { net.name().into() } else { format!("{} account #{index}", net.name()) }
}

/// Account `index`'s public key, from maki; an answer to send back if maki can't give it.
fn key(index: u32) -> Result<[u8; 33], Answer> {
    if index >= H {
        return Err(Answer::new(BAD));
    }
    wallet::public(&path(index)).map(|p| p.key).map_err(|e| match e {
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

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

fn answer(m: &[u8]) -> Answer {
    if m.len() > MAX_MESSAGE {
        return Answer::new(BAD);
    }
    let (Some(&kind), Some(net), Some(index)) = (
        m.first(),
        m.get(1).and_then(|n| network(*n)),
        m.get(2..6).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
    ) else {
        return Answer::new(BAD);
    };
    let rest = &m[6..];
    let result = match kind {
        ACCOUNT if rest.is_empty() => share(net, index),
        ADDRESS if rest.is_empty() => compare(net, index),
        TRANSACTION => transaction(net, index, rest),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key and address, once the owner agrees: view only, but the computer
/// learns the account and everything it does.
fn share(net: Network, index: u32) -> Result<Answer, Answer> {
    let key = key(index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(net, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&key).text(&address(&key)))
}

/// `D`: the address on maki's screen, for the owner to compare with the computer's.
fn compare(net: Network, index: u32) -> Result<Answer, Answer> {
    let address = address(&key(index)?);
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&format!("Account #{index}")).value(net.name()).mono(&address))
        .signatures(0);
    let status = match asked.show() {
        Ok(maki_app::Answer::Yes) => OK,
        Ok(maki_app::Answer::No) => DENIED,
        Ok(maki_app::Answer::NoAnswer) => NO_ANSWER,
        Err(Error::Locked) => return Err(Answer::new(LOCKED)),
        Err(_) => return Err(refused("too much to show on maki's screen")),
    };
    Ok(Answer::new(status).text(&address))
}

/// `T`: a transaction, read strictly, shown (what it sends and to whom, with its tag; what hands
/// the account over; the fee; whatever maki can't read), and signed on a yes.
fn transaction(net: Network, index: u32, bytes: &[u8]) -> Result<Answer, Answer> {
    let key = key(index)?;
    let tx = Transaction::parse(bytes).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&tx, &key, net).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    match wallet::sign_ecdsa(&path(index), &sign::digest(bytes)) {
        Ok((signature, _)) => Ok(Answer::new(OK).bytes(&sign::der(&signature))),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
}

fn draw(index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok(key) = key(index) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = address(&key);
    if as_text {
        let caption = if index == 0 { String::from("xrp account") } else { format!("account #{index}") };
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
                let mut m = vec![0u8; MAX_MESSAGE];
                // longer than it holds, it's longer than a message may be: `answer` says so
                let reply = match link::read(&mut m) {
                    Some(n) if n <= m.len() => answer(&m[..n]),
                    _ => Answer::new(BAD),
                };
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
