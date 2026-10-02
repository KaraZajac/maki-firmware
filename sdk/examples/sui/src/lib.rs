//! Sui: maki's Sui account, as an app from the maki store (ARCHITECTURE.md, "Wallets are apps").
//! The account is Ed25519's, by SLIP-10 at `m/44'/784'/i'/0'/0'`: the first is every Sui wallet's
//! (Slush's, Ledger's, Sui's TypeScript library's), the next ones Slush's and Ledger's, so the
//! phrase works there too. maki keeps the key (the wallet permission, Ed25519 on `m/44'/784'` and
//! nothing else); this app reads what it's asked to sign with maki's code (`maki-sui`: strictly, as
//! Sui's validators read it; SUI and tokens sent, from coins or the address balance, objects sent
//! and stake spelled out; the most the fee can be; a Move call it can't read flagged, with what
//! it's given; anything that would let another key or account act for this one refused), shows it
//! on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code: the centre shows it as text, left and
//! right step through accounts.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. A
//! message starts with what it is, the network (0, Sui's own; 1, its test network) and the account
//! (a u32, little-endian: `i` of `m/44'/784'/i'/0'/0'`), and is at most 4096 bytes; an answer starts
//! with a status, then its fields (a string as a u16 length, little-endian, and its UTF-8; REFUSED
//! is followed by why):
//!
//! - `A` network, account: the account's public key (a length byte, 32, then the Ed25519 key, as a signature
//!   carries it) and its address, once the owner agrees to share them;
//! - `D` network, account: the owner's answer to the address on maki's screen (OK, it matches; DENIED, it
//!   doesn't), then the address either way;
//! - `T` network, account, then a transaction's data, the BCS of its `TransactionData` as @mysten/sui's
//!   `Transaction.build()` makes it and Sui's APIs take it, without the intent's three bytes in front (maki
//!   puts them there itself, and signs nothing but a transaction's data): read, shown, and signed on a yes.
//!   The answer is the Ed25519 signature, 64 bytes, of the BLAKE2b-256 of the intent message; Sui takes it
//!   after the account's flag (0) and before its key, 97 bytes, in base64. One for another network, or not
//!   this account's, is refused with why, before anything is shown.
//!
//! A transaction names its network when its fee or funds come from the address balance, or when
//! it says in which epochs it's valid; one that doesn't is for the network maki desktop says, and
//! maki shows it as that.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_sui::{Address, Network, Transaction, address, address_of, display, path, signing_digest};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not this account's, another network's, or what Sui would refuse.
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

/// The account, as the owner reads it: `sui`, `sui testnet account #2`.
fn which(network: Network, index: u32) -> String {
    let name = match network {
        Network::Mainnet => "sui",
        Network::Testnet => "sui testnet",
    };
    if index == 0 { name.into() } else { format!("{name} account #{index}") }
}

/// Account `index`'s key and address, from maki; an answer to send back if maki can't give them.
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

/// `T`: a transaction's data, read strictly (another account's, another network's, or anything Sui
/// would refuse, refused before anything is shown), shown (the network, what it does, the most the
/// fee can be, whatever maki can't read), and signed on a yes.
fn sign(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let data = &m[HEAD..];
    let (_, me) = account(index)?;
    let tx = Transaction::parse(data).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&tx, &me, network).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    match wallet::sign_ed25519(&path(index), &signing_digest(data)) {
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
    let caption = if index == 0 { String::from("sui account") } else { format!("account #{index}") };
    if as_text {
        screen::text_centred(2, &caption, Style::Small, Color::Light);
        // 66 characters: five lines of sixteen at most, as wide as maki's screen holds
        for (i, start) in (0..address.len()).step_by(16).enumerate() {
            screen::text_centred(
                18 + i as i32 * 15,
                &address[start..(start + 16).min(address.len())],
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
                // longer than it holds, it's longer than a message may be: not read at all
                let reply = match link::read(&mut m) {
                    Some(n) if n <= m.len() => answer(&m[..n]),
                    _ => Answer::new(BAD),
                };
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
