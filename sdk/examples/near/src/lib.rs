//! NEAR: maki's NEAR account, as an app from the maki store (ARCHITECTURE.md, "Wallets are apps").
//! The account is the implicit account of SLIP-10's Ed25519 key at `m/44'/397'/i'`: the first is the
//! one MyNearWallet, near-cli and Trust Wallet make from a phrase, so the phrase works there too
//! (Ledger's NEAR app uses another key, `44'/397'/0'/0'/1'`). maki keeps the key (the wallet
//! permission, Ed25519 on `m/44'/397'` and nothing else); this app reads what it's asked to sign
//! with maki's code (`maki-near`: strictly, as nearcore reads it; NEAR and tokens sent, calls, keys,
//! staking and code spelled out; the most the fee can be; a call it can't read flagged; anything
//! that would hand the account, its code or what it holds to another called out), shows it on
//! maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's name as a QR code: the centre shows it as text, left and right
//! step through accounts.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. Each
//! starts with what it is, the network (0 for NEAR's own, 1 for its test network) and the account
//! (a u32, little-endian: `i` of `m/44'/397'/i'`); each answer with a status, then its fields (a
//! string as a u16 length, little-endian, and its UTF-8; REFUSED is followed by why):
//!
//! - `A` network, account: the account's key as NEAR's transactions carry it, a length byte (33), the key's
//!   kind (0, Ed25519) and its 32 bytes, then the account's name (its implicit account, 64 hex digits), once
//!   the owner agrees to share them;
//! - `D` network, account: the account's name, on maki's screen for the owner to compare with the computer's;
//!   the owner's answer (OK, it matches; DENIED, it doesn't), then the name either way;
//! - `T` network, account, then a transaction's borsh bytes, unsigned (near-api-js's `encodeTransaction`):
//!   read, shown, and signed on a yes; the signature, 64 bytes, Ed25519 over the transaction's SHA-256. The
//!   signed transaction NEAR's nodes take is the transaction's bytes, a 0 for the signature's kind, and the
//!   signature.
//!
//! NEAR's transactions don't name their network: the network byte decides what maki calls it, which
//! tokens it knows, and which names give a transaction away as the other network's.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_near::{Key, Network, Transaction, account_id, display, hash, path};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, or not this account's.
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

/// The account, as the owner reads it: `near`, `near testnet account #2`.
fn which(network: Network, index: u32) -> String {
    let name = match network {
        Network::Mainnet => "near",
        Network::Testnet => "near testnet",
    };
    if index == 0 { name.into() } else { format!("{name} account #{index}") }
}

/// Account `index`'s key, from maki; an answer to send back if maki can't give it.
fn key(index: u32) -> Result<Key, Answer> {
    wallet::ed25519_public(&path(index)).map_err(|e| match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that account"),
    })
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

/// `A`: the account's key and name, once the owner agrees: view only, but everything the account
/// does is theirs to see.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m).filter(|_| m.len() == HEAD) else { return Err(Answer::new(BAD)) };
    let key = key(index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(network, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[33, 0]).bytes(&key).text(&account_id(&key)))
}

/// `D`: the account's name, on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m).filter(|_| m.len() == HEAD) else { return Err(Answer::new(BAD)) };
    let name = account_id(&key(index)?);
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new("Account").value(&which(network, index)).mono(&name))
        .signatures(0)
        .show();
    match asked {
        Ok(answer) => Ok(Answer::new(status(answer)).text(&name)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't show it")),
    }
}

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

/// `T`: a transaction's borsh bytes, read strictly (another account's, anything NEAR would refuse,
/// or another network's, refused before anything is shown), shown (the network, what it does, the
/// most the fee can be, whatever maki can't read), and signed on a yes.
fn sign(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let bytes = &m[HEAD..];
    let key = key(index)?;
    let tx = Transaction::parse(bytes).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&tx, &key, network).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    said_yes(asked.show())?;
    match wallet::sign_ed25519(&path(index), &hash(bytes)) {
        Ok(signature) => Ok(Answer::new(OK).bytes(&signature)),
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
    let name = account_id(&key);
    let caption = if index == 0 { String::from("near account") } else { format!("account #{index}") };
    if as_text {
        screen::text_centred(2, &caption, Style::Small, Color::Light);
        // 64 hex digits: four lines of sixteen, the screen's width in Mono
        for (i, start) in (0..name.len()).step_by(16).enumerate() {
            screen::text_centred(20 + i as i32 * 15, &name[start..start + 16], Style::Mono, Color::Light);
        }
    } else {
        let side = screen::qr(0, 0, name.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, name.as_bytes(), 94);
        let short = format!("{}…{}", &name[..6], &name[name.len() - 4..]);
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
