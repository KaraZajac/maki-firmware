//! TON: maki's TON account, as an app from the maki store (ARCHITECTURE.md, "Wallets are apps").
//! The account's key is SLIP-10's at `m/44'/607'/network'/0'/i'/0'`, as Ledger's TON app has it
//! (Ledger Live's account `i`, and Tonkeeper's with a Ledger), so the phrase in a Ledger opens the
//! same account. On TON a key's money sits in a wallet contract, each kind at an address of its
//! own: maki knows the two that hold people's, v4R2 (Ledger's, and every wallet's for years) and W5
//! (v5R1, today's wallets' first choice). maki keeps the key (the wallet permission, Ed25519 on
//! `m/44'/607'` and nothing else); this app reads what a wallet asks its key to sign with maki's
//! code (`maki-ton`: the request and the messages in it, strictly, as the wallet's code and TON
//! read them; TON and jettons sent and to whom, comments, anything that sends everything, closes
//! the wallet or lets another take from it, loudly; what maki can't read, flagged), shows it on
//! maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows the account's address as a QR code, its v4R2 wallet's (the menu's "W5 wallet"
//! shows W5's): the centre shows it as text, left and right step through accounts.
//!
//! maki desktop talks to it over the link, in the messages every account coin's app speaks. Each
//! starts with what it is, the network (0 TON, 1 its test network) and the account (a u32,
//! little-endian: `i` of `m/44'/607'/network'/0'/i'/0'`); each answer with a status (0 OK, 1
//! denied, 2 no answer, 3 locked, 4 bad, 5 refused and why), then its fields (a string as a u16
//! length, little-endian, and its UTF-8):
//!
//! - `A` network, account[, wallet]: the account's key, as a length byte (32) and the key (what a wallet's
//!   data holds), and the wallet's address (non-bounceable, as wallets show their own: `UQ…`, or `0Q…` on the
//!   test network), once the owner agrees to share them;
//! - `D` network, account[, wallet]: the wallet's address, put on maki's screen for the owner to compare with
//!   the computer's; the owner's answer (OK, it matches; DENIED, it doesn't), then maki's address either way;
//! - `T` network, account, then a request: the cell a wallet's key signs (@ton/ton hands it to a wallet's
//!   signer), in a bag of cells as @ton/core writes one: v4R2's (its subwallet, valid until, seqno, op and
//!   messages) or W5's (`sign`, its wallet ID, valid until, seqno, actions). Read, shown, and signed on a
//!   yes: the signature, 64 bytes, Ed25519 of the cell's hash, which goes before the request in the wallet's
//!   external message (v4R2) or after it (W5).
//!
//! The wallet, for `A` and `D`, is a string after the account: `v4R2` or `v5R1`; with nothing
//! after the account, v4R2. A request names its own: by its first bits and its wallet ID, which
//! for W5 is the network's too.

use maki_app::wallet::{self, Page, Review};
use maki_app::*;
use maki_ton::display;
use maki_ton::{Boc, Key, Network, Request, Wallet, path};

const ACCOUNT: u8 = b'A';
const SHOW: u8 = b'D';
const TRANSACTION: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not something maki can read, not this account's, or too much to show.
const REFUSED: u8 = 5;

/// A message's head: what it is, the network, the account.
const HEAD: usize = 6;

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
    let index = u32::from_le_bytes(m.get(2..HEAD)?.try_into().ok()?);
    (index < H).then_some((network, index))
}

/// The wallet an `A` or `D` names after its head: a string and nothing after it; or nothing, for
/// v4R2.
fn named_wallet(m: &[u8]) -> Result<Wallet, Answer> {
    let rest = &m[HEAD..];
    if rest.is_empty() {
        return Ok(Wallet::V4R2);
    }
    let id = rest
        .get(..2)
        .map(|n| u16::from_le_bytes([n[0], n[1]]) as usize)
        .filter(|&n| rest.len() == 2 + n)
        .and_then(|_| core::str::from_utf8(&rest[2..]).ok())
        .ok_or_else(|| Answer::new(BAD))?;
    Wallet::from_id(id).ok_or_else(|| refused("a TON wallet maki doesn't know: it knows v4R2 and v5R1"))
}

/// The account as the owner hears of it: `ton`, `ton testnet account #2`.
fn which(network: Network, index: u32) -> String {
    let net = if network == Network::Test { "ton testnet" } else { "ton" };
    if index == 0 { net.into() } else { format!("{net} account #{index}") }
}

/// Account `index`'s key, from maki; an answer to send back if maki can't give it.
fn key(network: Network, index: u32) -> Result<Key, Answer> {
    wallet::ed25519_public(&path(network, index)).map_err(|e| match e {
        Error::Locked => Answer::new(LOCKED),
        _ => refused("maki wouldn't give this app that account"),
    })
}

/// A wallet's address, as wallets show their own: non-bounceable, flagged for the test network.
fn address(wallet: Wallet, key: &Key, network: Network) -> String {
    wallet.address(key, network).friendly(false, network == Network::Test)
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

/// `A`: the account's key and a wallet's address, once the owner agrees: nothing secret (all a
/// wallet does is public on TON), but it ties this account to the computer asking.
fn share(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let wallet = named_wallet(m)?;
    let key = key(network, index)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(network, index)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60);
    said_yes(asked.show())?;
    Ok(Answer::new(OK).bytes(&[32]).bytes(&key).text(&address(wallet, &key, network)))
}

/// `D`: a wallet's address, on maki's screen for the owner to compare with the computer's. maki's
/// address goes back whatever they say.
fn compare(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let wallet = named_wallet(m)?;
    let address = address(wallet, &key(network, index)?, network);
    let net = if network == Network::Test { "TON testnet" } else { "TON" };
    let heading = if index == 0 { String::from("Account") } else { format!("Account #{index}") };
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&heading).value(&format!("{net}, {} wallet", wallet.name())).mono(&address))
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

/// `T`: a wallet's request, read strictly (one TON or its wallet would refuse, one maki can't
/// show, another wallet's or another network's, refused before anything is shown), shown, and
/// signed on a yes: the hash of its cell.
fn transaction(m: &[u8]) -> Result<Answer, Answer> {
    let Some((network, index)) = head(m) else { return Err(Answer::new(BAD)) };
    let key = key(network, index)?;
    let boc = Boc::parse(&m[HEAD..]).map_err(|e| refused(&e.to_string()))?;
    let request = Request::parse(&boc).map_err(|e| refused(&e.to_string()))?;
    let review = display::review(&request, &key, network).map_err(|e| refused(&e.to_string()))?;
    let mut asked = Review::new("Sign and send").detail(&review.summary).timeout(300).signatures(1);
    for p in review.pages {
        asked = asked.page(Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose));
    }
    said_yes(asked.show())?;
    match wallet::sign_ed25519(&path(network, index), &boc.hash()) {
        Ok(signature) => Ok(Answer::new(OK).bytes(&signature)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("maki couldn't sign it")),
    }
}

fn draw(wallet: Wallet, index: u32, as_text: bool) {
    screen::clear(Color::Dark);
    let Ok(key) = wallet::ed25519_public(&path(Network::Main, index)) else {
        screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
        screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
        screen::present();
        return;
    };
    let address = address(wallet, &key, Network::Main);
    if as_text {
        let caption = if index == 0 {
            format!("ton {} wallet", wallet.name())
        } else {
            format!("account #{index}, {}", wallet.name())
        };
        screen::text_centred(2, &caption, Style::Small, Color::Light);
        for (i, start) in (0..address.len()).step_by(12).enumerate() {
            screen::text_centred(
                20 + i as i32 * 15,
                &address[start..(start + 12).min(address.len())],
                Style::Mono,
                Color::Light,
            );
        }
    } else {
        let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
        screen::clear(Color::Dark);
        screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
        let short = format!("{}…{} {}", &address[..6], &address[address.len() - 4..], wallet.name());
        screen::text_centred(97, &short, Style::Small, Color::Light);
    }
    screen::present();
}

/// The menu's one item: the other wallet.
fn menu_for(wallet: Wallet) {
    let _ = menu(&[if wallet == Wallet::V4R2 { "W5 wallet" } else { "v4R2 wallet" }]);
}

fn main() {
    let (mut wallet, mut index, mut as_text, mut shown) = (Wallet::V4R2, 0u32, false, true);
    menu_for(wallet);
    loop {
        if shown {
            draw(wallet, index, as_text);
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
            Event::Menu(0) => {
                wallet = if wallet == Wallet::V4R2 { Wallet::V5R1 } else { Wallet::V4R2 };
                menu_for(wallet);
            }
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
