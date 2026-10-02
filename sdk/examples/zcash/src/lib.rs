//! Zcash: maki's Zcash wallet, transparent, as an app from the maki store (ARCHITECTURE.md,
//! "Wallets are apps"). The account is BIP32's on secp256k1 at `m/44'/133'/0'`, its receiving
//! (`/0/i`) and change (`/1/i`) t-addresses under it (`t1…`), as Ledger's Zcash app, Zashi, zcashd and
//! Zallet make transparent keys from the same phrase; the test network's at `m/44'/1'/0'` (`tm…`).
//! maki keeps the keys (the wallet permission, on those paths and nothing else); this app reads what
//! it's asked to sign with maki's code (`maki-zec`, as the Bitcoin app reads a PSBT: every input must
//! be this wallet's, change must name one of its keys and pay it, the fee is what the inputs hold
//! less what the outputs pay, shown beside ZIP-317's conventional fee), shows each payment, the
//! change and the fee on maki's own review screen, and signs every input once the owner says yes.
//! Zcash's signatures (ZIP-244's digest) cover every input's amount and script, so a coin said to
//! hold what it doesn't spoils them all, and the app keeps nothing between requests. A transaction
//! with shielded parts is refused: maki can't see into them.
//!
//! Opened, it shows a receiving address as a QR code: left and right step through them, the centre
//! shows it as text, and the menu switches between Zcash and its test network.
//!
//! maki desktop talks to it over the link. Each message starts with what it is, then the network (0
//! Zcash, 1 its test network), and is 4096 bytes at most; each answer starts with a status, then its
//! fields (a string as a u16 length and UTF-8, numbers little-endian):
//!
//! - `A` network: the account's key at `m/44'/133'/0'`, compressed (33 bytes), and chain code (32), then its
//!   first receiving address (a string, to check the key by), once the owner agrees to share them: view only,
//!   but every address the account will ever have;
//! - `D` network, chain (u8: 0 receive, 1 change), index (u32, below 2^31): that address, on maki's screen
//!   for the owner to compare; their say (OK it matches, DENIED it doesn't), then maki's address either way;
//! - `T` network, then a transaction (`maki_zec::request`: the transaction unsigned, version 5, as zcashd and
//!   librustzcash write it; what each coin it spends holds, its script and key; how each output is to be
//!   shown, change by its key): checked, shown, and on a yes signed, answered with each input's signature in
//!   order, each a u8 length and then the signature as its script pushes it (DER, then SIGHASH_ALL's byte 1).
//!   An input's script is that push, then its key's (`0x21` and the 33 bytes).
//!
//! Statuses: 0 OK, 1 DENIED, 2 NO_ANSWER, 3 LOCKED, 4 BAD (not a message this app takes), 5 REFUSED,
//! then why (a string): not this wallet's, not something maki will sign, too much to show.

use maki_app::wallet::{HostKeys, Page, Review};
use maki_app::*;
use maki_zec::request::Derivation;
use maki_zec::{Account, Network, Request, display};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const SIGN: u8 = b'T';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not this wallet's, not a transaction maki will sign, too much to show.
const REFUSED: u8 = 5;

/// The longest message, either way.
const MAX_MESSAGE: usize = 4096;

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

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()))
}

/// Why maki-zec wouldn't, as an answer: maki locked, or the reason.
fn refusal(e: maki_zec::Error) -> Answer {
    match e {
        maki_zec::Error::Keys(maki_hd::Error::Locked) => Answer::new(LOCKED),
        e => refused(&e.to_string()),
    }
}

/// The owner's answer to a review, as a status, or the answer to send back if it couldn't be
/// shown.
fn owner(asked: Result<maki_app::Answer, Error>) -> Result<u8, Answer> {
    match asked {
        Ok(maki_app::Answer::Yes) => Ok(OK),
        Ok(maki_app::Answer::No) => Ok(DENIED),
        Ok(maki_app::Answer::NoAnswer) => Ok(NO_ANSWER),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(refused("too much to show on maki's screen")),
    }
}

fn page(p: display::Page) -> Page { Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose) }

fn answer(m: &[u8]) -> Answer {
    let network = m.get(1).and_then(|n| Network::from_byte(*n));
    let result = match (m.first(), network) {
        _ if m.len() > MAX_MESSAGE => Err(Answer::new(BAD)),
        (Some(&ACCOUNT), Some(net)) if m.len() == 2 => share(net),
        (Some(&ADDRESS), Some(net)) if m.len() == 7 => compare(net, m[2], u32_at(m, 3).unwrap_or(u32::MAX)),
        (Some(&SIGN), Some(net)) => sign(net, &m[2..]),
        _ => Err(Answer::new(BAD)),
    };
    result.unwrap_or_else(|a| a)
}

/// `A`: the account's key and chain code, once the owner agrees: view only, but it's every address
/// the account will ever have.
fn share(net: Network) -> Result<Answer, Answer> {
    let account = Account::new(&HostKeys, net).map_err(refusal)?;
    let first = account.address(Derivation { chain: 0, index: 0 }).map_err(refusal)?;
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", net.name()))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60)
        .show();
    match owner(asked)? {
        OK => Ok(Answer::new(OK).bytes(&account.public.key).bytes(&account.public.chain_code).text(&first)),
        status => Ok(Answer::new(status)),
    }
}

/// `D`: an address, put on maki's screen for the owner to compare with the computer's.
fn compare(net: Network, chain: u8, index: u32) -> Result<Answer, Answer> {
    let key = Derivation::new(chain, index).ok_or(Answer::new(BAD))?;
    let address = Account::new(&HostKeys, net).and_then(|a| a.address(key)).map_err(refusal)?;
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(page(display::address_page(&address, key, net)))
        .signatures(0)
        .show();
    Ok(Answer::new(owner(asked)?).text(&address))
}

/// `T`: a transaction, checked (every input this wallet's, change only where it's ours, nothing
/// shielded, for the network upgrade in force), shown, and signed on a yes: each input's signature.
fn sign(net: Network, bytes: &[u8]) -> Result<Answer, Answer> {
    let request = Request::parse(bytes).map_err(refusal)?;
    let account = Account::new(&HostKeys, net).map_err(refusal)?;
    let checked = account.check(&request).map_err(refusal)?;
    let review = display::review(&checked);
    let mut asked = Review::new("Sign and send")
        .detail(&review.summary)
        .timeout(300)
        // a signature for each input, all of them this wallet's
        .signatures(request.coins.len() as u32);
    for p in review.pages {
        asked = asked.page(page(p));
    }
    match owner(asked.show())? {
        OK => {}
        status => return Ok(Answer::new(status)),
    }
    let signatures = account.sign(&checked).map_err(refusal)?;
    Ok(signatures.iter().fold(Answer::new(OK), |a, s| a.bytes(&[s.len() as u8]).bytes(s)))
}

/// What the screen shows when the app is open: a receiving address.
struct View {
    network: Network,
    index: u32,
    as_text: bool,
}

const MENU: [&str; 1] = ["Zcash or testnet"];

impl View {
    fn draw(&self) {
        screen::clear(Color::Dark);
        let key = Derivation { chain: 0, index: self.index };
        let Ok(address) = Account::new(&HostKeys, self.network).and_then(|a| a.address(key)) else {
            screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
            screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
            screen::present();
            return;
        };
        let test = if self.network == Network::Testnet { " testnet" } else { "" };
        let caption = format!("receive #{}{test}", self.index);
        if self.as_text {
            screen::text_centred(2, &caption, Style::Small, Color::Light);
            for (i, start) in (0..address.len()).step_by(14).enumerate() {
                screen::text_centred(
                    18 + i as i32 * 15,
                    &address[start..(start + 14).min(address.len())],
                    Style::Mono,
                    Color::Light,
                );
            }
        } else {
            // base58: the address as it is, its capitals matter
            let side = screen::qr(0, 0, address.as_bytes(), 94).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, 0, address.as_bytes(), 94);
            screen::text_centred(97, &caption, Style::Small, Color::Light);
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&MENU);
    let mut view = View { network: Network::Mainnet, index: 0, as_text: false };
    let mut shown = true;
    loop {
        if shown {
            view.draw();
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; MAX_MESSAGE];
                let n = link::read(&mut m).unwrap_or(0);
                // a message longer than the buffer isn't one this app takes
                let reply = if n > m.len() { Answer::new(BAD) } else { answer(&m[..n]) };
                let _ = link::reply(&reply.0);
            }
            Event::Left => view.index = view.index.saturating_sub(1),
            Event::Right => view.index = (view.index + 1).min(maki_hd::HARDENED - 1),
            Event::Centre => view.as_text = !view.as_text,
            Event::Menu(0) => {
                view.network =
                    if view.network == Network::Mainnet { Network::Testnet } else { Network::Mainnet }
            }
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
