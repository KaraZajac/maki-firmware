//! Litecoin: maki's Litecoin wallet, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). Litecoin's transactions, signatures and PSBTs are Bitcoin's, so it's Bitcoin's wallet
//! code (`maki-btc`) on Litecoin's networks: the native SegWit (BIP84, `ltc1q…`) and taproot (BIP86,
//! `ltc1p…`) accounts at coin type 2, as Litecoin Core, Electrum-LTC and Ledger make them from the
//! same phrase, and the test network's. maki keeps the keys (the wallet permission, on those paths
//! and no others); this app reads what it's asked to sign the way the Bitcoin app does (every input
//! must be this wallet's, change must derive from its change chain, amounts come from the
//! transactions spent), shows each payment, the change and the fee on maki's own review screen, and
//! signs once the owner says yes.
//!
//! Opened, it shows a receiving address as a QR code: left and right step through them, the centre
//! shows it as text, and the menu picks the account, the network, or the account's key and
//! descriptor.
//!
//! maki desktop talks to it over the link, in the Bitcoin app's messages (the same client speaks to
//! both). Each message starts with what it is; each answer with a status, then its fields (strings
//! as a u16 length and the bytes, numbers little-endian):
//!
//! - `A` network, kind: the account's key (zpub, or xpub for taproot) and its output descriptor, once the
//!   owner agrees to share it;
//! - `D` network, kind, change, index (u32): an address, once the owner has compared it on maki's screen with
//!   the computer's;
//! - `P` network, total (u32), offset (u32), then a piece of a PSBT: the last piece is checked, shown and
//!   signed, and answered with the signed PSBT's size (or why not);
//! - `G` offset (u32): a piece of the PSBT last signed: total, offset, the bytes.
//!
//! Network is 0 (litecoin) or 1 (its test network); kind 0 (native SegWit) or 1 (taproot).

use maki_app::wallet::{HostKeys, Page, Review};
use maki_app::*;
use maki_btc::psbt::Psbt;
use maki_btc::{Account, Kind, Network, display, wallet as btc};

const ACCOUNT: u8 = b'A';
const ADDRESS: u8 = b'D';
const SIGN: u8 = b'P';
const SIGNED: u8 = b'G';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not this wallet's, not a PSBT maki can read, too big to go through.
const REFUSED: u8 = 5;
/// A piece taken: send the next.
const MORE: u8 = 6;

/// The biggest PSBT this app takes in, and the pieces it comes and goes in.
const MAX_PSBT: usize = 256 * 1024;
const PIECE: usize = 4000;
/// More outputs than this and a transaction isn't gone through page by page with any care.
const MAX_OUTPUTS: usize = 64;

fn network(n: u8) -> Option<Network> {
    match n {
        0 => Some(Network::Litecoin),
        1 => Some(Network::LitecoinTest),
        _ => None,
    }
}

fn kind(k: u8) -> Option<Kind> {
    match k {
        0 => Some(Kind::Segwit),
        1 => Some(Kind::Taproot),
        _ => None,
    }
}

/// An answer: the status, then its fields.
struct Answer(Vec<u8>);

impl Answer {
    fn new(status: u8) -> Answer { Answer(vec![status]) }

    fn text(mut self, s: &str) -> Answer {
        self.0.extend_from_slice(&(s.len() as u16).to_le_bytes());
        self.0.extend_from_slice(s.as_bytes());
        self
    }

    fn u32(mut self, n: u32) -> Answer {
        self.0.extend_from_slice(&n.to_le_bytes());
        self
    }

    fn bytes(mut self, b: &[u8]) -> Answer {
        self.0.extend_from_slice(b);
        self
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap()))
}

/// What maki's keys said, as an answer.
fn keys_status(e: maki_hd::Error) -> u8 {
    match e {
        maki_hd::Error::Locked => LOCKED,
        _ => REFUSED,
    }
}

fn owner(a: maki_app::Answer) -> u8 {
    match a {
        maki_app::Answer::Yes => OK,
        maki_app::Answer::No => DENIED,
        maki_app::Answer::NoAnswer => NO_ANSWER,
    }
}

/// The PSBT coming in, and the one last signed.
#[derive(Default)]
struct Wallet {
    incoming: Vec<u8>,
    incoming_total: usize,
    signed: Vec<u8>,
}

impl Wallet {
    fn answer(&mut self, m: &[u8]) -> Answer {
        match m.first() {
            Some(&ACCOUNT) => share(m),
            Some(&ADDRESS) => compare(m),
            Some(&SIGN) => self.sign_piece(m),
            Some(&SIGNED) => self.signed_piece(m),
            _ => Answer::new(BAD),
        }
    }

    fn sign_piece(&mut self, m: &[u8]) -> Answer {
        let (Some(net), Some(total), Some(offset)) =
            (m.get(1).and_then(|n| network(*n)), u32_at(m, 2), u32_at(m, 6))
        else {
            return Answer::new(BAD);
        };
        let (total, offset, piece) = (total as usize, offset as usize, &m[10..]);
        if total > MAX_PSBT {
            return Answer::new(REFUSED).text(&format!("a PSBT bigger than {} KiB", MAX_PSBT / 1024));
        }
        if offset == 0 {
            self.incoming.clear();
            self.incoming_total = total;
        }
        if offset != self.incoming.len() || total != self.incoming_total || offset + piece.len() > total {
            self.incoming.clear();
            return Answer::new(BAD);
        }
        self.incoming.extend_from_slice(piece);
        if self.incoming.len() < total {
            return Answer::new(MORE);
        }
        let bytes = std::mem::take(&mut self.incoming);
        match sign(net, &bytes) {
            Ok(signed) => {
                self.signed = signed;
                Answer::new(OK).u32(self.signed.len() as u32)
            }
            Err(a) => a,
        }
    }

    fn signed_piece(&self, m: &[u8]) -> Answer {
        let Some(offset) = u32_at(m, 1) else { return Answer::new(BAD) };
        if self.signed.is_empty() {
            return Answer::new(BAD);
        }
        let start = (offset as usize).min(self.signed.len());
        let end = (start + PIECE).min(self.signed.len());
        Answer::new(OK).u32(self.signed.len() as u32).u32(start as u32).bytes(&self.signed[start..end])
    }
}

/// The account's name, as the owner sees it: `litecoin`, `litecoin testnet taproot`.
fn which(net: Network, k: Kind) -> String {
    match k {
        Kind::Segwit => display::network_name(net).to_string(),
        Kind::Taproot => format!("{} taproot", display::network_name(net)),
    }
}

/// `A`: the account's key and descriptor, once the owner agrees: view only, but it's every
/// address the account will ever have.
fn share(m: &[u8]) -> Answer {
    let (Some(net), Some(k)) = (m.get(1).and_then(|n| network(*n)), m.get(2).and_then(|k| kind(*k))) else {
        return Answer::new(BAD);
    };
    let account = match Account::new(&HostKeys, net, k) {
        Ok(a) => a,
        Err(btc::Error::Keys(e)) => return Answer::new(keys_status(e)),
        Err(_) => return Answer::new(REFUSED),
    };
    let asked = Review::new("Share account?")
        .detail(&format!("{}, view only", which(net, k)))
        .answers("share", "don't")
        .signatures(0)
        .timeout(60)
        .show();
    match asked.map(owner) {
        Ok(OK) => Answer::new(OK).text(&account.zpub()).text(&account.descriptor()),
        Ok(s) => Answer::new(s),
        Err(Error::Locked) => Answer::new(LOCKED),
        Err(_) => Answer::new(NO_ANSWER),
    }
}

/// `D`: an address, put on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Answer {
    let (Some(net), Some(k), Some(change), Some(index)) =
        (m.get(1).and_then(|n| network(*n)), m.get(2).and_then(|k| kind(*k)), m.get(3), u32_at(m, 4))
    else {
        return Answer::new(BAD);
    };
    let address = match Account::new(&HostKeys, net, k).and_then(|a| a.address(*change == 1, index)) {
        Ok(a) => a,
        Err(btc::Error::Keys(e)) => return Answer::new(keys_status(e)),
        Err(_) => return Answer::new(BAD),
    };
    let page = display::address_page(&address, *change == 1, index, net);
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&page.heading).value(&page.value).mono(&page.mono))
        .signatures(0)
        .show();
    match asked.map(owner) {
        Ok(status) => Answer::new(status).text(&address),
        Err(Error::Locked) => Answer::new(LOCKED),
        Err(_) => Answer::new(NO_ANSWER),
    }
}

/// A whole PSBT: checked (every input this wallet's, amounts from what they spend, change only
/// where it's ours), shown, and signed on a yes. The signed PSBT, or the answer saying why not.
fn sign(net: Network, bytes: &[u8]) -> Result<Vec<u8>, Answer> {
    let mut psbt = Psbt::parse(bytes)
        .map_err(|e| Answer::new(REFUSED).text(&format!("not a PSBT maki can read: {e}")))?;
    // native SegWit's account, and taproot's where the PSBT has taproot in it
    let mut accounts = Vec::with_capacity(2);
    for k in [Kind::Segwit, Kind::Taproot] {
        if k == Kind::Taproot && !psbt.has_taproot() {
            continue;
        }
        match Account::new(&HostKeys, net, k) {
            Ok(a) => accounts.push(a),
            Err(btc::Error::Keys(e)) => return Err(Answer::new(keys_status(e))),
            Err(e) => return Err(Answer::new(REFUSED).text(&e.to_string())),
        }
    }
    let review = btc::review(&psbt, &accounts).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    ask_to_sign(&review)?;
    btc::sign(&mut psbt, &accounts).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    Ok(psbt.serialize())
}

/// The owner's say on a transaction: each payment, the change and the fee on maki's review screen,
/// allowing a signature for each input on a yes.
fn ask_to_sign(review: &btc::Review) -> Result<(), Answer> {
    if review.outputs.len() > MAX_OUTPUTS {
        return Err(Answer::new(REFUSED)
            .text(&format!("more than {MAX_OUTPUTS} outputs to go through on maki's screen")));
    }
    let mut asked = Review::new("Sign and spend")
        .detail(&display::amount(review.spent(), review.network))
        .answers("sign", "reject")
        .timeout(300);
    for p in review.pages() {
        asked = asked.page(Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose));
    }
    // one signature for each input, all of them this wallet's
    match asked.signatures(review.inputs as u32).show().map(owner) {
        Ok(OK) => Ok(()),
        Ok(s) => Err(Answer::new(s)),
        Err(Error::Locked) => Err(Answer::new(LOCKED)),
        Err(_) => Err(Answer::new(NO_ANSWER)),
    }
}

/// What the screen shows when the app is open.
struct View {
    network: Network,
    kind: Kind,
    index: u32,
    as_text: bool,
    shows: Shows,
}

/// An address, the account's key, or its descriptor.
#[derive(Clone, Copy, PartialEq)]
enum Shows {
    Address,
    Key,
    Descriptor,
}

const MENU: [&str; 3] = ["Taproot or SegWit", "Litecoin or testnet", "Account key"];

impl View {
    fn draw(&self) {
        screen::clear(Color::Dark);
        let account = match Account::new(&HostKeys, self.network, self.kind) {
            Ok(a) => a,
            Err(_) => {
                screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
                screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
                screen::present();
                return;
            }
        };
        let test = if self.network == Network::LitecoinTest { " testnet" } else { "" };
        let (text, caption) = match self.shows {
            Shows::Key => {
                let which = if self.kind == Kind::Taproot { "taproot account" } else { "account key" };
                (account.zpub(), format!("{which}{test}"))
            }
            Shows::Descriptor => (account.descriptor(), "descriptor".to_string()),
            Shows::Address => {
                let tap = if self.kind == Kind::Taproot { " taproot" } else { "" };
                (
                    account.address(false, self.index).unwrap_or_default(),
                    format!("receive #{}{tap}{test}", self.index),
                )
            }
        };
        if self.as_text {
            screen::text_centred(2, &caption, Style::Small, Color::Light);
            for (i, start) in (0..text.len()).step_by(14).enumerate().take(6) {
                screen::text_centred(
                    18 + i as i32 * 15,
                    &text[start..(start + 14).min(text.len())],
                    Style::Mono,
                    Color::Light,
                );
            }
        } else {
            let upper = text.to_uppercase();
            // bech32 addresses make smaller codes in capitals, which every wallet reads
            let data = if self.shows == Shows::Address { upper.as_bytes() } else { text.as_bytes() };
            let side = screen::qr(0, 0, data, 94).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, 0, data, 94);
            screen::text_centred(97, &caption, Style::Small, Color::Light);
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&MENU);
    let mut view = View {
        network: Network::Litecoin,
        kind: Kind::Segwit,
        index: 0,
        as_text: false,
        shows: Shows::Address,
    };
    let mut wallet = Wallet::default();
    let mut shown = true;
    loop {
        if shown {
            view.draw();
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; 4096];
                let n = link::read(&mut m).unwrap_or(0).min(m.len());
                let answer = wallet.answer(&m[..n]);
                let _ = link::reply(&answer.0);
            }
            Event::Left if view.shows == Shows::Address => view.index = view.index.saturating_sub(1),
            Event::Right if view.shows == Shows::Address => {
                view.index = (view.index + 1).min(maki_btc::bip32::HARDENED - 1)
            }
            Event::Centre => view.as_text = !view.as_text,
            Event::Menu(0) => {
                view.kind = if view.kind == Kind::Segwit { Kind::Taproot } else { Kind::Segwit }
            }
            Event::Menu(1) => {
                view.network =
                    if view.network == Network::Litecoin { Network::LitecoinTest } else { Network::Litecoin }
            }
            Event::Menu(2) => {
                view.shows = match view.shows {
                    Shows::Address => Shows::Key,
                    Shows::Key => Shows::Descriptor,
                    Shows::Descriptor => Shows::Address,
                }
            }
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
