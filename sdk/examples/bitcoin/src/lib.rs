//! Bitcoin: maki's Bitcoin wallet, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). Two accounts, the standard ones, so the phrase works in other wallets too: native
//! SegWit (BIP84) and taproot (BIP86), on bitcoin and the test networks. maki keeps the keys
//! (the wallet permission, on those four paths and no others); this app reads what it's asked to
//! sign with maki's wallet code (`maki-btc`: every input must be this wallet's, change must derive
//! from its change chain, amounts come from the transactions spent), shows each payment, the
//! change and the fee on maki's own review screen, and signs once the owner says yes.
//!
//! Opened, it shows a receiving address as a QR code: left and right step through them, the
//! centre shows it as text, and the menu picks the account, the network, or the account's key
//! and descriptor (the descriptor as Sparrow and the like scan it, for a watch-only wallet).
//!
//! With no cable at all, too: the menu's Sign from a QR code reads a PSBT off wallet software's
//! screen (camera), as Sparrow, Nunchuk and BlueWallet show them in turn to Keystone, Passport and
//! the like: a UR `crypto-psbt` in parts (Blockchain Commons' UR, its fountain codes filling in
//! parts missed), or one base64 code for a small one. It's checked and gone through as any
//! other, and the signed PSBT shown back the same way, a part at a time, for the wallet to scan.
//!
//! maki desktop (and wallet software through it) talks to it over the link. Each message starts
//! with what it is; each answer with a status, then its fields (strings as a u16 length and the
//! bytes, numbers little-endian):
//!
//! - `A` network, kind: the account's key (zpub, or xpub for taproot) and its output descriptor,
//!   once the owner agrees to share it;
//! - `D` network, kind, change, index (u32): an address, once the owner has compared it on maki's
//!   screen with the computer's;
//! - `P` network, total (u32), offset (u32), then a piece of a PSBT: the last piece is checked,
//!   shown and signed, and answered with the signed PSBT's size (or why not);
//! - `G` offset (u32): a piece of the PSBT last signed: total, offset, the bytes.
//!
//! Network is 0 (bitcoin) or 1 (the test networks); kind 0 (native SegWit) or 1 (taproot).

use maki_app::wallet::{HostKeys, Page, Review};
use maki_app::*;
use maki_btc::psbt::Psbt;
use maki_btc::{display, wallet as btc, Account, Kind, Network};

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
/// A signed PSBT's parts, a QR code each: a fragment's most bytes, so a part is QR code version 8
/// at most (279 capitals), which maki draws two pixels a module; and how long each shows.
const FRAGMENT: usize = 100;
const PART_MS: u32 = 300;

fn network(n: u8) -> Option<Network> {
    match n {
        0 => Some(Network::Bitcoin),
        1 => Some(Network::Testnet),
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

fn u32_at(b: &[u8], at: usize) -> Option<u32> { b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) }

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
        let (Some(net), Some(total), Some(offset)) = (m.get(1).and_then(|n| network(*n)), u32_at(m, 2), u32_at(m, 6)) else {
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
    let which = match k {
        Kind::Segwit => display::network_name(net).to_string(),
        Kind::Taproot => format!("{} taproot", display::network_name(net)),
    };
    let asked = Review::new("Share account?").detail(&format!("{which}, view only")).answers("share", "don't").signatures(0).timeout(60).show();
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
    let mut psbt = Psbt::parse(bytes).map_err(|e| Answer::new(REFUSED).text(&format!("not a PSBT maki can read: {e}")))?;
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
    if review.outputs.len() > MAX_OUTPUTS {
        return Err(Answer::new(REFUSED).text(&format!("more than {MAX_OUTPUTS} outputs to go through on maki's screen")));
    }
    let mut asked = Review::new("Sign and spend").detail(&display::amount(review.spent(), net)).answers("sign", "reject").timeout(300);
    for p in review.pages() {
        asked = asked.page(Page::new(&p.heading).value(&p.value).mono(&p.mono));
    }
    // one signature for each input, all of them this wallet's
    let asked = asked.signatures(review.inputs as u32).show();
    match asked.map(owner) {
        Ok(OK) => {}
        Ok(s) => return Err(Answer::new(s)),
        Err(Error::Locked) => return Err(Answer::new(LOCKED)),
        Err(_) => return Err(Answer::new(NO_ANSWER)),
    }
    btc::sign(&mut psbt, &accounts).map_err(|e| Answer::new(REFUSED).text(&e.to_string()))?;
    Ok(psbt.serialize())
}

/// A CBOR byte string (RFC 8949): what a UR `crypto-psbt` holds.
fn cbor_bytes(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut out = match n {
        0..=23 => vec![0x40 | n as u8],
        24..=0xff => vec![0x58, n as u8],
        0x100..=0xffff => vec![0x59, (n >> 8) as u8, n as u8],
        _ => [&[0x5a][..], &(n as u32).to_be_bytes()].concat(),
    };
    out.extend_from_slice(data);
    out
}

/// What's in a CBOR byte string that's all of `b`.
fn from_cbor_bytes(b: &[u8]) -> Option<&[u8]> {
    let (&head, rest) = b.split_first()?;
    if head >> 5 != 2 {
        return None;
    }
    let (len, rest) = match head & 31 {
        n @ 0..=23 => (n as usize, rest),
        24 => (*rest.first()? as usize, rest.get(1..)?),
        25 => (u16::from_be_bytes(rest.get(..2)?.try_into().ok()?) as usize, rest.get(2..)?),
        26 => (u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize, rest.get(4..)?),
        _ => return None,
    };
    (rest.len() == len).then_some(rest)
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.trim().trim_end_matches('=').bytes() {
        acc = acc << 6 | B64.iter().position(|&b| b == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn reading(parts: usize, of: usize) {
    screen::clear(Color::Dark);
    screen::text_centred(24, "Reading the PSBT", Style::Bold, Color::Light);
    let line = if of > 0 { format!("{parts} of {of} parts") } else { "the first part".into() };
    screen::text_centred(50, &line, Style::Regular, Color::Light);
    screen::text_centred(80, "any button stops", Style::Small, Color::Light);
    screen::present();
}

/// A PSBT read off wallet software's screen: a UR `crypto-psbt` in parts (or whole), or a base64
/// code. Why not, if it isn't one, or the owner stopped.
fn scan_psbt() -> Result<Vec<u8>, String> {
    let mut decoder = ur::Decoder::default();
    let mut seen = std::collections::BTreeSet::new();
    let mut of = 0;
    loop {
        reading(seen.len(), of);
        let mut buf = vec![0u8; 4400];
        let Some(text) = camera::scan_qr(&mut buf) else { return Err("stopped".into()) };
        let text = text.trim();
        if text.starts_with("cHNidP8") {
            return unbase64(text).ok_or_else(|| "not base64".into());
        }
        // URs are in capitals in QR codes, and read in small letters
        let lower = text.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("ur:crypto-psbt/").or_else(|| lower.strip_prefix("ur:psbt/")) else {
            return Err("that isn't a PSBT".into());
        };
        let cbor = match ur::ur::decode(&lower) {
            Ok((ur::ur::Kind::SinglePart, cbor)) => cbor,
            Ok((ur::ur::Kind::MultiPart, _)) => {
                if decoder.receive(&lower).is_err() {
                    // another PSBT's parts: start again with this one
                    decoder = ur::Decoder::default();
                    seen.clear();
                    if decoder.receive(&lower).is_err() {
                        return Err("a part maki can't read".into());
                    }
                }
                if let Some((n, total)) = rest.split_once('/').and_then(|(i, _)| i.split_once('-')) {
                    if let (Ok(n), Ok(total)) = (n.parse::<usize>(), total.parse::<usize>()) {
                        of = total;
                        seen.insert(n.min(total + 1));
                    }
                }
                if !decoder.complete() {
                    continue;
                }
                decoder.message().ok().flatten().ok_or("parts that don't add up")?
            }
            Err(_) => return Err("a code maki can't read".into()),
        };
        return from_cbor_bytes(&cbor).map(|b| b.to_vec()).ok_or_else(|| "not a PSBT inside".into());
    }
}

/// A signed PSBT, shown a part at a time as a UR `crypto-psbt`, for the wallet to scan, until the
/// centre; whether the owner left the app meanwhile.
fn show_psbt(psbt: &[u8]) -> bool {
    let Ok(mut encoder) = ur::Encoder::new(&cbor_bytes(psbt), FRAGMENT, "crypto-psbt") else { return false };
    let mut hidden = false;
    loop {
        if !hidden {
            let Ok(part) = encoder.next_part() else { return false };
            let code = part.to_uppercase();
            screen::clear(Color::Dark);
            let side = screen::qr(0, 0, code.as_bytes(), HEIGHT).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, (HEIGHT - side) / 2, code.as_bytes(), HEIGHT);
            screen::present();
        }
        match wait(if hidden { None } else { Some(PART_MS) }) {
            Event::Centre | Event::Left | Event::Right => return false,
            Event::Hidden => hidden = true,
            Event::Shown => hidden = false,
            Event::Exit => return true,
            _ => {}
        }
    }
}

/// Why `sign` didn't, in words, from its answer.
fn refusal(a: &Answer) -> String {
    match a.0.first() {
        Some(&DENIED) => "you said no".into(),
        Some(&NO_ANSWER) => "no answer".into(),
        Some(&LOCKED) => "maki is locked".into(),
        Some(&REFUSED) => {
            let n = a.0.get(1..3).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as usize);
            String::from_utf8_lossy(a.0.get(3..3 + n).unwrap_or_default()).chars().take(60).collect()
        }
        _ => "it isn't one maki signs".into(),
    }
}

/// What the screen shows when the app is open.
struct View {
    network: Network,
    kind: Kind,
    index: u32,
    as_text: bool,
    shows: Shows,
    /// why Sign from a QR code didn't, for a moment
    note: String,
}

/// An address, the account's key, or its descriptor.
#[derive(Clone, Copy, PartialEq)]
enum Shows {
    Address,
    Key,
    Descriptor,
}

const MENU: [&str; 4] = ["Taproot or SegWit", "Bitcoin or testnet", "Account key", "Sign from a QR code"];

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
        let (text, caption) = if self.shows == Shows::Key {
            let which = if self.kind == Kind::Taproot { "taproot account" } else { "account key" };
            (account.zpub(), which.to_string())
        } else if self.shows == Shows::Descriptor {
            (account.descriptor(), "descriptor, for Sparrow".to_string())
        } else {
            let address = account.address(false, self.index).unwrap_or_default();
            let tap = if self.kind == Kind::Taproot { " taproot" } else { "" };
            let net = if self.network == Network::Testnet { " testnet" } else { "" };
            (address, format!("receive #{}{tap}{net}", self.index))
        };
        if !self.note.is_empty() {
            screen::text_centred(30, "Not signed:", Style::Bold, Color::Light);
            screen::text_centred(52, &self.note, Style::Small, Color::Light);
            screen::text_centred(80, "centre: back", Style::Small, Color::Light);
        } else if self.as_text {
            screen::text_centred(2, &caption, Style::Small, Color::Light);
            for (i, start) in (0..text.len()).step_by(14).enumerate().take(6) {
                screen::text_centred(18 + i as i32 * 15, &text[start..(start + 14).min(text.len())], Style::Mono, Color::Light);
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
    let mut view = View { network: Network::Bitcoin, kind: Kind::Segwit, index: 0, as_text: false, shows: Shows::Address, note: String::new() };
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
            Event::Centre | Event::Left | Event::Right if !view.note.is_empty() => view.note.clear(),
            Event::Left if view.shows == Shows::Address => view.index = view.index.saturating_sub(1),
            Event::Right if view.shows == Shows::Address => view.index = (view.index + 1).min(maki_btc::bip32::HARDENED - 1),
            Event::Centre => view.as_text = !view.as_text,
            Event::Menu(0) => view.kind = if view.kind == Kind::Segwit { Kind::Taproot } else { Kind::Segwit },
            Event::Menu(1) => view.network = if view.network == Network::Bitcoin { Network::Testnet } else { Network::Bitcoin },
            Event::Menu(2) => {
                view.shows = match view.shows {
                    Shows::Address => Shows::Key,
                    Shows::Key => Shows::Descriptor,
                    Shows::Descriptor => Shows::Address,
                }
            }
            // no cable: a PSBT off the wallet's screen, signed, and shown back
            Event::Menu(3) => match scan_psbt() {
                Ok(psbt) => match sign(view.network, &psbt) {
                    Ok(signed) => {
                        if show_psbt(&signed) {
                            return;
                        }
                    }
                    Err(a) => view.note = refusal(&a),
                },
                Err(why) if why == "stopped" => {}
                Err(why) => view.note = why,
            },
            Event::Hidden => shown = false,
            Event::Shown => shown = true,
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
