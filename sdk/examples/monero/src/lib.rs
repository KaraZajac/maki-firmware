//! Monero: maki's Monero wallet, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). The account is the one Ledger's Monero app makes from the same recovery phrase (the
//! key at `m/44'/128'/0'/0/0`, hashed to the spend key: `maki-xmr`), so the phrase gives the same
//! wallet there. maki keeps the keys (the wallet permission, on `m/44'/128'` and no other): this
//! app shows the account's addresses, has maki show its owner the 25 words that restore the
//! wallet in any Monero wallet, which it never sees itself, and spends: it shows each payment, the
//! change and the fee on maki's own review screen, and on a yes maki makes the transaction and
//! signs it.
//!
//! Opened, it shows the primary address as a QR code: left and right step through the account's
//! subaddresses, the centre shows the address as text, and the menu has the backup words and the
//! network (Monero, or its testnet and stagenet, for trying things out).
//!
//! maki desktop (for its own wallet, and for the Monero GUI's view-only wallets) talks to it over
//! the link. A message starts with what it is; an answer with a status, then its fields (strings
//! as a u16 length and the bytes, numbers little-endian):
//!
//! - `D` network, account (u32), index (u32): an address, once the owner has compared it on
//!   maki's screen with the computer's (account 0's index 0 is the primary address);
//! - `W` network: the primary address and the secret view key (32 bytes), once the owner agrees
//!   to let the computer watch the wallet: see what comes in, and nothing to spend with;
//! - `K` count (u8), then each output (80 bytes: its transaction's key, its index there (u64), the
//!   subaddress it was paid to (account and index, u32s) and its key): each one's key image and
//!   what proves it (96 bytes), for a wallet that's watching to see what's spent. Only once the
//!   owner has let a computer watch;
//! - `S` network, total (u32), offset (u32), then a piece of what to pay (`maki_xmr::request`):
//!   the last piece is shown and, on a yes, made and signed by maki, and answered with the signed
//!   transaction's size (or why not);
//! - `G` offset (u32): a piece of the transaction last signed (`maki_xmr::spend::Signed`): total,
//!   offset, the bytes.
//!
//! Network is 0 (Monero), 1 (testnet) or 2 (stagenet).

use maki_app::wallet::{self, Page, Review, HARDENED};
use maki_app::*;
use maki_xmr::request::{Request, MAX_INPUTS};
use maki_xmr::{Kind, Network};

const ADDRESS: u8 = b'D';
const WATCH: u8 = b'W';
const KEY_IMAGES: u8 = b'K';
const SIGN: u8 = b'S';
const SIGNED: u8 = b'G';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;
/// Refused, with why: not this wallet's, not a request maki signs, too big.
const REFUSED: u8 = 5;
/// A piece taken: send the next.
const MORE: u8 = 6;

/// The account, as Ledger's Monero app has account 0.
const ACCOUNT: [u32; 5] = [44 | HARDENED, 128 | HARDENED, HARDENED, 0, 0];

/// The biggest request this app takes in (16 inputs), and the pieces things go in.
const MAX_REQUEST: usize = 64 * 1024;
const PIECE: usize = 4000;
/// Outputs a `K` asks about at once: their key images fit one answer.
const MAX_KEY_IMAGES: usize = 40;
/// Kept once the owner has let a computer watch the wallet.
const WATCHED: &str = "watched";

fn network(n: u8) -> Option<Network> {
    match n {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet),
        2 => Some(Network::Stagenet),
        _ => None,
    }
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> { b.get(at..at + 4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) }

/// Account `major`'s address `minor`: the primary address for 0 and 0, a subaddress otherwise.
/// maki makes its keys.
fn address(net: Network, major: u32, minor: u32) -> Result<String, Error> {
    let (spend, view) = wallet::subaddress(&ACCOUNT, major, minor)?;
    let kind = if (major, minor) == (0, 0) { Kind::Standard } else { Kind::Subaddress };
    Ok(maki_xmr::address(net, kind, &spend, &view))
}

/// Which address it is, as the owner reads it: "Primary address", "Subaddress 3", and the network
/// unless it's Monero itself.
fn caption(net: Network, major: u32, minor: u32) -> String {
    let which = match (major, minor) {
        (0, 0) => String::from("Primary address"),
        (0, i) => format!("Subaddress {i}"),
        (a, i) => format!("Subaddress {a}/{i}"),
    };
    if net == Network::Mainnet { which } else { format!("{which}, {}", net.name()) }
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

fn owner(a: maki_app::Answer) -> u8 {
    match a {
        maki_app::Answer::Yes => OK,
        maki_app::Answer::No => DENIED,
        maki_app::Answer::NoAnswer => NO_ANSWER,
    }
}

/// What asking maki came to, as an answer.
fn failed(e: Error) -> Answer {
    match e {
        Error::Locked => Answer::new(LOCKED),
        _ => Answer::new(NO_ANSWER),
    }
}

/// `D`: an address, put on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Answer {
    let (Some(net), Some(major), Some(minor)) = (m.get(1).and_then(|n| network(*n)), u32_at(m, 2), u32_at(m, 6)) else {
        return Answer::new(BAD);
    };
    let address = match address(net, major, minor) {
        Ok(a) => a,
        Err(Error::Locked) => return Answer::new(LOCKED),
        Err(_) => return Answer::new(BAD),
    };
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&caption(net, major, minor)).mono(&address))
        .signatures(0)
        .show();
    match asked {
        Ok(a) if owner(a) == OK || owner(a) == DENIED => Answer::new(owner(a)).text(&address),
        Ok(_) => Answer::new(NO_ANSWER),
        Err(e) => failed(e),
    }
}

/// `W`: the secret view key, and the address it watches, once the owner agrees: the computer sees
/// what comes in, and has nothing to spend with.
fn watch(m: &[u8]) -> Answer {
    let Some(net) = m.get(1).and_then(|n| network(*n)) else { return Answer::new(BAD) };
    let address = match address(net, 0, 0) {
        Ok(a) => a,
        Err(Error::Locked) => return Answer::new(LOCKED),
        Err(_) => return Answer::new(BAD),
    };
    let asked = Review::new("Let computer watch?")
        .detail("it sees what comes in; spending still needs you")
        .answers("share", "don't")
        .page(Page::new("Watch only").mono(&address).prose("The view key: this wallet's payments and balance, and nothing to spend with."))
        .signatures(1)
        .timeout(60)
        .show();
    match asked.map(owner) {
        Ok(OK) => {}
        Ok(s) => return Answer::new(s),
        Err(e) => return failed(e),
    }
    match wallet::monero_view_key(&ACCOUNT) {
        Ok(key) => {
            let _ = storage::set(WATCHED, &[1]);
            Answer::new(OK).text(&address).bytes(&key)
        }
        Err(e) => failed(e),
    }
}

/// `K`: outputs' key images, with their proofs, for a computer that's watching.
fn key_images(m: &[u8]) -> Answer {
    let Some(&n) = m.get(1) else { return Answer::new(BAD) };
    let n = n as usize;
    if n == 0 || n > MAX_KEY_IMAGES || m.len() != 2 + 80 * n {
        return Answer::new(BAD);
    }
    if storage::get(WATCHED, &mut [0u8; 1]).is_none() {
        return Answer::new(REFUSED).text("let maki desktop watch this wallet first");
    }
    let mut answer = Answer::new(OK);
    for o in m[2..].chunks_exact(80) {
        let index = u64::from_le_bytes(o[32..40].try_into().unwrap());
        let (major, minor) = (u32_at(o, 40).unwrap(), u32_at(o, 44).unwrap());
        match wallet::monero_key_image(&ACCOUNT, o[..32].try_into().unwrap(), index, major, minor, o[48..].try_into().unwrap()) {
            Ok((image, proof)) => answer = answer.bytes(&image).bytes(&proof),
            Err(Error::Locked) => return Answer::new(LOCKED),
            Err(_) => return Answer::new(REFUSED).text("an output that isn't this wallet's"),
        }
    }
    answer
}

/// A whole request: shown, and on a yes made and signed by maki. The signed transaction, or the
/// answer saying why not.
fn sign(net: Network, bytes: &[u8]) -> Result<Vec<u8>, Answer> {
    let request = Request::parse(bytes).map_err(|e| Answer::new(REFUSED).text(&format!("{e}")))?;
    if request.network != net {
        return Err(Answer::new(REFUSED).text("a payment on another network"));
    }
    let mut asked = Review::new("Sign and spend").detail(&request.summary()).answers("sign", "reject").timeout(300);
    for p in request.pages() {
        asked = asked.page(Page::new(&p.heading).value(&p.value).mono(&p.mono).prose(&p.prose));
    }
    // one signature for each input
    match asked.signatures(request.inputs.len() as u32).show().map(owner) {
        Ok(OK) => {}
        Ok(s) => return Err(Answer::new(s)),
        Err(e) => return Err(failed(e)),
    }
    match wallet::monero_sign(&ACCOUNT, bytes) {
        Ok(Ok(signed)) => Ok(signed),
        Ok(Err(why)) => Err(Answer::new(REFUSED).text(&why)),
        Err(e) => Err(failed(e)),
    }
}

/// The request coming in, and the transaction last signed.
#[derive(Default)]
struct Wallet {
    incoming: Vec<u8>,
    incoming_total: usize,
    signed: Vec<u8>,
}

impl Wallet {
    fn answer(&mut self, m: &[u8]) -> Answer {
        match m.first() {
            Some(&ADDRESS) => compare(m),
            Some(&WATCH) => watch(m),
            Some(&KEY_IMAGES) => key_images(m),
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
        if total > MAX_REQUEST {
            return Answer::new(REFUSED).text(&format!("more than {MAX_INPUTS} inputs at once"));
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
        let bytes = core::mem::take(&mut self.incoming);
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

/// What the screen shows when the app is open.
struct View {
    network: Network,
    index: u32,
    as_text: bool,
    /// the address last drawn, and for what: maki's curve work isn't done again for a redraw
    drawn: Option<(Network, u32, String)>,
}

const MENU: [&str; 2] = ["Backup words", "Network"];

impl View {
    fn draw(&mut self) {
        screen::clear(Color::Dark);
        let fresh = match &self.drawn {
            Some((n, i, a)) if *n == self.network && *i == self.index => Ok(a.clone()),
            _ => address(self.network, 0, self.index),
        };
        let Ok(address) = fresh else {
            self.drawn = None;
            screen::text_centred(40, "maki is locked", Style::Regular, Color::Light);
            screen::text_centred(58, "enter its PIN first", Style::Small, Color::Light);
            screen::present();
            return;
        };
        self.drawn = Some((self.network, self.index, address.clone()));
        if self.as_text {
            // 95 characters, seven lines of them
            for (i, start) in (0..address.len()).step_by(14).enumerate() {
                screen::text_centred(2 + i as i32 * 15, &address[start..(start + 14).min(address.len())], Style::Mono, Color::Light);
            }
        } else {
            let data = address.as_bytes();
            let side = screen::qr(0, 0, data, 94).unwrap_or(0);
            screen::clear(Color::Dark);
            screen::qr((WIDTH - side) / 2, 0, data, 94);
            let which = if self.index == 0 { String::from("primary") } else { format!("subaddress #{}", self.index) };
            let net = if self.network == Network::Mainnet { String::new() } else { format!(" {}", self.network.name()) };
            screen::text_centred(97, &format!("{which}{net}"), Style::Small, Color::Light);
        }
        screen::present();
    }
}

fn main() {
    let _ = menu(&MENU);
    let mut view = View { network: Network::Mainnet, index: 0, as_text: false, drawn: None };
    let mut w = Wallet::default();
    let mut shown = true;
    loop {
        if shown {
            view.draw();
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; 4096];
                let n = link::read(&mut m).unwrap_or(0).min(m.len());
                let reply = w.answer(&m[..n]);
                let _ = link::reply(&reply.0);
            }
            Event::Left => view.index = view.index.saturating_sub(1),
            Event::Right => view.index = view.index.saturating_add(1),
            Event::Centre => view.as_text = !view.as_text,
            // maki asks, then shows the words itself: they never come here
            Event::Menu(0) => {
                let _ = wallet::show_backup(&ACCOUNT);
            }
            Event::Menu(1) => {
                view.network = match view.network {
                    Network::Mainnet => Network::Stagenet,
                    Network::Stagenet => Network::Testnet,
                    Network::Testnet => Network::Mainnet,
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
