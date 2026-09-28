//! Monero: maki's Monero wallet, as an app from the maki store (ARCHITECTURE.md, "Wallets are
//! apps"). The account is the one Ledger's Monero app makes from the same recovery phrase (the
//! key at `m/44'/128'/0'/0/0`, hashed to the spend key: `maki-xmr`), so the phrase gives the same
//! wallet there. maki keeps the keys (the wallet permission, on `m/44'/128'` and no other): this
//! app shows the account's addresses, and has maki show its owner the 25 words that restore the
//! wallet in any Monero wallet, which it never sees itself.
//!
//! Opened, it shows the primary address as a QR code: left and right step through the account's
//! subaddresses, the centre shows the address as text, and the menu has the backup words and the
//! network (Monero, or its testnet and stagenet, for trying things out).
//!
//! maki desktop talks to it over the link. A message starts with what it is; an answer with a
//! status, then its fields (strings as a u16 length and the bytes, numbers little-endian):
//!
//! - `D` network, account (u32), index (u32): an address, once the owner has compared it on
//!   maki's screen with the computer's (account 0's index 0 is the primary address).
//!
//! Network is 0 (Monero), 1 (testnet) or 2 (stagenet).

use maki_app::wallet::{self, Page, Review, HARDENED};
use maki_app::*;
use maki_xmr::{Kind, Network};

const ADDRESS: u8 = b'D';

/// What an answer's first byte says.
const OK: u8 = 0;
const DENIED: u8 = 1;
const NO_ANSWER: u8 = 2;
const LOCKED: u8 = 3;
const BAD: u8 = 4;

/// The account, as Ledger's Monero app has account 0.
const ACCOUNT: [u32; 5] = [44 | HARDENED, 128 | HARDENED, HARDENED, 0, 0];

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
fn answer(status: u8, text: &str) -> Vec<u8> {
    let mut a = vec![status];
    if !text.is_empty() {
        a.extend_from_slice(&(text.len() as u16).to_le_bytes());
        a.extend_from_slice(text.as_bytes());
    }
    a
}

/// `D`: an address, put on maki's screen for the owner to compare with the computer's.
fn compare(m: &[u8]) -> Vec<u8> {
    let (Some(net), Some(major), Some(minor)) = (m.get(1).and_then(|n| network(*n)), u32_at(m, 2), u32_at(m, 6)) else {
        return answer(BAD, "");
    };
    let address = match address(net, major, minor) {
        Ok(a) => a,
        Err(Error::Locked) => return answer(LOCKED, ""),
        Err(_) => return answer(BAD, ""),
    };
    let asked = Review::new("Same on computer?")
        .answers("matches", "doesn't match")
        .page(Page::new(&caption(net, major, minor)).mono(&address))
        .signatures(0)
        .show();
    match asked {
        Ok(maki_app::Answer::Yes) => answer(OK, &address),
        Ok(maki_app::Answer::No) => answer(DENIED, &address),
        Ok(maki_app::Answer::NoAnswer) => answer(NO_ANSWER, ""),
        Err(Error::Locked) => answer(LOCKED, ""),
        Err(_) => answer(NO_ANSWER, ""),
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
    let mut shown = true;
    loop {
        if shown {
            view.draw();
        }
        match wait(None) {
            Event::Message => {
                let mut m = vec![0u8; 4096];
                let n = link::read(&mut m).unwrap_or(0).min(m.len());
                let reply = match m[..n].first() {
                    Some(&ADDRESS) => compare(&m[..n]),
                    _ => answer(BAD, ""),
                };
                let _ = link::reply(&reply);
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
