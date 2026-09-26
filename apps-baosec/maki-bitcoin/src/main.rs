//! maki's Bitcoin app: the wallet's receiving addresses on maki's own screen, as a QR code and
//! as text, so someone paying you can scan an address that never passed through a computer.
//!
//! Left and right go through the addresses, the centre switches between the code and the text,
//! and the menu shows the account's public key as a code (for a watch-only wallet on a phone) or
//! switches between bitcoin and the test networks. Signing happens in asks, from the desktop app.

use blitstr2::GlyphStyle;
use maki_launcher::{Focus, MenuMessage};
use maki_ui::{Key, Screen, H, LINE, SMALL_LINE, W};
use num_traits::{FromPrimitive, ToPrimitive};

const SERVER_NAME: &str = "_maki bitcoin_";
/// Addresses are shown in fixed-width type, 15 characters to a line.
const WIDTH: usize = 15;

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
enum Op {
    /// Scalar from the launcher: `arg1..arg4` are key characters.
    KeyPress = 0,
    /// Scalar from the launcher: `arg1` is a `Focus`.
    Focus = 1,
    /// The launcher asking for our menu's items, or saying which the owner picked.
    Menu = 2,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Qr,
    Text,
    /// the account's public key, as a code
    Account,
}

struct App {
    screen: Screen,
    keys: maki_keys::Keys,
    network: u8,
    index: u32,
    view: View,
    front: bool,
    /// the address on screen: (network, index, address)
    address: Option<(u8, u32, String)>,
    /// the account's zpub: (network, zpub)
    account: Option<(u8, String)>,
}

/// Why maki-keys had nothing to show.
fn trouble(result: u32) -> &'static str {
    match result {
        maki_keys::RESULT_NO_PHRASE => "No recovery phrase yet",
        maki_keys::RESULT_NOT_NOW => "maki is locked",
        _ => "Couldn't make the keys",
    }
}

impl App {
    fn testnet(&self) -> bool { self.network == maki_keys::NETWORK_TESTNET }

    fn address(&mut self) -> Result<String, u32> {
        if let Some((n, i, a)) = &self.address {
            if (*n, *i) == (self.network, self.index) {
                return Ok(a.clone());
            }
        }
        let w = self.keys.btc_address(self.network, false, self.index, false);
        if w.result != maki_keys::RESULT_OK {
            return Err(w.result);
        }
        self.address = Some((self.network, self.index, w.text.clone()));
        Ok(w.text)
    }

    fn zpub(&mut self) -> Result<String, u32> {
        if let Some((n, z)) = &self.account {
            if *n == self.network {
                return Ok(z.clone());
            }
        }
        let w = self.keys.btc_account(self.network, false);
        if w.result != maki_keys::RESULT_OK {
            return Err(w.result);
        }
        self.account = Some((self.network, w.text.clone()));
        Ok(w.text)
    }

    fn title(&self) -> String {
        format!("{} #{}", if self.testnet() { "Testnet" } else { "Receive" }, self.index)
    }

    fn message(&self, title: &str, text: &str) {
        let s = &self.screen;
        s.begin();
        s.titled_bar(title, "", false);
        s.text(s.bar + 30, LINE, GlyphStyle::Regular, false, true, text);
        s.end();
    }

    fn draw(&mut self) {
        if !self.front {
            return;
        }
        let first = match self.view {
            View::Account => self.account.is_none(),
            _ => self.address.is_none(),
        };
        if first {
            // the keys come from the recovery phrase, which takes maki a moment the first time
            self.message("Bitcoin", "One moment…");
        }
        let top = self.screen.bar + 3;
        let room = H - SMALL_LINE - 3 - top;
        match self.view {
            View::Account => match self.zpub() {
                Ok(zpub) => {
                    let s = &self.screen;
                    s.begin();
                    s.titled_bar(if self.testnet() { "Account vpub" } else { "Account zpub" }, "", false);
                    if !s.qr(&zpub, W / 2, top, room) {
                        s.text(top, LINE * 8, GlyphStyle::Monospace, false, false, &lines(&zpub).join("\n"));
                    }
                    s.action_bar("done", false);
                    s.end();
                }
                Err(e) => self.message("Bitcoin", trouble(e)),
            },
            view => match self.address() {
                Ok(address) => {
                    let title = self.title();
                    let s = &self.screen;
                    s.begin();
                    s.titled_bar(&title, "", false);
                    if view == View::Qr {
                        // bech32 in capitals is the same address, and makes a smaller code
                        s.qr(&address.to_uppercase(), W / 2, top, room);
                        s.action_bar("as text", true);
                    } else {
                        let rows = lines(&address);
                        s.text(top + 4, LINE * rows.len() as isize + 2, GlyphStyle::Monospace, false, false, &rows.join("\n"));
                        let y = top + 8 + LINE * rows.len() as isize;
                        s.text(y, 13, GlyphStyle::Small, false, true, "left, right: other addresses");
                        s.action_bar("as QR code", true);
                    }
                    s.end();
                }
                Err(e) => self.message("Bitcoin", trouble(e)),
            },
        }
    }

    fn key(&mut self, key: Key) {
        match (self.view, key) {
            (View::Account, Key::Confirm) => self.view = View::Qr,
            (View::Account, _) => return,
            (_, Key::Left) if self.index > 0 => self.index -= 1,
            (_, Key::Right) if self.index < 0x7fff_ffff => self.index += 1,
            (View::Qr, Key::Confirm) => self.view = View::Text,
            (View::Text, Key::Confirm) => self.view = View::Qr,
            _ => return,
        }
        self.draw();
    }

    fn menu(&self) -> [&'static str; 2] {
        ["Account key", if self.testnet() { "Use bitcoin" } else { "Use testnet" }]
    }

    /// An item of our menu was picked; the launcher gives the screen back after.
    fn picked(&mut self, i: usize) {
        match i {
            0 => self.view = View::Account,
            1 => {
                self.network = if self.testnet() { maki_keys::NETWORK_BITCOIN } else { maki_keys::NETWORK_TESTNET };
                self.index = 0;
                self.view = View::Qr;
            }
            _ => {}
        }
    }
}

/// An address or key in lines that fit across the screen.
fn lines(text: &str) -> Vec<String> {
    text.chars().collect::<Vec<_>>().chunks(WIDTH).map(|c| c.iter().collect()).collect()
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-bitcoin PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME, None).expect("can't register server");
    maki_launcher::Launcher::new(&xns)
        .expect("couldn't connect to the launcher")
        .register(
            "Bitcoin",
            SERVER_NAME,
            Op::KeyPress.to_u32().unwrap(),
            Op::Focus.to_u32().unwrap(),
            Op::Menu.to_u32().unwrap(),
            Some(&maki_icons::BITCOIN),
        )
        .expect("couldn't register with the launcher");

    let mut app = App {
        screen: Screen::new(&xns),
        keys: maki_keys::Keys::new(&xns).expect("couldn't connect to maki-keys"),
        network: maki_keys::NETWORK_BITCOIN,
        index: 0,
        view: View::Qr,
        front: false,
        address: None,
        account: None,
    };

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(Op::KeyPress) => xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                for k in [k1, k2, k3, k4] {
                    if let Some(key) = char::from_u32(k as u32).and_then(Key::from_char) {
                        if app.front {
                            app.key(key);
                        }
                    }
                }
            }),
            Some(Op::Focus) => xous::msg_scalar_unpack!(msg, focus, _, _, _, {
                app.front = focus == Focus::Foreground.to_usize().unwrap();
                app.draw();
            }),
            Some(Op::Menu) => match MenuMessage::of(&msg) {
                Some(MenuMessage::Fill) => MenuMessage::fill(&mut msg, &app.menu()),
                Some(MenuMessage::Picked(i)) => app.picked(i),
                None => {}
            },
            None => log::warn!("unknown opcode {}", msg.body.id()),
        }
    }
}
