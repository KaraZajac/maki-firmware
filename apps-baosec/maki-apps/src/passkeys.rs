//! maki's Passkeys app: the passkeys maki holds, one at a time, with the site each is for and
//! whose it is. Left and right go through them; the menu deletes the one on screen, once the
//! owner says so.
//!
//! The vault's FIDO authenticator makes and uses passkeys (OpenSK, in the secret basis). This
//! only reads its store, and deletes from it, telling maki-keys so the vault re-reads it.

use std::io::Read;

use blitstr2::GlyphStyle;
use maki_launcher::Answer;
use maki_ui::{Key, LINE, Screen};

/// How long the owner has to answer (the emulator skips through idle time: longer there).
const ASK_TIMEOUT_S: u32 = maki_launcher::ask_timeout(30);
/// A site in fixed-width type: 15 characters to a line, three lines.
const SITE_WIDTH: usize = 15;
const SITE_LINES: usize = 3;

struct Passkey {
    slot: usize,
    rp_id: String,
    user: Option<String>,
}

pub(crate) struct Passkeys {
    screen: Screen,
    keys: maki_keys::Keys,
    launcher: maki_launcher::Launcher,
    pddb: pddb::Pddb,
    list: Vec<Passkey>,
    index: usize,
    front: bool,
}

impl Passkeys {
    pub(crate) fn new(xns: &xous_names::XousNames, launcher: maki_launcher::Launcher) -> Self {
        Passkeys {
            screen: Screen::new(xns),
            keys: maki_keys::Keys::new(xns).expect("couldn't connect to maki-keys"),
            launcher,
            pddb: pddb::Pddb::new(),
            list: Vec::new(),
            index: 0,
            front: false,
        }
    }

    /// In front: the store is read afresh, since sites add passkeys whenever they like.
    pub(crate) fn focus(&mut self, front: bool) {
        self.front = front;
        if front {
            self.load();
        }
        self.draw();
    }

    /// Read the store afresh: the authenticator adds passkeys whenever a site asks it to.
    fn load(&mut self) {
        let mut list = Vec::new();
        if let Ok(keys) = self.pddb.list_keys(maki_fido::DICT, None) {
            for key in keys {
                let Some(slot) = key.parse::<usize>().ok().filter(|n| maki_fido::CREDENTIALS.contains(n))
                else {
                    continue;
                };
                let Ok(mut k) = self.pddb.get(maki_fido::DICT, &key, None, false, false, None, None::<fn()>)
                else {
                    continue;
                };
                let mut v = Vec::new();
                if k.read_to_end(&mut v).is_ok() {
                    if let Some(s) = maki_fido::summary(&v) {
                        list.push(Passkey { slot, rp_id: s.rp_id.into(), user: s.user.map(|u| u.into()) });
                    }
                }
                // the record holds the credential's private key
                v.fill(0);
            }
        }
        list.sort_by(|a, b| (&a.rp_id, &a.user).cmp(&(&b.rp_id, &b.user)));
        self.list = list;
        self.index = self.index.min(self.list.len().saturating_sub(1));
    }

    fn draw(&self) {
        if !self.front {
            return;
        }
        let s = &self.screen;
        s.begin();
        match self.list.get(self.index) {
            None => {
                s.titled_bar("Passkeys", "", false);
                s.text(s.bar + 24, LINE, GlyphStyle::Bold, false, true, "No passkeys yet");
                s.text(s.bar + 26 + LINE, 13, GlyphStyle::Small, false, true, "sites save them here");
                s.text(s.bar + 42 + LINE * 2, 13, GlyphStyle::Small, false, true, "left + right: menu");
            }
            Some(p) => {
                s.titled_bar(&format!("Passkey {}/{}", self.index + 1, self.list.len()), "", false);
                let top = s.bar + 4;
                let site = maki_proto::site::lines(&p.rp_id, SITE_WIDTH, SITE_LINES).join("\n");
                s.text(top, LINE * SITE_LINES as isize + 2, GlyphStyle::Monospace, false, false, &site);
                let y = top + LINE * SITE_LINES as isize + 4;
                s.text(y, LINE, GlyphStyle::Bold, false, false, p.user.as_deref().unwrap_or("no name given"));
                // nothing for the centre to do here: left and right go through them
                s.action_bar("", self.list.len() > 1);
            }
        }
        s.end();
    }

    pub(crate) fn key(&mut self, key: Key) {
        let n = self.list.len();
        if !self.front || n < 2 {
            return;
        }
        match key {
            // the jog dial too: down to the next, up to the one before
            Key::Left | Key::Up => self.index = (self.index + n - 1) % n,
            Key::Right | Key::Down => self.index = (self.index + 1) % n,
            _ => return,
        }
        self.draw();
    }

    pub(crate) fn menu(&self) -> &'static [&'static str] {
        if self.list.is_empty() { &[] } else { &["Delete this passkey"] }
    }

    /// An item of the menu: the only one deletes the passkey on screen.
    pub(crate) fn picked(&mut self, i: usize) {
        if i == 0 {
            self.delete();
        }
    }

    /// Delete the passkey on screen, once the owner says so on maki: a site that relies on it
    /// won't let them in with it again.
    fn delete(&mut self) {
        let Some(p) = self.list.get(self.index) else { return };
        let user = p.user.clone().unwrap_or_default();
        let answer = self.launcher.ask(&p.rp_id, "Delete passkey?", &user, &[], ASK_TIMEOUT_S);
        if !matches!(answer, Ok(Answer::Allowed(_))) {
            return;
        }
        let slot = p.slot.to_string();
        match self.pddb.delete_key(maki_fido::DICT, &slot, None) {
            Ok(()) => {
                self.pddb.sync().ok();
                log::info!("passkey for {} deleted", p.rp_id);
                self.keys.fido_store_changed();
            }
            Err(e) => log::error!("couldn't delete the passkey: {:?}", e),
        }
        self.load();
    }
}
