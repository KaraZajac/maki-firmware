//! Menus: maki's own (left and right together on the home screen) and each app's (the same,
//! inside it).
//!
//! One item at a time: left and right go through them, the centre picks. There's no way out
//! but an item, so every menu has one: Close for maki's, Exit for an app's, added by the launcher
//! so no app can leave it out.

use blitstr2::GlyphStyle;

use crate::ui::{Key, LINE, Screen};

pub(crate) struct Menu {
    /// what the menu belongs to: "maki", or the app's name
    pub(crate) title: String,
    pub(crate) items: Vec<String>,
    pub(crate) selected: usize,
}

impl Menu {
    pub(crate) fn new(title: &str, items: Vec<String>) -> Self { Menu { title: title.into(), items, selected: 0 } }

    pub(crate) fn draw(&self, screen: &Screen, clock: &str, linked: bool) {
        screen.begin();
        screen.status_bar(clock, linked);
        let top = screen.bar + 8;
        screen.text(top, LINE, GlyphStyle::Small, false, true, &format!("{} menu", self.title));
        if let Some(item) = self.items.get(self.selected) {
            screen.text(top + 30, LINE + 4, GlyphStyle::Bold, false, true, item);
        }
        screen.dots(self.items.len(), self.selected, top + 62);
        screen.action_bar("choose", self.items.len() > 1);
        screen.end();
    }

    /// Left, right: move. Centre: returns the item picked. The menu chord means nothing here.
    pub(crate) fn key(&mut self, key: Key) -> Option<usize> {
        let n = self.items.len().max(1);
        match key {
            Key::Left => self.selected = (self.selected + n - 1) % n,
            Key::Right => self.selected = (self.selected + 1) % n,
            Key::Confirm => return Some(self.selected),
            Key::Menu => {}
        }
        None
    }
}
