use core::fmt::Write as TextViewWrite;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use blitstr2::GlyphStyle;
use ux_api::minigfx::*;
use ux_api::service::api::Gid;
use ux_api::service::gfx::Gfx;
use ux_api::widgets::ScrollableList;
use xous::CID;

use crate::storage::Manager;
use crate::*;

const FAST_SCROLL_DELAY_MS: u64 = 1300;
const KEYUP_DELAY_MS: u64 = 100;
/// How many elements to skip through on fast scroll
const PAGE_INCREMENT: usize = 6;

pub const DEFAULT_FONT: GlyphStyle = GlyphStyle::Regular;
pub const FONT_LIST: [&'static str; 6] = ["regular", "tall", "mono", "bold", "large", "small"];
pub fn name_to_style(name: &str) -> Option<GlyphStyle> {
    match name {
        "regular" => Some(GlyphStyle::Regular),
        "tall" => Some(GlyphStyle::Tall),
        "mono" => Some(GlyphStyle::Monospace),
        "cjk" => Some(GlyphStyle::Cjk),
        "bold" => Some(GlyphStyle::Bold),
        "large" => Some(GlyphStyle::Large),
        "small" => Some(GlyphStyle::Small),
        _ => None,
    }
}
fn style_to_name(style: &GlyphStyle) -> String {
    match style {
        GlyphStyle::Regular => "regular".to_string(),
        GlyphStyle::Monospace => "mono".to_string(),
        GlyphStyle::Cjk => "cjk".to_string(),
        GlyphStyle::Bold => "bold".to_string(),
        GlyphStyle::Large => "large".to_string(),
        GlyphStyle::Small => "small".to_string(),
        GlyphStyle::Tall => "tall".to_string(),
        _ => "regular".to_string(),
    }
}
const VAULT_CONFIG_DICT: &'static str = "vault.config";
const VAULT_CONFIG_KEY_FONT: &'static str = "fontstyle";

pub enum NavDir {
    Up,
    Down,
    Autotype,
}

/// Centralizes tunable UI parameters for TOTP
struct TotpLayout {}
impl TotpLayout {
    pub fn totp_box() -> RoundedRectangle {
        RoundedRectangle::new(Rectangle::new(Point::new(0, 0), Point::new(127, 40)), 0)
    }

    /// Vertical margin for the font because the centering algorithm also aligns-top, and we want a little
    /// more verticale space for aesthetic reasons than the centering algorithm gives by default.
    pub fn totp_font_vmargin() -> Point { Point::new(0, 4) }

    pub fn totp_margin() -> Point { Point::new(10, 0) }

    pub fn totp_font() -> GlyphStyle { GlyphStyle::ExtraLarge }

    pub fn timer_box() -> Rectangle { Rectangle::new(Point::new(0, 40), Point::new(127, 50)) }

    pub fn list_box() -> Rectangle { Rectangle::new(Point::new(0, 50), Point::new(127, 127)) }

    pub fn list_font() -> GlyphStyle { GlyphStyle::Regular }
}

pub struct VaultUi {
    main_cid: CID,
    gfx: Gfx,
    display_list: ScrollableList,
    item_lists: Arc<Mutex<ItemLists>>,
    mode: Arc<Mutex<VaultMode>>,

    /// totp redraw state
    totp_code: Option<String>,
    last_epoch: u64,

    pddb: RefCell<Pddb>,
    item_height: isize,
    style: GlyphStyle,
    storage_manager: Manager,

    usb_dev: usb_bao1x::UsbHid,
    last_key_time: u64,
    start_hold_time: u64,
    tt: ticktimer_server::Ticktimer,

    /// maki launcher focus; the vault draws only while in front
    focused: bool,
    /// maki: the entry on screen, an index into the current mode's list. One entry is shown at a
    /// time; left and right go through them.
    carousel: usize,
}

impl VaultUi {
    pub fn new(
        xns: &xous_names::XousNames,
        cid: xous::CID,
        item_lists: Arc<Mutex<ItemLists>>,
        mode: Arc<Mutex<VaultMode>>,
    ) -> Self {
        let pddb = pddb::Pddb::new();
        let mut totp_list = ScrollableList::default();
        totp_list
            .set_margin(TotpLayout::totp_margin())
            .pane_size(TotpLayout::list_box())
            .style(TotpLayout::list_font());
        totp_list.set_autoflush(false);

        let tt = ticktimer_server::Ticktimer::new().unwrap();
        let now = tt.elapsed_ms();
        let gfx = Gfx::new(&xns).unwrap();
        let style = DEFAULT_FONT;
        let glyph_height = gfx.glyph_height_hint(style).unwrap() as isize;
        let height = gfx.screen_size().unwrap().y;
        Self {
            main_cid: cid,
            gfx,
            display_list: totp_list,
            item_lists,
            mode,
            totp_code: None,
            last_epoch: crate::totp::get_current_unix_time().expect("couldn't get current time") / 30,
            pddb: RefCell::new(pddb),
            item_height: height / glyph_height,
            style,
            storage_manager: Manager::new(xns),
            usb_dev: usb_bao1x::UsbHid::new(),
            tt,
            last_key_time: now,
            start_hold_time: now,
            focused: false,
            carousel: 0,
        }
    }

    pub(crate) fn refresh_draw_list(&mut self) {
        let mode = { (*self.mode.lock().unwrap()).clone() };

        let mut locked_lists = if let Ok(g) = self.item_lists.try_lock() {
            g
        } else {
            log::warn!("Couldn't get lock in refresh_draw_list; aborting the refresh");
            return;
        };
        let full_list = locked_lists.full_list(mode);
        self.display_list.clear();
        for item in full_list.iter() {
            self.display_list.add_item(0, &item.name());
        }
        if self.carousel >= full_list.len() {
            self.carousel = full_list.len().saturating_sub(1);
        }
    }

    /// How many entries the current mode has.
    pub(crate) fn len(&self) -> usize {
        let mode = *self.mode.lock().unwrap();
        self.item_lists.lock().unwrap().full_list(mode).len()
    }

    pub(crate) fn update_selected_totp_code(&mut self) -> Option<String> {
        if *self.mode.lock().unwrap() != VaultMode::Totp {
            return None;
        }
        let item = self.get_selected_item()?;
        match crate::totp::db_str_to_code(&item.extra) {
            Ok(s) => {
                self.totp_code = Some(s.clone());
                Some(s)
            }
            _ => {
                self.totp_code = None;
                None
            }
        }
    }

    pub(crate) fn get_selected_item(&self) -> Option<ListItem> {
        let mode = *self.mode.lock().unwrap();
        let mut locked_lists = self.item_lists.lock().unwrap();
        locked_lists.full_list(mode).get(self.carousel).cloned()
    }

    pub(crate) fn selected_entry(&self) -> Option<SelectedEntry> {
        let mode = *self.mode.lock().unwrap();
        if let Some(li) = self.get_selected_item() {
            let name = li.name().to_owned();
            Some(SelectedEntry { key_guid: li.guid, description: name, mode })
        } else {
            None
        }
    }

    pub(crate) fn basis_change(&mut self) {
        self.item_lists.lock().unwrap().clear_all();
        self.display_list.clear();
    }

    pub(crate) fn store_glyph_style(&mut self, style: GlyphStyle) {
        self.pddb
            .borrow()
            .delete_key(VAULT_CONFIG_DICT, VAULT_CONFIG_KEY_FONT, Some(pddb::PDDB_DEFAULT_SYSTEM_BASIS))
            .ok();

        match self.pddb.borrow().get(
            VAULT_CONFIG_DICT,
            VAULT_CONFIG_KEY_FONT,
            Some(pddb::PDDB_DEFAULT_SYSTEM_BASIS),
            true,
            true,
            Some(32),
            Some(vault2::basis_change),
        ) {
            Ok(mut style_key) => {
                style_key.write(style_to_name(&style).as_bytes()).ok();
            }
            _ => panic!("PDDB access erorr"),
        };
        self.pddb.borrow().sync().ok();
    }

    pub(crate) fn apply_glyph_style(&mut self) {
        let style = match self.pddb.borrow().get(
            VAULT_CONFIG_DICT,
            VAULT_CONFIG_KEY_FONT,
            Some(pddb::PDDB_DEFAULT_SYSTEM_BASIS),
            true,
            true,
            Some(32),
            Some(vault2::basis_change),
        ) {
            Ok(mut style_key) => {
                let mut name_bytes = Vec::<u8>::new();
                match style_key.read_to_end(&mut name_bytes) {
                    Ok(_len) => {
                        log::debug!(
                            "name_bytes: {:?} {:?}",
                            name_bytes,
                            String::from_utf8(name_bytes.to_vec())
                        );
                        name_to_style(&String::from_utf8(name_bytes).unwrap_or("regular".to_string()))
                            .unwrap_or(GlyphStyle::Regular)
                    }
                    Err(_) => GlyphStyle::Regular,
                }
            }
            _ => {
                log::warn!("PDDB access error reading default glyph size");
                GlyphStyle::Regular
            }
        };
        self.display_list.style(style);
        let glyph_height = self.gfx.glyph_height_hint(style).unwrap();
        self.item_height = glyph_height as isize + 2; // +2 because of the border width
        self.item_lists.lock().unwrap().set_items_per_screen(
            (self.gfx.screen_size().unwrap().y - 2 * self.item_height) / self.item_height,
        );
        self.style = style;
    }

    /// Clear the entire screen.
    pub fn clear_area(&self) { self.gfx.clear().ok(); }

    pub fn set_focus(&mut self, focused: bool) { self.focused = focused; }

    /// Redraw the screen: one entry at a time (maki's three-button model). Authenticator shows a
    /// code, big, with the time it has left; Passwords a site and its username. Left and right go
    /// through them, the centre types the code or the password into the computer, and left and
    /// right together open the menu (the launcher's).
    pub fn redraw(&mut self) {
        if !self.focused {
            return;
        }
        let mode_at_entry = (*self.mode.lock().unwrap()).clone();
        self.clear_area();
        let n = self.len();
        if n == 0 {
            let (title, hint) = match mode_at_entry {
                VaultMode::Totp => ("No codes yet", "add one from a QR code"),
                VaultMode::Password => ("No logins yet", "the browser saves them here"),
            };
            self.band(28, 18, GlyphStyle::Bold, false, title);
            self.band(50, 14, GlyphStyle::Small, false, hint);
            self.band(86, 14, GlyphStyle::Small, false, "left + right: menu");
            if mode_at_entry == VaultMode::Totp {
                self.action_bar("scan a QR code", false);
            }
            self.gfx.flush().ok();
            return;
        }
        let Some(item) = self.get_selected_item() else {
            self.gfx.flush().ok();
            return;
        };
        match mode_at_entry {
            VaultMode::Totp => {
                self.band(2, 16, GlyphStyle::Bold, false, item.name());
                if self.totp_code.is_none() {
                    self.update_selected_totp_code();
                }
                let code = match &self.totp_code {
                    // in two halves, easier to read off
                    Some(c) if c.len() >= 6 => {
                        let (a, b) = c.split_at(c.len() / 2);
                        format!("{} {}", a, b)
                    }
                    Some(c) => c.clone(),
                    None => String::from("------"),
                };
                self.band(26, 34, TotpLayout::totp_font(), false, &code);

                // the time the code has left
                let step = item.extra.split(':').nth(2).and_then(|s| s.parse::<u64>().ok()).filter(|&s| s > 0).unwrap_or(30);
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let epoch = now_ms / (step * 1000);
                if self.last_epoch != epoch {
                    self.last_epoch = epoch;
                    self.update_selected_totp_code();
                }
                let left_ms = step * 1000 - now_ms % (step * 1000);
                let (x0, x1, y) = (14isize, 114isize, 66isize);
                let filled = x0 + ((x1 - x0) as u64 * left_ms / (step * 1000)) as isize;
                self.gfx
                    .draw_rectangle(Rectangle::new_with_style(
                        Point::new(x0, y),
                        Point::new(x1, y + 5),
                        DrawStyle::new(PixelColor::Dark, PixelColor::Light, 1),
                    ))
                    .ok();
                self.gfx
                    .draw_rectangle(Rectangle::new_with_style(
                        Point::new(x0, y),
                        Point::new(filled, y + 5),
                        DrawStyle::new(PixelColor::Light, PixelColor::Light, 1),
                    ))
                    .ok();
                self.arrows_at(40, n);
                self.band(80, 14, GlyphStyle::Small, false, &format!("{} of {}", self.carousel + 1, n));
                self.action_bar("type code", false);
            }
            VaultMode::Password => {
                // the list item is "site", and its extra the username (see actions.rs)
                self.band(18, 18, GlyphStyle::Bold, false, item.name());
                self.band(40, 16, GlyphStyle::Regular, false, &item.extra);
                let used = match item.count {
                    0 => String::from("never used"),
                    1 => String::from("used once"),
                    c => format!("used {} times", c),
                };
                self.band(60, 14, GlyphStyle::Small, false, &used);
                self.arrows_at(36, n);
                self.band(80, 14, GlyphStyle::Small, false, &format!("{} of {}", self.carousel + 1, n));
                self.action_bar("type password", false);
            }
        }
        self.gfx.flush().ok();
    }

    /// Text centred in a band across the screen, light on dark (`highlight`: dark on light).
    fn band(&self, top: isize, height: isize, style: GlyphStyle, highlight: bool, s: &str) {
        let mut tv = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(Point::new(0, top), Point::new(128, top + height))),
        );
        tv.style = style;
        tv.invert = !highlight;
        tv.draw_border = false;
        tv.ellipsis = true;
        tv.margin = Point::new(2, 0);
        write!(tv, "{}", s).ok();
        self.gfx.draw_textview(&mut tv).ok();
    }

    /// Arrows at the sides, at height `y`, when there's more than one entry to go through.
    fn arrows_at(&self, y: isize, n: usize) {
        if n < 2 {
            return;
        }
        for i in 0..6 {
            let style = DrawStyle::new(PixelColor::Light, PixelColor::Light, 1);
            self.gfx.draw_line(Line::new_with_style(Point::new(3 + i, y - i), Point::new(3 + i, y + i), style)).ok();
            self.gfx
                .draw_line(Line::new_with_style(Point::new(124 - i, y - i), Point::new(124 - i, y + i), style))
                .ok();
        }
    }

    /// The bottom line: what the centre does, boxed, as the launcher's screens show it.
    fn action_bar(&self, action: &str, _arrows: bool) {
        let mut tv = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(Point::new(12, 116), Point::new(116, 128))),
        );
        tv.style = GlyphStyle::Small;
        tv.invert = false;
        tv.draw_border = false;
        tv.ellipsis = true;
        tv.margin = Point::new(3, 0);
        write!(tv, "{}", action).ok();
        self.gfx.draw_textview(&mut tv).ok();
    }

    /// Returns `true` if in longpress state. Only call this once per key hit input.
    pub(crate) fn manage_longpress(&mut self) -> bool {
        let now = self.tt.elapsed_ms();
        if now - self.last_key_time > KEYUP_DELAY_MS {
            self.start_hold_time = now;
        }
        self.last_key_time = now;
        now - self.start_hold_time > FAST_SCROLL_DELAY_MS
    }

    /// Left (`Up`) and right (`Down`) go through the entries, round and round; `Autotype` types
    /// the code or the password on screen into the computer.
    pub(crate) fn nav(&mut self, dir: NavDir) {
        let mode_at_entry = (*self.mode.lock().unwrap()).clone();
        let n = self.len();
        match dir {
            NavDir::Up if n > 0 => self.carousel = (self.carousel + n - 1) % n,
            NavDir::Down if n > 0 => self.carousel = (self.carousel + 1) % n,
            NavDir::Autotype => match mode_at_entry {
                VaultMode::Password => {
                    if let Some(item) = self.get_selected_item() {
                        if let Err(e) = self.handle_autotype(item.guid, false) {
                            log::warn!("couldn't type the password: {}", e);
                        }
                    }
                }
                VaultMode::Totp => {
                    if let Some(code) = self.update_selected_totp_code() {
                        // ignore USB errors while sending code
                        self.usb_dev.send_str(&code).ok();
                    }
                }
            },
            _ => {}
        }
        self.totp_code = None;
    }

    /// Type the username of the login on screen into the computer.
    pub(crate) fn type_username(&mut self) {
        if let Some(item) = self.get_selected_item() {
            if let Err(e) = self.handle_autotype(item.guid, true) {
                log::warn!("couldn't type the username: {}", e);
            }
        }
    }

    pub(crate) fn filter(&mut self, criteria: &String) {
        self.item_lists.lock().unwrap().filter(self.mode.lock().unwrap().clone(), criteria);
    }

    pub(crate) fn handle_autotype(&mut self, guid: String, type_username: bool) -> Result<(), String> {
        // we re-fetch the entry for autotype, because the PDDB could have unmounted a basis.
        let atime = utc_now().timestamp() as u64;
        let pddb_binding = self.pddb.borrow();

        let mut record = pddb_binding
            .get(vault2::VAULT_PASSWORD_DICT, &guid, None, false, false, None, Some(vault2::basis_change))
            .map_err(|e| format!("couldn't access key {}: {:?}", guid, e))?;
        let mut data = Vec::<u8>::new();
        record.read_to_end(&mut data).map_err(|_| format!("Couldn't access key {}", guid))?;
        let mut pw = crate::storage::PasswordRecord::try_from(data)
            .map_err(|_| format!("Couldn't deserialize {}", guid))?;
        let to_type = if type_username { &pw.username } else { &pw.password };
        self.usb_dev.send_str(to_type).ok(); // ignore USB errors
        pw.count += 1;
        pw.atime = atime;

        // this get determines which basis the key is in
        let app_data = pddb_binding
            .get(vault2::VAULT_PASSWORD_DICT, &guid, None, true, true, Some(256), Some(vault2::basis_change))
            .map_err(|e| format!("error updating key atime: {:?}", e))?;
        let basis = app_data.attributes().map_err(|_| "couldn't get attributes")?.basis;

        // delete the old key
        pddb_binding
            .delete_key(vault2::VAULT_PASSWORD_DICT, &guid, Some(&basis))
            .map_err(|_| "Couldn't delete previous pw entry")?;

        // write the new key in
        let mut record = pddb_binding
            .get(
                vault2::VAULT_PASSWORD_DICT,
                &guid,
                Some(&basis),
                false,
                true,
                Some(vault2::VAULT_ALLOC_HINT),
                Some(vault2::basis_change),
            )
            .map_err(|e| format!("couldn't update key {}: {:?}", guid, e))?;
        let ser: Vec<u8> = crate::storage::PasswordRecord::into(pw);
        record.write(&ser).map_err(|e| format!("couldn't update key {}: {:?}", guid, e))?;

        self.pddb.borrow().sync().ok();
        Ok(())
    }
}
