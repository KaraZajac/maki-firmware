//! Initiative, for the table beside Dice: who's in the fight, in initiative order, and their hit
//! points. The centre passes the turn to whoever's next, counting the rounds (a monster at 0 is
//! skipped; a player at 0 still gets a turn, for death saves). Left and right pick someone, and the
//! jog dial on maki's side takes a hit point off them or gives one back, a point a click.
//!
//! The menu adds someone: a class, for a player, or a monster, their hit points, and their
//! initiative, a d20 rolled to start with (the dial changes what's picked, left and right move, the
//! centre adds them). It edits or removes whoever's picked, rolls initiative for everyone (a player
//! who rolled their own puts it in with Edit), starts a new fight (the monsters go, the players stay
//! as they are) or gives everyone a long rest (hit points back to full). The table is kept, so
//! leaving the app doesn't end the fight.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// Who can be at the table: a class, for a player, then the monsters.
const NAMES: [&str; 24] = [
    "Fighter",
    "Wizard",
    "Rogue",
    "Cleric",
    "Ranger",
    "Paladin",
    "Barbarian",
    "Bard",
    "Druid",
    "Monk",
    "Sorcerer",
    "Warlock",
    "Goblin",
    "Kobold",
    "Orc",
    "Skeleton",
    "Zombie",
    "Wolf",
    "Bandit",
    "Cultist",
    "Gnoll",
    "Ogre",
    "Troll",
    "Dragon",
];
/// Where the monsters start in `NAMES`.
const MONSTERS: u8 = 12;
/// The most at the table at once.
const MOST: usize = 16;
/// A combatant as it's kept: name, which of that name, hit points and their most, initiative.
const KEPT: usize = 7;

/// The table's rows: how many show at once, where they start, and how high each is.
const ROWS: usize = 5;
const ROWS_TOP: i32 = 14;
const ROW: i32 = 16;
/// The line above the foot.
const FOOT: i32 = 97;
/// How long after the dial stops that hit points are kept, in milliseconds.
const SETTLE: u32 = 1500;

/// The form's stops: the name, the hit points' three digits, initiative's two, and cancel.
const STOP_HP: usize = 1;
const STOP_INIT: usize = 4;
const STOP_CANCEL: usize = 6;

const MENU: [&str; 6] = ["Add", "Edit", "Remove", "Roll initiative", "New fight", "Long rest"];

#[derive(Clone, Copy, PartialEq, Eq)]
struct Combatant {
    /// Its place in `NAMES`, and which of that name it is: Goblin 2 is the second.
    name: u8,
    n: u8,
    hp: u16,
    max: u16,
    init: u8,
}

impl Combatant {
    fn monster(&self) -> bool { self.name >= MONSTERS }

    /// A monster at 0 is dead: its turns are skipped.
    fn out(&self) -> bool { self.monster() && self.hp == 0 }
}

/// What someone's called: "Goblin", and "Goblin 2" for the second.
fn label(name: u8, n: u8) -> Buf<16> {
    let mut b = Buf::new();
    let _ = write!(b, "{}", NAMES[name as usize]);
    if n > 1 {
        let _ = write!(b, " {n}");
    }
    b
}

struct Table {
    all: [Combatant; MOST],
    count: usize,
    /// Whose turn it is, and the round. Until a turn has passed, the turn is the top's, whoever
    /// that is as the order changes.
    turn: usize,
    round: u16,
    passed: bool,
}

impl Table {
    fn load() -> Table {
        let mut t = Table {
            all: [Combatant { name: 0, n: 1, hp: 1, max: 1, init: 0 }; MOST],
            count: 0,
            turn: 0,
            round: 1,
            passed: false,
        };
        let mut b = [0u8; 5 + MOST * KEPT];
        let Some(len) = storage::get("table", &mut b) else { return t };
        if !(5..=b.len()).contains(&len) {
            return t;
        }
        for c in b[5..len].chunks_exact(KEPT).take(b[4] as usize) {
            let (hp, max) = (u16::from_le_bytes([c[2], c[3]]), u16::from_le_bytes([c[4], c[5]]));
            if (c[0] as usize) < NAMES.len() && (1..=999).contains(&max) && hp <= max {
                t.all[t.count] = Combatant { name: c[0], n: c[1].max(1), hp, max, init: c[6].min(99) };
                t.count += 1;
            }
        }
        t.round = u16::from_le_bytes([b[0], b[1]]).max(1);
        t.turn = (b[2] as usize).min(t.count.saturating_sub(1));
        t.passed = b[3] != 0;
        t
    }

    fn save(&self) {
        let mut b = [0u8; 5 + MOST * KEPT];
        b[..2].copy_from_slice(&self.round.to_le_bytes());
        b[2] = self.turn as u8;
        b[3] = self.passed as u8;
        b[4] = self.count as u8;
        for (c, out) in self.list().iter().zip(b[5..].chunks_exact_mut(KEPT)) {
            out[0] = c.name;
            out[1] = c.n;
            out[2..4].copy_from_slice(&c.hp.to_le_bytes());
            out[4..6].copy_from_slice(&c.max.to_le_bytes());
            out[6] = c.init;
        }
        let _ = storage::set("table", &b[..5 + self.count * KEPT]);
    }

    fn list(&self) -> &[Combatant] { &self.all[..self.count] }

    fn find(&self, name: u8, n: u8) -> Option<usize> {
        self.list().iter().position(|c| c.name == name && c.n == n)
    }

    /// The first number no one else of that name at the table has (the one at `except` aside).
    fn free_n(&self, name: u8, except: Option<usize>) -> u8 {
        (1..=MOST as u8)
            .find(|&n| {
                !self.list().iter().enumerate().any(|(i, c)| Some(i) != except && c.name == name && c.n == n)
            })
            .unwrap_or(1)
    }

    /// In initiative order again, highest first (and among equals, who was there first): the turn
    /// stays with whoever has it, once one has passed.
    fn sort(&mut self) {
        let had = self.list().get(self.turn).map(|c| (c.name, c.n));
        let all = &mut self.all[..self.count];
        for i in 1..all.len() {
            let mut j = i;
            while j > 0 && all[j - 1].init < all[j].init {
                all.swap(j - 1, j);
                j -= 1;
            }
        }
        self.turn = match had {
            Some((name, n)) if self.passed => self.find(name, n).unwrap_or(0),
            _ => 0,
        };
    }

    /// Someone new, in initiative order: where they went.
    fn add(&mut self, c: Combatant) -> Option<usize> {
        if self.count == MOST {
            return None;
        }
        self.all[self.count] = c;
        self.count += 1;
        self.sort();
        self.find(c.name, c.n)
    }

    fn remove(&mut self, at: usize) {
        if at >= self.count {
            return;
        }
        self.all.copy_within(at + 1..self.count, at);
        self.count -= 1;
        if at < self.turn {
            self.turn -= 1;
        }
        if self.turn >= self.count {
            self.turn = 0;
        }
    }

    /// The turn to whoever's next, past any dead monsters, and a new round after the last.
    fn pass(&mut self) {
        for _ in 0..self.count {
            self.turn += 1;
            if self.turn == self.count {
                self.turn = 0;
                self.round = self.round.saturating_add(1);
            }
            if !self.all[self.turn].out() {
                break;
            }
        }
        self.passed = true;
    }

    /// The fight from the top of round 1.
    fn restart(&mut self) {
        self.round = 1;
        self.passed = false;
        self.sort();
    }
}

/// A number with its digit at `place` (1, 10, 100) turned one up or down, round from 9 to 0.
fn spin(value: u16, place: u16, up: bool) -> u16 {
    let d = value / place % 10;
    let to = if up { (d + 1) % 10 } else { (d + 9) % 10 };
    value - d * place + to * place
}

/// `text` cut to fit `room` pixels, with ".." where it's cut.
fn fit(text: &str, style: Style, room: i32) -> Buf<20> {
    let mut b = Buf::new();
    let mut end = text.len();
    loop {
        b.clear();
        let _ = b.write_str(&text[..end]);
        if end < text.len() {
            let _ = b.write_str("..");
        }
        if end == 0 || screen::text_width(b.as_str(), style) <= room {
            return b;
        }
        end = text[..end].char_indices().last().map_or(0, |(i, _)| i);
    }
}

/// Adding someone (`editing` None) or changing someone: what the form holds, and the stop picked.
struct Form {
    editing: Option<usize>,
    name: u8,
    hp: u16,
    init: u8,
    stop: usize,
}

struct App {
    table: Table,
    form: Option<Form>,
    /// Who's picked, and the first row showing.
    picked: usize,
    first: usize,
    /// Hit points the dial has taken off the one picked (below 0) or given back, since picking
    /// them, and whether they're kept yet.
    change: i32,
    unsaved: bool,
    /// What the foot says, for a while.
    note: Buf<32>,
}

impl App {
    fn pick(&mut self, at: usize) {
        self.picked = at.min(self.table.count.saturating_sub(1));
        self.first = self.first.min(self.picked).min(self.table.count.saturating_sub(ROWS));
        if self.picked >= self.first + ROWS {
            self.first = self.picked + 1 - ROWS;
        }
        self.change = 0;
    }

    fn say(&mut self, what: &str) {
        self.note.clear();
        let _ = self.note.write_str(what);
    }

    /// The dial: a hit point off the one picked, or one back, no lower than 0 or higher than their
    /// most.
    fn dial(&mut self, up: bool) {
        let Some(c) = self.table.all[..self.table.count].get_mut(self.picked) else { return };
        let was = c.hp;
        c.hp = if up { (c.hp + 1).min(c.max) } else { c.hp.saturating_sub(1) };
        if c.hp != was {
            self.change += if up { 1 } else { -1 };
            self.unsaved = true;
        }
    }

    /// The table's event: false to leave.
    fn table_event(&mut self, event: Event) -> bool {
        // what the dial did is kept once it stops, or anything else happens
        if self.unsaved && !matches!(event, Event::Up | Event::Down) {
            self.table.save();
            self.unsaved = false;
        }
        if !matches!(event, Event::Timeout | Event::Hidden | Event::Shown) {
            self.note.clear();
        }
        let count = self.table.count;
        match event {
            Event::Left => self.pick(self.picked.saturating_sub(1)),
            Event::Right => self.pick(self.picked + 1),
            Event::Up | Event::Down => self.dial(event == Event::Up),
            Event::Centre if count > 0 => {
                self.table.pass();
                self.pick(self.table.turn);
                self.table.save();
            }
            Event::Menu(0) if count == MOST => self.say("the table's full"),
            Event::Menu(0) => {
                let mut last = [0u8; 3];
                let (name, hp) = match storage::get("last", &mut last) {
                    Some(3) if (last[0] as usize) < NAMES.len() => {
                        (last[0], u16::from_le_bytes([last[1], last[2]]))
                    }
                    _ => (0, 10),
                };
                let init = 1 + random_below(20) as u8;
                self.form = Some(Form { editing: None, name, hp: hp.clamp(1, 999), init, stop: 0 });
            }
            Event::Menu(1..) if count == 0 => self.say("add someone first"),
            Event::Menu(1) => {
                let c = self.table.all[self.picked];
                self.form =
                    Some(Form { editing: Some(self.picked), name: c.name, hp: c.max, init: c.init, stop: 0 });
            }
            Event::Menu(2) => {
                let c = self.table.all[self.picked];
                self.table.remove(self.picked);
                self.pick(self.picked);
                self.note.clear();
                let _ = write!(self.note, "{} is out", label(c.name, c.n).as_str());
                self.table.save();
            }
            Event::Menu(3) => {
                for c in self.table.all[..count].iter_mut() {
                    c.init = 1 + random_below(20) as u8;
                }
                self.table.restart();
                self.pick(0);
                self.say("rolled: round 1");
                self.table.save();
            }
            Event::Menu(4) => {
                let mut kept = 0;
                for i in 0..count {
                    if !self.table.all[i].monster() {
                        self.table.all[kept] = self.table.all[i];
                        kept += 1;
                    }
                }
                self.table.count = kept;
                self.table.restart();
                self.pick(0);
                self.say("a new fight: round 1");
                self.table.save();
            }
            Event::Menu(5) => {
                for c in self.table.all[..count].iter_mut() {
                    c.hp = c.max;
                }
                self.change = 0;
                self.say("everyone's rested");
                self.table.save();
            }
            Event::Exit => {
                self.table.save();
                return false;
            }
            _ => {}
        }
        true
    }

    /// The form's event.
    fn form_event(&mut self, event: Event) {
        let Some(f) = &mut self.form else { return };
        match event {
            Event::Left => f.stop = f.stop.saturating_sub(1),
            Event::Right => f.stop = (f.stop + 1).min(STOP_CANCEL),
            Event::Up | Event::Down => {
                let up = event == Event::Up;
                let names = NAMES.len() as u8;
                match f.stop {
                    0 => f.name = if up { (f.name + 1) % names } else { (f.name + names - 1) % names },
                    STOP_HP..STOP_INIT => f.hp = spin(f.hp, 10u16.pow((STOP_INIT - 1 - f.stop) as u32), up),
                    STOP_INIT..STOP_CANCEL => {
                        f.init = spin(f.init as u16, 10u16.pow((STOP_CANCEL - 1 - f.stop) as u32), up) as u8
                    }
                    _ => {}
                }
            }
            Event::Centre if f.stop == STOP_CANCEL => self.form = None,
            Event::Centre => {
                let (name, hp, init) = (f.name, f.hp.max(1), f.init);
                let at = match f.editing {
                    Some(at) => {
                        let n = if self.table.all[at].name == name {
                            self.table.all[at].n
                        } else {
                            self.table.free_n(name, Some(at))
                        };
                        let c = &mut self.table.all[at];
                        c.hp = if c.hp == c.max { hp } else { c.hp.min(hp) };
                        *c = Combatant { name, n, hp: c.hp, max: hp, init };
                        self.table.sort();
                        self.table.find(name, n)
                    }
                    None => {
                        let n = self.table.free_n(name, None);
                        let mut last = [name, 0, 0];
                        last[1..].copy_from_slice(&hp.to_le_bytes());
                        let _ = storage::set("last", &last);
                        self.table.add(Combatant { name, n, hp, max: hp, init })
                    }
                };
                self.form = None;
                self.pick(at.unwrap_or(0));
                self.table.save();
                self.unsaved = false;
            }
            _ => {}
        }
    }

    fn draw(&self) {
        screen::clear(Color::Dark);
        match &self.form {
            Some(f) => self.draw_form(f),
            None => self.draw_table(),
        }
        screen::present();
    }

    fn draw_table(&self) {
        let t = &self.table;
        if t.count == 0 {
            screen::text_centred(24, "No one yet", Style::Bold, Color::Light);
            screen::text_centred(48, "menu: Add, for each", Style::Small, Color::Light);
            screen::text_centred(60, "player and monster", Style::Small, Color::Light);
        } else {
            let mut round = Buf::<16>::new();
            let _ = write!(round, "Round {}", t.round);
            screen::text(2, 0, round.as_str(), Style::Small, Color::Light);
            let hint = "dial: hit points";
            let w = screen::text_width(hint, Style::Small);
            screen::text(WIDTH - 2 - w, 0, hint, Style::Small, Color::Light);
            screen::line(0, ROWS_TOP - 2, WIDTH - 1, ROWS_TOP - 2, Color::Light);
            for (row, (i, c)) in t.list().iter().enumerate().skip(self.first).take(ROWS).enumerate() {
                draw_row(ROWS_TOP + row as i32 * ROW, c, i == t.turn, i == self.picked);
            }
        }
        screen::line(0, FOOT, WIDTH - 1, FOOT, Color::Light);
        let mut foot = Buf::<40>::new();
        if self.change != 0 {
            let c = &t.all[self.picked];
            let (n, what) = if self.change < 0 { (-self.change, "damage") } else { (self.change, "healing") };
            let _ = write!(foot, "{}: {n} {what}", label(c.name, c.n).as_str());
        } else if !self.note.is_empty() {
            let _ = foot.write_str(self.note.as_str());
        } else if t.count > 0 {
            let _ = foot.write_str("centre: next turn");
        }
        screen::text_centred(FOOT + 2, foot.as_str(), Style::Small, Color::Light);
    }

    fn draw_form(&self, f: &Form) {
        let adding = f.editing.is_none();
        screen::text(2, 0, if adding { "Add" } else { "Edit" }, Style::Bold, Color::Light);
        let hint = "dial: change";
        let w = screen::text_width(hint, Style::Small);
        screen::text(WIDTH - 2 - w, 2, hint, Style::Small, Color::Light);
        // the name they'll have
        let n = match f.editing {
            Some(at) if self.table.all[at].name == f.name => self.table.all[at].n,
            at => self.table.free_n(f.name, at),
        };
        let name = label(f.name, n);
        let on = f.stop == 0;
        if on {
            screen::fill_rect(8, 20, WIDTH - 16, 17, Color::Light);
        } else {
            screen::rect(8, 20, WIDTH - 16, 17, Color::Light);
        }
        let colour = if on { Color::Dark } else { Color::Light };
        screen::text_centred(21, name.as_str(), Style::Regular, colour);
        screen::text(8, 46, "Hit points", Style::Small, Color::Light);
        digits(WIDTH - 8 - 3 * 14 + 2, 43, f.hp, 3, STOP_HP, f.stop);
        screen::text(8, 66, "Initiative", Style::Small, Color::Light);
        digits(WIDTH - 8 - 2 * 14 + 2, 63, f.init as u16, 2, STOP_INIT, f.stop);
        let on = f.stop == STOP_CANCEL;
        let w = screen::text_width("cancel", Style::Small) + 10;
        let x = WIDTH - 8 - w;
        if on {
            screen::fill_rect(x, 82, w, 13, Color::Light);
        } else {
            screen::rect(x, 82, w, 13, Color::Light);
        }
        screen::text(x + 5, 82, "cancel", Style::Small, if on { Color::Dark } else { Color::Light });
        screen::line(0, FOOT, WIDTH - 1, FOOT, Color::Light);
        let foot = match (on, adding) {
            (true, _) => "centre: cancel",
            (false, true) => "centre: add",
            (false, false) => "centre: done",
        };
        screen::text_centred(FOOT + 2, foot, Style::Small, Color::Light);
    }
}

/// A row of the table: whose turn it is (a pointer), initiative, name (struck through at 0) and hit
/// points; the one picked light.
fn draw_row(y: i32, c: &Combatant, turn: bool, picked: bool) {
    let colour = if picked { Color::Dark } else { Color::Light };
    if picked {
        screen::fill_rect(0, y, WIDTH, ROW, Color::Light);
    }
    if turn {
        for i in 0..4 {
            screen::line(1 + i, y + 4 + i, 1 + i, y + 11 - i, colour);
        }
    }
    let mut init = Buf::<4>::new();
    let _ = write!(init, "{}", c.init);
    screen::text(7, y + 2, init.as_str(), Style::Small, colour);
    let mut hp = Buf::<8>::new();
    let _ = write!(hp, "{}/{}", c.hp, c.max);
    let w = screen::text_width(hp.as_str(), Style::Small);
    screen::text(WIDTH - 2 - w, y + 2, hp.as_str(), Style::Small, colour);
    let name = label(c.name, c.n);
    let name = fit(name.as_str(), Style::Regular, WIDTH - 2 - w - 4 - 21);
    let nw = screen::text(21, y, name.as_str(), Style::Regular, colour);
    if c.hp == 0 {
        screen::line(21, y + 8, 21 + nw, y + 8, colour);
    }
}

/// A number as digit wheels, 14 pixels apart, the one at `stop` picked.
fn digits(x: i32, y: i32, value: u16, places: u32, first: usize, stop: usize) {
    for k in 0..places {
        let d = value / 10u16.pow(places - 1 - k) % 10;
        let cx = x + k as i32 * 14;
        let on = stop == first + k as usize;
        if on {
            screen::fill_rect(cx, y, 12, 17, Color::Light);
        } else {
            screen::rect(cx, y, 12, 17, Color::Light);
        }
        let mut b = Buf::<2>::new();
        let _ = write!(b, "{d}");
        let w = screen::text_width(b.as_str(), Style::Regular);
        screen::text(
            cx + (12 - w) / 2,
            y + 1,
            b.as_str(),
            Style::Regular,
            if on { Color::Dark } else { Color::Light },
        );
    }
}

fn main() {
    let _ = menu(&MENU);
    let table = Table::load();
    let turn = table.turn;
    let mut app = App { table, form: None, picked: 0, first: 0, change: 0, unsaved: false, note: Buf::new() };
    app.pick(turn);
    loop {
        app.draw();
        let event = wait(if app.unsaved { Some(SETTLE) } else { None });
        match event {
            // the menu leaves the form for the table, and does what it says there
            Event::Menu(_) | Event::Exit if app.form.is_some() => app.form = None,
            _ if app.form.is_some() => {
                app.form_event(event);
                continue;
            }
            _ => {}
        }
        if !app.table_event(event) {
            return;
        }
    }
}

maki_app::main!(main);
