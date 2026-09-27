//! Runs a bundle on this computer as maki would: the same host code (maki-wasm), with maki's
//! bar above the app, the screen in the terminal or saved as PNG, and key presses from the
//! keyboard or a script.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use maki_bundle::Manifest;
use maki_wasm::{Canvas, Color, Event, Platform, Style, TOP, WIDTH};

/// maki's screen, 128 pixels square, true for light.
pub type Screen = [[bool; WIDTH]; WIDTH];

/// What's shown above an app: its name, the sideloaded mark, the clock and a rule.
pub fn bar(name: &str, sideloaded: bool, clock: &str) -> Canvas {
    let mut c = Canvas::default();
    let mut x = 2;
    if sideloaded {
        // a light square with a dark "!": the mark sideloaded apps always carry
        c.rect(1, 3, 9, 10, Color::Light, true);
        c.rect(5, 5, 1, 4, Color::Dark, true);
        c.rect(5, 10, 1, 1, Color::Dark, true);
        x = 13;
    }
    // the name, cut to leave room for the clock
    let room = WIDTH as i32 - 40 - x;
    let mut shown = String::new();
    for ch in name.chars() {
        let trial = format!("{shown}{ch}");
        if Canvas::text_width(&trial, Style::Bold) > room {
            shown.push('…');
            break;
        }
        shown = trial;
    }
    c.text(x, 0, &shown, Style::Bold, Color::Light);
    let w = Canvas::text_width(clock, Style::Small);
    c.text(WIDTH as i32 - 40 + (40 - w) / 2, 2, clock, Style::Small, Color::Light);
    c.line(0, 16, WIDTH as i32 - 1, 16, Color::Light);
    c
}

pub fn compose(bar: &Canvas, app: &Canvas) -> Screen {
    let mut s = [[false; WIDTH]; WIDTH];
    for (y, row) in s.iter_mut().enumerate() {
        for (x, px) in row.iter_mut().enumerate() {
            *px = if y < TOP { bar.get(x as i32, y as i32) } else { app.get(x as i32, (y - TOP) as i32) };
        }
    }
    s
}

pub fn save_png(screen: &Screen, path: &std::path::Path, scale: usize) -> Result<(), String> {
    let side = WIDTH * scale;
    let mut data = vec![0u8; side * side];
    for y in 0..side {
        for x in 0..side {
            data[y * side + x] = if screen[y / scale][x / scale] { 255 } else { 0 };
        }
    }
    let file = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), side as u32, side as u32);
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
    writer.write_image_data(&data).map_err(|e| e.to_string())
}

fn clock() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{:02}:{:02}", secs / 3600 % 24, secs / 60 % 60)
}

/// One scripted step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    Event(Event),
    /// Opens the menu (left and right together) and picks this: an app item, App info (just
    /// after the app's items) or Exit (after that).
    Menu(u32),
}

/// `left,right*3,centre,menu:0,timeout,exit`
pub fn parse_presses(s: &str) -> Result<Vec<Press>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, times) = match part.split_once('*') {
            Some((n, t)) => (n, t.parse::<usize>().map_err(|_| format!("bad count in {part}"))?),
            None => (part, 1),
        };
        let press = match name {
            "left" | "l" => Press::Event(Event::Left),
            "right" | "r" => Press::Event(Event::Right),
            "centre" | "center" | "c" => Press::Event(Event::Centre),
            "timeout" | "t" => Press::Event(Event::Timeout),
            "exit" => Press::Event(Event::Exit),
            m if m.starts_with("menu:") => {
                Press::Menu(m[5..].parse().map_err(|_| format!("bad menu item in {part}"))?)
            }
            other => return Err(format!("no press \"{other}\": left, right, centre, timeout, menu:N or exit")),
        };
        out.extend(std::iter::repeat_n(press, times));
    }
    Ok(out)
}

pub struct Options {
    pub presses: Option<Vec<Press>>,
    /// Save the last frame here.
    pub shot: Option<PathBuf>,
    /// Save every frame here, numbered.
    pub frames: Option<PathBuf>,
    pub scale: usize,
    pub verified: bool,
    pub storage: Option<PathBuf>,
    pub sideloaded: bool,
}

struct Shared {
    manifest: Manifest,
    options: Options,
    script: VecDeque<Press>,
    /// Events already decided, delivered before anything else.
    queued: VecDeque<Event>,
    menu: Vec<String>,
    last: Canvas,
    frame: usize,
    storage: BTreeMap<String, Vec<u8>>,
    started: Instant,
    logs: Vec<String>,
    interactive: bool,
}

pub struct Sim(Rc<RefCell<Shared>>);

fn load_storage(path: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let unhex = |h: &str| (0..h.len() / 2).filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()).collect::<Vec<u8>>();
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(k, v)| (String::from_utf8_lossy(&unhex(k)).into_owned(), unhex(v)))
        .collect()
}

fn save_storage(path: &std::path::Path, storage: &BTreeMap<String, Vec<u8>>) {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let text: String = storage.iter().map(|(k, v)| format!("{} {}\n", hex(k.as_bytes()), hex(v))).collect();
    std::fs::write(path, text).ok();
}

impl Shared {
    fn screen(&self) -> Screen { compose(&bar(&self.manifest.name, self.options.sideloaded, &clock()), &self.last) }

    fn draw_terminal(&self, footer: &str) {
        let s = self.screen();
        let mut out = String::from("\x1b[H");
        for y in (0..WIDTH).step_by(2) {
            for x in 0..WIDTH {
                out.push(match (s[y][x], s[y + 1][x]) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                });
            }
            out.push_str("\x1b[K\r\n");
        }
        out.push_str(&format!("\x1b[K{footer}\r\n"));
        let last_log = self.logs.last().map(String::as_str).unwrap_or("");
        out.push_str(&format!("\x1b[Klog: {last_log}\r\n"));
        let mut stdout = std::io::stdout();
        stdout.write_all(out.as_bytes()).ok();
        stdout.flush().ok();
    }
}

const HELP: &str = "←/→ move · enter centre · m menu (left+right) · q exit";

impl Sim {
    pub fn new(manifest: Manifest, options: Options) -> Sim {
        let storage = options.storage.as_deref().map(load_storage).unwrap_or_default();
        let interactive = options.presses.is_none();
        let script = options.presses.clone().unwrap_or_default().into();
        Sim(Rc::new(RefCell::new(Shared {
            manifest,
            options,
            script,
            queued: VecDeque::new(),
            menu: Vec::new(),
            last: Canvas::default(),
            frame: 0,
            storage,
            started: Instant::now(),
            logs: Vec::new(),
            interactive,
        })))
    }

    pub fn handle(&self) -> Sim { Sim(self.0.clone()) }

    pub fn finish(&self) -> Result<(), String> {
        let s = self.0.borrow();
        if let Some(path) = &s.options.shot {
            save_png(&s.screen(), path, s.options.scale)?;
        }
        if let Some(path) = &s.options.storage {
            save_storage(path, &s.storage);
        }
        Ok(())
    }

    /// The menu, as maki's launcher shows it: the app's items, App info, Exit.
    fn menu_event(s: &mut Shared, pick: u32) -> Event {
        let items = s.menu.len() as u32;
        if pick < items {
            s.queued.push_back(Event::Shown);
            Event::Menu(pick)
        } else if pick == items {
            let m = &s.manifest;
            let info = format!(
                "App info: {} {} ({}), {} KiB storage, backup {}",
                m.name,
                m.label,
                m.id,
                m.storage_kib,
                if m.backup { "on" } else { "off" }
            );
            eprintln!("{info}");
            s.logs.push(info);
            Event::Shown
        } else {
            Event::Exit
        }
    }

    fn interactive_wait(s: &mut Shared, timeout: Option<Duration>) -> Event {
        use crossterm::event::{poll, read, Event as Term, KeyCode, KeyEventKind};
        s.draw_terminal(HELP);
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let left = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            if left == Some(Duration::ZERO) {
                return Event::Timeout;
            }
            if !poll(left.unwrap_or(Duration::from_secs(3600))).unwrap_or(false) {
                continue;
            }
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Left | KeyCode::Char('a') | KeyCode::Char('h') => return Event::Left,
                KeyCode::Right | KeyCode::Char('d') | KeyCode::Char('l') => return Event::Right,
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Down => return Event::Centre,
                KeyCode::Char('q') | KeyCode::Esc => return Event::Exit,
                KeyCode::Char('m') | KeyCode::Up | KeyCode::Tab => {
                    let pick = Self::interactive_menu(s);
                    // the app was hidden while the menu showed
                    let event = Self::menu_event(s, pick);
                    s.queued.push_back(event);
                    return Event::Hidden;
                }
                _ => {}
            }
        }
    }

    fn interactive_menu(s: &mut Shared) -> u32 {
        use crossterm::event::{read, Event as Term, KeyCode, KeyEventKind};
        let mut items = s.menu.clone();
        items.push("App info".into());
        items.push("Exit".into());
        let mut at = 0usize;
        loop {
            let line: Vec<String> =
                items.iter().enumerate().map(|(i, it)| if i == at { format!("[{it}]") } else { it.clone() }).collect();
            s.draw_terminal(&format!("menu: {}", line.join("  ")));
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Left | KeyCode::Char('a') | KeyCode::Char('h') => at = at.saturating_sub(1),
                KeyCode::Right | KeyCode::Char('d') | KeyCode::Char('l') => at = (at + 1).min(items.len() - 1),
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Down => return at as u32,
                KeyCode::Char('q') | KeyCode::Esc => return (items.len() - 1) as u32,
                _ => {}
            }
        }
    }
}

impl Platform for Sim {
    fn wait(&mut self, timeout: Option<Duration>) -> Event {
        let mut s = self.0.borrow_mut();
        if let Some(e) = s.queued.pop_front() {
            return e;
        }
        if s.interactive {
            return Self::interactive_wait(&mut s, timeout);
        }
        match s.script.pop_front() {
            Some(Press::Event(e)) => e,
            Some(Press::Menu(pick)) => {
                let event = Self::menu_event(&mut s, pick);
                s.queued.push_back(event);
                Event::Hidden
            }
            None => Event::Exit,
        }
    }

    fn present(&mut self, canvas: &Canvas) {
        let mut s = self.0.borrow_mut();
        s.last = canvas.clone();
        s.frame += 1;
        if let Some(dir) = s.options.frames.clone() {
            let path = dir.join(format!("frame-{:04}.png", s.frame));
            if let Err(e) = save_png(&s.screen(), &path, s.options.scale) {
                eprintln!("{e}");
            }
        }
        if s.interactive {
            s.draw_terminal(HELP);
        }
    }

    fn set_menu(&mut self, items: &[String]) { self.0.borrow_mut().menu = items.to_vec() }

    fn millis(&self) -> u64 { self.0.borrow().started.elapsed().as_millis() as u64 }

    fn unix_time(&self) -> Option<(u64, bool)> {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some((t, self.0.borrow().options.verified))
    }

    fn random(&mut self, buf: &mut [u8]) { getrandom::fill(buf).expect("no randomness") }

    fn log(&mut self, line: &str) {
        let mut s = self.0.borrow_mut();
        if !s.interactive {
            eprintln!("app: {line}");
        }
        s.logs.push(line.to_string());
    }

    fn storage_get(&mut self, key: &str) -> Option<Vec<u8>> { self.0.borrow().storage.get(key).cloned() }

    fn storage_set(&mut self, key: &str, value: &[u8]) -> Result<(), ()> {
        self.0.borrow_mut().storage.insert(key.into(), value.into());
        Ok(())
    }

    fn storage_delete(&mut self, key: &str) -> bool { self.0.borrow_mut().storage.remove(key).is_some() }

    fn storage_keys(&mut self) -> Vec<String> { self.0.borrow().storage.keys().cloned().collect() }
}
