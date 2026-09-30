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
use maki_wasm::{Answer, Ask, Canvas, Color, Event, Platform, Review, Style, TOP, WIDTH};

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

fn clock(secs: u64) -> String { format!("{:02}:{:02}", secs / 3600 % 24, secs / 60 % 60) }

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

/// One scripted step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Press {
    Event(Event),
    /// Opens the menu (left and right together) and picks this: an app item, App info (just
    /// after the app's items) or Exit (after that).
    Menu(u32),
    /// The owner's answer to the app's next ask.
    Answer(Answer),
    /// A message from the computer: the app's answer is printed.
    Message(Vec<u8>),
    /// What the camera sees at the app's next scan.
    Qr(String),
    /// The accelerometer from now on, in milli-g.
    Tilt([i16; 3]),
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
            "up" | "u" => Press::Event(Event::Up),
            "down" | "d" => Press::Event(Event::Down),
            "right" | "r" => Press::Event(Event::Right),
            "centre" | "center" | "c" => Press::Event(Event::Centre),
            "timeout" | "t" => Press::Event(Event::Timeout),
            "exit" => Press::Event(Event::Exit),
            "yes" => Press::Answer(Answer::Yes),
            "no" => Press::Answer(Answer::No),
            m if m.starts_with("msg:") => Press::Message(m.as_bytes()[4..].to_vec()),
            h if h.starts_with("hex:") => {
                Press::Message(from_hex(&h[4..]).ok_or_else(|| format!("hex:BYTES in hex, not {h}"))?)
            }
            q if q.starts_with("qr:") => Press::Qr(q[3..].to_string()),
            t if t.starts_with("tilt:") => {
                Press::Tilt(parse_xyz(&t[5..]).ok_or_else(|| format!("tilt:X;Y;Z in milli-g, not {t}"))?)
            }
            m if m.starts_with("menu:") => {
                Press::Menu(m[5..].parse().map_err(|_| format!("bad menu item in {part}"))?)
            }
            other => {
                return Err(format!(
                    "no press \"{other}\": left, right, centre, up, down, timeout, menu:N, exit, yes or no for an ask, msg:TEXT or hex:BYTES for a message, qr:TEXT for a scan, tilt:X;Y;Z"
                ));
            }
        };
        out.extend(std::iter::repeat_n(press, times));
    }
    Ok(out)
}

/// "X;Y;Z", milli-g (semicolons: the presses are comma-separated).
/// Bytes from hex, two digits each.
fn from_hex(h: &str) -> Option<Vec<u8>> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
}

pub fn parse_xyz(s: &str) -> Option<[i16; 3]> {
    let v: Vec<i16> = s.split([';', ',']).map(|p| p.trim().parse().ok()).collect::<Option<_>>()?;
    v.try_into().ok()
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
    /// The key the bundle is signed with: apps' keys depend on it, as on maki.
    pub developer: [u8; 32],
    /// The accelerometer, milli-g: face up and still unless `--motion` says.
    pub motion: [i16; 3],
}

/// The BIP39 test phrase, whose seed the simulator derives apps' keys from. Never for anything
/// real: everyone knows it.
const TEST_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

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
    /// The time when it started, in seconds since 1970.
    started_unix: u64,
    /// Scripted runs keep time of their own, so they come out the same each time: the time
    /// that `timeout` presses let pass, each the whole of the wait it ends.
    slept: Duration,
    logs: Vec<String>,
    interactive: bool,
    /// the test phrase's seed, worked out the first time an app asks for a key
    seed: Option<[u8; 64]>,
    /// the message the app was given and hasn't answered
    message: Option<Vec<u8>>,
    /// what the camera sees at the next scan
    qr: Option<String>,
}

pub struct Sim(Rc<RefCell<Shared>>);

fn load_storage(path: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let unhex = |h: &str| {
        (0..h.len() / 2)
            .filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok())
            .collect::<Vec<u8>>()
    };
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
    fn screen(&self) -> Screen {
        compose(&bar(&self.manifest.name, self.options.sideloaded, &clock(self.unix())), &self.last)
    }

    /// How long it has run: on the wall clock in the terminal, the script's own time otherwise.
    fn elapsed(&self) -> Duration { if self.interactive { self.started.elapsed() } else { self.slept } }

    fn unix(&self) -> u64 { self.started_unix + self.elapsed().as_secs() }

    fn draw_terminal(&self, footer: &str) {
        let s = self.screen();
        let mut out = String::from("\x1b[H");
        for rows in s.chunks_exact(2) {
            for (&top, &bottom) in rows[0].iter().zip(&rows[1]) {
                out.push(match (top, bottom) {
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

const HELP: &str = "←/→ move · ↑/↓ jog dial · enter centre · m menu (left+right) · q exit";

/// Whether maki gives the app the jog dial: it says host API 8 or later.
fn knows_jog(manifest: &Manifest) -> bool { manifest.api >= maki_wasm::API_JOG }

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
            started_unix: now(),
            slept: Duration::ZERO,
            logs: Vec::new(),
            interactive,
            seed: None,
            message: None,
            qr: None,
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
        use crossterm::event::{Event as Term, KeyCode, KeyEventKind, poll, read};
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
                KeyCode::Enter | KeyCode::Char(' ') => return Event::Centre,
                // the jog dial on maki's side, for apps that know it (host API 8), as on maki
                KeyCode::Up | KeyCode::Char('w') | KeyCode::Char('k') if knows_jog(&s.manifest) => {
                    return Event::Up;
                }
                KeyCode::Down | KeyCode::Char('s') | KeyCode::Char('j') if knows_jog(&s.manifest) => {
                    return Event::Down;
                }
                KeyCode::Char('q') | KeyCode::Esc => return Event::Exit,
                KeyCode::Char('m') | KeyCode::Tab => {
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

    /// An ask in the terminal: y or n, or Esc (or the time running out) for no answer.
    fn interactive_ask(s: &mut Shared, ask: &Ask) -> Answer {
        use crossterm::event::{Event as Term, KeyCode, KeyEventKind, poll, read};
        let label = |l: &str, default: &str| if l.is_empty() { default.to_string() } else { l.to_string() };
        let prompt = format!(
            "ask: {} {} · y {} · n {} · {} s",
            ask.question,
            ask.detail,
            label(&ask.yes, "allow"),
            label(&ask.no, "deny"),
            ask.timeout_s
        );
        s.draw_terminal(&prompt);
        let deadline = Instant::now() + Duration::from_secs(ask.timeout_s as u64);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !poll(left).unwrap_or(false) {
                if Instant::now() >= deadline {
                    return Answer::NoAnswer;
                }
                continue;
            }
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Char('y') => return Answer::Yes,
                KeyCode::Char('n') => return Answer::No,
                KeyCode::Esc => return Answer::NoAnswer,
                _ => {}
            }
        }
    }

    fn interactive_review(s: &mut Shared, review: &Review) -> Answer {
        use crossterm::event::{Event as Term, KeyCode, KeyEventKind, poll, read};
        let deadline = Instant::now() + Duration::from_secs(review.timeout_s as u64);
        let mut page = 0usize;
        loop {
            let footer = match review.pages.get(page) {
                Some(p) => format!(
                    "review {}/{}: [{}] {} {} {} · right: next · left: back",
                    page + 1,
                    review.pages.len(),
                    p.heading,
                    p.value,
                    p.mono.replace('\n', " "),
                    p.prose.replace('\n', " ")
                ),
                None => format!(
                    "review: {} {} · y {} · n {} · left: back",
                    review.question,
                    review.detail,
                    if review.yes.is_empty() { "sign" } else { &review.yes },
                    if review.no.is_empty() { "reject" } else { &review.no }
                ),
            };
            s.draw_terminal(&footer);
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || !poll(left).unwrap_or(false) {
                if Instant::now() >= deadline {
                    return Answer::NoAnswer;
                }
                continue;
            }
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            let on_question = page >= review.pages.len();
            match k.code {
                KeyCode::Right | KeyCode::Enter if !on_question => page += 1,
                KeyCode::Left => page = page.saturating_sub(1),
                KeyCode::Char('y') if on_question => return Answer::Yes,
                KeyCode::Char('n') if on_question => return Answer::No,
                KeyCode::Esc => return Answer::NoAnswer,
                _ => {}
            }
        }
    }

    /// A scan in the terminal: type what the QR code says, then enter; Esc cancels.
    fn interactive_scan(s: &mut Shared) -> Option<String> {
        use crossterm::event::{Event as Term, KeyCode, KeyEventKind, read};
        let mut text = String::new();
        loop {
            s.draw_terminal(&format!("scan: type the QR code's text, enter when done, esc cancels: {text}"));
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Enter => return Some(text),
                KeyCode::Esc => return None,
                KeyCode::Backspace => {
                    text.pop();
                }
                KeyCode::Char(c) => text.push(c),
                _ => {}
            }
        }
    }

    fn interactive_menu(s: &mut Shared) -> u32 {
        use crossterm::event::{Event as Term, KeyCode, KeyEventKind, read};
        let mut items = s.menu.clone();
        items.push("App info".into());
        items.push("Exit".into());
        let mut at = 0usize;
        loop {
            let line: Vec<String> = items
                .iter()
                .enumerate()
                .map(|(i, it)| if i == at { format!("[{it}]") } else { it.clone() })
                .collect();
            s.draw_terminal(&format!("menu: {}", line.join("  ")));
            let Ok(Term::Key(k)) = read() else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Left | KeyCode::Char('a') | KeyCode::Char('h') => at = at.saturating_sub(1),
                KeyCode::Right | KeyCode::Char('d') | KeyCode::Char('l') => {
                    at = (at + 1).min(items.len() - 1)
                }
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Down => return at as u32,
                KeyCode::Char('q') | KeyCode::Esc => return (items.len() - 1) as u32,
                _ => {}
            }
        }
    }
}

impl Sim {
    /// The BIP39 test phrase's seed, which the simulator's keys come from (said once).
    fn test_seed(&self) -> [u8; 64] {
        let mut s = self.0.borrow_mut();
        if s.seed.is_none() {
            let words: Vec<&str> = TEST_PHRASE.split(' ').collect();
            s.seed = Some(maki_seed::seed(&words, ""));
            let note = "keys: from the BIP39 test phrase (abandon ... about), as on a maki set up with it: never use them for anything real";
            if !s.interactive {
                eprintln!("{note}");
            }
            s.logs.push(note.into());
        }
        s.seed.unwrap()
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
        loop {
            return match s.script.pop_front() {
                Some(Press::Event(Event::Timeout)) => {
                    s.slept += timeout.unwrap_or_default();
                    Event::Timeout
                }
                Some(Press::Event(Event::Up | Event::Down)) if !knows_jog(&s.manifest) => {
                    eprintln!(
                        "script: the jog dial goes to apps of host API {} or later, and this one says {}: skipped",
                        maki_wasm::API_JOG,
                        s.manifest.api
                    );
                    continue;
                }
                Some(Press::Event(e)) => e,
                Some(Press::Menu(pick)) => {
                    let event = Self::menu_event(&mut s, pick);
                    s.queued.push_back(event);
                    Event::Hidden
                }
                Some(Press::Answer(a)) => {
                    eprintln!("script: {a:?}, but the app asked nothing: skipped");
                    continue;
                }
                Some(Press::Qr(text)) => {
                    s.qr = Some(text);
                    continue;
                }
                Some(Press::Tilt(xyz)) => {
                    s.options.motion = xyz;
                    continue;
                }
                Some(Press::Message(m)) => {
                    if s.message.take().is_some() {
                        eprintln!("message: the app went on without answering");
                    }
                    if !s.manifest.permissions.iter().any(|(p, _)| *p == maki_bundle::Permission::Link) {
                        eprintln!("message: refused, the app hasn't the link permission");
                        continue;
                    }
                    s.message = Some(m);
                    Event::Message
                }
                None => Event::Exit,
            };
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

    fn millis(&self) -> u64 { self.0.borrow().elapsed().as_millis() as u64 }

    fn unix_time(&self) -> Option<(u64, bool)> {
        let s = self.0.borrow();
        Some((s.unix(), s.options.verified))
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

    fn ask(&mut self, ask: &Ask) -> Answer {
        let mut s = self.0.borrow_mut();
        let answer = if s.interactive {
            Self::interactive_ask(&mut s, ask)
        } else {
            match s.script.front() {
                Some(Press::Answer(a)) => {
                    let a = *a;
                    s.script.pop_front();
                    a
                }
                _ => Answer::NoAnswer,
            }
        };
        let line = format!("ask \"{}\" ({}): {answer:?}", ask.question, ask.detail);
        if !s.interactive {
            eprintln!("{line}");
        }
        s.logs.push(line);
        // as on maki, the app was hidden while the ask showed
        s.queued.push_back(Event::Hidden);
        s.queued.push_back(Event::Shown);
        answer
    }

    /// A wallet app's keys from the BIP39 test phrase, never the owner's: the keys maki would use
    /// for it on a maki set up with that phrase. The session has held the path to the app's own.
    fn wallet(&mut self, op: u8, path: &[u32], digest: &[u8]) -> Result<Vec<u8>, i32> {
        let seed = self.test_seed();
        let keys = maki_hd::seed::SeedKeys::from_seed(&seed).map_err(|_| maki_wasm::FAILED)?;
        // no randomness in the simulator's Schnorr signatures: the same every run, for tests
        maki_hd::seed::answer(&keys, op, path, digest, &[0; 32]).map_err(|e| match e {
            maki_hd::Error::Path => maki_wasm::REFUSED,
            _ => maki_wasm::FAILED,
        })
    }

    /// A wallet's backup words, as maki shows them: asked about first (a review with no pages),
    /// then a word to a page. In the terminal, the words show there; scripted, they're written
    /// to stderr (they're the test phrase's: nobody's real wallet).
    fn show_backup(&mut self, path: &[u32]) -> Result<Answer, i32> {
        let seed = self.test_seed();
        let keys = maki_hd::seed::SeedKeys::from_seed(&seed).map_err(|_| maki_wasm::FAILED)?;
        let words = maki_hd::seed::answer(&keys, maki_hd::op::MONERO_WORDS, path, &[], &[0; 32]).map_err(
            |e| match e {
                maki_hd::Error::Path => maki_wasm::NOT_FOUND,
                _ => maki_wasm::FAILED,
            },
        )?;
        let words = String::from_utf8(words).map_err(|_| maki_wasm::FAILED)?;
        let ask = Review {
            question: "Show backup words?".into(),
            detail: "anyone who sees them can spend".into(),
            yes: "show".into(),
            no: "don't".into(),
            pages: Vec::new(),
            timeout_s: 60,
        };
        match self.review(&ask) {
            Answer::Yes => {}
            other => return Ok(other),
        }
        let n = words.split(' ').count();
        let pages = words
            .split(' ')
            .enumerate()
            .map(|(i, w)| maki_wasm::Page {
                heading: format!("Word {} of {n}", i + 1),
                value: w.into(),
                ..Default::default()
            })
            .collect();
        let shown = Review {
            question: "Wrote them down?".into(),
            detail: format!("{n} words, in order"),
            yes: "done".into(),
            no: "close".into(),
            pages,
            timeout_s: 900,
        };
        let mut s = self.0.borrow_mut();
        if s.interactive {
            Self::interactive_review(&mut s, &shown);
        } else {
            eprintln!("  maki shows its owner the backup words (never the app): {words}");
        }
        s.logs.push(format!("backup words shown: {n}"));
        Ok(Answer::Yes)
    }

    /// A review: in the terminal, a page at a time (left and right), then y or n; scripted, the
    /// next answer in the script, its pages written to stderr.
    fn review(&mut self, review: &Review) -> Answer {
        let mut s = self.0.borrow_mut();
        let answer = if s.interactive {
            Self::interactive_review(&mut s, review)
        } else {
            for p in &review.pages {
                eprintln!(
                    "  [{}] {} {} {}",
                    p.heading,
                    p.value,
                    p.mono.replace('\n', " "),
                    p.prose.replace('\n', " ")
                );
            }
            match s.script.front() {
                Some(Press::Answer(a)) => {
                    let a = *a;
                    s.script.pop_front();
                    a
                }
                _ => Answer::NoAnswer,
            }
        };
        let line = format!(
            "review \"{}\" ({}), {} pages: {answer:?}",
            review.question,
            review.detail,
            review.pages.len()
        );
        if !s.interactive {
            eprintln!("{line}");
        }
        s.logs.push(line);
        s.queued.push_back(Event::Hidden);
        s.queued.push_back(Event::Shown);
        answer
    }

    /// From the BIP39 test phrase, never the owner's: the same keys maki would give this app on
    /// a maki set up with that phrase.
    fn app_secret(&mut self, label: &str) -> Option<[u8; 32]> {
        let seed = self.test_seed();
        let s = self.0.borrow();
        let (id, developer) = (s.manifest.id.clone(), s.options.developer);
        maki_seed::app_secret(&seed, &id, &developer, label)
    }

    /// The next `qr:` press's text (scripted), or what's typed in (in the terminal).
    fn scan_qr(&mut self) -> Option<String> {
        let mut s = self.0.borrow_mut();
        let scanned = if s.interactive {
            Self::interactive_scan(&mut s)
        } else {
            // a qr: press waiting before the app's next event
            match s.script.front() {
                Some(Press::Qr(_)) => match s.script.pop_front() {
                    Some(Press::Qr(text)) => Some(text),
                    _ => None,
                },
                _ => s.qr.take(),
            }
        };
        let line = format!("scanned: {scanned:?}");
        if !s.interactive {
            eprintln!("{line}");
        }
        s.logs.push(line);
        scanned
    }

    fn motion(&mut self) -> Option<[i16; 3]> { Some(self.0.borrow().options.motion) }

    fn message(&mut self) -> Option<Vec<u8>> { self.0.borrow().message.clone() }

    fn reply(&mut self, reply: &[u8]) -> bool {
        let mut s = self.0.borrow_mut();
        if s.message.take().is_none() {
            return false;
        }
        let shown = match std::str::from_utf8(reply) {
            Ok(text) if !text.chars().any(|c| c.is_control() && c != '\n') => format!("{text:?}"),
            _ => reply.iter().map(|b| format!("{b:02x}")).collect(),
        };
        let line = format!("answer: {shown}");
        if !s.interactive {
            eprintln!("{line}");
        }
        s.logs.push(line);
        true
    }

    fn type_text(&mut self, text: &str) -> bool {
        let mut s = self.0.borrow_mut();
        let line = format!("typed: {text:?}");
        if !s.interactive {
            eprintln!("{line}");
        }
        s.logs.push(line);
        true
    }
}
