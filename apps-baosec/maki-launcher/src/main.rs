//! maki launcher: the boot image, the home screen, the owner of input focus, and the screen
//! that asks the owner to approve things.
//!
//! The launcher is the only process that registers with bao-video for key presses. While an app
//! is in front, keys are relayed to that app and nowhere else; on the home screen they move the
//! selection. Apps join the home screen by registering at startup (see `lib.rs`), so nothing here
//! is specific to any one app.
//!
//! An ask (`Launcher::ask`) takes the screen from whatever is in front, keeps the keys to itself
//! until the owner decides or it times out, then gives the screen back. That's how a request
//! from the browser reaches the owner wherever they are.

mod api;
mod splash;
use std::collections::VecDeque;
use std::fmt::Write;

use api::*;
use blitstr2::GlyphStyle;
use num_traits::{FromPrimitive, ToPrimitive};
use ux_api::minigfx::*;
use ux_api::platform::{HEIGHT, WIDTH};
use ux_api::service::api::Gid;
use ux_api::service::gfx::Gfx;
use ux_api::widgets::{ScrollableList, TextAlignment};
use xous_ipc::Buffer;

/// The boot image stays up at least this long, so a fast mount doesn't just flash it.
const SPLASH_MIN_MS: u64 = 1500;
/// Width of the clock's slot at the right end of the status bar.
const CLOCK_WIDTH: isize = 40;
const NAME: &str = "maki";
/// An ask shows its site in fixed-width type (8 pixels a character), 15 characters to a line,
/// on three lines, or two when there's a list to pick from.
const SITE_WIDTH: usize = 15;
const SITE_LINES: usize = 3;
/// Line heights of the fonts an ask uses.
const LINE: isize = 16;
const SMALL_LINE: isize = 12;

struct App {
    name: String,
    conn: xous::CID,
    key_op: usize,
    focus_op: usize,
}

fn set_focus(app: &App, focus: Focus) {
    xous::send_message(
        app.conn,
        xous::Message::new_scalar(app.focus_op, focus.to_usize().unwrap(), 0, 0, 0),
    )
    .ok();
}

/// Local wall-clock time as `HH:MM`, or `--:--` until something has set it. The module has no
/// battery, so the clock starts unset on every boot. A trailing `?` marks a time that nothing
/// has verified (the desktop app's own clock, or the vault's QR code).
#[cfg(feature = "board-baosec")]
fn clock_text(time_conn: xous::CID, verified: bool) -> String {
    use bao1x_hal_service::api::TimeOp;
    let is_set = matches!(
        xous::send_message(
            time_conn,
            xous::Message::new_blocking_scalar(TimeOp::WallClockTimeInit.to_usize().unwrap(), 0, 0, 0, 0),
        ),
        Ok(xous::Result::Scalar2(_, 1))
    );
    if !is_set {
        return String::from("--:--");
    }
    match xous::send_message(
        time_conn,
        xous::Message::new_blocking_scalar(TimeOp::GetLocalTimeMs.to_usize().unwrap(), 0, 0, 0, 0),
    ) {
        Ok(xous::Result::Scalar2(lo, hi)) => {
            let ms = ((hi as u64) << 32) | lo as u64;
            let secs = (ms / 1000) % 86_400;
            format!("{:02}:{:02}{}", secs / 3600, (secs % 3600) / 60, if verified { "" } else { "?" })
        }
        _ => String::from("--:--"),
    }
}

#[cfg(not(feature = "board-baosec"))]
fn clock_text(_time_conn: xous::CID, _verified: bool) -> String { String::from("--:--") }

struct Home {
    gfx: Gfx,
    list: ScrollableList,
    bar_height: isize,
    clock: String,
    /// the desktop app is linked over USB
    linked: bool,
}

impl Home {
    fn new(xns: &xous_names::XousNames) -> Self {
        let mut list = ScrollableList::default();
        list.set_alignment(TextAlignment::Center);
        let bar_height = list.row_height() as isize;
        Home { gfx: Gfx::new(xns).unwrap(), list, bar_height, clock: String::from("--:--"), linked: false }
    }

    fn splash(&self) {
        self.gfx.bitmap(&splash::BITMAP, None, None).ok();
        self.gfx.flush().ok();
    }

    fn redraw(&mut self) {
        self.gfx.flush().ok();
        self.gfx.clear().ok();
        let clock = self.clock.clone();
        self.status_bar(&clock);

        // the apps; the list flushes everything queued above when it draws
        let top = self.bar_height + 4;
        self.list.pane_size(Rectangle::new(Point::new(0, 0), Point::new(WIDTH as isize, HEIGHT as isize - top)));
        self.list.draw(top);
    }

    /// An ask: who is asking, what they want, and how to answer. Everything is laid out at fixed
    /// places, so nothing a requester sends can push the answer hints off the screen.
    fn draw_prompt(&mut self, req: &AskRequest, selected: usize, remaining_s: u32) {
        self.gfx.flush().ok();
        self.gfx.clear().ok();
        self.status_bar(&format!("{}s", remaining_s));

        // light on dark like the home screen; `highlight` (dark on light) for the choice on
        // offer, as the home screen marks its selection. Everything but the site ends in "…" if
        // it runs long; the site is laid out to fit, since its end is the part that must show.
        let text = |gfx: &Gfx, top: isize, height: isize, style: GlyphStyle, highlight: bool, s: &str| {
            let mut tv = TextView::new(
                Gid::dummy(),
                TextBounds::BoundingBox(Rectangle::new(Point::new(0, top), Point::new(WIDTH as isize, top + height))),
            );
            tv.style = style;
            tv.invert = !highlight;
            tv.draw_border = false;
            tv.ellipsis = style != GlyphStyle::Monospace;
            tv.margin = Point::new(2, 0);
            write!(tv, "{}", s).ok();
            gfx.draw_textview(&mut tv).ok();
        };

        let n = req.choices.len();
        let site_lines = if n > 1 { SITE_LINES - 1 } else { SITE_LINES };
        let mut y = self.bar_height + 4;
        let site = maki_proto::site::lines(&req.subject, SITE_WIDTH, site_lines).join("\n");
        text(&self.gfx, y, LINE * site_lines as isize + 2, GlyphStyle::Monospace, false, &site);
        y += LINE * site_lines as isize + 4;

        if n > 1 {
            text(&self.gfx, y, LINE, GlyphStyle::Regular, false, &format!("{} {}/{}", req.question, selected + 1, n));
        } else {
            text(&self.gfx, y, LINE, GlyphStyle::Regular, false, &req.question);
        }
        y += LINE;
        match req.choices.get(selected) {
            Some(choice) => text(&self.gfx, y, LINE, GlyphStyle::Regular, true, choice),
            None => text(&self.gfx, y, LINE, GlyphStyle::Bold, false, &req.detail),
        }

        let bottom = HEIGHT as isize;
        let (allow, deny) = if n > 0 { ("use", "cancel") } else { ("allow", "deny") };
        text(&self.gfx, bottom - SMALL_LINE, SMALL_LINE, GlyphStyle::Small, false, &format!("Press: {allow}  Left: {deny}"));
        if n > 1 {
            text(&self.gfx, bottom - 2 * SMALL_LINE, SMALL_LINE, GlyphStyle::Small, false, "Up/Down: another");
        }
        self.gfx.flush().ok();
    }

    /// The bar across the top: the name on the left, `right` (the clock, or an ask's countdown)
    /// on the right, and a dot between while the desktop app is linked.
    fn status_bar(&mut self, right: &str) {
        let mut name = TextView::new(
            Gid::dummy(),
            TextBounds::BoundingBox(Rectangle::new(
                Point::new(0, 0),
                Point::new(WIDTH as isize - CLOCK_WIDTH, self.bar_height),
            )),
        );
        name.style = GlyphStyle::Bold;
        name.invert = true;
        name.draw_border = false;
        name.margin = Point::new(2, 0);
        write!(name, "{}", NAME).ok();
        self.gfx.draw_textview(&mut name).ok();

        let mut clock = TextView::new(
            Gid::dummy(),
            TextBounds::CenteredTop(Rectangle::new(
                Point::new(WIDTH as isize - CLOCK_WIDTH, 2),
                Point::new(WIDTH as isize, self.bar_height),
            )),
        );
        clock.style = GlyphStyle::Small;
        clock.invert = true;
        clock.draw_border = false;
        clock.margin = Point::new(0, 0);
        write!(clock, "{}", right).ok();
        self.gfx.draw_textview(&mut clock).ok();

        // a dot left of the clock while the desktop app is linked
        if self.linked {
            self.gfx
                .draw_circle(Circle::new_with_style(
                    Point::new(WIDTH as isize - CLOCK_WIDTH - 6, self.bar_height / 2),
                    2,
                    DrawStyle::new(PixelColor::Light, PixelColor::Light, 1),
                ))
                .ok();
        }

        self.gfx
            .draw_line(Line::new_with_style(
                Point::new(0, self.bar_height + 1),
                Point::new(WIDTH as isize, self.bar_height + 1),
                DrawStyle::new(PixelColor::Light, PixelColor::Light, 1),
            ))
            .ok();
    }
}

struct Prompt {
    /// the asker's message, held until it's answered: the asker stays blocked until then
    msg: xous::MessageEnvelope,
    req: AskRequest,
    selected: usize,
    /// ticktimer milliseconds when it gives up. Kept as a deadline rather than counted down
    /// by ticks: ticks queue up while the launcher is starved, and a burst of them would eat
    /// the owner's time.
    deadline_ms: u64,
}

impl Prompt {
    fn remaining_s(&self, now_ms: u64) -> u32 { ((self.deadline_ms.saturating_sub(now_ms) + 999) / 1000) as u32 }
}

/// Asks waiting for the owner, and the one on screen.
struct Asking {
    queue: VecDeque<(xous::MessageEnvelope, AskRequest)>,
    current: Option<Prompt>,
    /// the app that was in front when asking began: it gets the screen back after
    resume: Option<usize>,
    tt: ticktimer_server::Ticktimer,
}

impl Asking {
    fn new() -> Self {
        Asking { queue: VecDeque::new(), current: None, resume: None, tt: ticktimer_server::Ticktimer::new().unwrap() }
    }

    fn active(&self) -> bool { self.current.is_some() }

    /// Take the screen from whatever is in front and show the first ask waiting, if any.
    fn start(&mut self, home: &mut Home, apps: &[App], front: &mut Option<usize>) {
        if self.current.is_some() || self.queue.is_empty() {
            return;
        }
        if let Some(i) = front.take() {
            set_focus(&apps[i], Focus::Background);
            self.resume = Some(i);
        }
        self.show_next(home);
    }

    fn show_next(&mut self, home: &mut Home) {
        if let Some((msg, req)) = self.queue.pop_front() {
            let now = self.tt.elapsed_ms();
            let prompt = Prompt { msg, deadline_ms: now + req.timeout_s.max(1) as u64 * 1000, req, selected: 0 };
            home.draw_prompt(&prompt.req, prompt.selected, prompt.remaining_s(now));
            self.current = Some(prompt);
        }
    }

    /// Answer the ask on screen; then show the next, or give the screen back.
    fn finish(&mut self, answer: u32, home: &mut Home, apps: &[App], front: &mut Option<usize>) {
        if let Some(Prompt { mut msg, mut req, selected, .. }) = self.current.take() {
            log::info!("ask from {} answered {}", req.subject, answer);
            req.answer = answer;
            req.choice = selected as u32;
            if let Some(mem) = msg.body.memory_message_mut() {
                let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
                buffer.replace(req).ok();
            }
            // dropping `msg` returns it, which unblocks the asker
        }
        if !self.queue.is_empty() {
            self.show_next(home);
        } else if let Some(i) = self.resume.take() {
            *front = Some(i);
            set_focus(&apps[i], Focus::Foreground);
        } else {
            home.redraw();
        }
    }

    /// A key while an ask is on screen: returns the answer once there is one.
    fn key(&mut self, c: char, home: &mut Home) -> Option<u32> {
        let p = self.current.as_mut()?;
        let n = p.req.choices.len();
        match c {
            '↑' if n > 1 => p.selected = (p.selected + n - 1) % n,
            '↓' if n > 1 => p.selected = (p.selected + 1) % n,
            // only a deliberate press allows: select, or the centre of the pad
            '∴' | '🔥' => return Some(ANSWER_ALLOWED),
            // down refuses a plain ask, as it does the vault's FIDO prompts
            '←' | '↓' => return Some(ANSWER_DENIED),
            _ => return None,
        }
        home.draw_prompt(&p.req, p.selected, p.remaining_s(self.tt.elapsed_ms()));
        None
    }

    /// Once a second while an ask is on screen: returns an answer when time is up.
    fn tick(&mut self, home: &mut Home) -> Option<u32> {
        let now = self.tt.elapsed_ms();
        let p = self.current.as_mut()?;
        match p.remaining_s(now) {
            0 => Some(ANSWER_TIMED_OUT),
            left => {
                home.draw_prompt(&p.req, p.selected, left);
                None
            }
        }
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki launcher PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_LAUNCHER, None).expect("can't register server");
    let conn = xous::connect(sid).unwrap();

    let mut home = Home::new(&xns);
    home.splash();

    #[cfg(feature = "board-baosec")]
    let time_conn =
        xous::connect(xous::SID::from_bytes(bao1x_hal_service::api::TIME_SERVER_PUBLIC).unwrap()).unwrap();
    #[cfg(not(feature = "board-baosec"))]
    let time_conn: xous::CID = 0;

    let gfx = Gfx::new(&xns).unwrap();
    gfx.register_listener(SERVER_NAME_LAUNCHER, LauncherOp::KeyPress.to_usize().unwrap());

    // The PDDB's first-boot format prompt is a modal; drawing the home screen before the mount
    // finishes would paint over it. Wait on a helper thread rather than here: apps register
    // before the mount is triggered, so blocking the main loop would deadlock the boot.
    std::thread::spawn(move || {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        let start = tt.elapsed_ms();
        pddb::Pddb::new().is_mounted_blocking();
        let shown = tt.elapsed_ms() - start;
        if shown < SPLASH_MIN_MS {
            tt.sleep_ms((SPLASH_MIN_MS - shown) as usize).ok();
        }
        xous::send_message(conn, xous::Message::new_scalar(LauncherOp::Ready.to_usize().unwrap(), 0, 0, 0, 0))
            .ok();
    });

    // keeps the clock current; the main loop only redraws when the minute changes
    std::thread::spawn(move || {
        let tt = ticktimer_server::Ticktimer::new().unwrap();
        loop {
            tt.sleep_ms(1000).ok();
            xous::send_message(conn, xous::Message::new_scalar(LauncherOp::Tick.to_usize().unwrap(), 0, 0, 0, 0))
                .ok();
        }
    });

    let mut apps: Vec<App> = Vec::new();
    let mut front: Option<usize> = None; // None is the home screen, or an ask
    let mut ready = false;
    let mut time_verified = false;
    let mut asking = Asking::new();

    loop {
        let msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(LauncherOp::Register) => {
                let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                let reg = match buffer.to_original::<AppRegistration, _>() {
                    Ok(reg) => reg,
                    Err(_) => {
                        log::error!("malformed app registration");
                        continue;
                    }
                };
                match xns.request_connection_blocking(&reg.server_name) {
                    Ok(app_conn) => {
                        log::info!("registered app '{}' ({})", reg.name, reg.server_name);
                        home.list.add_item(0, &reg.name);
                        apps.push(App {
                            name: reg.name,
                            conn: app_conn,
                            key_op: reg.key_op as usize,
                            focus_op: reg.focus_op as usize,
                        });
                        if ready && front.is_none() && !asking.active() {
                            home.redraw();
                        }
                    }
                    Err(e) => log::error!("couldn't connect to app server {}: {:?}", reg.server_name, e),
                }
            }
            Some(LauncherOp::Ready) => {
                ready = true;
                home.clock = clock_text(time_conn, time_verified);
                if !asking.queue.is_empty() {
                    asking.start(&mut home, &apps, &mut front);
                } else if front.is_none() {
                    home.redraw();
                }
            }
            Some(LauncherOp::Tick) => {
                if asking.active() {
                    if let Some(answer) = asking.tick(&mut home) {
                        asking.finish(answer, &mut home, &apps, &mut front);
                    }
                } else if ready && front.is_none() {
                    let now = clock_text(time_conn, time_verified);
                    if now != home.clock {
                        home.clock = now;
                        home.redraw();
                    }
                }
            }
            Some(LauncherOp::Ask) => {
                let request = {
                    let buffer = unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                    buffer.to_original::<AskRequest, _>()
                };
                match request {
                    Ok(req) => {
                        log::info!("ask from {}", req.subject);
                        asking.queue.push_back((msg, req));
                        if ready {
                            asking.start(&mut home, &apps, &mut front);
                        }
                    }
                    // dropping the message answers it as it came: timed out
                    Err(_) => log::error!("malformed ask"),
                }
            }
            Some(LauncherOp::KeyPress) if asking.active() => xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                for k in [k1, k2, k3, k4] {
                    match char::from_u32(k as u32) {
                        Some('\u{0}') | None => {}
                        Some(c) => {
                            if let Some(answer) = asking.key(c, &mut home) {
                                asking.finish(answer, &mut home, &apps, &mut front);
                                break; // the rest belonged to this ask
                            }
                        }
                    }
                }
            }),
            Some(LauncherOp::KeyPress) => xous::msg_scalar_unpack!(msg, k1, k2, k3, k4, {
                match front {
                    Some(i) => {
                        let app = &apps[i];
                        xous::try_send_message(app.conn, xous::Message::new_scalar(app.key_op, k1, k2, k3, k4))
                            .ok();
                    }
                    None if ready => {
                        for k in [k1, k2, k3, k4] {
                            match char::from_u32(k as u32) {
                                Some(c @ ('↑' | '↓')) => {
                                    home.list.key_action(c);
                                    home.redraw();
                                }
                                Some('∴') => {
                                    let (_, index) = home.list.get_selected_index();
                                    if let Some(app) = apps.get(index) {
                                        log::info!("bringing '{}' to the front", app.name);
                                        front = Some(index);
                                        set_focus(app, Focus::Foreground);
                                    }
                                    // anything after the select key belongs to the app, not us
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    None => {}
                }
            }),
            Some(LauncherOp::Home) if asking.active() => {
                // the app that was in front went home while asked to wait: home is where the
                // screen goes after the ask
                asking.resume = None;
            }
            Some(LauncherOp::Home) => {
                if let Some(i) = front.take() {
                    log::info!("'{}' returned to the home screen", apps[i].name);
                    set_focus(&apps[i], Focus::Background);
                }
                if ready {
                    home.clock = clock_text(time_conn, time_verified);
                    home.redraw();
                }
            }
            Some(LauncherOp::TimeState) => xous::msg_scalar_unpack!(msg, state, _, _, _, {
                time_verified = state == 2;
                home.clock = clock_text(time_conn, time_verified);
                if ready && front.is_none() && !asking.active() {
                    home.redraw();
                }
            }),
            Some(LauncherOp::LinkState) => xous::msg_scalar_unpack!(msg, linked, _, _, _, {
                home.linked = linked != 0;
                if ready && front.is_none() && !asking.active() {
                    home.redraw();
                }
            }),
            None => log::error!("unknown launcher opcode {}", msg.body.id()),
        }
    }
}
