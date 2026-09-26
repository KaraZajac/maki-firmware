//! BAOKEY launcher: the boot image, the home screen, and the owner of input focus.
//!
//! The launcher is the only process that registers with bao-video for key presses. While an app
//! is in front, keys are relayed to that app and nowhere else; on the home screen they move the
//! selection. Apps join the home screen by registering at startup (see `lib.rs`), so nothing here
//! is specific to any one app.

mod api;
mod splash;
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
const NAME: &str = "BAOKEY";

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
/// battery, so the clock starts unset on every boot.
#[cfg(feature = "board-baosec")]
fn clock_text(time_conn: xous::CID) -> String {
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
            format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
        }
        _ => String::from("--:--"),
    }
}

#[cfg(not(feature = "board-baosec"))]
fn clock_text(_time_conn: xous::CID) -> String { String::from("--:--") }

struct Home {
    gfx: Gfx,
    list: ScrollableList,
    bar_height: isize,
    clock: String,
}

impl Home {
    fn new(xns: &xous_names::XousNames) -> Self {
        let mut list = ScrollableList::default();
        list.set_alignment(TextAlignment::Center);
        let bar_height = list.row_height() as isize;
        Home { gfx: Gfx::new(xns).unwrap(), list, bar_height, clock: String::from("--:--") }
    }

    fn splash(&self) {
        self.gfx.bitmap(&splash::BITMAP, None, None).ok();
        self.gfx.flush().ok();
    }

    fn redraw(&mut self) {
        self.gfx.flush().ok();
        self.gfx.clear().ok();

        // status bar: name on the left, clock on the right
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
        write!(clock, "{}", self.clock).ok();
        self.gfx.draw_textview(&mut clock).ok();

        self.gfx
            .draw_line(Line::new_with_style(
                Point::new(0, self.bar_height + 1),
                Point::new(WIDTH as isize, self.bar_height + 1),
                DrawStyle::new(PixelColor::Light, PixelColor::Light, 1),
            ))
            .ok();

        // the apps; the list flushes everything queued above when it draws
        let top = self.bar_height + 4;
        self.list.pane_size(Rectangle::new(Point::new(0, 0), Point::new(WIDTH as isize, HEIGHT as isize - top)));
        self.list.draw(top);
    }
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("BAOKEY launcher PID is {}", xous::process::id());

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
    let mut front: Option<usize> = None; // None is the home screen
    let mut ready = false;

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
                        if ready && front.is_none() {
                            home.redraw();
                        }
                    }
                    Err(e) => log::error!("couldn't connect to app server {}: {:?}", reg.server_name, e),
                }
            }
            Some(LauncherOp::Ready) => {
                ready = true;
                home.clock = clock_text(time_conn);
                if front.is_none() {
                    home.redraw();
                }
            }
            Some(LauncherOp::Tick) => {
                if ready && front.is_none() {
                    let now = clock_text(time_conn);
                    if now != home.clock {
                        home.clock = now;
                        home.redraw();
                    }
                }
            }
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
            Some(LauncherOp::Home) => {
                if let Some(i) = front.take() {
                    log::info!("'{}' returned to the home screen", apps[i].name);
                    set_focus(&apps[i], Focus::Background);
                }
                if ready {
                    home.clock = clock_text(time_conn);
                    home.redraw();
                }
            }
            None => log::error!("unknown launcher opcode {}", msg.body.id()),
        }
    }
}
