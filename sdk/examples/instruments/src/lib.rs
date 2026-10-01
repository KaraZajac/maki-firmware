//! Instruments: maki's accelerometer as three instruments, left and right going from one to the
//! next. The centre does what each page's bottom line says, the jog dial is its knob, and the menu
//! calibrates it.
//!
//! - **G-meter**, for a car, a bike or a ride: a ball in a ring moves the way you're pushed (braking sends it
//!   up, a left turn right), with its last two seconds as a trail and the most in each direction round the
//!   ring; beside it the g now and the peaks braking, accelerating and each way round. The dial sets the
//!   ring's scale (up to 5 g, reading to 8 for a ride). Calibrated: keep still for its up, then pull away
//!   straight for its forward.
//! - **Tilt**, a pilot's attitude indicator and slip ball, maki held up facing you: the horizon, the bank
//!   against the scale above it, and the ball in its tube below. Both read the one thing, which way is down:
//!   they can't tell a turn or a speeding up from a tilt, so when maki's pushed more or less than 1 g the
//!   horizon hides behind ACCEL, and the ball carries on. The centre sets level; the dial moves the little
//!   aircraft.
//! - **Level**, a spirit level: a bull's-eye lying flat, a tube standing on an edge, the screen lit and LEVEL
//!   within a tenth of a degree, an arrow at the end to raise otherwise. The centre holds the reading; the
//!   dial sets how far the bubble goes. Calibrated by the flip: read it, turn it round on the same spot, read
//!   it again.

use core::f32::consts::PI;
use std::collections::VecDeque;
use std::fmt::Write;

use maki_app::screen::Toward;
use maki_app::*;

/// maki's accelerometer as its screen is: x toward the right edge, y toward the top, z out of the
/// screen, each reading the push that holds maki up (face up and still: 0, 0, +1 g). An axis
/// that reads the other way on the badge has -1 here.
const SIGN: [f32; 3] = [1.0, 1.0, 1.0];
/// How often it reads, and how often the screen may change.
const READ_MS: u32 = 20;
const DRAW_MS: u64 = 50;

const PAGES: usize = 3;
const G_METER: usize = 0;
const TILT: usize = 1;
const LEVEL: usize = 2;

/// The g-meter's ring: its scales in g, which it starts on, and where it is.
const SCALES: [f32; 6] = [0.5, 1.0, 1.5, 2.0, 3.0, 5.0];
const SCALE: usize = 2;
const CX: i32 = 47;
const CY: i32 = 48;
const R: i32 = 45;
/// Smoothing, as time constants in seconds: the ball, the peaks (so a kerb's spike isn't one), the
/// horizon, the slip ball, the bubble.
const TAU_BALL: f32 = 0.1;
const TAU_PEAK: f32 = 0.4;
const TAU_HORIZON: f32 = 0.15;
const TAU_SLIP: f32 = 0.3;
const TAU_BUBBLE: f32 = 0.3;
/// The trail: two seconds of the ball.
const TRAIL: usize = 40;
/// Level within this, in degrees, and out again past the other.
const LEVEL_IN: f32 = 0.1;
const LEVEL_OUT: f32 = 0.15;

type V3 = [f32; 3];

fn dot(a: V3, b: V3) -> f32 { a[0] * b[0] + a[1] * b[1] + a[2] * b[2] }
fn cross(a: V3, b: V3) -> V3 {
    [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]
}
fn scale(a: V3, k: f32) -> V3 { [a[0] * k, a[1] * k, a[2] * k] }
fn sub(a: V3, b: V3) -> V3 { [a[0] - b[0], a[1] - b[1], a[2] - b[2]] }
fn len(a: V3) -> f32 { dot(a, a).sqrt() }
fn unit(a: V3) -> V3 { scale(a, 1.0 / len(a).max(1e-6)) }
fn deg(r: f32) -> f32 { r * 180.0 / PI }
fn rad(d: f32) -> f32 { d * PI / 180.0 }

/// An exponential average: `tau` seconds, `dt` since the last.
fn smooth(was: f32, now: f32, tau: f32, dt: f32) -> f32 { was + (now - was) * dt / (tau + dt) }
fn smooth3(was: V3, now: V3, tau: f32, dt: f32) -> V3 {
    [smooth(was[0], now[0], tau, dt), smooth(was[1], now[1], tau, dt), smooth(was[2], now[2], tau, dt)]
}

/// Calibrating, a step at a time.
#[derive(Clone, Copy, PartialEq)]
enum Calibrating {
    /// the g-meter: keep still, then pull away
    Still {
        since: u64,
    },
    Forward {
        since: Option<u64>,
        way: [f32; 2],
    },
    /// the level: the first reading, then turned round
    First {
        since: u64,
    },
    /// `moved`: it has been, since the first reading. Not moved, the second reading would be the
    /// first again, and the surface's own tilt would become "level"
    Turned {
        since: u64,
        first: [f32; 3],
        moved: bool,
    },
}

/// What's kept: the g-meter's up and forward, the tilt's level, the level's offsets (flat x and y,
/// and on an edge) and its zero, and the choices.
struct Kept {
    up: Option<V3>,
    forward: Option<V3>,
    tilt_level: Option<V3>,
    offset: [f32; 3],
    zero: Option<[f32; 3]>,
    scale: usize,
    units: u8,
    page: usize,
    nudge: i32,
    reach: u8,
}

impl Kept {
    fn load() -> Kept {
        let mut k = Kept {
            up: None,
            forward: None,
            tilt_level: None,
            offset: [0.0; 3],
            zero: None,
            scale: SCALE,
            units: 0,
            page: G_METER,
            nudge: 0,
            reach: 1,
        };
        let mut b = [0u8; 128];
        let Some(n) = storage::get("kept", &mut b) else { return k };
        if n != 97 {
            return k;
        }
        let f = |i: usize| f32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        let v = |i: usize| [f(i), f(i + 1), f(i + 2)];
        let some = |i: usize| (len(v(i)) > 0.5).then(|| v(i));
        k.up = some(0);
        k.forward = some(3);
        k.tilt_level = some(6);
        k.offset = v(9);
        k.zero = (b[96] & 1 != 0).then(|| v(12));
        k.scale = (f(15) as usize).min(SCALES.len() - 1);
        k.units = (f(16) as u8).min(2);
        k.page = (f(17) as usize).min(PAGES - 1);
        k.nudge = f(18) as i32;
        k.reach = (f(19) as u8).min(3);
        k
    }

    fn save(&self) {
        let mut b = [0u8; 97];
        let mut put = |i: usize, x: f32| b[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
        for (i, v) in [self.up, self.forward, self.tilt_level].iter().enumerate() {
            for (j, x) in v.unwrap_or([0.0; 3]).into_iter().enumerate() {
                put(i * 3 + j, x);
            }
        }
        for j in 0..3 {
            put(9 + j, self.offset[j]);
            put(12 + j, self.zero.map_or(0.0, |z| z[j]));
        }
        put(15, self.scale as f32);
        put(16, self.units as f32);
        put(17, self.page as f32);
        put(18, self.nudge as f32);
        put(19, self.reach as f32);
        b[96] = self.zero.is_some() as u8;
        let _ = storage::set("kept", &b);
    }
}

struct App {
    kept: Kept,
    page: usize,
    calibrating: Option<Calibrating>,
    /// the reading, smoothed each way, and when it was
    raw: V3,
    ball: V3,
    peak: V3,
    horizon: V3,
    slip: V3,
    bubble: V3,
    last: u64,
    /// the g-meter: the trail, the most each way (braking, accelerating, left, right), the most
    /// in each 15 degrees round, and when the last record was set
    trail: VecDeque<(f32, f32)>,
    peaks: [f32; 4],
    sectors: [f32; 24],
    /// the level: readings a quarter second apart for the last second, what the centre holds, and
    /// whether it's level (for the margin in and out)
    history: VecDeque<[f32; 3]>,
    held: Option<[f32; 3]>,
    level: bool,
    /// lying flat (a bull's-eye) or on an edge (a tube), kept between 40 and 50 degrees
    flat: bool,
    note: &'static str,
    note_until: u64,
    /// uncalibrated, the g-meter's up: the first second maki's still, and since when it's been
    still_since: Option<u64>,
    auto_up: Option<V3>,
}

impl App {
    /// The g-meter's frame: up, forward, right, whether calibrated or taken from how maki's held
    /// (upright, facing you: up the screen's top, forward into it).
    fn frame(&self) -> (V3, V3, V3) {
        let up = self.kept.up.or(self.auto_up).unwrap_or([0.0, 1.0, 0.0]);
        let forward = self.kept.forward.unwrap_or_else(|| {
            let into = [0.0, 0.0, -1.0];
            let top = [0.0, 1.0, 0.0];
            // whichever of into the screen and toward its top is the more level, made level
            let flat = |v: V3| sub(v, scale(up, dot(v, up)));
            let (a, b) = (flat(into), flat(top));
            unit(if len(a) >= len(b) { a } else { b })
        });
        let right = unit(cross(forward, up));
        (up, forward, right)
    }

    /// A reading: every smoothing moves on.
    fn read(&mut self, now: u64) {
        let Some((x, y, z)) = motion::read() else { return };
        let v = [SIGN[0] * x as f32 / 1000.0, SIGN[1] * y as f32 / 1000.0, SIGN[2] * z as f32 / 1000.0];
        let dt = (now.saturating_sub(self.last) as f32 / 1000.0).clamp(0.001, 0.5);
        if self.last == 0 {
            (self.ball, self.peak, self.horizon, self.slip, self.bubble) = (v, v, v, v, v);
        }
        self.last = now;
        self.raw = v;
        self.ball = smooth3(self.ball, v, TAU_BALL, dt);
        self.peak = smooth3(self.peak, v, TAU_PEAK, dt);
        self.horizon = smooth3(self.horizon, v, TAU_HORIZON, dt);
        self.slip = smooth3(self.slip, v, TAU_SLIP, dt);
        self.bubble = smooth3(self.bubble, v, TAU_BUBBLE, dt);
        // the level's readings a second back, a quarter second apart
        if self.history.back().is_none_or(|_| now % 250 < READ_MS as u64) {
            self.history.push_back(self.angles(self.bubble));
            if self.history.len() > 5 {
                self.history.pop_front();
            }
        }
        // uncalibrated, up is the way maki's pushed once it's been still a second
        if self.kept.up.is_none() && self.auto_up.is_none() {
            if len(sub(self.raw, self.peak)) > 0.02 {
                self.still_since = Some(now);
            } else if now >= *self.still_since.get_or_insert(now) + 1000 {
                self.auto_up = Some(unit(self.peak));
            }
        }
        let known = self.kept.up.is_some() || self.auto_up.is_some();
        if self.page == G_METER && self.calibrating.is_none() && known {
            let (_, forward, right) = self.frame();
            let (long, lat) = (dot(self.ball, forward), dot(self.ball, right));
            self.trail.push_back((-lat, -long));
            if self.trail.len() > TRAIL {
                self.trail.pop_front();
            }
            let (long, lat) = (dot(self.peak, forward), dot(self.peak, right));
            for (i, v) in [-long, long, -lat, lat].iter().enumerate() {
                self.peaks[i] = self.peaks[i].max(*v);
            }
            let (px, py) = (-lat, -long);
            let g = (px * px + py * py).sqrt();
            if g > 0.05 {
                let sector = ((py.atan2(px) + PI) / (2.0 * PI) * 24.0) as usize % 24;
                self.sectors[sector] = self.sectors[sector].max(g);
            }
        }
    }

    /// The level's angles, degrees: flat, x and y and the whole; on an edge, the edge's (in
    /// all three), all less their offsets and any zero.
    fn angles(&self, v: V3) -> [f32; 3] {
        let a = if self.flat {
            let x = deg(v[0].atan2(v[2]));
            let y = deg(v[1].atan2(v[2]));
            [x - self.kept.offset[0], y - self.kept.offset[1], 0.0]
        } else {
            let e = deg(v[0].atan2(v[1])) - self.kept.offset[2];
            [e, 0.0, 0.0]
        };
        let a = match self.kept.zero {
            Some(z) => [a[0] - z[0], a[1] - z[1], 0.0],
            None => a,
        };
        [a[0], a[1], if self.flat { (a[0] * a[0] + a[1] * a[1]).sqrt() } else { a[0].abs() }]
    }

    /// Flat or on an edge, from how far the screen is from level: flat within 40 degrees, on an
    /// edge past 50, as it was between.
    fn which_way(&mut self) {
        let v = self.bubble;
        let off = deg((v[2] / len(v).max(1e-6)).clamp(-1.0, 1.0).acos());
        if off < 40.0 {
            self.flat = true;
        } else if off > 50.0 {
            self.flat = false;
        }
    }

    fn say(&mut self, what: &'static str, now: u64) {
        self.note = what;
        self.note_until = now + 2500;
    }

    fn set_menu(&self) {
        let _ = match self.page {
            G_METER => menu(&["Calibrate", "Clear calibration"]),
            TILT => menu(&["Clear level"]),
            _ => menu(&["Calibrate", "Zero here", "Clear zero", "Units"]),
        };
        // the level reads finest at 2 g; the g-meter wants room for a kerb, or a ride
        let g = if self.page == G_METER { if SCALES[self.kept.scale] >= 3.0 { 8 } else { 4 } } else { 2 };
        motion::range(g);
    }

    /// Calibration's next step, from the readings.
    fn calibrate(&mut self, now: u64) {
        let Some(c) = self.calibrating else { return };
        let moving = len(sub(self.raw, self.peak)) > 0.02;
        match c {
            Calibrating::Still { since } => {
                if moving {
                    self.calibrating = Some(Calibrating::Still { since: now });
                } else if now >= since + 2000 {
                    if (len(self.peak) - 1.0).abs() > 0.05 {
                        self.calibrating = Some(Calibrating::Still { since: now });
                        return;
                    }
                    self.kept.up = Some(unit(self.peak));
                    self.kept.forward = None;
                    self.calibrating = Some(Calibrating::Forward { since: None, way: [0.0; 2] });
                }
            }
            Calibrating::Forward { since, way } => {
                // the first steady push of 0.1 g across, its way holding within 3 degrees for
                // half a second, is forward (a car pulling away is pushed forward)
                let up = self.kept.up.unwrap_or([0.0, 1.0, 0.0]);
                let across = sub(self.ball, scale(up, dot(self.ball, up)));
                let (_, f, r) = self.frame();
                let (a, b) = (dot(across, f), dot(across, r));
                let g = (a * a + b * b).sqrt();
                if g < 0.1 {
                    self.calibrating = Some(Calibrating::Forward { since: None, way: [0.0; 2] });
                    return;
                }
                let dir = [a / g, b / g];
                match since {
                    Some(t) if dir[0] * way[0] + dir[1] * way[1] > rad(3.0).cos() => {
                        if now >= t + 500 {
                            self.kept.forward = Some(unit(across));
                            self.kept.save();
                            self.calibrating = None;
                            self.clear_peaks();
                            self.say("calibrated", now);
                        }
                    }
                    _ => self.calibrating = Some(Calibrating::Forward { since: Some(now), way: dir }),
                }
            }
            Calibrating::First { since } => {
                if moving {
                    self.calibrating = Some(Calibrating::First { since: now });
                } else if now >= since + 2000 {
                    let first = self.raw_angles();
                    self.calibrating = Some(Calibrating::Turned { since: now + 3000, first, moved: false });
                }
            }
            Calibrating::Turned { since, first, moved } => {
                // turned round: once it's moved, then been still for 2 s
                if moving || now < since {
                    if moving {
                        self.calibrating =
                            Some(Calibrating::Turned { since: now.max(since), first, moved: true });
                    }
                } else if moved && now >= since + 2000 {
                    let second = self.raw_angles();
                    let o = &mut self.kept.offset;
                    if self.flat {
                        o[0] = (first[0] + second[0]) / 2.0;
                        o[1] = (first[1] + second[1]) / 2.0;
                    } else {
                        o[2] = (first[0] + second[0]) / 2.0;
                    }
                    self.kept.zero = None;
                    self.kept.save();
                    self.calibrating = None;
                    self.say("calibrated", now);
                }
            }
        }
    }

    /// The level's angles before offsets: what calibration averages.
    fn raw_angles(&self) -> [f32; 3] {
        let v = self.peak;
        if self.flat {
            [deg(v[0].atan2(v[2])), deg(v[1].atan2(v[2])), 0.0]
        } else {
            [deg(v[0].atan2(v[1])), 0.0, 0.0]
        }
    }

    fn clear_peaks(&mut self) {
        self.peaks = [0.0; 4];
        self.sectors = [0.0; 24];
        self.trail.clear();
    }
}

/// A number with two decimals, as the g-meter shows g.
fn g_text(g: f32) -> Buf<8> {
    let mut b = Buf::new();
    let _ = write!(b, "{:.2}", g.max(0.0));
    b
}

fn draw_g_meter(app: &App) {
    let full = SCALES[app.kept.scale];
    let px = R as f32 / full;
    // the ring: three circles and the cross
    for ring in 1..=3 {
        circle(CX, CY, R * ring / 3, Color::Light);
    }
    screen::line(CX - R, CY, CX + R, CY, Color::Light);
    screen::line(CX, CY - R, CX, CY + R, Color::Light);
    // the most each way round, as dots
    for (i, &g) in app.sectors.iter().enumerate() {
        if g > 0.0 {
            let a = (i as f32 + 0.5) / 24.0 * 2.0 * PI - PI;
            let r = (g * px).min(R as f32);
            screen::fill_rect(
                CX + (a.cos() * r) as i32 - 1,
                CY - (a.sin() * r) as i32 - 1,
                2,
                2,
                Color::Light,
            );
        }
    }
    // the trail, and the ball
    let at = |(x, y): (f32, f32)| {
        let (dx, dy) = (x * px, y * px);
        let d = (dx * dx + dy * dy).sqrt();
        let k = if d > R as f32 { R as f32 / d } else { 1.0 };
        (CX + (dx * k) as i32, CY - (dy * k) as i32)
    };
    let mut prev = None;
    for &p in &app.trail {
        let q = at(p);
        if let Some((x0, y0)) = prev {
            screen::line(x0, y0, q.0, q.1, Color::Light);
        }
        prev = Some(q);
    }
    let (_, forward, right) = app.frame();
    let (bx, by) = at((-dot(app.ball, right), -dot(app.ball, forward)));
    screen::fill_rect(bx - 3, by - 3, 7, 7, Color::Dark);
    screen::fill_rect(bx - 2, by - 2, 5, 5, Color::Light);
    // the numbers: g now, and the peaks each way
    let (long, lat) = (dot(app.ball, forward), dot(app.ball, right));
    let x = 98;
    screen::text(x, 0, g_text((long * long + lat * lat).sqrt()).as_str(), Style::Bold, Color::Light);
    screen::text(x, 15, "g", Style::Small, Color::Light);
    let labels = ["brk", "acc", "lft", "rgt"];
    for (i, label) in labels.iter().enumerate() {
        let y = 26 + i as i32 * 17;
        screen::text(x, y, label, Style::Small, Color::Light);
        screen::text(x, y + 8, g_text(app.peaks[i]).as_str(), Style::Small, Color::Light);
    }
    let mut s = Buf::<12>::new();
    let _ = write!(s, "{full} g");
    screen::text(x, 98, s.as_str(), Style::Small, Color::Light);
    let foot = if app.kept.up.is_none() { "menu: calibrate" } else { "centre: clear" };
    screen::text((96 - screen::text_width(foot, Style::Small)) / 2, 98, foot, Style::Small, Color::Light);
}

fn circle(cx: i32, cy: i32, r: i32, color: Color) {
    let steps = (r * 2).max(12);
    let mut prev = (cx + r, cy);
    for i in 1..=steps {
        let a = i as f32 / steps as f32 * 2.0 * PI;
        let p = (cx + (a.cos() * r as f32).round() as i32, cy + (a.sin() * r as f32).round() as i32);
        screen::line(prev.0, prev.1, p.0, p.1, color);
        prev = p;
    }
}

/// The horizon's roll and pitch, degrees, maki held upright facing you: roll right wing down, pitch
/// nose (the screen's far side) up. Less the level set, if any.
fn attitude(v: V3, level: Option<V3>) -> (f32, f32) {
    let angles = |v: V3| (deg(v[0].atan2(v[1])), deg((-v[2] / len(v).max(1e-6)).clamp(-1.0, 1.0).asin()));
    let (roll, pitch) = angles(v);
    match level {
        Some(l) => {
            let (r0, p0) = angles(l);
            (roll - r0, pitch - p0)
        }
        None => (roll, pitch),
    }
}

fn draw_tilt(app: &App) {
    let (cx, cy) = (WIDTH / 2, 46);
    let (roll, pitch) = attitude(app.horizon, app.kept.tilt_level);
    let accel = (len(app.horizon) - 1.0).abs() > 0.05;
    // 2 pixels a degree; the aircraft nudged by the dial
    let p = (pitch + app.kept.nudge as f32) * 2.0;
    // the horizon: the ladder's zero line, turned by the roll about the aircraft
    let t = rad(roll).tan().clamp(-20.0, 20.0);
    let lift = p / rad(roll).cos().abs().max(0.05);
    let horizon_y = |x: i32| cy as f32 + lift - t * (x - cx) as f32;
    if !accel {
        // the ground light, a column at a time
        for x in 0..WIDTH {
            let y = (horizon_y(x).round() as i32).clamp(0, 92);
            if y < 92 {
                screen::fill_rect(x, y, 1, 92 - y, Color::Light);
            }
        }
        // the pitch ladder, every 5 degrees, the tens longer
        let (s, c) = rad(-roll).sin_cos();
        for step in [-20, -15, -10, -5, 5, 10, 15, 20] {
            let half = if step % 10 == 0 { 14.0 } else { 7.0 };
            let off = -(step as f32) * 2.0 + p;
            let at = |dx: f32| (cx as f32 + dx * c - off * s, cy as f32 + dx * s + off * c);
            let (a, b) = (at(-half), at(half));
            screen::line(a.0 as i32, a.1 as i32, b.0 as i32, b.1 as i32, Color::Invert);
        }
    } else {
        screen::fill_rect(cx - 26, cy - 10, 52, 20, Color::Light);
        screen::text_centred(cy - 7, "ACCEL", Style::Bold, Color::Dark);
    }
    // the roll scale above: ticks at 10, 20, 30, 45 and 60, and the sky pointer turning with the
    // horizon, filled past 35 degrees
    let r = 40.0;
    for tick in [-60, -45, -30, -20, -10, 0, 10, 20, 30, 45, 60] {
        let long = tick % 30 == 0;
        let a = rad(tick as f32 - 90.0);
        let (x0, y0) = (cx as f32 + a.cos() * r, cy as f32 + a.sin() * r);
        let k = if long { 6.0 } else { 3.0 };
        let (x1, y1) = (cx as f32 + a.cos() * (r + k), cy as f32 + a.sin() * (r + k));
        screen::line(x0 as i32, y0 as i32, x1 as i32, y1 as i32, Color::Invert);
    }
    if !accel {
        let a = rad(-roll - 90.0);
        let tip = (cx as f32 + a.cos() * (r - 1.0), cy as f32 + a.sin() * (r - 1.0));
        let (s, c) = (a + PI / 2.0).sin_cos();
        let base =
            |side: f32| (tip.0 - a.cos() * 6.0 + c * 4.0 * side, tip.1 - a.sin() * 6.0 + s * 4.0 * side);
        let (b1, b2) = (base(1.0), base(-1.0));
        screen::line(tip.0 as i32, tip.1 as i32, b1.0 as i32, b1.1 as i32, Color::Invert);
        screen::line(tip.0 as i32, tip.1 as i32, b2.0 as i32, b2.1 as i32, Color::Invert);
        screen::line(b1.0 as i32, b1.1 as i32, b2.0 as i32, b2.1 as i32, Color::Invert);
        if roll.abs() > 35.0 {
            screen::line(
                tip.0 as i32,
                tip.1 as i32,
                ((b1.0 + b2.0) / 2.0) as i32,
                ((b1.1 + b2.1) / 2.0) as i32,
                Color::Invert,
            );
        }
    }
    // the aircraft: its wings and a dot
    screen::fill_rect(cx - 30, cy - 1, 20, 3, Color::Invert);
    screen::fill_rect(cx + 10, cy - 1, 20, 3, Color::Invert);
    screen::fill_rect(cx - 1, cy - 1, 3, 3, Color::Invert);
    // the slip ball: a tube, lines a ball apart, a ball's width 4.5 degrees
    screen::fill_rect(0, 92, WIDTH, 18, Color::Dark);
    screen::rect(28, 95, 72, 12, Color::Light);
    screen::line(59, 93, 59, 108, Color::Light);
    screen::line(68, 93, 68, 108, Color::Light);
    let slip = deg(app.slip[0].atan2(app.slip[1]));
    let bx = (WIDTH / 2) as f32 + (slip / 4.5 * 9.0).clamp(-27.0, 27.0);
    screen::fill_rect(bx as i32 - 4, 97, 8, 8, Color::Light);
    let mut bank = Buf::<8>::new();
    let _ = write!(bank, "{:.0}", roll.abs());
    screen::text(2, 96, bank.as_str(), Style::Small, Color::Light);
}

fn draw_level(app: &App, now: u64) {
    let a = app.held.unwrap_or_else(|| app.angles(app.bubble));
    let lit = app.level;
    let (back, fore) = if lit { (Color::Light, Color::Dark) } else { (Color::Dark, Color::Light) };
    screen::clear(back);
    // the reading, a second's average (or what's held), in the units picked
    let shown = app.held.unwrap_or_else(|| {
        let n = app.history.len().max(1) as f32;
        let sum = app.history.iter().fold([0.0; 3], |s, h| [s[0] + h[0], s[1] + h[1], s[2] + h[2]]);
        [sum[0] / n, sum[1] / n, sum[2] / n]
    });
    let unit_text = |deg_value: f32, out: &mut Buf<12>| {
        let _ = match app.kept.units {
            0 => write!(out, "{:.1}", deg_value.abs()),
            1 => write!(out, "{:.1}", (rad(deg_value).tan() * 100.0).abs()),
            _ => write!(out, "{:.0}", (rad(deg_value).tan() * 1000.0).abs()),
        };
    };
    let mut big = Buf::<12>::new();
    unit_text(shown[2], &mut big);
    let unit = ["deg", "%", "mm/m"][app.kept.units as usize];
    if app.flat {
        // a bull's-eye: the bubble floats uphill, a square root's scale
        let (cx, cy, ring) = (38, 50, 36);
        circle(cx, cy, ring, fore);
        circle(cx, cy, 8, fore);
        let reach = [2.0, 5.0, 10.0, 20.0][app.kept.reach as usize];
        let r = (ring as f32 - 5.0) * (a[2] / reach).min(1.0).sqrt();
        let (dx, dy) = if a[2] > 1e-4 { (a[0] / a[2], a[1] / a[2]) } else { (0.0, 0.0) };
        let (bx, by) = (cx + (dx * r) as i32, cy - (dy * r) as i32);
        screen::fill_rect(bx - 4, by - 4, 9, 9, fore);
        screen::fill_rect(bx - 2, by - 2, 5, 5, back);
        // the reading, and x and y
        big_at(80, 22, big.as_str(), fore);
        screen::text(84, 50, unit, Style::Small, fore);
        let mut xy = Buf::<12>::new();
        unit_text(a[0], &mut xy);
        screen::text(80, 66, "x", Style::Small, fore);
        screen::text(90, 66, xy.as_str(), Style::Small, fore);
        let mut yy = Buf::<12>::new();
        unit_text(a[1], &mut yy);
        screen::text(80, 80, "y", Style::Small, fore);
        screen::text(90, 80, yy.as_str(), Style::Small, fore);
    } else {
        // a tube along the bottom: the bubble goes to the high end
        big_at((WIDTH - 60) / 2, 10, big.as_str(), fore);
        screen::text_centred(46, unit, Style::Small, fore);
        screen::rect(8, 64, 112, 16, fore);
        screen::line(56, 62, 56, 81, fore);
        screen::line(72, 62, 72, 81, fore);
        let reach = [2.0, 5.0, 10.0, 20.0][app.kept.reach as usize];
        let x = (a[0] / reach).clamp(-1.0, 1.0);
        let off = x.signum() * x.abs().sqrt() * 50.0;
        let bx = 64 + off as i32;
        screen::fill_rect(bx - 7, 67, 14, 10, fore);
        if !app.level {
            // an arrow at the end to raise: the low one
            // an arrow up at the low end: raise it
            let low_left = a[0] > 0.0;
            let ax = if low_left { 16 } else { WIDTH - 17 };
            for i in 0..7 {
                screen::line(ax - i, 84 + i, ax + i, 84 + i, fore);
            }
            screen::fill_rect(ax - 2, 91, 5, 4, fore);
        }
    }
    if app.level {
        if app.flat {
            screen::text(78, 0, "LEVEL", Style::Bold, fore);
        } else {
            screen::text_centred(82, "LEVEL", Style::Bold, fore);
        }
    }
    let foot = if app.held.is_some() {
        "held: centre lets go"
    } else if now < app.note_until {
        app.note
    } else {
        "centre: hold"
    };
    screen::text_centred(98, foot, Style::Small, fore);
}

/// The level's reading in big digits, a degree's ring after it.
fn big_at(x: i32, y: i32, text: &str, color: Color) {
    let mut h = 24;
    while h > 12 && screen::segments_size(text, h, Toward::Bottom).0 > 44 {
        h -= 2;
    }
    screen::segments(x, y, text, h, Toward::Bottom, color);
}

fn draw(app: &App, now: u64) {
    screen::clear(Color::Dark);
    if let Some(c) = app.calibrating {
        let (title, lines): (&str, [&str; 3]) = match c {
            Calibrating::Still { .. } => ("Calibrate", ["Stop, and keep", "maki still", "on level ground"]),
            Calibrating::Forward { .. } => {
                ("Calibrate", ["Now pull away", "briskly, straight", "(centre: skip)"])
            }
            Calibrating::First { .. } => ("Calibrate", ["Keep it still", "on the surface", "a moment"]),
            Calibrating::Turned { .. } => ("Calibrate", ["Turn it round,", "same spot,", "and let go"]),
        };
        screen::text_centred(4, title, Style::Bold, Color::Light);
        for (i, line) in lines.iter().enumerate() {
            screen::text_centred(30 + i as i32 * 16, line, Style::Regular, Color::Light);
        }
        screen::text_centred(98, "left: cancel", Style::Small, Color::Light);
        screen::present();
        return;
    }
    match app.page {
        G_METER => draw_g_meter(app),
        TILT => draw_tilt(app),
        _ => draw_level(app, now),
    }
    if app.page != LEVEL && now < app.note_until {
        let w = screen::text_width(app.note, Style::Bold) + 10;
        screen::fill_rect((WIDTH - w) / 2, 40, w, 18, Color::Dark);
        screen::rect((WIDTH - w) / 2, 40, w, 18, Color::Light);
        screen::text_centred(41, app.note, Style::Bold, Color::Light);
    }
    screen::present();
}

fn main() {
    let kept = Kept::load();
    let page = kept.page;
    let mut app = App {
        kept,
        page,
        calibrating: None,
        raw: [0.0, 0.0, 1.0],
        ball: [0.0; 3],
        peak: [0.0; 3],
        horizon: [0.0; 3],
        slip: [0.0; 3],
        bubble: [0.0; 3],
        last: 0,
        trail: VecDeque::new(),
        peaks: [0.0; 4],
        sectors: [0.0; 24],
        history: VecDeque::new(),
        held: None,
        level: false,
        flat: true,
        note: "",
        note_until: 0,
        still_since: None,
        auto_up: None,
    };
    app.set_menu();
    if motion::read().is_none() {
        screen::clear(Color::Dark);
        screen::text_centred(40, "no accelerometer here", Style::Small, Color::Light);
        screen::present();
        while wait(None) != Event::Exit {}
        return;
    }
    let mut drawn = 0;
    loop {
        let now = millis();
        app.read(now);
        app.which_way();
        app.calibrate(now);
        let a = app.angles(app.bubble);
        app.level = if app.level { a[2] < LEVEL_OUT } else { a[2] < LEVEL_IN };
        if now >= drawn + DRAW_MS || drawn == 0 {
            draw(&app, now);
            drawn = now.max(1);
        }
        let event = wait(Some(READ_MS));
        let now = millis();
        if event != Event::Timeout {
            drawn = 0;
        }
        if app.calibrating.is_some() {
            match event {
                Event::Left => app.calibrating = None,
                Event::Centre if matches!(app.calibrating, Some(Calibrating::Forward { .. })) => {
                    // no pulling away: forward is into the screen, or toward its top
                    app.kept.forward = None;
                    app.kept.save();
                    app.calibrating = None;
                    app.say("calibrated", now);
                }
                Event::Exit => return,
                _ => {}
            }
            continue;
        }
        match event {
            Event::Left | Event::Right => {
                app.page = if event == Event::Right {
                    (app.page + 1) % PAGES
                } else {
                    (app.page + PAGES - 1) % PAGES
                };
                app.kept.page = app.page;
                app.held = None;
                app.kept.save();
                app.set_menu();
            }
            Event::Up | Event::Down => {
                let up = event == Event::Up;
                match app.page {
                    G_METER => {
                        let s = app.kept.scale;
                        app.kept.scale = if up { (s + 1).min(SCALES.len() - 1) } else { s.saturating_sub(1) };
                        app.set_menu();
                    }
                    TILT => app.kept.nudge = (app.kept.nudge + if up { 1 } else { -1 }).clamp(-10, 10),
                    _ => {
                        let r = app.kept.reach;
                        app.kept.reach = if up { r.saturating_sub(1) } else { (r + 1).min(3) };
                    }
                }
                app.kept.save();
            }
            Event::Centre => match app.page {
                G_METER => app.clear_peaks(),
                TILT => {
                    app.kept.tilt_level = Some(app.horizon);
                    app.kept.nudge = 0;
                    app.kept.save();
                    app.say("level set", now);
                }
                _ => {
                    // held: the reading from before the press, which tilts maki
                    app.held = match app.held {
                        Some(_) => None,
                        None => app.history.front().copied().or(Some(app.angles(app.bubble))),
                    };
                }
            },
            Event::Menu(i) => match (app.page, i) {
                (G_METER, 0) => app.calibrating = Some(Calibrating::Still { since: now }),
                (G_METER, _) => {
                    app.kept.up = None;
                    app.kept.forward = None;
                    app.kept.save();
                    app.say("cleared", now);
                }
                (TILT, _) => {
                    app.kept.tilt_level = None;
                    app.kept.save();
                    app.say("cleared", now);
                }
                (_, 0) => {
                    app.kept.zero = None;
                    app.calibrating = Some(Calibrating::First { since: now });
                }
                (_, 1) => {
                    let a = app.angles(app.bubble);
                    let z = app.kept.zero.unwrap_or([0.0; 3]);
                    app.kept.zero = Some([a[0] + z[0], a[1] + z[1], 0.0]);
                    app.kept.save();
                    app.say("zeroed", now);
                }
                (_, 2) => {
                    app.kept.zero = None;
                    app.kept.save();
                    app.say("zero cleared", now);
                }
                (_, _) => {
                    app.kept.units = (app.kept.units + 1) % 3;
                    app.kept.save();
                }
            },
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
