//! IPC between the launcher and the apps it manages.

/// xous-names name of the launcher's server.
pub const SERVER_NAME_LAUNCHER: &str = "_maki launcher_";

/// How long an ask waits: `normal_s` on a badge, and hours in a demo build (`MAKI_DEMO`). The
/// emulator skips through idle time, the faster the quieter maki is, so a scripted press can
/// come many device minutes after its screen went up.
pub const fn ask_timeout(normal_s: u32) -> u32 {
    if option_env!("MAKI_DEMO").is_some() { 6 * 3600 } else { normal_s }
}

/// Sent as `arg1` of an app's `focus_op` scalar whenever the app moves to or from the front.
#[derive(Debug, Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum Focus {
    Background = 0,
    Foreground = 1,
    /// The owner picked Exit from the app's menu: in the background, and done with. (Apps that
    /// only ask whether they're in front can treat it as Background.)
    Exited = 2,
}

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum LauncherOp {
    /// Memory message carrying an `AppRegistration`.
    Register = 0,
    /// Scalar from bao-video; `arg1..arg4` are key characters.
    KeyPress = 1,
    /// Scalar from the app in front: return to the home screen.
    Home = 2,
    /// Scalar from our own helper thread once the PDDB has mounted; safe to draw from here on.
    Ready = 3,
    /// Scalar from our own timer thread, once a second, to keep the clock current.
    Tick = 4,
    /// Scalar from maki-link: `arg1` is 0 (unset), 1 (unverified) or 2 (verified).
    TimeState = 5,
    /// Scalar from maki-link: `arg1` is 1 while the desktop app is linked, 0 otherwise.
    LinkState = 6,
    /// Memory message (mutable lend) carrying an `AskRequest`: shown over whatever is in front,
    /// answered when the owner decides or it times out.
    Ask = 7,
    /// Memory message carrying an `AppRegistration` whose `server_name` and `key_op` name an
    /// app to take off the home screen (the rest is ignored): an installed app removed.
    Unregister = 8,
}

/// A decision for the owner, which the launcher shows over whatever is on screen. The app in
/// front is put in the background while it shows, and brought back after.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AskRequest {
    /// Who is asking, shown largest: a site's hostname. A long one is broken at dots, and if it
    /// still doesn't fit its start is cut, never its end.
    pub subject: String,
    /// What they want, in a few words: "Fill login?"
    pub question: String,
    /// What it's about, one line (a username). Not shown when there are choices.
    pub detail: String,
    /// Alternatives to pick from; empty for a plain allow or deny.
    pub choices: Vec<String>,
    /// What there is to check before deciding (a transaction's payments, an address), gone
    /// through with left and right before the answers.
    pub pages: Vec<Page>,
    /// The answers' labels, or empty for "allow" and "deny".
    pub yes: String,
    pub no: String,
    pub timeout_s: u32,
    /// Set by the launcher: 0 allowed, 1 denied, 2 timed out.
    pub answer: u32,
    /// Set by the launcher: the choice picked, when allowed.
    pub choice: u32,
}

/// A page of an ask. The launcher breaks one that doesn't fit onto more screens, repeating the
/// heading, so nothing on it is ever cut.
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Page {
    /// a few words, at the top: "Send 1 of 2"
    pub heading: String,
    /// the thing to check, bold: "0.0007 BTC"
    pub value: String,
    /// in fixed-width type across as many lines as it takes: an address
    pub mono: String,
}

/// The owner's decision on an `AskRequest`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(dead_code)] // the client side's (lib.rs); the launcher itself answers in codes
pub enum Answer {
    /// Allowed; with choices, the index of the one picked.
    Allowed(usize),
    Denied,
    TimedOut,
}

pub(crate) const ANSWER_ALLOWED: u32 = 0;
pub(crate) const ANSWER_DENIED: u32 = 1;
pub(crate) const ANSWER_TIMED_OUT: u32 = 2;

/// Sent once by an app at startup to appear on the home screen.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppRegistration {
    /// Name shown on the home screen.
    pub name: String,
    /// xous-names server the launcher connects to for this app.
    pub server_name: String,
    /// Scalar opcode that receives key presses while the app is in front.
    pub key_op: u32,
    /// Scalar opcode that receives a `Focus` value on every change.
    pub focus_op: u32,
    /// Opcode for the app's menu (see `AppMenu`), or 0 for none: its menu is then just Exit.
    pub menu_op: u32,
    /// A 64x64 icon in `maki_icons` form, or empty for the app's initial in a square.
    pub icon: Vec<u32>,
}

/// An app's menu, which the launcher shows when the owner presses left and right together in it.
///
/// The launcher lends this to the app's `menu_op` for the app to fill in, then shows the items
/// with Exit after them. If the owner picks one of the app's items, the app gets the same
/// `menu_op` again as a scalar, `arg1` the index, and then its focus back. Exit takes the app to
/// the background. Fill it in promptly: the launcher waits.
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AppMenu {
    pub items: Vec<String>,
}
