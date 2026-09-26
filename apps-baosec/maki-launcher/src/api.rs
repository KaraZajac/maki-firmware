//! IPC between the launcher and the apps it manages.

/// xous-names name of the launcher's server.
pub const SERVER_NAME_LAUNCHER: &str = "_maki launcher_";

/// Sent as `arg1` of an app's `focus_op` scalar whenever the app moves to or from the front.
#[derive(Debug, Copy, Clone, PartialEq, Eq, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum Focus {
    Background = 0,
    Foreground = 1,
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
    pub timeout_s: u32,
    /// Set by the launcher: 0 allowed, 1 denied, 2 timed out.
    pub answer: u32,
    /// Set by the launcher: the choice picked, when allowed.
    pub choice: u32,
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
}
