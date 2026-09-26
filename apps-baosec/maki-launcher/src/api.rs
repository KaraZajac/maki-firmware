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
}

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
