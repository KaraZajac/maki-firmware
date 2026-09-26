//! IPC between the launcher and the apps it manages.

/// xous-names name of the launcher's server.
pub const SERVER_NAME_LAUNCHER: &str = "_BAOKEY launcher_";

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
    KeyPress,
    /// Scalar from the home menu; `arg1` is the index of the app to bring to the front.
    Launch,
    /// Scalar from the app in front: return to the home screen.
    Home,
    /// Scalar from the home menu after a selection. Nothing to do: the app is drawing now.
    MenuDone,
    /// Scalar from our own helper thread once the PDDB has mounted; safe to draw from here on.
    Ready,
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
