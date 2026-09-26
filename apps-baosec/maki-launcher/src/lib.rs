//! Client side of the maki launcher.
//!
//! An app registers once at startup and starts in the background. From then on it receives
//! key presses only while it is in front, plus a `Focus` scalar on every change. An app in the
//! background must not draw. Nothing enforces that yet; it belongs with the app-isolation work.
//!
//! Apps follow the three-button model (ARCHITECTURE.md): left and right move, the centre (`🔥`)
//! confirms what the screen offers. Left and right pressed together never reach an app: the
//! launcher shows the app's menu (`AppMenu`) instead, with Exit, which is how every app is left.

pub mod api;
pub use api::*;
use num_traits::ToPrimitive;
use xous_ipc::Buffer;

pub struct Launcher {
    conn: xous::CID,
}

impl Launcher {
    /// Blocks until the launcher is running.
    pub fn new(xns: &xous_names::XousNames) -> Result<Self, xous::Error> {
        let conn = xns.request_connection_blocking(SERVER_NAME_LAUNCHER)?;
        Ok(Launcher { conn })
    }

    /// Put this app on the home screen. `menu_op` is 0 for an app with no menu of its own; the
    /// icon is 64x64 in `maki_icons` form.
    pub fn register(
        &self,
        name: &str,
        server_name: &str,
        key_op: u32,
        focus_op: u32,
        menu_op: u32,
        icon: Option<&[u32; 128]>,
    ) -> Result<(), xous::Error> {
        let reg = AppRegistration {
            name: name.into(),
            server_name: server_name.into(),
            key_op,
            focus_op,
            menu_op,
            icon: icon.map(|i| i.to_vec()).unwrap_or_default(),
        };
        let buf = Buffer::into_buf(reg).or(Err(xous::Error::InternalError))?;
        buf.lend(self.conn, LauncherOp::Register.to_u32().unwrap()).map(|_| ())
    }

    /// Tell the home screen whether the clock is trustworthy: 0 unset, 1 unverified, 2 verified.
    pub fn set_time_state(&self, state: u8) -> Result<(), xous::Error> {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(LauncherOp::TimeState.to_usize().unwrap(), state as usize, 0, 0, 0),
        )
        .map(|_| ())
    }

    /// Tell the home screen whether the desktop app is linked.
    pub fn set_link_state(&self, linked: bool) -> Result<(), xous::Error> {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(LauncherOp::LinkState.to_usize().unwrap(), linked as usize, 0, 0, 0),
        )
        .map(|_| ())
    }

    /// Ask the owner, over whatever is on screen, and wait for the answer: they allow (picking
    /// one of `choices`, if there are any), deny, or let `timeout_s` run out. One ask shows at a
    /// time; others wait their turn, and their time doesn't start until they show.
    pub fn ask(
        &self,
        subject: &str,
        question: &str,
        detail: &str,
        choices: &[String],
        timeout_s: u32,
    ) -> Result<Answer, xous::Error> {
        let request = AskRequest {
            subject: subject.into(),
            question: question.into(),
            detail: detail.into(),
            choices: choices.to_vec(),
            timeout_s,
            answer: ANSWER_TIMED_OUT,
            choice: 0,
        };
        let mut buf = Buffer::into_buf(request).or(Err(xous::Error::InternalError))?;
        buf.lend_mut(self.conn, LauncherOp::Ask.to_u32().unwrap())?;
        let answered = buf.to_original::<AskRequest, _>().or(Err(xous::Error::InternalError))?;
        Ok(match answered.answer {
            ANSWER_ALLOWED => Answer::Allowed(answered.choice as usize),
            ANSWER_DENIED => Answer::Denied,
            _ => Answer::TimedOut,
        })
    }

    /// Return to the home screen. Stop drawing *before* calling this, or the app's next frame
    /// can land on top of the home screen.
    pub fn home(&self) -> Result<(), xous::Error> {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(LauncherOp::Home.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .map(|_| ())
    }
}

/// For an app's `menu_op` handler: the launcher is either asking for the menu's items (fill them
/// in with `items`) or saying which one the owner picked.
pub enum MenuMessage {
    Fill,
    Picked(usize),
}

impl MenuMessage {
    pub fn of(msg: &xous::MessageEnvelope) -> Option<MenuMessage> {
        if msg.body.memory_message().is_some() {
            Some(MenuMessage::Fill)
        } else {
            msg.body.scalar_message().map(|s| MenuMessage::Picked(s.arg1))
        }
    }

    /// Answer a `Fill` with the app's items. The launcher adds Exit after them.
    pub fn fill(msg: &mut xous::MessageEnvelope, items: &[&str]) {
        if let Some(mem) = msg.body.memory_message_mut() {
            let mut buffer = unsafe { Buffer::from_memory_message_mut(mem) };
            buffer.replace(AppMenu { items: items.iter().map(|s| s.to_string()).collect() }).ok();
        }
    }
}
