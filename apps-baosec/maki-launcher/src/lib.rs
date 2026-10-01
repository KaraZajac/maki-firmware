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

    /// Take an app off the home screen: the one registered with this server and key opcode. If
    /// it's in front, the home screen comes back.
    pub fn unregister(&self, server_name: &str, key_op: u32) -> Result<(), xous::Error> {
        let reg = AppRegistration {
            name: String::new(),
            server_name: server_name.into(),
            key_op,
            focus_op: 0,
            menu_op: 0,
            icon: Vec::new(),
        };
        let buf = Buffer::into_buf(reg).or(Err(xous::Error::InternalError))?;
        buf.lend(self.conn, LauncherOp::Unregister.to_u32().unwrap()).map(|_| ())
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
        self.send_ask(AskRequest {
            subject: subject.into(),
            question: question.into(),
            detail: detail.into(),
            choices: pack_choices(choices),
            pages: String::new(),
            yes: String::new(),
            no: String::new(),
            timeout_s,
            app: 0,
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag: 0,
        })
    }

    /// `ask` with no choices, which this process can take back with `withdraw(tag)` until it's
    /// answered: a passkey's question, which the computer may cancel or give up on. `tag` is
    /// nonzero, and the asker's own.
    pub fn ask_tagged(
        &self,
        subject: &str,
        question: &str,
        detail: &str,
        timeout_s: u32,
        tag: u32,
    ) -> Result<Answer, xous::Error> {
        self.send_ask(AskRequest {
            subject: subject.into(),
            question: question.into(),
            detail: detail.into(),
            choices: String::new(),
            pages: String::new(),
            yes: String::new(),
            no: String::new(),
            timeout_s,
            app: 0,
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag,
        })
    }

    /// Take back this process's ask `tag`, waiting or on screen: its asker hears it timed out. An
    /// ask still on its way to the launcher isn't there to take back yet, so an asker that must
    /// see it gone sends this until its ask returns.
    pub fn withdraw(&self, tag: u32) -> Result<(), xous::Error> {
        xous::send_message(
            self.conn,
            xous::Message::new_scalar(LauncherOp::Withdraw.to_usize().unwrap(), tag as usize, 0, 0, 0),
        )
        .map(|_| ())
    }

    /// An installed app's question for the owner (the app host asks for it): shown under the
    /// app's own bar, its name and, if it's sideloaded, the mark, with `yes` and `no` as the
    /// answers ("allow" and "deny" if empty).
    #[allow(clippy::too_many_arguments)]
    pub fn ask_app(
        &self,
        name: &str,
        sideloaded: bool,
        question: &str,
        detail: &str,
        yes: &str,
        no: &str,
        timeout_s: u32,
    ) -> Result<Answer, xous::Error> {
        self.send_ask(AskRequest {
            subject: name.into(),
            question: question.into(),
            detail: detail.into(),
            choices: String::new(),
            pages: String::new(),
            yes: yes.into(),
            no: no.into(),
            timeout_s,
            app: if sideloaded { ASK_APP_SIDELOADED } else { ASK_APP_STORE },
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag: 0,
        })
    }

    /// An installed app's review for the owner (a wallet app's, before it signs; the app host
    /// asks for it): `pages` to go through, then `question` with `yes` and `no`, all under the
    /// app's own bar, its name and, if it's sideloaded, the mark.
    #[allow(clippy::too_many_arguments)]
    pub fn review_app(
        &self,
        name: &str,
        sideloaded: bool,
        question: &str,
        detail: &str,
        pages: Vec<Page>,
        yes: &str,
        no: &str,
        timeout_s: u32,
    ) -> Result<Answer, xous::Error> {
        self.send_ask(AskRequest {
            subject: name.into(),
            question: question.into(),
            detail: detail.into(),
            choices: String::new(),
            pages: pack_pages(&pages),
            yes: yes.into(),
            no: no.into(),
            timeout_s,
            app: if sideloaded { ASK_APP_SIDELOADED } else { ASK_APP_STORE },
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag: 0,
        })
    }

    /// Ask with something to check first: the owner goes through `pages` with left and right
    /// (the centre moves on), then answers `yes` or `no` ("sign", "reject"). `subject`,
    /// `question` and `detail` show with the answers, as a plain ask shows them.
    #[allow(clippy::too_many_arguments)]
    pub fn review(
        &self,
        subject: &str,
        question: &str,
        detail: &str,
        pages: Vec<Page>,
        yes: &str,
        no: &str,
        timeout_s: u32,
    ) -> Result<Answer, xous::Error> {
        self.send_ask(AskRequest {
            subject: subject.into(),
            question: question.into(),
            detail: detail.into(),
            choices: String::new(),
            pages: pack_pages(&pages),
            yes: yes.into(),
            no: no.into(),
            timeout_s,
            app: 0,
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag: 0,
        })
    }

    fn send_ask(&self, request: AskRequest) -> Result<Answer, xous::Error> {
        // `into_buf` would size the buffer by the struct, one page, which a review with many
        // pages outgrows: room for the text, plus its bookkeeping
        let text = request.pages.len() + request.choices.len();
        let mut buf = Buffer::new((4096 + text).next_multiple_of(4096));
        buf.replace(request).or(Err(xous::Error::InternalError))?;
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
