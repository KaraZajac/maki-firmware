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
    /// Scalar from an asker: `arg1` is the `tag` of one of its asks, waiting or on screen, to take
    /// back (a passkey's question the computer cancelled). It's answered as timed out.
    Withdraw = 9,
}

/// A decision for the owner, which the launcher shows over whatever is on screen. The app in
/// front is put in the background while it shows, and brought back after.
///
/// Its lists travel packed, a string each (`pack_choices`, `pack_pages`): xous-ipc serializes
/// with 256 bytes of scratch space, and a list takes room there for every entry, so a review of
/// 25 pages (a Monero wallet's backup words) couldn't be sent. A string takes none.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct AskRequest {
    /// Who is asking, shown largest: a site's hostname. A long one is broken at dots, and if it
    /// still doesn't fit its start is cut, never its end.
    pub subject: String,
    /// What they want, in a few words: "Fill login?"
    pub question: String,
    /// What it's about, one line (a username). Not shown when there are choices.
    pub detail: String,
    /// Alternatives to pick from, packed; empty for a plain allow or deny.
    pub choices: String,
    /// What there is to check before deciding (a transaction's payments, an address), gone
    /// through with left and right before the answers; packed.
    pub pages: String,
    /// The answers' labels, or empty for "allow" and "deny".
    pub yes: String,
    pub no: String,
    pub timeout_s: u32,
    /// Asked by an installed app (`ASK_APP_STORE`, `ASK_APP_SIDELOADED`), whose name is the
    /// subject; 0 for maki's own asks. An app's ask is drawn under the app's bar, with no site,
    /// so it can't pass for maki asking on a site's behalf.
    pub app: u8,
    /// Set by the launcher: 0 allowed, 1 denied, 2 timed out.
    pub answer: u32,
    /// Set by the launcher: the choice picked, when allowed.
    pub choice: u32,
    /// The asker's own name for this ask, to take it back with `Withdraw`; 0 for none.
    pub tag: u32,
}

/// `AskRequest::app`: an app from the store is asking.
pub const ASK_APP_STORE: u8 = 1;
/// A sideloaded app is asking: its bar carries the sideloaded mark.
pub const ASK_APP_SIDELOADED: u8 = 2;

/// A page of an ask. The launcher breaks one that doesn't fit onto more screens, repeating the
/// heading, so nothing on it is ever cut.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// a few words, at the top: "Send 1 of 2"
    pub heading: String,
    /// the thing to check, bold: "0.0007 BTC"
    pub value: String,
    /// in fixed-width type across as many lines as it takes: an address
    pub mono: String,
    /// in maki's small type, words wrapped to fit, after `mono`: what something means, in words
    pub prose: String,
}

/// Starts each entry of a packed list.
const ENTRY: char = '\u{1e}';
/// Separates the parts of a packed page.
const PART: char = '\u{1f}';

/// Text into a packed list, without the separators (which would show as nothing anyway).
fn pack_text(out: &mut String, text: &str) {
    out.extend(text.chars().map(|c| if c == ENTRY || c == PART { ' ' } else { c }));
}

/// `AskRequest::choices`, packed.
#[allow(dead_code)] // the client side's (lib.rs)
pub fn pack_choices(choices: &[String]) -> String {
    let mut out = String::new();
    for choice in choices {
        out.push(ENTRY);
        pack_text(&mut out, choice);
    }
    out
}

/// `AskRequest::pages`, packed.
#[allow(dead_code)] // the client side's (lib.rs)
pub fn pack_pages(pages: &[Page]) -> String {
    let mut out = String::new();
    for page in pages {
        out.push(ENTRY);
        for (i, text) in [&page.heading, &page.value, &page.mono, &page.prose].into_iter().enumerate() {
            if i > 0 {
                out.push(PART);
            }
            pack_text(&mut out, text);
        }
    }
    out
}

impl AskRequest {
    /// Its choices, unpacked.
    #[allow(dead_code)] // the launcher's (main.rs)
    pub fn choices(&self) -> Vec<String> { self.choices.split(ENTRY).skip(1).map(String::from).collect() }

    /// Its pages, unpacked.
    #[allow(dead_code)] // the launcher's (main.rs)
    pub fn pages(&self) -> Vec<Page> {
        self.pages
            .split(ENTRY)
            .skip(1)
            .map(|packed| {
                let mut parts = packed.split(PART).map(String::from);
                let mut part = || parts.next().unwrap_or_default();
                Page { heading: part(), value: part(), mono: part(), prose: part() }
            })
            .collect()
    }
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

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use rkyv::rancor::Failure;
    use rkyv::ser::allocator::SubAllocator;
    use rkyv::ser::writer::Buffer as Writer;

    use super::*;

    fn asking(choices: &[String], pages: &[Page]) -> AskRequest {
        AskRequest {
            subject: "Monero".into(),
            question: "Wrote them down?".into(),
            detail: "25 words, in order".into(),
            choices: pack_choices(choices),
            pages: pack_pages(pages),
            yes: "done".into(),
            no: "close".into(),
            timeout_s: 900,
            app: ASK_APP_STORE,
            answer: ANSWER_TIMED_OUT,
            choice: 0,
            tag: 0,
        }
    }

    fn words() -> Vec<Page> {
        (1..=25)
            .map(|i| Page {
                heading: format!("Word {i} of 25"),
                value: "tavern".into(),
                mono: String::new(),
                prose: "Write it down, in order. Keep it off computers.".into(),
            })
            .collect()
    }

    #[test]
    fn lists_unpack_as_they_were_packed() {
        let choices = vec!["alice".to_string(), String::new(), "bob@example.com".into()];
        let req = asking(&choices, &words());
        assert_eq!(req.pages(), words());
        assert_eq!(req.choices(), choices);
        let none = asking(&[], &[]);
        assert!(none.pages().is_empty() && none.choices().is_empty());
        // an empty choice is still a choice, and an empty page still a page
        assert_eq!(asking(&[String::new()], &[]).choices(), vec![String::new()]);
        assert_eq!(asking(&[], &[Page::default()]).pages(), vec![Page::default()]);
    }

    #[test]
    fn the_separators_in_text_make_nothing_more() {
        let sneaky = format!("a{ENTRY}b{PART}c");
        let req = asking(&[sneaky.clone()], &[Page { heading: sneaky, ..Default::default() }]);
        assert_eq!(req.choices(), vec!["a b c".to_string()]);
        assert_eq!(req.pages(), vec![Page { heading: "a b c".into(), ..Default::default() }]);
    }

    /// As xous-ipc's `Buffer::replace` serializes: 256 bytes of scratch space, which a list of
    /// 25 pages outgrew (16 was the most).
    #[test]
    fn a_long_review_goes_through_ipc() {
        let req = asking(&vec!["a login".to_string(); 100], &[words(), words(), words(), words()].concat());
        let mut out = vec![0u8; 64 * 1024];
        let mut scratch = [MaybeUninit::<u8>::uninit(); 256];
        let serialized = rkyv::api::low::to_bytes_in_with_alloc::<_, _, Failure>(
            &req,
            Writer::from(&mut out[..]),
            SubAllocator::new(&mut scratch),
        );
        assert!(serialized.is_ok());
    }
}
