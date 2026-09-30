//! maki's own apps, in one process: Passkeys (passkeys.rs). It keeps its own screen state; this
//! registers it with the launcher and hands it its key presses, focus and menu. maki's own apps
//! share a process to spare the badge's memory: each process carries its own runtime and stacks,
//! and at boot the badge is near its limit (DEVELOPMENT.md, "Known issues"). Bitcoin was here;
//! wallets are apps from the maki store now (ARCHITECTURE.md, "Wallets are apps").

mod passkeys;

use maki_launcher::{Focus, MenuMessage};
use maki_ui::Key;
use num_traits::{FromPrimitive, ToPrimitive};

const SERVER_NAME: &str = "_maki apps_";

// Each built-in app gets its own Key/Focus/Menu opcodes, prefixed with its name so a second app
// can sit beside the first.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, num_derive::FromPrimitive, num_derive::ToPrimitive)]
enum Op {
    PasskeysKey = 3,
    PasskeysFocus = 4,
    PasskeysMenu = 5,
}

/// The keys in a key-press scalar from the launcher.
fn keys_of(msg: &xous::MessageEnvelope) -> Vec<Key> {
    msg.body
        .scalar_message()
        .map(|s| [s.arg1, s.arg2, s.arg3, s.arg4].iter().filter_map(|&k| char::from_u32(k as u32).and_then(Key::from_char)).collect())
        .unwrap_or_default()
}

/// Whether a focus scalar puts the app in front.
fn in_front(msg: &xous::MessageEnvelope) -> bool {
    msg.body.scalar_message().map(|s| s.arg1 == Focus::Foreground.to_usize().unwrap()).unwrap_or(false)
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("maki-apps PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME, None).expect("can't register server");
    let launcher = maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher");
    #[allow(clippy::single_element_loop)] // the built-in apps registered here: one so far
    for (name, key, focus, menu, icon) in [
        ("Passkeys", Op::PasskeysKey, Op::PasskeysFocus, Op::PasskeysMenu, &maki_icons::PASSKEYS),
    ] {
        launcher
            .register(name, SERVER_NAME, key.to_u32().unwrap(), focus.to_u32().unwrap(), menu.to_u32().unwrap(), Some(icon))
            .expect("couldn't register with the launcher");
    }

    let mut passkeys = passkeys::Passkeys::new(&xns, launcher);

    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(Op::PasskeysKey) => keys_of(&msg).into_iter().for_each(|k| passkeys.key(k)),
            Some(Op::PasskeysFocus) => passkeys.focus(in_front(&msg)),
            Some(Op::PasskeysMenu) => match MenuMessage::of(&msg) {
                Some(MenuMessage::Fill) => MenuMessage::fill(&mut msg, passkeys.menu()),
                Some(MenuMessage::Picked(i)) => passkeys.picked(i),
                None => {}
            },
            None => log::warn!("unknown opcode {}", msg.body.id()),
        }
    }
}
