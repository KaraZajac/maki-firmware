//! BAOKEY launcher: the home screen, and the owner of input focus.
//!
//! The launcher is the only process that registers with bao-video for key presses. While an app
//! is in front, keys are relayed to that app and nowhere else; on the home screen they drive the
//! menu. Apps join the menu by registering at startup (see `lib.rs`), so nothing here is specific
//! to any one app.

mod api;
use api::*;
use num_traits::{FromPrimitive, ToPrimitive};
use ux_api::menu::{MenuItem, MenuPayload, menu_matic};
use ux_api::service::gfx::Gfx;
use xous_ipc::Buffer;

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

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("BAOKEY launcher PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let sid = xns.register_name(SERVER_NAME_LAUNCHER, None).expect("can't register server");
    let conn = xous::connect(sid).unwrap();

    let menu_sid = xous::create_server().unwrap();
    let menu = menu_matic(Vec::new(), "BAOKEY", Some(menu_sid), conn, LauncherOp::MenuDone.to_usize().unwrap())
        .expect("couldn't create home menu");

    let gfx = Gfx::new(&xns).unwrap();
    gfx.register_listener(SERVER_NAME_LAUNCHER, LauncherOp::KeyPress.to_usize().unwrap());

    // The PDDB's first-boot format and PIN prompts are modals; drawing the home screen before the
    // mount finishes would paint over them. Wait on a helper thread rather than here: apps register
    // before the mount is triggered, so blocking the main loop would deadlock the boot.
    std::thread::spawn(move || {
        pddb::Pddb::new().is_mounted_blocking();
        xous::send_message(conn, xous::Message::new_scalar(LauncherOp::Ready.to_usize().unwrap(), 0, 0, 0, 0))
            .ok();
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
                        let index = apps.len();
                        menu.add_item(MenuItem {
                            name: reg.name.clone(),
                            action_conn: Some(conn),
                            action_opcode: LauncherOp::Launch.to_u32().unwrap(),
                            action_payload: MenuPayload::Scalar([index as u32, 0, 0, 0]),
                            close_on_select: true,
                        });
                        log::info!("registered app '{}' ({})", reg.name, reg.server_name);
                        apps.push(App {
                            name: reg.name,
                            conn: app_conn,
                            key_op: reg.key_op as usize,
                            focus_op: reg.focus_op as usize,
                        });
                        if ready && front.is_none() {
                            menu.redraw();
                        }
                    }
                    Err(e) => log::error!("couldn't connect to app server {}: {:?}", reg.server_name, e),
                }
            }
            Some(LauncherOp::Ready) => {
                ready = true;
                if front.is_none() {
                    menu.redraw();
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
                                // the menu indexes its items on select, so an empty menu can't take one
                                Some('∴') if apps.is_empty() => {}
                                Some(c @ ('∴' | '↑' | '↓')) => menu.key_press(c),
                                _ => {}
                            }
                        }
                    }
                    None => {}
                }
            }),
            Some(LauncherOp::Launch) => xous::msg_scalar_unpack!(msg, index, _, _, _, {
                if let Some(app) = apps.get(index) {
                    log::info!("bringing '{}' to the front", app.name);
                    front = Some(index);
                    set_focus(app, Focus::Foreground);
                }
            }),
            Some(LauncherOp::Home) => {
                if let Some(i) = front.take() {
                    log::info!("'{}' returned to the home screen", apps[i].name);
                    set_focus(&apps[i], Focus::Background);
                }
                if ready {
                    menu.redraw();
                }
            }
            Some(LauncherOp::MenuDone) => {}
            None => log::error!("unknown launcher opcode {}", msg.body.id()),
        }
    }
}
