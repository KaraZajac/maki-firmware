// Changed for maki (a fork of Xous: github.com/KaraZajac/maki-firmware) in 2026; its git history says what.
mod ux;
use ux::*;
mod itemcache;
use itemcache::*;
mod actions;
use actions::ActionOp;
mod storage;
mod submenu;
mod totp;
pub mod vault_api;
pub use vault_api::*;
mod generator;
mod link;
mod vendor_commands;

use core::sync::atomic::{AtomicBool, Ordering};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use locales::t;
use num_traits::*;
use pddb::Pddb;
use vault2::Transport;
use vault2::ctap::main_hid::HidIterType;
use vault2::env::Env;
use vault2::env::xous::XousEnv;
use xous::msg_blocking_scalar_unpack;
use xous_ipc::Buffer;
use xous_usb_hid::device::fido::*;

use crate::vendor_commands::VendorSession;

/*
Dev status & notes --

UI interaction planning.

Main mode of interaction is QR code scanning. This should be accessible with a single button. Thus:

1. middle center button pops up QR code scanner. Behavior then depends on the code scanned.
  Note: will need a menu item to replace passwords - we should keep the old passwords in case it's needed?

Observation: left/right paging buttons don't do a lot with O(hundreds) passwords, but scrolling
is fast. So don't implement left/right paging as on Precursor, freeing up two buttons.

2. Left button: pops up text entry to filter lists

3. Right button: "action" button - used to type the current password, and/or approve FIDO sigs

4. Up/down/select jog: exclusively for menu interactions. Menus are always linear, with select.

This UI design does not allow for hierarchical menus because there isn't a "back" button, but
we *could*, possibly, if we really needed menu hierarchies, repurpose a left/right button as
a hierarchy nav function.

-> But can we keep the menu shallow?

Architectural notes --

Data is long-term stored in the PDDB. Each of the three modes have their own dictionary
(OpenSK/FIDO2, passwords, totp).

The data is read into an `ItemList`, which is a RAM-based structure that caches all the PDDB data for
fast sorting, searching etc. `ItemList` is where meta-operations like search & sort happen.

For rendering the data is then copied into a UI element, such as a `ScrollableList`, based on
the currently active mode.
  */

pub(crate) const SERVER_NAME_VAULT2: &str = "_Vault2_";

#[derive(Copy, Clone, PartialEq, Eq, Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum VaultMode {
    Totp,
    Password,
}

#[derive(Debug, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
pub struct SelectedEntry {
    pub key_guid: String,
    pub description: String,
    pub mode: VaultMode,
}

/// Add a TOTP entry from a QR code, through the camera, and show the codes again.
fn scan_qr(
    actions_conn: xous::CID,
    allow_totp_rendering: &AtomicBool,
    tt: &ticktimer_server::Ticktimer,
    vault_ui: &mut VaultUi,
) {
    allow_totp_rendering.store(false, Ordering::SeqCst);
    xous::send_message(
        actions_conn,
        xous::Message::new_blocking_scalar(ActionOp::AcquireQr.to_usize().unwrap(), 0, 0, 0, 0),
    )
    .ok();
    // wait a moment for the last frame to clear before redrawing the UI
    tt.sleep_ms(100).ok();
    allow_totp_rendering.store(true, Ordering::SeqCst);
    // reload DB to pickup the new data
    xous::send_message(
        actions_conn,
        xous::Message::new_blocking_scalar(ActionOp::ReloadDb.to_usize().unwrap(), 0, 0, 0, 0),
    )
    .ok();
    vault_ui.refresh_draw_list();
    vault_ui.redraw();
}

/// Show one kind of record: TOTP codes, which tick, or passwords.
fn switch_mode(
    to: VaultMode,
    mode: &Mutex<VaultMode>,
    actions_conn: xous::CID,
    pump_conn: xous::CID,
    pace: &totp::Pace,
    allow_totp_rendering: &AtomicBool,
    vault_ui: &mut VaultUi,
) {
    // the lock has to be released before the reload below, which reads the mode
    *mode.lock().unwrap() = to;
    if to == VaultMode::Password {
        allow_totp_rendering.store(false, Ordering::SeqCst);
    }
    xous::send_message(
        actions_conn,
        xous::Message::new_blocking_scalar(ActionOp::ReloadDb.to_usize().unwrap(), 0, 0, 0, 0),
    )
    .ok();
    // the list on screen is built per mode: without this, passwords showed an empty frame
    vault_ui.refresh_draw_list();
    if to == VaultMode::Totp {
        allow_totp_rendering.store(true, Ordering::SeqCst);
        pace.start(pump_conn);
    }
    vault_ui.redraw();
}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Vault2 PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();
    let tt = ticktimer_server::Ticktimer::new().unwrap();

    // Register the server with xous
    let sid = xns.register_name(SERVER_NAME_VAULT2, None).expect("can't register server");
    let conn = xous::connect(sid).unwrap();

    // global shared state
    let mode = Arc::new(Mutex::new(VaultMode::Totp));
    let allow_totp_rendering = Arc::new(AtomicBool::new(true));
    let item_lists = Arc::new(Mutex::new(ItemLists::new()));
    let action_active = Arc::new(AtomicBool::new(false));
    // Protects access to the openSK PDDB entries from simultaneous readout on the UX while OpenSK is updating
    let opensk_mutex = Arc::new(Mutex::new(0));
    let allow_host = Arc::new(AtomicBool::new(false));

    let mut vault_ui = VaultUi::new(&xns, conn, item_lists.clone(), mode.clone());

    // spawn the TOTP pumper
    let pump_sid = xous::create_server().unwrap();
    let pace = Arc::new(totp::Pace::default());
    crate::totp::pumper(mode.clone(), pump_sid, conn, allow_totp_rendering.clone(), pace.clone());
    let pump_conn = xous::connect(pump_sid).unwrap();

    // maki: key presses arrive through the launcher, and only while the vault is in front.
    // The launcher is itself a filtered listener on the `Gfx` subsystem, so modals still take
    // precedence exactly as before.
    // Two ways in from the home screen, one per kind of record: same keys, and each entry's own
    // focus message says which to open on.
    let launcher = maki_launcher::Launcher::new(&xns).expect("couldn't connect to the launcher");
    for (name, focus_op, icon) in [
        ("Authenticator", VaultOp::FocusChange, &maki_icons::AUTHENTICATOR),
        ("Passwords", VaultOp::FocusPasswords, &maki_icons::PASSWORDS),
    ] {
        launcher
            .register(
                name,
                SERVER_NAME_VAULT2,
                VaultOp::KeyPress.to_u32().unwrap(),
                focus_op.to_u32().unwrap(),
                VaultOp::AppMenu.to_u32().unwrap(),
                Some(icon),
            )
            .expect("couldn't register with the launcher");
    }

    // maki: logins and codes for the browser, approved on screen
    link::start(conn);

    // maki: the records live in the secret basis, which opens with the PIN, after this has
    // loaded its lists; load them again then
    thread::spawn(move || {
        maki_keys::Keys::new(&xous_names::XousNames::new().unwrap())
            .expect("couldn't connect to maki-keys")
            .wait_unlocked();
        xous::send_message(
            conn,
            xous::Message::new_scalar(VaultOp::ReloadDbAndFullRedraw.to_usize().unwrap(), 0, 0, 0, 0),
        )
        .ok();
    });

    // spawn the actions server. This is responsible for grooming the UX elements. It
    // has to be in its own thread because it uses blocking modal calls that would cause
    // redraws of the background list to block/fail.
    let actions_sid = xous::create_server().unwrap();

    let _ = thread::spawn({
        let main_conn = conn.clone();
        let sid = actions_sid.clone();
        let mode = mode.clone();
        let item_lists = item_lists.clone();
        let action_active = action_active.clone();
        move || {
            let mut manager = crate::actions::ActionManager::new(main_conn, mode, item_lists, action_active);
            loop {
                let msg = xous::receive_message(sid).unwrap();
                let opcode: Option<ActionOp> = FromPrimitive::from_usize(msg.body.id());
                log::debug!("{:?}", opcode);
                match opcode {
                    Some(ActionOp::MenuAddnew) => {
                        manager.activate();
                        manager.menu_addnew(); // this is responsible for updating the item cache
                        manager.deactivate();
                    }
                    Some(ActionOp::MenuDeleteStage2) => {
                        let buffer =
                            unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                        let entry = buffer.to_original::<SelectedEntry, _>().unwrap();
                        manager.activate();
                        manager.menu_delete(entry);
                        manager.retrieve_db();
                        manager.deactivate();
                    }
                    Some(ActionOp::MenuEditStage2) => {
                        let buffer =
                            unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                        let entry = buffer.to_original::<SelectedEntry, _>().unwrap();
                        manager.activate();
                        manager.menu_edit(&entry); // this is responsible for updating the item cache
                        manager.update_db_entry(&entry);
                        manager.deactivate();
                    }
                    Some(ActionOp::MenuUnlockBasis) => {
                        manager.activate();
                        manager.unlock_basis();
                        manager.item_lists.lock().unwrap().clear(VaultMode::Password); // clear the cached item list for passwords (totp/fido are not cached and don't need clearing)
                        manager.retrieve_db();
                        manager.deactivate();
                    }
                    Some(ActionOp::MenuManageBasis) => {
                        manager.activate();
                        manager.manage_basis();
                        manager.item_lists.lock().unwrap().clear(VaultMode::Password); // clear the cached item list for passwords
                        manager.retrieve_db();
                        manager.deactivate();
                    }
                    Some(ActionOp::MenuClose) => {
                        // dummy activate/de-activate cycle because we have to trigger a redraw of the
                        // underlying UX
                        manager.activate();
                        manager.deactivate();
                    }
                    Some(ActionOp::UpdateOneItem) => {
                        let buffer =
                            unsafe { Buffer::from_memory_message(msg.body.memory_message().unwrap()) };
                        let entry = buffer.to_original::<SelectedEntry, _>().unwrap();
                        manager.activate();
                        manager.update_db_entry(&entry);
                        manager.deactivate();
                    }
                    Some(ActionOp::UpdateMode) => msg_blocking_scalar_unpack!(msg, _, _, _, _, {
                        // the password DBs are now not shared between modes, so no need to re-retrieve it.
                        if manager.is_db_empty() {
                            manager.retrieve_db();
                        }
                        xous::return_scalar(msg.sender, 1).unwrap();
                    }),
                    Some(ActionOp::ReloadDb) => msg_blocking_scalar_unpack!(msg, _, _, _, _, {
                        manager.retrieve_db();
                        xous::return_scalar(msg.sender, 1).unwrap();
                    }),
                    Some(ActionOp::AcquireQr) => msg_blocking_scalar_unpack!(msg, _, _, _, _, {
                        manager.acquire_qr();
                        manager.retrieve_db();
                        xous::return_scalar(msg.sender, 1).unwrap();
                    }),
                    Some(ActionOp::Quit) => {
                        break;
                    }
                    None => {
                        log::error!("msg could not be decoded {:?}", msg);
                    }
                    #[cfg(feature = "vault-testing")]
                    Some(ActionOp::GenerateTests) => {
                        manager.populate_tests();
                        manager.retrieve_db();
                    }
                }
            }
            xous::destroy_server(sid).ok();
        }
    });

    let actions_conn = xous::connect(actions_sid).unwrap();

    // spawn the FIDO2 USB handler
    let _ = thread::spawn({
        let allow_host = allow_host.clone();
        let opensk_mutex = opensk_mutex.clone();
        let conn = conn.clone();
        move || {
            let mut vendor_session = VendorSession::default();
            // maki: the passkeys' secrets come from the recovery phrase, through maki-keys, which
            // hands them to this process alone: claim that before anything else can
            let keys = maki_keys::Keys::new(&xous_names::XousNames::new().unwrap())
                .expect("couldn't connect to maki-keys");
            if !keys.claim_fido() {
                log::error!("another process has the FIDO role: no passkeys");
            }
            // block until the PDDB is mounted
            let pddb = pddb::Pddb::new();
            pddb.is_mounted_blocking();
            // maki: and until the PIN has opened the secret basis, so that the FIDO store lands
            // in it, not in the system basis, and there's a phrase to derive the secrets from
            // (during setup the PIN comes first)
            keys.wait_phrase();

            let mut env = XousEnv::new(conn);
            match keys.fido_keys() {
                Some(mut secrets) => {
                    env.set_phrase_keys(&secrets);
                    secrets.fill(0);
                    log::info!("FIDO: secrets from the recovery phrase");
                }
                None => log::error!("maki-keys gave no FIDO secrets: no credential can be made"),
            }
            let mut ctap = vault2::Ctap::new(env, Instant::now());
            let mut generation = keys.status_and_generation().1;
            loop {
                match ctap.env().main_hid_connection().u2f_wait_incoming() {
                    Ok(msg) => {
                        // maki: nothing is answered while maki is locked. The secret basis is
                        // closed, and the store would read the system basis instead, even make
                        // keys there. The request is dropped (the browser tries again) until the
                        // PIN opens the basis, and then the store re-reads what it holds.
                        let (state, now) = keys.status_and_generation();
                        if state != maki_keys::State::Unlocked {
                            log::info!("FIDO request while locked: waiting for the PIN");
                            keys.wait_unlocked();
                            ctap.env().store().refresh();
                            generation = keys.status_and_generation().1;
                            continue;
                        }
                        // and a restore may have added passkeys to the store behind its back
                        if now != generation {
                            generation = now;
                            ctap.env().store().refresh();
                        }
                        ctap.update_timeouts(Instant::now());
                        let mutex = opensk_mutex.lock().unwrap();
                        log::trace!("Received U2F packet");
                        let typed_reply =
                            ctap.process_hid_packet(&msg.packet, Transport::MainHid, Instant::now());
                        match typed_reply {
                            HidIterType::Ctap(reply) => {
                                for pkt_reply in reply {
                                    let mut reply = RawFidoReport::default();
                                    reply.packet.copy_from_slice(&pkt_reply);
                                    let status = ctap.env().main_hid_connection().u2f_send(reply);
                                    match status {
                                        Ok(()) => {
                                            log::trace!("Sent U2F packet");
                                        }
                                        Err(e) => {
                                            log::error!("Error sending U2F packet: {:?}", e);
                                        }
                                    }
                                }
                            }
                            HidIterType::Vendor(msg) => {
                                let reply = match vendor_commands::handle_vendor_data(
                                    msg.cmd as u8,
                                    msg.cid,
                                    msg.payload,
                                    &mut vendor_session,
                                ) {
                                    Ok(return_payload) => {
                                        // if None, this means we've finished parsing all that
                                        // was needed, and we handle/respond with real data

                                        match return_payload {
                                            Some(data) => data,
                                            None => {
                                                log::debug!("starting processing of vendor data...");
                                                let resp = vendor_commands::handle_vendor_command(
                                                    &mut vendor_session,
                                                    allow_host.load(Ordering::SeqCst),
                                                );
                                                log::debug!("finished processing of vendor data!");

                                                match vendor_session.is_backup() {
                                                    true => {
                                                        if vendor_session.has_backup_data() {
                                                            resp
                                                        } else {
                                                            vendor_session = VendorSession::default();
                                                            resp
                                                        }
                                                    }
                                                    false => {
                                                        vendor_session = VendorSession::default();
                                                        resp
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(session_error) => {
                                        // reset the session
                                        vendor_session = VendorSession::default();

                                        session_error.ctaphid_error(msg.cid)
                                    }
                                };
                                for pkt_reply in reply {
                                    let mut reply = RawFidoReport::default();
                                    reply.packet.copy_from_slice(&pkt_reply);
                                    let status = ctap.env().main_hid_connection().u2f_send(reply);
                                    match status {
                                        Ok(()) => {
                                            log::trace!("Sent U2F packet");
                                        }
                                        Err(e) => {
                                            log::error!("Error sending U2F packet: {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        drop(mutex);
                    }
                    Err(e) => match e {
                        _ => {
                            log::warn!("FIDO listener got an error: {:?}", e);
                        }
                    },
                }
            }
        }
    });

    let menu_sid = xous::create_server().unwrap();
    let menu_mgr = submenu::create_submenu(conn, actions_conn, menu_sid);
    let modals = modals::Modals::new(&xns).unwrap();
    vault_ui.apply_glyph_style();

    // give the system a second to stabilize, then try to mount
    tt.sleep_ms(1000).ok();
    let pddb = pddb::Pddb::new();
    pddb.try_mount();

    // reload the database
    xous::send_message(
        actions_conn,
        xous::Message::new_blocking_scalar(ActionOp::ReloadDb.to_usize().unwrap(), 0, 0, 0, 0),
    )
    .ok();
    vault_ui.refresh_draw_list();

    #[cfg(not(feature = "hosted-baosec"))]
    {
        // check/trigger swap encryption before starting the main loop
        let xns = xous_names::XousNames::new().unwrap();
        let keystore = keystore::Keystore::new(&xns);
        const THROW_AWAY_SERVER: &'static str = "_use once server_";
        const THROW_AWAY_OP: usize = 42;
        // idle forever, maybe turn this into a full blocking server that just parks and ends
        let status_server = xns.register_name(THROW_AWAY_SERVER, None).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(200)); // settle the system a little bit out of sheer paranoia

        let rand = xous::create_server_id().unwrap().to_array();
        let token = [rand[0], rand[1], rand[2]];
        keystore.ensure_swap_encryption(THROW_AWAY_SERVER, THROW_AWAY_OP, token).unwrap();
        let modals = modals::Modals::new(&xns).unwrap();
        let mut in_progress = false;
        let mut msg_opt = None;
        loop {
            xous::reply_and_receive_next(status_server, &mut msg_opt).unwrap();
            let msg = msg_opt.as_mut().unwrap();
            if msg.body.id() == THROW_AWAY_OP {
                if let Some(scalar) = msg.body.scalar_message() {
                    if token == [scalar.arg2 as u32, scalar.arg3 as u32, scalar.arg4 as u32] {
                        let progress = scalar.arg1 as u32;
                        if progress == 100 {
                            break;
                        }
                        if !in_progress {
                            modals.start_progress("Encrypting apps...", progress, 100, 0).ok();
                            in_progress = true;
                        } else {
                            modals.update_progress(progress).ok();
                        }
                    }
                }
            }
        }
        if in_progress {
            modals.finish_progress().ok();
        }
    }

    // maki: the pumper starts when the vault comes to the front (see `totp::Pace`)
    let mut menu_active = false;
    loop {
        let mut msg = xous::receive_message(sid).unwrap();
        log::trace!("Got message: {:?}", msg.body.id());
        match FromPrimitive::from_usize(msg.body.id()) {
            Some(VaultOp::Redraw) => {
                vault_ui.redraw();
            }
            Some(VaultOp::ReloadDbAndFullRedraw) => {
                xous::send_message(
                    actions_conn,
                    xous::Message::new_blocking_scalar(ActionOp::ReloadDb.to_usize().unwrap(), 0, 0, 0, 0),
                )
                .ok();
                vault_ui.refresh_draw_list();
                vault_ui.redraw();
            }
            Some(op @ (VaultOp::FocusChange | VaultOp::FocusPasswords)) => xous::msg_scalar_unpack!(msg, focus, _, _, _, {
                let foreground = focus == maki_launcher::Focus::Foreground.to_usize().unwrap();
                vault_ui.set_focus(foreground);
                pace.focused.store(foreground, Ordering::SeqCst);
                if foreground {
                    let wanted =
                        if matches!(op, VaultOp::FocusPasswords) { VaultMode::Password } else { VaultMode::Totp };
                    let current = *mode.lock().unwrap();
                    if menu_active {
                        menu_mgr.redraw();
                    } else if current != wanted {
                        switch_mode(wanted, &mode, actions_conn, pump_conn, &pace, &allow_totp_rendering, &mut vault_ui);
                    } else {
                        vault_ui.refresh_draw_list();
                        vault_ui.redraw();
                    }
                    if *mode.lock().unwrap() == VaultMode::Totp {
                        pace.start(pump_conn);
                    }
                }
            }),
            Some(VaultOp::MenuHome) => {
                // stop drawing first: the menu's MenuDone, which follows this, triggers a redraw
                vault_ui.set_focus(false);
                launcher.home().ok();
            }
            Some(VaultOp::MenuDone) => {
                menu_active = false;
                // update the TOTP codes, in case there were changes
                vault_ui.refresh_draw_list();
                allow_totp_rendering.store(true, Ordering::SeqCst);
                vault_ui.redraw();
            }
            Some(VaultOp::KeyPress) => xous::msg_scalar_unpack!(msg, k1, _k2, _k3, _k4, {
                // maki's three buttons: left and right go through the entries, the centre types the
                // code or the password on screen. The jog dial does the same, for anyone who likes it.
                let k = char::from_u32(k1 as u32).unwrap_or('\u{0000}');
                log::debug!("key {:x}", k1);
                match k {
                    '←' | '↑' => {
                        vault_ui.nav(NavDir::Up);
                        vault_ui.redraw();
                    }
                    '→' | '↓' => {
                        vault_ui.nav(NavDir::Down);
                        vault_ui.redraw();
                    }
                    '🔥' | '∴' => {
                        if vault_ui.len() > 0 {
                            vault_ui.nav(NavDir::Autotype);
                            vault_ui.redraw();
                        } else if *mode.lock().unwrap() == VaultMode::Totp {
                            scan_qr(actions_conn, &allow_totp_rendering, &tt, &mut vault_ui);
                        }
                    }
                    _ => log::trace!("unhandled key {}", k),
                }
            }),
            Some(VaultOp::AppMenu) => {
                let current = *mode.lock().unwrap();
                let empty = vault_ui.len() == 0;
                let items: &[&str] = match (current, empty) {
                    (VaultMode::Totp, true) => &["Add from QR code"],
                    (VaultMode::Totp, false) => &["Add from QR code", "Delete this code"],
                    (VaultMode::Password, true) => &[],
                    (VaultMode::Password, false) => &["Type username", "Delete this login"],
                };
                match maki_launcher::MenuMessage::of(&msg) {
                    Some(maki_launcher::MenuMessage::Fill) => maki_launcher::MenuMessage::fill(&mut msg, items),
                    Some(maki_launcher::MenuMessage::Picked(i)) => match items.get(i) {
                        Some(&"Add from QR code") => scan_qr(actions_conn, &allow_totp_rendering, &tt, &mut vault_ui),
                        Some(&"Type username") => vault_ui.type_username(),
                        Some(&"Delete this code") | Some(&"Delete this login") => {
                            allow_totp_rendering.store(false, Ordering::SeqCst);
                            if let Some(entry) = vault_ui.selected_entry() {
                                let buf = Buffer::into_buf(entry).expect("IPC error");
                                buf.lend(actions_conn, ActionOp::MenuDeleteStage2.to_u32().unwrap())
                                    .expect("messaging error");
                            }
                            allow_totp_rendering.store(current == VaultMode::Totp, Ordering::SeqCst);
                            vault_ui.refresh_draw_list();
                            vault_ui.redraw();
                        }
                        _ => {}
                    },
                    None => {}
                }
            }
            Some(VaultOp::MenuEditStage1) => {
                // stage 1 happens here because the filtered list and selection entry are in the responsive UX
                // section.
                log::debug!("selecting entry for edit");
                // this will block redraws
                allow_totp_rendering.store(false, Ordering::SeqCst);
                if let Some(entry) = vault_ui.selected_entry() {
                    let buf = Buffer::into_buf(entry).expect("IPC error");
                    buf.lend(actions_conn, ActionOp::MenuEditStage2.to_u32().unwrap())
                        .expect("messaging error");
                } else {
                    modals.show_notification(t!("vault.error.nothing_selected", locales::LANG), None).ok();
                }
                allow_totp_rendering.store(true, Ordering::SeqCst);
            }
            Some(VaultOp::MenuChangeFont) => {
                for item in FONT_LIST {
                    modals.add_list_item(item).expect("couldn't build radio item list");
                }
                allow_totp_rendering.store(false, Ordering::SeqCst);
                match modals.get_radiobutton(t!("vault.select_font", locales::LANG)) {
                    Ok(style) => {
                        vault_ui.store_glyph_style(name_to_style(&style).unwrap_or(DEFAULT_FONT));
                        vault_ui.apply_glyph_style();
                    }
                    _ => log::error!("get_radiobutton failed"),
                }
                allow_totp_rendering.store(true, Ordering::SeqCst);
            }
            Some(VaultOp::MenuDeleteStage1) => {
                allow_totp_rendering.store(false, Ordering::SeqCst);
                if let Some(entry) = vault_ui.selected_entry() {
                    let buf = Buffer::into_buf(entry).expect("IPC error");
                    buf.lend(actions_conn, ActionOp::MenuDeleteStage2.to_u32().unwrap())
                        .expect("messaging error");
                } else {
                    modals.show_notification(t!("vault.error.nothing_selected", locales::LANG), None).ok();
                }
                xous::send_message(
                    actions_conn,
                    xous::Message::new_blocking_scalar(ActionOp::ReloadDb.to_usize().unwrap(), 0, 0, 0, 0),
                )
                .ok();
                allow_totp_rendering.store(true, Ordering::SeqCst);
                vault_ui.refresh_draw_list();
                vault_ui.redraw();
            }
            Some(VaultOp::BasisChange) => {
                vault_ui.basis_change();
                xous::send_message(
                    conn,
                    xous::Message::new_blocking_scalar(
                        VaultOp::ReloadDbAndFullRedraw.to_usize().unwrap(),
                        0,
                        0,
                        0,
                        0,
                    ),
                )
                .ok();
            }
            Some(VaultOp::ShowQr) => {
                let previous = allow_totp_rendering.load(Ordering::SeqCst);
                allow_totp_rendering.store(false, Ordering::SeqCst);
                let mut test_data = [0u8; 40];
                #[cfg(feature = "hosted-baosec")]
                let mut trng = bao1x_emu::trng::Trng::new(&xns).unwrap();
                #[cfg(not(feature = "hosted-baosec"))]
                let mut trng = bao1x_hal_service::trng::Trng::new(&xns).unwrap();
                trng.fill_bytes_via_next(&mut test_data);
                let encoded = base45::encode(&test_data);
                modals.show_notification("", Some(&encoded)).ok();
                allow_totp_rendering.store(previous, Ordering::SeqCst);
            }
            _ => {
                log::error!("Got unknown message: {:?}", msg);
            }
        }
    }
}
