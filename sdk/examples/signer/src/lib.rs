//! The permissions at work: a signing key of the app's own from the recovery phrase (keys),
//! a signature only once the owner says yes on maki's ask screen (ask), and a line typed into
//! the computer (keyboard). The centre signs; the menu types.

#![no_std]

use core::fmt::Write;

use maki_app::*;

/// Which of the app's keys: an app can have many, one per label.
const LABEL: &str = "signer";
const MESSAGE: &[u8] = b"hello from maki";

fn hex<const N: usize>(out: &mut Buf<N>, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

fn draw(status: &str) {
    screen::clear(Color::Dark);
    screen::text(2, 2, "This app's key", Style::Small, Color::Light);
    match keys::public_key(LABEL) {
        Ok(key) => {
            // the first half of it, a line of fixed-width type each 8 bytes
            for (i, part) in key[..16].chunks(8).enumerate() {
                let mut line = Buf::<16>::new();
                hex(&mut line, part);
                screen::text(2, 18 + i as i32 * 15, line.as_str(), Style::Mono, Color::Light);
            }
        }
        Err(_) => {
            screen::text(2, 18, "not while locked", Style::Regular, Color::Light);
        }
    }
    screen::text_centred(58, status, Style::Small, Color::Light);
    screen::text_centred(94, "centre: sign", Style::Small, Color::Light);
    screen::present();
}

fn main() {
    let _ = menu(&["Type a test line"]);
    let mut status = Buf::<48>::new();
    let _ = write!(status, "nothing signed yet");
    loop {
        draw(status.as_str());
        match wait(None) {
            Event::Centre => {
                let asked = Ask::new("Sign a test message?")
                    .detail("\"hello from maki\", with this app's key")
                    .answers("sign", "cancel")
                    .show();
                status.clear();
                match asked {
                    Ok(Answer::Yes) => match keys::sign(LABEL, MESSAGE) {
                        Ok(signature) => {
                            let _ = write!(status, "signed ");
                            hex(&mut status, &signature[..6]);
                            let _ = write!(status, "...");
                        }
                        Err(_) => {
                            let _ = write!(status, "couldn't sign");
                        }
                    },
                    Ok(Answer::No) => {
                        let _ = write!(status, "not signed: you said no");
                    }
                    _ => {
                        let _ = write!(status, "not signed: no answer");
                    }
                }
            }
            Event::Menu(0) => {
                status.clear();
                let _ = match keyboard::type_text("hello from maki\n") {
                    Ok(()) => write!(status, "typed a line"),
                    Err(_) => write!(status, "couldn't type: not plugged in"),
                };
            }
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
