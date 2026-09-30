//! Hello as a native app (maki.toml: `kind = "native"`): the same code as examples/hello. maki
//! runs it in a process of its own, confined to its memory and to maki's app service.

#![no_std]

use maki_app::*;

fn main() {
    let started = millis();
    loop {
        screen::clear(Color::Dark);
        screen::text_centred(30, "Hello, maki!", Style::Bold, Color::Light);
        screen::text_centred(50, "native, confined", Style::Small, Color::Light);
        let mut up = Buf::<24>::new();
        let _ = core::fmt::Write::write_fmt(&mut up, format_args!("up {} s", (millis() - started) / 1000));
        screen::text_centred(66, up.as_str(), Style::Small, Color::Light);
        screen::present();
        if wait(Some(1000)) == Event::Exit {
            return;
        }
    }
}

maki_app::main!(main);
