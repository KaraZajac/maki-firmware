//! The smallest maki app: says hello until the owner leaves.

#![no_std]

use maki_app::*;

fn main() {
    loop {
        screen::clear(Color::Dark);
        screen::text_centred(38, "Hello, maki!", Style::Bold, Color::Light);
        screen::text_centred(58, "left+right: menu", Style::Small, Color::Light);
        screen::present();
        if wait(None) == Event::Exit {
            return;
        }
    }
}

maki_app::main!(main);
