# Making apps for maki

maki runs apps you install without flashing firmware: `.maki` bundles, each a WebAssembly
module with a manifest, an icon and your signature (ARCHITECTURE.md in the BAOKEY repo, "Apps
you can install"). Anyone can build one and sideload it through maki desktop; maki shows the
owner what it is, where it's from and what it may do before installing it, and a sideloaded
app carries a mark in maki's top bar for as long as it's installed.

This directory has the Rust crate apps are written with (`maki-app`), three examples, and the
`maki` tool that packs, signs, checks and simulates them.

## Quick start

```sh
rustup target add wasm32-unknown-unknown
cargo install --path maki                  # the maki tool
maki keygen                                # your developer key, once: keep it safe
maki build examples/dice                   # build, pack and sign
maki run target/maki/com.leviathan.maki.dice.maki    # try it in this terminal
```

`maki new my-app` starts an app of your own: its `Cargo.toml` (using this SDK), `maki.toml` and a
first screen, ready for `maki build my-app`.

Then install it on the maki plugged into this computer, with maki desktop running:

```sh
maki install target/maki/com.leviathan.maki.dice.maki
```

or from maki desktop's Apps section ("Install from file…"), and go through what maki shows
you: what the app is, that it's sideloaded, your developer key (compare it with what `maki`
printed), what it may do, and "install". Updates go the same way.

In the simulator: left and right arrows are maki's left and right, enter is the centre, `m`
opens the menu (on maki, left and right together), `q` leaves. `--press left,centre*3,menu:0`
runs presses instead, `--shot out.png` saves the last frame, `--storage file` keeps the app's
storage between runs.

## An app

A `cdylib` crate with a `maki.toml` beside its `Cargo.toml`:

```toml
id = "org.example.dice"      # reverse-DNS, lower case; yours for good
name = "Dice"                # as the home screen shows it
version = 1                  # goes up with every release: maki won't go back
label = "1.0"
storage = 1                  # KiB of storage it needs
memory = 64                  # KiB of memory
backup = true                # its data in maki's backup, unless the owner says otherwise
description = "Rolls dice."
icon = "icon.png"            # 64x64, as it should look on maki: light shapes on dark

[permissions]                # none yet: they come with the functions that use them
```

```rust
#![no_std]

use maki_app::*;

fn main() {
    let _ = menu(&["Reset"]);
    loop {
        screen::clear(Color::Dark);
        screen::text_centred(40, "Hello, maki!", Style::Bold, Color::Light);
        screen::present();
        match wait(None) {
            Event::Centre => log("pressed"),
            Event::Menu(0) => log("reset"),
            Event::Exit => return,
            _ => {}
        }
    }
}

maki_app::main!(main);
```

The app draws, then waits for the next event, and returns from `main` when told to exit.

## What an app gets

- **The screen below maki's bar**: 128 by 110 pixels, one bit each. Draw with `screen::`
  `clear`, `pixel`, `line`, `rect`, `fill_rect`, `text` (maki's fonts: `Regular`, `Bold`,
  `Small`, `Mono`, `Tall`), `blit` (a 1-bit bitmap, leftmost pixel in each byte's top bit), `qr`,
  then `present`. Colours are `Dark`, `Light` and `Invert`.
- **Events** from `wait(timeout)`: `Left`, `Right`, `Centre`, `Menu(i)` for the app's own menu
  items (`menu(&[...])`, up to six), `Hidden` and `Shown` when something else takes the screen
  for a while (an ask, the menu), `Timeout`, and `Exit`: save anything worth saving and return.
  Waiting again after `Exit` stops the app.
- **Storage** of its own, up to its manifest's `storage`: `storage::get`, `set`, `delete`,
  `key` (keys up to 48 bytes, values up to 16 KiB), `get_u32` and `set_u32`.
- **Time**: `millis()` since the app started, `unix_time()` if maki knows it, and
  `time_verified()`: whether it was checked against Roughtime rather than taken from the computer.
- **Randomness** from maki's TRNG: `random`, `random_below`.
- `log` for maki's debug log, and `abort` to stop with a message on screen (a panic does too).

Left and right pressed together are always maki's: they open the app's menu, which ends with
App info (where it's from, its permissions, its storage, whether it's backed up, Remove) and
Exit. An app can't draw over maki's bar.

## Limits

- An app that works for long without waiting is stopped as not responding: wait with
  `Some(0)` now and then in long loops.
- Memory: what the manifest asks for, 1 MiB at most. The stack lives in it: `maki build`
  gives apps 16 KiB rather than the linker's 1 MiB (building with cargo yourself, pass
  `-C link-arg=-zstack-size=16384`, as `.cargo/config.toml` here does). Storage: 256 KiB at most.
- Only `maki` functions can be imported (no WASI), and there's no start function: the build
  `maki build` makes is what maki takes, and `maki inspect` says whether it would.
- Updates must be signed with the same developer key and have a higher version. Lose the key
  and you can't update your app: back it up.

## Other languages

Anything that compiles to wasm32 works: export `memory` and a `maki_main` taking and returning
nothing, import the functions in `maki-app/src/lib.rs` (module `maki`), and pack the `.wasm`
with `maki pack --code app.wasm`.
