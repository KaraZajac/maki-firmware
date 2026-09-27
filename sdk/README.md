# Making apps for maki

maki runs apps you install without flashing firmware: `.maki` bundles, each a WebAssembly
module with a manifest, an icon and your signature (ARCHITECTURE.md in the BAOKEY repo, "Apps
you can install"). Anyone can build one and sideload it through maki desktop; maki shows the
owner what it is, where it's from and what it may do before installing it, and a sideloaded
app carries a mark in maki's top bar for as long as it's installed.

This directory has the Rust crate apps are written with (`maki-app`), seven examples (Hello,
Dice, Tally; Signer and Sensors, which use permissions; SSH, maki's SSH key, which answers
maki desktop's SSH agent; and Hello Native, Hello built as a native app), and the `maki` tool
that packs, signs, checks and simulates them.

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
opens the menu (on maki, left and right together), `q` leaves; when the app asks, `y` or `n`
answers. `--press left,centre*3,menu:0` runs presses instead (with `yes` or `no` for each
ask, `msg:TEXT` to send the app a message, whose answer is printed, `qr:TEXT` for what the
camera sees at its next scan, and `tilt:X;Y;Z` to move the accelerometer, which `--motion
X,Y,Z` sets to start with), `--shot out.png` saves the last frame, `--storage file` keeps the app's storage between
runs. Typing is printed rather than typed, and an app's keys come from the BIP39 test phrase
("abandon" eleven times, then "about"): the keys maki would give it with that phrase, never
anything you'd use for real.

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

[permissions]                # each with why, in your words: the owner reads it at install
keys = "For a signing key of its own."
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

And with a permission, which the manifest asks for with a line saying why (maki shows the owner
the line, and what the permission could do, before installing; it refuses an app that calls a
function whose permission it didn't ask for):

- **`ask`**: `Ask::new("Sign in?").detail("as kara").answers("sign", "cancel").show()` puts the
  question on maki's own ask screen, under the app's bar, and waits: `Yes`, `No`, or `NoAnswer`
  if the owner lets it time out (30 s unless `.timeout(s)` says, up to 120). The app gets
  `Hidden` and `Shown` around it.
- **`keys`**: secrets of the app's own from maki's recovery phrase, named by a label (up to 32
  bytes): `keys::secret(label)` (32 bytes), or the Ed25519 key made from it, which maki holds and
  signs with, `keys::public_key(label)` and `keys::sign(label, message)`. Different for every
  app, developer key and label; the same on any maki restored from the phrase; none while maki
  is locked. An update keeps them only if it's signed with the same developer key.
- **`keyboard`**: `keyboard::type_text(text)` types printable ASCII, newlines and tabs (1024
  bytes at a time) into the computer as a USB keyboard, while the app is in front, with "typing"
  in maki's bar. The owner is warned at install: it could type commands.
- **`link`**: messages with software on the computer, through maki desktop. The software sends
  one (maki desktop's local socket takes `{"id":1,"type":"appMessage","app":"your.app.id",
  "data":"<base64>"}`), the app gets `Event::Message`, `link::read`s it and `link::reply`s once
  (up to 4096 bytes each way; what they mean is between the app and the software). If the app
  isn't running, maki starts it without the screen to answer, unless another app is open, and
  ends it once it's had nothing to do for 30 s; it can still `Ask` meanwhile, and the owner can
  open it. The SSH example is one: maki desktop's SSH agent sends it ssh's requests.
- **`camera`**: `camera::scan_qr(&mut buf)` puts maki's own QR scanner on screen, while the app
  is in front, and returns the code's text, or None if the owner pressed a button to cancel
  (the press doesn't reach the app).
- **`motion`**: `motion::read()` gives the accelerometer's x, y and z in thousandths of a g (face
  up and still: about 0, 0, 1000), while the app is in front. Warned at install: it could pick up
  typing nearby.

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

## Native apps

The same source builds as a native app too: machine code for maki's processor, run in a process
of its own at full speed, with threads. Say so in `maki.toml` (`kind = "native"`), make the crate
a library as well (`crate-type = ["cdylib", "rlib"]`), and give it the memory its code, data,
heap and 64 KiB of stack need (`examples/hello-native` asks for 512 KiB). `maki build` builds it
for Xous's target, `riscv32imac-unknown-xous-elf` (Xous's Rust toolchain has it: see Xous's
README), in a small program that calls the app's `maki_main`; `maki pack`, `maki inspect` and
`maki reproduce` work as for WebAssembly, and the simulator (`maki run`) runs WebAssembly only.

maki runs a native app confined by its kernel: the stub it starts in loads it, connects it to
maki's app service (which does for it what a WebAssembly app's imports do, with the same
permissions), to the ticktimer and to the log, and then confines itself for good. The app keeps
those three connections and its own memory, up to what its manifest asks for, and can't make
new connections or map anything else. Rust's `std` works (threads, `Vec`, `String`, `println!`
to maki's log), but not what needs other servers: the time comes from `maki_app::unix_time`,
not `SystemTime`, and nothing reaches the network or files. A native app names the firmware it
was built for (`maki-native-1`); maki refuses one built for another.

## The maki store

Apps in the maki store are reviewed, built from their source by the store, and stamped: the
store's catalogue key signs a stamp naming the bundle you signed (its hash, ID, version,
developer key and permissions), which goes in the bundle after your signature. maki checks the
stamp against the store's root before it says "maki store" on the install screen; everything
else is sideloaded. An app from the store updates only from the store, and a stamped bundle is
still yours: an update needs your key as well as a new stamp.

The store builds each app from its source before stamping it: `maki reproduce APP.maki DIR`
builds the app in DIR and checks that the bundle holds what that makes (its manifest, icon and
code). Builds come out the same wherever they're made, given the same Rust: pin it with a
`rust-toolchain.toml` beside your `maki.toml` so the store builds with yours.

`maki inspect` says whether a bundle is stamped. The `maki store` commands are the store's own
side (its keys, roots, stamps, revocation lists and index; `maki store` lists them), and
DEVELOPMENT.md in the BAOKEY repo ("The maki store") says how they're used. Until the store
opens, maki trusts a development store, which stamps these examples.

## Other languages

Anything that compiles to wasm32 works: export `memory` and a `maki_main` taking and returning
nothing, import the functions in `maki-app/src/lib.rs` (module `maki`), and pack the `.wasm`
with `maki pack --code app.wasm`.
