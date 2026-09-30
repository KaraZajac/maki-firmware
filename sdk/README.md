# Making apps for maki

maki runs apps you install without flashing firmware: `.maki` bundles, each a WebAssembly
module with a manifest, an icon and your signature (ARCHITECTURE.md in the maki repo, "Apps
you can install"). Anyone can build one and sideload it through maki desktop; maki shows the
owner what it is, where it's from and what it may do before installing it, and a sideloaded
app carries a mark in maki's top bar for as long as it's installed.

This directory has the Rust crate apps are written with (`maki-app`), twenty-eight examples, and
the `maki` tool that packs, signs, checks and simulates them. The examples:

- **Hello**, **Dice** and **Tally**: a screen, the buttons, storage and randomness. Dice takes the
  die from the jog dial on maki's side (host API 8): 3d6, 1d20, as players say them.
- **Initiative**, beside Dice at the table: a fight's turn order and hit points, the centre
  passing the turn and the jog dial taking damage off whoever's picked or healing them; someone
  new is added on a form of digit wheels, and the table is kept.
- **Signer** and **Sensors**, which use permissions: asking the owner, keys of their own, the
  camera and the accelerometer.
- **SSH**: maki's SSH key, which answers maki desktop's SSH agent (the link permission), and
  git's commits sent whole by maki desktop's `maki-ssh-keygen`, shown by subject and author before
  it signs; and a certificate authority's key, turned on from its menu, for `ssh-keygen -s -U`.
- **Nostr**: your Nostr key, which sites use through the maki extension's `window.nostr`
  (NIP-07): maki asks before a site sees it and shows each event before signing it with the key
  it holds (host API 2's Schnorr keys). Opened, it shows the npub as a QR code.
- **Age**: your age key, which maki holds (host API 2's X25519 keys): anyone encrypts files to its
  recipient with age as it is, and maki desktop's `age-plugin-maki` asks it to decrypt one, which
  it asks its owner about first.
- **OpenPGP**: an OpenPGP key (Ed25519 to sign, Curve25519 to decrypt, host API 2's X25519),
  for maki desktop's `maki-gpg` (git's `gpg.program`): what's signed comes whole, and maki makes
  the signature itself, a commit read out by its subject first; a message's session key is
  unwrapped on maki once its owner says yes. GnuPG imports its key and verifies what it signs.
- **Minisign**: a minisign key, which maki holds: maki desktop's `maki-minisign` hashes a file as
  minisign does and asks it to sign; it asks its owner, with the file's name and size, and signs
  a trusted comment dated by maki's own clock. minisign itself checks the signatures.
- **Wi-Fi**: networks as QR codes for guests to join, from a QR code the camera reads (a router's
  sticker, a phone's share screen) or from the computer (the link permission).
- **Passphrase**: diceware passphrases from maki's random number generator and the EFF's long
  word list, typed into the computer on request (the keyboard permission).
- **Contacts**: your card as a QR code, signed with a key of its own, to swap at the con; it
  checks the cards it scans itself (Ed25519, in WebAssembly), and maki desktop sets yours and
  saves the people you met.
- **Notes**: secrets read on maki and never on the computer again, from maki desktop (maki asks
  first) or a QR code, typed into a field on request; the computer sees their titles alone.
- **Scanner**: reads a QR code and shows what it says, a page at a time, and types it into the
  computer (camera and keyboard); text that would press Enter or Tab waits for the centre first.
- **Snake**: the game, steered the way it's to go with the jog dial and left and right, timed
  with `wait`.
- **Marble**: a maze, new every time, and a marble that rolls the way maki is tilted (the motion
  permission), into the hole at the far corner.
- **Breakout**: the bricks and the ball, off a paddle that follows maki's tilt, or left and right
  without an accelerometer.
- **Magic 8-Ball**: ask a question and shake maki (the motion permission, read every 40 ms), and
  one of the classic twenty answers floats up in its triangle; a bump isn't a shake, and a button
  press does too.
- **Sudo**: each command sudo runs waits for a yes on maki (host API 7's `AskPages`): maki
  desktop's sudo plugin asks it once sudoers says yes, with the whole command, and it shows the
  command line (quoted as a shell would take it back), what it's given to run with beyond what
  every command gets, and who asked where, then signs the request with its key (the keys
  permission), which the plugin checks against the key root keeps.
- **Status**: a sign readable across the room, in big letters it draws itself with `blit`, which
  software on the computer can set (the link permission).
- **Bitcoin** and **Ethereum**: maki's wallets, in the maki store (host API 3's wallet
  permission). maki keeps the keys; each reads what it's asked to sign with maki's own wallet
  code (`maki-btc`, `maki-eth`), shows it on maki's review screen and signs once the owner says
  yes. maki desktop, wallet software and sites talk to them over the link (PROTOCOL.md, "The
  wallets"). Opened, each shows an address as a QR code. Bitcoin signs with no cable too: it reads
  a PSBT off wallet software's screen (a UR `crypto-psbt` in parts, as Sparrow shows them) and
  shows the signed one back the same way, and shows its descriptor for Sparrow to scan. And
  multisig wallets (`maki-btc`'s `multisig`, P2WSH): its key for one (BIP48's), a wallet added
  once its owner has gone through every key on maki (from maki desktop, or its descriptor read off
  the coordinator's screen), then what spends from it signed, checked against the wallet as
  added: its scripts rebuilt from its keys, change only where it's the wallet's. Ethereum
  is a QR-code wallet for MetaMask (Keystone's protocol, ERC-4527): its account as a UR
  `crypto-hdkey` for MetaMask to add, and MetaMask's `eth-sign-request`s read off its screen, gone
  through on maki and answered with an `eth-signature`.
- **Monero**: the Monero wallet Ledger's Monero app makes from the same phrase (host APIs 4
  and 5): its address and subaddresses as QR codes; from its menu, the 25 words that restore it
  in any Monero wallet, which maki shows its owner itself; the view key, for maki desktop or the
  Monero GUI to watch the wallet, once the owner says so; and spending, each payment, the change
  and the fee on maki's review screen, then the transaction made and signed by maki.
- **Solana**: the Solana account Phantom and Solflare make from the same phrase (host API 6's
  Ed25519 wallets): its address as a QR code, for sites through the maki extension (a wallet as
  the Wallet Standard has them) and maki desktop's wallet. It reads each transaction with maki's
  code (`maki-sol`), as Solana's runtime does: SOL and tokens sent, spelled out, a token's
  recipient as their own address when the transaction proves the token account is theirs, the most
  the fee can be, and anything else flagged, with whether it's given the account's signature.
- **Hello Native**, Hello built as a native app, and **Pomodoro**, a native focus timer whose
  pie empties like a clock while you work and fills back up while you rest; the jog dial sets its
  minutes.

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
runs. A scripted run keeps time of its own, so it comes out the same each time: only `timeout`
lets time pass, the whole of the wait it ends (`timeout*60`, in an app that waits a second at a
time, is a minute). Typing is printed rather than typed, and an app's keys come from the BIP39 test phrase
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
  Waiting again after `Exit` stops the app. Host API 8 adds `Up` and `Down`, the jog dial on
  maki's side; only an app whose `api` is 8 or more gets them, or a native app built for
  `maki-native-2` (an older one would read them as a timeout), and in `maki run` they're
  `--press up,down`, or the arrow keys.
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
  `Hidden` and `Shown` around it. Host API 7 adds `AskPages`, for what an ask's line can't hold:
  pages first on maki's review screen, as a wallet's review has them, then the question (120 s
  unless it says, up to 300), and a yes that allows no signatures. It builds in bytes the app
  lends it (a static for a big one: an app's stack is 16 KiB); `api = 7` in `maki.toml`.
- **`keys`**: secrets of the app's own from maki's recovery phrase, named by a label (up to 32
  bytes): `keys::secret(label)` (32 bytes), or the Ed25519 key made from it, which maki holds and
  signs with, `keys::public_key(label)` and `keys::sign(label, message)`. Different for every
  app, developer key and label; the same on any maki restored from the phrase; none while maki
  is locked. An update keeps them only if it's signed with the same developer key. Host API 2
  adds a BIP340 (Schnorr, secp256k1) key for each label too, as Nostr and Taproot use:
  `keys::schnorr_public_key(label)` (x-only) and `keys::schnorr_sign(label, &hash)`, which signs a
  32-byte hash with fresh randomness from maki's TRNG; its secret is tagged apart from the
  Ed25519 one. And an X25519 key (RFC 7748), as age uses: `keys::x25519_public_key(label)` and
  `keys::x25519_agree(label, &peer)`, the shared secret to derive a key from; tagged apart too. An
  app that calls them says `api = 2` in its `maki.toml`, and maki's install check holds it to
  that.
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
- **`wallet`** (host API 3): keys from maki's recovery phrase at the standard BIP32 paths, as
  other wallets derive them, for the accounts the manifest names and no others:

  ```toml
  [wallet]
  paths = ["m/84'/0'", "m/86'/0'"]   # a purpose and a coin type, hardened; up to 8
  ```

  maki shows the owner the coins those paths are for when installing, and refuses a call for a
  key off them. `wallet::fingerprint()`, `wallet::public(path)` (with its chain code, for an
  xpub), `wallet::uncompressed(path)` and `wallet::taproot_output(path)` give public keys;
  `wallet::sign_ecdsa(path, &digest)` (RFC 6979, low s, with the recovery ID) and
  `wallet::sign_schnorr(path, &digest, Tweak::Taproot)` (BIP340, fresh randomness) sign, but only
  after the owner says yes to a review: `Review::new("Sign and spend").detail("0.0007 BTC")
  .page(Page::new("Send").value("0.0007 BTC").mono(address)).signatures(inputs).show()` puts the
  pages on maki's review screen under the app's bar, then the question, and a yes allows that
  many signatures in the next two minutes (a new review ends what the last allowed). The keys
  never leave maki, which does the curve work itself: the app never holds a secret key, and
  WebAssembly would be far too slow for it. `wallet::HostKeys` is maki's keys as a
  `maki_hd::Keys`, for `maki-btc` and `maki-eth`, which do the rest. `Error::Locked` while maki
  is locked or has no phrase; `Error::Refused` off the paths, or without a yes. Host API 4 adds
  Monero, on its coin type alone (`m/44'/128'`): `wallet::monero(path)`, the account's public
  spend and view keys, `wallet::subaddress(path, account, index)`, a subaddress's (with
  `maki-xmr` to make the addresses), and `wallet::show_backup(path)`, which has maki show its
  owner the account's 25 words on its own screens once they've said they want them: the app
  hears whether they were shown, never the words. Host API 5 spends Monero:
  `wallet::monero_view_key(path)` (after a yes, one of what it allows) for a computer to watch
  the wallet, `wallet::monero_key_image(path, tx_key, index, account, subaddress, key)` for an
  output's key image and its proof, and `wallet::monero_sign(path, &request)`, where the request
  (`maki_xmr::request`) says what to spend and pay: maki makes the whole transaction itself (the
  outputs, the range proof, a signature for each input, as many as the yes allowed) and hands it
  back, or says why not. Host API 6 adds Ed25519 wallets, as Solana's are: `curve = "ed25519"`
  under `[wallet]` (paths such as `m/44'/501'`), then `wallet::ed25519_public(path)`, the key by
  SLIP-10 (every step of the path hardened), and `wallet::sign_ed25519(path, &message)`, a
  signature over the whole message (up to 16 KiB; Ed25519 hashes what it signs itself), one of
  what a yes allows. An Ed25519 wallet has those keys alone, and a secp256k1 wallet none of them.
  The wallet examples show how: they need `std` (for their allocator), so
  their `Cargo.toml` asks for `maki-app` with `default-features = false, features = ["std",
  "wallet"]`.

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
`maki reproduce` work as for WebAssembly, and the simulator (`maki run`) runs WebAssembly only:
to try a native app there, build it with `kind = "wasm"`.

maki runs a native app confined by its kernel: the stub it starts in loads it, connects it to
maki's app service (which does for it what a WebAssembly app's imports do, with the same
permissions), to the ticktimer and to the log, and then confines itself for good. The app keeps
those three connections and its own memory, up to what its manifest asks for, and can't make
new connections or map anything else. Rust's `std` works (threads, `Vec`, `String`, `println!`
to maki's log), but not what needs other servers: the time comes from `maki_app::unix_time`,
not `SystemTime`, and nothing reaches the network or files. A native app names the app service
it was built for, `maki-native-2` (the one with the jog dial), and maki refuses one built for a
service it doesn't have. It runs apps built for `maki-native-1` as well, without the dial: to
build one that maki from before the dial runs too, say `firmware = "maki-native-1"` in
`maki.toml`.

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
`rust-toolchain.toml` beside your `maki.toml` so the store builds with yours. An app that uses
crates by path (this SDK's, say) also needs them where they were, relative to the app: the store
checks out the whole repository the app's source names, so keep them in it. Cargo tells crates
apart by a hash of where they're from, and one outside your workspace goes into it with its
whole path; so an app that builds any (the wallet examples use `libs/maki-btc` and `libs/maki-eth`)
is built through a wrapper that sees them all inside it, as native apps are, and needs
`crate-type = ["cdylib", "rlib"]` to be linked from it. The wrappers build in your cache
(`$XDG_CACHE_HOME/maki`, or `~/.cache/maki`), outside the source they link to.

`maki inspect` says whether a bundle is stamped. The `maki store` commands are the store's own
side (its keys, roots, stamps, revocation lists and index; `maki store` lists them), and
DEVELOPMENT.md in the maki repo ("The maki store") says how they're used. Until the store
opens, maki trusts a development store, which stamps these examples.

## Other languages

Anything that compiles to wasm32 works: export `memory` and a `maki_main` taking and returning
nothing, import the functions in `maki-app/src/lib.rs` (module `maki`), and pack the `.wasm`
with `maki pack --code app.wasm`.
