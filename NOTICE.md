# NOTICE

**maki-firmware** is the firmware of maki, a security key for the DEF CON 34 badge
(https://github.com/KaraZajac/maki). It's a fork of **Xous**
(https://github.com/betrusted-io/xous-core), by bunnie, Sean Cross and the Xous contributors.

## Xous: Apache License 2.0

Xous is licensed under the Apache License, Version 2.0: `LICENSE`, and `LICENSES/Apache-2.0.txt`.
Its files stay under it, with their authors' notices, including the ones maki changed. Some of
Xous's crates are also offered under the MIT License, as their `Cargo.toml` says (the kernel,
`xous`, `xous-ipc` and the core services), and some of its parts have licenses of their own, as
their folders say: `vault2`'s CTAP code is Google's OpenSK (Apache-2.0), the vendored
`curve25519-dalek` and `ed25519-dalek` in `loader/` and `bao1x-boot/` are BSD-3-Clause, and the
glyphs in `libs/blitstr2` are described in its `LEGAL.md` (Unifont, under the SIL Open Font
License 1.1).

**Files of Xous that maki changed** say so at their top: "Changed for maki (a fork of Xous:
github.com/KaraZajac/maki-firmware) in 2026". This repository's history says what changed. Two
changed files can't carry the note: `Cargo.lock`, which cargo writes, and
`apps-baosec/vault2/locales/i18n.json`, whose format has no comments. Files maki added to one
of Xous's crates say "Added for maki" at their top, and are under that crate's license.

## maki: MIT License

maki's own code is licensed under the MIT License: `LICENSES/MIT.txt`, Copyright (c) 2026
.leviathan. It's everything maki added, each crate's `Cargo.toml` saying `license = "MIT"`:

- `apps-baosec/maki-launcher`, `maki-app-host`, `maki-apps` and `maki-spawn`
- `services/maki-keys` and `services/maki-link`
- `libs/maki-*` and `libs/roughtime`
- `sdk/`: the `maki-app` crate, the `maki` tool and the example apps (`sdk/LICENSE`)

Apps written with the SDK are their authors', under whatever license they choose; an app built
with it contains `maki-app`, whose MIT notice goes with it.

## Parts of maki's code that came from elsewhere

- `libs/usbd-serial` is usbd-serial by Matti Virkkunen (MIT: its `LICENSE`), vendored and changed
  for maki as its `MAKI.md` says.
- `libs/maki-xmr`: its Bulletproofs+ and its hash onto the curve are ported from monero-oxide
  (MIT, Copyright (c) 2022-2025 Luke Parker, (c) 2025-2026 monero-oxide Developers:
  `LICENSE-monero-oxide`); its English word list is Monero's (BSD-3-Clause, Copyright (c)
  2014-2024 The Monero Project: the notice is at the top of `src/english.rs`). Its tests use
  Monero's test vectors, with Monero's license beside them (`tests/monero-crypto.LICENSE`).
- `libs/maki-seed`: BIP 39's English word list (MIT, Copyright (c) 2013 Marek Palatinus, Pavol
  Rusnak, Aaron Voisine, Sean Bowe: `LICENSE-bip39`).
- `libs/maki-kas`: its signature hash is ported from rusty-kaspa v2.1.0 (ISC, Copyright (c)
  2022-2024 Kaspa developers: `LICENSE-rusty-kaspa`).
- `libs/maki-zec`: its tests use zcash-test-vectors' ZIP-244 and ZIP-320 vectors, unchanged
  (MIT, Copyright (c) 2018-2021 The Electric Coin Company), with their license beside them
  (`tests/fixtures/LICENSE-zcash-test-vectors`).
- `apps-baosec/maki-spawn/build.rs` is adapted from cortex-m's (MIT, Copyright (c) 2016 Jorge
  Aparicio and The Embedded Devices Working Group Developers).
- `sdk/examples/passphrase` uses the EFF's Long Wordlist, under the Creative Commons Attribution
  3.0 US License, as its `README.md` says.
- `sdk/examples/sokoban` ships 148 of David W. Skinner's Microban levels, unchanged, which he lets
  anyone distribute "provided they remain properly credited": his name and email are with them, at
  the top of `src/microban.txt`, and the app credits him on its Levels screen.

## What's in the firmware you flash

`THIRD-PARTY-NOTICES.md` lists every crate compiled into the badge image (the loader, the kernel
and each service) with its license and its authors' notices, and the glyphs and data it carries;
`sdk/THIRD-PARTY-NOTICES.md` does the same for the maki store's apps, which are built from `sdk/`.
`tools/maki-notices.py` makes both, from the build's own dependency graph; each release carries
them. None of it is under a copyleft license.
