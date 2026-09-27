#!/bin/sh
# Builds the stub native maki apps start in, and writes the flat binary maki's app host embeds
# (apps-baosec/maki-app-host/src/spawn.bin). Run it after changing the stub, and commit both.
#
#     sh apps-baosec/maki-spawn/build-stub.sh      (from xous-core)
set -eu
cd "$(dirname "$0")/../.."
# a no_std program on this target has to abort on panic; its own target directory keeps the
# workspace's builds, which unwind, as they are
CARGO_PROFILE_RELEASE_PANIC=abort cargo build -p maki-spawn --target riscv32imac-unknown-xous-elf \
    --release --target-dir target/maki-spawn
cargo run -q -p xous-tools --bin xous-copy-object -- \
    target/maki-spawn/riscv32imac-unknown-xous-elf/release/maki-spawn apps-baosec/maki-app-host/src/spawn.bin
