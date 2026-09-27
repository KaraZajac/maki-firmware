#!/bin/sh
# Remakes the development store: the store maki's firmware trusts until the real one opens, so
# the store can be tried out end to end (DEVELOPMENT.md, "The store's keys"). Its keys are never
# committed; KEYS is a directory holding root1.key, root2.key and root3.key (any two sign a
# root) and catalogue1.key and catalogue2.key (roots 1 and 2 name them in turn).
#
#     sh make.sh KEYS [MAKI]      MAKI: the SDK's tool (default: maki on the PATH)
#
# Root 1 is what the firmware carries; root 2, signed by two of root 1's keys, replaces the
# catalogue key, so maki and maki desktop must follow the chain before anything else checks
# out. The apps are the SDK's examples (libs/maki-wasm/tests/fixtures, each what its source in
# sdk/examples builds to: `maki reproduce` says so), stamped by catalogue key 2;
# revocations.txt is the revocation list's source. Everything lasts ten years: this is for
# tests and the emulator's demo, not for anyone's badge.
set -eu
KEYS=$1
MAKI=${2:-maki}
HERE=$(cd "$(dirname "$0")" && pwd)
FIXTURES=$HERE/../../maki-wasm/tests/fixtures
DAYS=3650

# The roots and the revocation list are made only if they aren't there: root 1 is what the
# firmware and maki desktop carry, so remaking it means changing theirs (delete roots/ first).
# The apps are stamped again each time, and the index signed again with a newer version.
ROOT_KEYS=$KEYS/root1.key,$KEYS/root2.key,$KEYS/root3.key
if [ ! -d "$HERE/roots" ]; then
    mkdir -p "$HERE/roots"
    "$MAKI" store root --version 1 --threshold 2 --keys "$ROOT_KEYS" --catalogue "$KEYS/catalogue1.key" \
        --expires-days $DAYS --sign "$KEYS/root1.key,$KEYS/root2.key" -o "$HERE/roots/1.bin"
    "$MAKI" store root --version 2 --threshold 2 --keys "$ROOT_KEYS" --catalogue "$KEYS/catalogue2.key" \
        --expires-days $DAYS --sign "$KEYS/root1.key,$KEYS/root3.key" -o "$HERE/roots/2.bin"
fi
rm -rf "$HERE/apps"
for app in dice sensors signer ssh; do
    "$MAKI" store add "$HERE" "$FIXTURES/$app.maki" --catalogue "$KEYS/catalogue2.key" --expires-days $DAYS
done
if [ ! -f "$HERE/revocations.bin" ]; then
    "$MAKI" store revoke --catalogue "$KEYS/catalogue2.key" --version 1 --expires-days $DAYS \
        --list "$HERE/revocations.txt" -o "$HERE/revocations.bin"
fi
