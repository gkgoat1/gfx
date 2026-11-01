#!/bin/bash
# Live loopback for `gfx send` / `gfx receive` over REAL magic-wormhole
# (plan-transfer.md M3). Opt-in: this touches the network
# (relay.magic-wormhole.io mailbox + transit) — LuLu will ask to approve
# `wormhole`/`Python` outbound on first use.
#
# Usage: scripts/transfer-loopback.sh [path-to-gfx-binary]
#
# Verifies a fixture repo survives a genuine wormhole round-trip with refs
# and content intact, and that a redact-in-flight send anonymizes the copy.

set -eu

GFX="${1:-}"
if [ -z "$GFX" ]; then
    for c in target/release/gfx target/debug/gfx; do
        [ -x "$c" ] && GFX="$c" && break
    done
fi
[ -n "$GFX" ] && [ -x "$GFX" ] || { echo "gfx binary not found; build with: cargo build --release --bin gfx" >&2; exit 2; }
command -v wormhole >/dev/null || { echo "wormhole not installed: brew install magic-wormhole" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'kill $SEND_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT INT TERM
SEND_PID=""

# --- fixture repo -------------------------------------------------------
git init -q -b main "$TMP/src"
echo alpha > "$TMP/src/a.txt"
git -C "$TMP/src" add .
git -C "$TMP/src" -c user.name=Alice -c user.email=alice@example.com commit -qm one
echo bravo > "$TMP/src/b.txt"
git -C "$TMP/src" add .
git -C "$TMP/src" -c user.name=Bob -c user.email=bob@example.com commit -qm two
git -C "$TMP/src" tag v1

# --- plain transfer -----------------------------------------------------
echo "== send (real wormhole) =="
"$GFX" send --repo "main:$TMP/src" --via wormhole > "$TMP/send.out" 2> "$TMP/send.err" &
SEND_PID=$!

# Wait (bounded) for the code line the sender relays from wormhole.
code=""
for _ in $(seq 1 60); do
    code=$(sed -n 's/^gfx send: transfer code: //p' "$TMP/send.out" 2>/dev/null | head -1)
    [ -n "$code" ] && break
    sleep 1
done
[ -n "$code" ] || { echo "FAIL: sender never printed a code"; cat "$TMP/send.err" >&2; exit 1; }
echo "code: $code"

echo "== receive =="
mkdir "$TMP/dest"
"$GFX" receive "$code" --via wormhole --dest-root "$TMP/dest"
wait $SEND_PID
SEND_PID=""

diff <(git -C "$TMP/src" for-each-ref --format='%(refname) %(objectname)') \
     <(git -C "$TMP/dest/main" for-each-ref --format='%(refname) %(objectname)') \
    || { echo "FAIL: refs differ"; exit 1; }
git -C "$TMP/dest/main" fsck --strict
[ "$(cat "$TMP/dest/main/a.txt" 2>/dev/null || git -C "$TMP/dest/main" show main:a.txt)" = "alpha" ] \
    || { echo "FAIL: content differs"; exit 1; }
echo "plain round-trip OK"

# --- redact in flight ---------------------------------------------------
echo "== send (anonymized) =="
"$GFX" send --repo "main:$TMP/src" --via wormhole \
    --passes redact --redact.collapse --redact.time-mode zero \
    > "$TMP/send2.out" 2> "$TMP/send2.err" &
SEND_PID=$!
code=""
for _ in $(seq 1 60); do
    code=$(sed -n 's/^gfx send: transfer code: //p' "$TMP/send2.out" 2>/dev/null | head -1)
    [ -n "$code" ] && break
    sleep 1
done
[ -n "$code" ] || { echo "FAIL: sender never printed a code"; cat "$TMP/send2.err" >&2; exit 1; }

mkdir "$TMP/dest2"
"$GFX" receive "$code" --via wormhole --dest-root "$TMP/dest2"
wait $SEND_PID
SEND_PID=""

idents=$(git -C "$TMP/dest2/main" log --all --format='%an <%ae> %at')
echo "$idents" | grep -q "Anonymous <anonymous@example.invalid> 0" || { echo "FAIL: not anonymized: $idents"; exit 1; }
echo "$idents" | grep -q "alice@example.com" && { echo "FAIL: source ident leaked"; exit 1; }
echo "anonymized round-trip OK"
echo "ALL OK"
