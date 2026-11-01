# Plan: `gfx send` / `gfx receive` — repository transfer over magic-wormhole / iroh

| Field    | Value |
|----------|-------|
| Status   | In progress (M0–M2 done) |
| Created  | 2026-11-01 |
| Updated  | 2026-11-01 (M1+M2: transport core, both transports, mock loopbacks) |
| Depends  | plan-multistream-pack.md (pack/unpack archives), plan-stream-files.md (stream endpoints), rewrite-cli.md, pack-cli.md |

---

## 1. Summary

Two new `gfx` subcommands that move repositories between machines with one
command per side:

- **`gfx send [--repo <name>:<path>]... [--via wormhole|sendme|auto] [pack flags]`**
  packs one or more repositories into a `.gfxpack` archive in a temporary
  directory (the exact `gfx pack` pipeline — passes, remotes capture, age
  encryption), hands the archive to a transfer tool, prints the transfer
  **code/ticket** the receiver needs, and waits for the transfer to
  complete. The temporary archive is deleted afterwards.
- **`gfx receive <code> [--via ...] [unpack flags]`** runs the transfer
  tool's receiver into a temporary directory, then materializes the archive
  exactly like `gfx unpack` (verify → import → per-repo artifacts), and
  deletes the temporary archive afterwards.

The headline composition: because `send` runs the full pack pipeline, the
sender can rewrite history *in flight* —
`gfx send --passes redact --redact.collapse --redact.time-mode zero`
delivers a fully anonymized copy without ever touching the source repo.

## 2. Non-goals

- Embedding a transfer protocol in Rust (no `magic-wormhole` crate, no
  `iroh` crate). Transports are external CLI tools; see D1.
- Self-hosted relay/mailbox configuration flags. Both tools honor their own
  environment/configuration; gfx does not re-expose it.
- Resumable or multi-archive transfers; one send = one archive = one code.
- `wormhole send --text` message sends, QR-code management, Tor flags.
  Tool stderr is passed through, so whatever the tool prints (including its
  QR code) is still shown.
- Windows support for the loopback test script (the Rust side is
  platform-neutral; the script is POSIX).

## 3. Constraints

1. **Fail closed on missing transport.** `--via <t>` names a tool that is
   not on `PATH` → exit 2 (usage) with the install hint
   (`brew install magic-wormhole` / `cargo install sendme`). `--via auto`
   with neither present → exit 2 listing both hints.
2. **Never weaken pack's safety posture.** `--save-remotes` keeps its
   credential-bearing-URL refusal; age flags work exactly as in `gfx pack`.
3. **Temp hygiene.** Each transfer runs in one fresh temp directory
   (`$TMPDIR/gfx-transfer-*`). It is removed when the command exits,
   success or failure — post-transfer there is nothing local worth keeping
   (the pack/unpack reports go to stdout; the archive lives on the
   receiver). Contrast `scripts/smoke-all-repos.py`, which retains failures
   for diagnosis: a failed transfer is diagnosed from the tool's own output,
   not from a half-written archive.
4. **The code is the capability.** Anyone holding the wormhole code or
   sendme ticket can fetch the archive. The docs must say so, and must point
   at `--encrypt-passphrase`/`--encrypt` for defense in depth (both
   transports are already end-to-end encrypted; age protects the archive at
   rest on the far side).
5. **No new mandatory dependencies.** Transport interaction is `std::process`
   + PATH lookup. No async runtime enters the tree.
6. **LuLu reality.** Both transports open outbound connections
   (wormhole: mailbox server `ws://relay.magic-wormhole.io`, transit
   sockets; sendme: iroh relays + hole-punching). First use will trigger
   LuLu approval prompts; that is expected and documented, not worked
   around.
7. **Byte-identical non-use.** No new subcommand given → every existing
   code path behaves exactly as before.

## 4. Research findings (empirical)

- R1. `wormhole` 0.22.0 (Homebrew `magic-wormhole`) is installed on this
  machine. Probed: `wormhole send` prints `Wormhole code is: <code>` (and a
  QR block, and `wormhole receive <code>` instructions) to **stderr**;
  stdout stays empty. The sender blocks until the receiver finishes, then
  exits 0. The mailbox rendezvous worked from this host without extra
  configuration.
- R2. wormhole automation surface: `send [--code <code>] [--code-length N]
  [--hide-progress]`; `receive [--accept-file] [-o <path>] <code>`.
  `--accept-file -o <path>` makes receive fully non-interactive.
- R3. `sendme` (iroh) is **not** installed here (`cargo install sendme`,
  ~55–93 MB dep tree). Its CLI: `sendme send <path>` prints a `blob…`
  ticket (older versions wrap it as `sendme receive <ticket>`) and then
  serves until Ctrl-C — **the sender process outlives the transfer**, unlike
  wormhole; `sendme receive <ticket>` has no output-path flag: it writes
  into the *current directory* under the source's name, via `.sendme-*`
  temp dirs, verified by blake3. gfx therefore runs the receive with
  `cwd` = the transfer temp dir and expects `<tmp>/archive.gfxpack`.
- R4. gfx's pack/unpack CLIs are already programmatically composable:
  `run_pack_cli_to(out, about, factories, argv)` and
  `run_unpack_cli_to(out, argv)` take argv vectors and return exit codes.
  Send/receive can build argv (`--out <tmp>` / `--archive <tmp>` injected)
  instead of duplicating any pack logic — pass-flag support, validation,
  and future flags come along for free (D2).
- R5. Existing exit-code discipline (plan-stream-files.md C3): usage errors
  exit 2, failures exit 1. Transport failures mid-transfer are exit 1;
  unknown/missing-transport and flag conflicts are exit 2.

## 5. Decision points

### D1 — External CLI transports, not embedded crates

Options: (a) embed `magic-wormhole`/`iroh` Rust crates; (b) shell out to
`wormhole` / `sendme` binaries.

Analysis: gfx is fully synchronous and already shells out to `git` for
every repository touch — process-spawning is the established architecture.
Option (a) would drag in tokio plus ~1.5 M SLoC of QUIC/crypto machinery
(sendme's own dep tree) to move a file that a 3 MB installed tool moves
today, and would couple gfx's release cadence to two fast-moving protocol
implementations. Option (b) makes each transport an optional, upgradable,
user-managed tool; absence is a clean usage error (C1).

**Decision: (b).** A `Transport` abstraction in `gfx-cli` (PATH discovery,
argv construction, output parsing) with two implementations:
`wormhole` and `sendme`. Adding a transport = one impl.

### D2 — send = pack-into-temp + transport; receive = transport + unpack

**Decision:** `gfx send` extracts its own transfer flags (`--via`,
`--code`) and forwards *everything else* verbatim to the pack CLI with
`--out <tmp>/archive.gfxpack` injected; `gfx receive` forwards the
remainder to the unpack CLI with `--archive <tmp>/archive.gfxpack`
injected (R4). No flag duplication, no pipeline reimplementation, and
`--passes redact --redact.collapse` in flight works on day one.

Default repo: if no `--repo` is given, `send` packs the current directory
as one repo named by its folder basename (git-style ergonomics; `pack`
itself keeps requiring explicit `--repo`). The archive's internal stream
name does not affect receive-side paths: unpack places repos under
`--dest-root` by archive name.

### D3 — Transport selection

`--via wormhole|sendme|auto`, default `auto`. Auto = first PATH hit in
order `wormhole`, `sendme` (wormhole first: installed here, interactive
code is friendlier than a long ticket). `--code <code>` is accepted by
both (wormhole: `--code`; sendme: not supported on send — pinning is a
usage error with `--via sendme`; on receive it is the positional code /
ticket for both).

### D4 — Surfacing the code/ticket

gfx spawns the sender with stderr piped and tee'd to gfx's stderr, scanning
lines for `Wormhole code is: (.+)` or `sendme receive (\S+)` / a bare
`blob[a-z0-9]{20,}` ticket; on match it prints a structured line to
stdout: `gfx send: transfer code: <code>`. If no line matches, the tool's
own output (already shown) is the fallback — gfx never hides it, and the
send is not failed for an unparseable line. For `sendme`, gfx additionally
prints `sendme serve mode: keep this process running until the receiver
finishes; Ctrl-C ends it` (R3).

### D5 — Default passes

Send forwards the registry defaults (`strip-blobs,remap`), i.e. an
identity rewrite for typical repos — consistent with `gfx pack` and with
"transfer does not silently alter history". Any pass flags the sender adds
are deliberate.

### D6 — Failure semantics mid-transfer

Sender tool exits non-zero (receiver declined, network lost, Ctrl-C) →
gfx reports the tool's stderr tail and exits 1. Receiver side: a failed
receive never produces an archive, so unpack never runs; a failed *unpack*
behaves exactly like `gfx unpack` on a corrupt archive (fail per repo,
`--keep-going` to continue). Ctrl-C during gfx receive: temp dir removed
by the same guard.

## 6. Milestones

Each milestone keeps the tree building and all prior tests green; commit
after each.

- **M0 — this plan.** ✓
- **M1 — transport core + wormhole.** ✓ `transfer.rs` in `gfx-cli`
  (TransportKind, PATH discovery, argv construction, code-line parsing as
  pure functions), `send_cli.rs` / `receive_cli.rs`, dispatch in
  `bin/gfx.rs`, temp lifecycle (C3). Tests use **mock transport binaries**
  (shell scripts on a temp PATH that record argv and emulate the code
  line / file delivery) so no network is touched: full send→receive
  loopback of two fixture repos through a real `gfx pack`/`gfx unpack`.
- **M2 — sendme transport + auto selection.** ✓ (landed with M1: the Transport abstraction covered both) Same mock-binary loopback
  for sendme semantics (cwd-relative receive, ticket parsing, serve-mode
  messaging, `--code` pinning rejected). Auto-order resolution test.
- **M3 — live loopback + docs.** `scripts/transfer-loopback.sh` (opt-in,
  POSIX): real `wormhole` send/receive of a fixture repo on one machine,
  asserting refs survive; documented as needing network + LuLu approval.
  `docs/transfer-cli.md` user surface (flags, security notes C4/C6, LuLu
  expectations); plan status → Implemented.
