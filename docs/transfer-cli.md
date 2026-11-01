# `gfx send` / `gfx receive` — repository transfer over wormhole / iroh

`gfx send` packs repositories into a `.gfxpack` archive (the exact
[`gfx pack`](pack-cli.md) pipeline) and transfers it to another machine
with a single command; `gfx receive` materializes it on the far side.
Design + rationale: [`plan-transfer.md`](plan-transfer.md) (D1–D6).

```sh
# sender                                          # receiver
gfx send                                          gfx receive 7-guitarist-revenge
```

With no `--repo`, send packs the **current directory** as one repo named
by its folder name. Otherwise: `--repo <name>:<path>` (repeatable), exactly
like `gfx pack`. Sources are read-only.

## Transports

Transports are external CLI tools (gfx embeds no protocol stack):

| `--via`    | tool                                   | notes |
|------------|----------------------------------------|-------|
| `wormhole` | `brew install magic-wormhole`          | default when installed; short human code; sender exits when the receiver finishes |
| `sendme`   | `cargo install sendme`                 | iroh/QUIC, hole-punched direct transfer; long `blob…` ticket; **sender keeps serving until Ctrl-C** |
| `auto`     | first PATH hit (wormhole, then sendme) | default |

A pinned `--via` whose tool is missing exits 2 with the install hint; so
does `auto` with neither installed. The tool's own output (progress, QR
code) is passed through to stderr; gfx prints the structured line
`gfx send: transfer code: <code>` on stdout as soon as the tool emits it.

**The code is the capability** — anyone holding the code/ticket can fetch
the archive. Both transports are end-to-end encrypted in flight; for
at-rest protection on the receiver's disk, add pack's `--encrypt` /
`--encrypt-passphrase`.

First use will trigger **LuLu** outbound-approval prompts (wormhole:
mailbox relay + transit sockets; sendme: iroh relays + QUIC). Approve the
tool, not gfx — gfx itself only reads/writes local files.

## Rewriting in flight

Every other `gfx send` flag is forwarded verbatim to `gfx pack`, so the
full pass surface applies. The transfer copy is rewritten, the source is
never touched:

```sh
# deliver a fully anonymized mirror
gfx send --passes redact --redact.collapse --redact.time-mode zero

# multi-repo, remotes captured, age-encrypted for a recipient
gfx send --repo alpha:/srv/alpha.git --repo beta:/srv/beta.git \
    --save-remotes --encrypt age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmr3052wsaemnusr345 \
    --code 7-correct-horse
```

- `--code <code>` pins the wormhole code instead of allocating one
  (rejected with `--via sendme`: tickets are content-bound).
- Default passes are the pack defaults (`strip-blobs,remap` — an identity
  rewrite for typical repos); transfer never silently alters history.

## Receiving

```sh
gfx receive 7-guitarist-revenge [--dest-root ~/incoming] [--worktree] [--restore-remotes]
```

Every other flag forwards to [`gfx unpack`](pack-cli.md): `--dest-root`
(parent directory, default `.`), `--repo <name>:<path>` per-repo overrides,
`--force`, `--worktree`, `--restore-remotes`, `--identity` (age), and
`--keep-going`. The archive lands in a temporary directory
(`$TMPDIR/gfx-transfer-*`), is unpacked, and the temp directory is
removed. Repos materialize under `<dest-root>/<archive-name>/` — `main` in
the examples above.

## Failure semantics

- Sender tool exits non-zero (receiver declined, network lost) → exit 1;
  the tool's diagnostics are on stderr.
- A failed receive never runs unpack. A failed *unpack* behaves like
  `gfx unpack` on a corrupt archive.
- A Ctrl-C/SIGKILL can leave a `gfx-transfer-*` directory in `$TMPDIR`;
  the OS temp cleaner reaps it.

## Verifying locally

`scripts/transfer-loopback.sh` runs a real wormhole round-trip of a
fixture repo on one machine (needs network + LuLu approval) and checks
refs, content, fsck, and an anonymized transfer.
