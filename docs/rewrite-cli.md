# `gfx rewrite` — CLI guide

`gfx` is a `git filter-repo`-style history rewriter: it names a sequence of
passes, runs one round of `git fast-export` → passes → `git fast-import`,
and writes `commit-map` / `ref-map` / run-report artifacts — the same
invocation shape as filter-repo, with explicit, user-ordered passes and
remap always composing last.

Design + rationale: [`plan-pass-driver-strip-blobs.md`](plan-pass-driver-strip-blobs.md)
(decisions D1–D4). This file is the user-facing surface.

## Installation / binaries

```
cargo build --release
target/release/gfx                    # all passes: strip-blobs, remap
target/release/examples/strip-blobs   # single-pass helper (flat flags)
target/release/examples/remap         # single-pass helper (flat flags)
```

Build the helpers with `cargo build --release --examples`.

## Safety model

- Bare repositories pass the safety check.
- Non-bare repositories are refused without `--force` (use a fresh
  `git clone --bare`).
- `--dry-run` runs export → passes → report and touches nothing: no
  import, no ref changes, no artifacts.
- Pass-order violations (`--passes remap,strip-blobs`) are usage errors
  validated **before** the repository is touched.

## Basic usage

```
# Dry-run: what would change?
gfx --repo my-repo.git --dry-run \
    --strip-blobs.larger-than 100K \
    --strip-blobs.content-signals

# Rewrite in place (bare repo).
gfx --repo my-repo.git \
    --strip-blobs.larger-than 100K \
    --strip-blobs.path-glob '**/*.min.js' \
    --strip-blobs.protect-glob '**/keep/**'
```

Afterwards, optionally reclaim space (printed as advice, never run for
you):

```
git -C my-repo.git reflog expire --expire=now --all && git -C my-repo.git gc --prune=now
```

## Flags

Global:

| Flag | Meaning |
|---|---|
| `--repo <path>` | repository to rewrite (default `.`) |
| `--passes <spec>` | comma-separated pass names in pipeline order (default `strip-blobs,remap`) |
| `--force` | override the safety check |
| `--dry-run` | no import, no ref changes, no artifacts |
| `--config <file>` | TOML flag defaults; CLI flags win (below) |
| `--help` | generated usage from the pass registry |

Pass flags are namespaced in composed binaries and flat in single-pass
helpers; the flat form is accepted in composed binaries when unambiguous.

### strip-blobs

| Flag | Meaning |
|---|---|
| `--strip-blobs.larger-than <size>` | strip blobs strictly larger than this (`512K`, `1M`, bytes) |
| `--strip-blobs.path-glob <glob>` | strip paths matching the glob (repeatable; `**` doublestar, byte-exact) |
| `--strip-blobs.protect-glob <glob>` | never strip matching paths (repeatable; defaults protect `**/.gitattributes`, `**/.gitignore`, `**/.gitmodules`) |
| `--strip-blobs.content-signals` | enable generated-content signals (off by default at the CLI; on by default in the library) |
| `--strip-blobs.strip-symlinks-too` | also judge symlink payloads |

Semantics (decision D1): the pass **drops** selected ops and never
synthesizes counter-ops. Consequences, deliberately chosen and reported:

- Removing an `M` that changed path `P` makes `P` revert to its last
  surviving content under **blob selection**; path selection never reverts.
- Copies/renames of selected content are dropped; each divergence is a
  report entry.
- Deletes of paths erased by the pass itself are normalized away.
- Commits left with zero surviving ops are **kept** (no `--prune-empty`
  in v1) and counted in the report.

### remap

| Flag | Meaning |
|---|---|
| `--remap.track-message-oids` | harvest old OIDs referenced in commit messages |

Remap runs last (enforced; naming it earlier is an error). It tracks the
old→new commit mapping; `commit-map` is finalized from fast-import's
exported marks after the round. In v1, remap flags rewritten commits via
`original-oid` bookkeeping — see the implementation note in
[plan §5.5](plan-pass-driver-strip-blobs.md).

### redact

Pass name `redact`; registered in the composed `gfx` binary but **not in
the default `--passes`** — redaction is always opt-in. Rewrites
`author`/`committer`/`tagger` identities and timestamps; never touches
ops, topology, marks, or messages (see the checklist below for what that
leaves behind).

| Flag | Meaning |
|---|---|
| `--redact.map <toml>` | exact `[[row]]` mappings (`name?`, `email?` wildcards, `new_name`, `new_email`); mutually exclusive with `--redact.pseudonymize` |
| `--redact.pseudonymize` | replace every ident with a deterministic pseudonym |
| `--redact.pseudonym-style ordinal\|hash` | `ordinal` (default): `User 1 <user1@example.invalid>`, derives nothing from input bytes, does not correlate across repos. `hash`: stable across repos but brute-forceable — convenience, not safety |
| `--redact.time-mode preserve\|zero\|shift\|bucket\|fuzz` | `preserve` (default) keeps epochs; `zero` collapses the time axis; `shift <secs>` preserves order/intervals; `bucket day\|week\|month` floors in UTC; `fuzz` jitters within a window (order *not* monotone) |
| `--redact.time-shift <secs>` | shift amount, e.g. `365d`, `2w`, or plain seconds |
| `--redact.time-bucket day\|week\|month` | bucket boundary (UTC) |
| `--redact.time-jitter <secs>` | fuzz window |
| `--redact.seed <n>` | fuzz seed (required for fuzz; invalid otherwise) |
| `--redact.keep-tz` | keep timezone offsets — they are **zeroed by default** in every mode (offsets are geographic metadata) |

Semantics (decision D1, doc-scoped): the pass **rewrites fields in place
and never restructures anything**. A commit whose idents and times the
policy leaves unchanged keeps its hash (a pinning table + `keep-tz` is a
byte-identity round).

- Time modes have documented consequences: `shift` preserves order and
  intervals (the interval fingerprint survives — by design, by choice);
  `zero` destroys the axis; `bucket` keeps coarse order; `fuzz` is
  deterministic obfuscation with a retained seed, not cryptography.
- Unparseable `when` fields keep their bytes only under
  `preserve` + `keep-tz`; every redacting mode regenerates them.
- Distinct idents mapped to one replacement (merge rows) are reported as
  `collision` entries — visible, never silent.
- Giving `--redact.*` flags without `redact` in `--passes` is a usage
  error: redaction is never silently skipped.

The `--redact.map` file:

```toml
[[row]]
name = "Alice"                # omit for a wildcard
email = "alice@example.com"   # omit for a wildcard
new_name = "Bot 1"
new_email = "bot1@ci.invalid"
```

TOML is UTF-8, so rows cannot express non-UTF-8 ident bytes; host code
injects an `IdentPolicy` for that.

### blob-xform

Pass name `blob-xform`; registered in the composed `gfx` binary but **not
in the default `--passes`** — content rewriting is always opt-in. Runs a
fallible transform chain over every blob payload (standalone blobs and
inline `M`/`N` data): **alter on success, retain the original bytes on
failure** (plan-blob-xform.md, decision D1). Never drops, synthesizes, or
reorders an event; commits referencing an altered blob get new hashes as
usual (remap owns that bookkeeping).

| Flag | Meaning |
|---|---|
| `--blob-xform.crlf-to-lf` | chain stage: CRLF/CR line endings become LF (byte-level, never fails) |
| `--blob-xform.trim-trailing-whitespace` | chain stage: strip trailing spaces/tabs per line (text blobs; non-UTF-8 ⇒ retained) |
| `--blob-xform.ensure-final-newline` | chain stage: end text blobs with exactly one newline (text blobs; empty stays empty) |
| `--blob-xform.skip-larger-than <size>` | leave blobs larger than this alone (counted as retained-guard) |
| `--blob-xform.max-output-bytes <size>` | discard a chain result larger than this; retain the original |
| `--blob-xform.include-special-modes` | also transform inline symlink/gitlink payloads (skipped by default) |
| `--blob-xform.cmd <shell>` | chain stage: pipe each blob through this shell command (repeatable) — stdin is the blob, stdout the replacement; non-zero exit (or capture overrun) retains the original. **The command is the purity contract**: gfx cannot enforce that it is deterministic. stderr is swallowed; no per-blob timeout in v1 |

- **Chain order is argv order**:
  `--blob-xform.crlf-to-lf --blob-xform.trim-trailing-whitespace` runs the
  line-ending fix first. Any stage failing retains the *original* bytes,
  not the last good intermediate (D1 atomicity).
- `blob-xform` in `--passes` with no transform flag is a usage error, and
  `--blob-xform.*` flags without the pass in `--passes` are a usage error:
  content rewriting is never silently skipped.
- Fixed stage order in the driver: blob-xform runs *before* strip-blobs,
  so size-based stripping judges post-transform sizes (plan-blob-xform.md
  D7).
- Standalone `blob` events carry no file mode: byte-level transforms like
  `crlf-to-lf` apply to *every* blob, binaries included. If a blob must
  not be touched, gate it with `--blob-xform.skip-larger-than` or keep
  binary history out of scope.
- **Symlink hazard (plan-blob-xform.md D5):** a symlink's target path is
  stored as blob bytes, and standalone blobs arrive before the commits
  that reference them, so the pass cannot know a blob is a symlink target.
  A transform that touches trailing bytes (`trim-trailing-whitespace`,
  `ensure-final-newline`) can therefore rewrite a symlink target — e.g.
  a link to `/opt/data /x` becomes `/opt/data /x` trimmed, or gains a
  newline. Inline `M` ops know their mode and skip `Symlink`/`Gitlink`
  payloads by default; standalone blobs cannot. If your history has
  symlinks with whitespace-sensitive targets, prefer injected,
  content-aware transforms over the built-ins.

## Pre-sharing checklist

Redacting idents and times does not make a repo anonymous. Before
sharing outside your organization, work through:

1. **Idents and times** — `--passes redact,remap` with
   `--redact.pseudonymize --redact.time-mode zero` is the strong default;
   `preserve` (with its default tz zeroing) is the internal-hand-off
   choice.
2. **Commit and tag messages** — `Signed-off-by:`, `Co-authored-by:`,
   quoted emails, and prose self-identification are **not** rewritten in
   v1 (message rewriting is a separate future pass). `git log --format=%B
   | grep -iE 'signed-off-by|@'` to see what would leak.
3. **Ref names** — `refs/heads/alice/fix-thing` leaks identity; rename or
   drop such refs first (v1 has no ref renaming).
4. **Paths** — `src/alice/…` leaks identity; path rewriting is out of
   scope for redact (a future anonymize pass covers it).
5. **The mapping artifact** — `<gitdir>/gfx/redact-map.txt`
   re-identifies the anonymized repo. It is the join key for any future
   message-rewrite pass; keep it out of the repository and out of shared
   backups.
6. **GPG signatures** — the driver strips signed tags
   (`--signed-tags=strip`); commits carrying signatures will fail
   verification after any rewrite.

## Config file

```toml
# gfx-rewrite.toml — table name is the pass, keys are flat flag names.
[strip-blobs]
larger-than = "1M"
path-glob = ["**/Cargo.lock", "*.min.js"]
content-signals = true

[redact]
pseudonymize = true
time-mode = "zero"

[remap]
track-message-oids = false
```

`gfx --repo my-repo.git --config gfx-rewrite.toml` — CLI flags override
file values; unknown passes or flags in the file are usage errors.

## Artifacts

- `commit-map` / `ref-map` / `run-report.txt` — driver artifacts.
- `strip-report.txt` — per-path stripping decisions (when the strip-blobs
  pass ran).
- `redact-map.txt` — **SENSITIVE**: the ident/time mapping produced by
  the redact pass. It re-identifies the anonymized repo; keep it local.

After a successful round, `<gitdir>/gfx/` contains:

| File | Content |
|---|---|
| `commit-map` | `old-oid new-oid` per line (post-finalization) |
| `ref-map` | `old-tip new-tip refname` (full before/after snapshot) |
| `run-report.txt` | pass summaries, byte counts, identity flag |
| `strip-report.txt` | strip totals + bounded per-op listing (`(divergent)` marks D1 divergences) |

Artifacts are deterministic: identical runs on clones of the same source
produce byte-identical files.

## Custom binaries

`gfx-cli` is a library: wrap any pass subset into a purpose-built binary
(plan §4.2, decision D4):

```rust
gfx_cli::rewrite_binary! {
    binary: "my-rewriter",
    about: "strip vendor blobs and remap",
    passes: [gfx_cli::passes::strip_blobs_factory(), gfx_cli::passes::remap_factory()],
}
```

Each pass crate also ships an example helper binary built exactly this
way (`examples/strip-blobs.rs`, `examples/remap.rs`).

## Known v1 limitations

- Buffered rounds: the export stream and event list live in memory.
- Empty branches (refs with no commits) are dropped by the round-trip.
- No `--prune-empty`, no `--replace-refs`, no partial-history
  (`--refs`) rewriting, no message-hash rewriting yet — see the plan's
  Deferred section.
- Redact does not rewrite messages, ref names, or paths — see the
  pre-sharing checklist above.
- `--redact.map` rows cannot express non-UTF-8 ident bytes (TOML
  limitation); use an injected `IdentPolicy` from host code.
- blob-xform's `--blob-xform.cmd` runs `sh -c` per blob with a bounded
  stdout capture (64 MiB unless `--blob-xform.max-output-bytes` says less);
  no per-blob timeout — a hung command hangs the run.

- Buffered rounds: the export stream and event list live in memory.
- Empty branches (refs with no commits) are dropped by the round-trip.
- No `--prune-empty`, no `--replace-refs`, no partial-history
  (`--refs`) rewriting, no message-hash rewriting yet — see the plan's
  Deferred section.
