# Plan: stream-file endpoints, `.gitignore` enforcement, and collapse anonymization

|            |                                                                    |
|------------|--------------------------------------------------------------------|
| Status     | In progress (M0–M5 done)                                           |
| Created    | 2026-10-08                                                         |
| Updated    | 2026-10-08 (M0)                                                    |
| Depends on | [plan-pass-driver-strip-blobs.md](plan-pass-driver-strip-blobs.md) §4 (driver), [plan-fast-export.md](plan-fast-export.md) §5–§7 (architecture, remap), [plan-redact-idents.md](plan-redact-idents.md) (redact pass), [plan-remote-data.md](plan-remote-data.md) (remotes policies), [rewrite-cli.md](rewrite-cli.md) (CLI surface) |

## Goal

Today every `gfx` round is **repo → repo**: `git fast-export` out of a real
repository, passes, `git fast-import` back into it. The pass pipeline itself
is already pure stream-in/stream-out (`transform_stream`, sans-IO); only the
*endpoints* are hard-wired to subprocesses. This plan makes the endpoints a
first-class choice so any combination works:

| Mode          | Invocation shape              | Meaning |
|---------------|-------------------------------|---------|
| repo → repo   | `gfx --repo R`                | today's in-place rewrite (unchanged) |
| repo → file   | `gfx --repo R --out S[.gz]`   | export → passes → stream file; repo untouched |
| file → repo   | `gfx --in S[.gz] --repo R`    | stream file → passes → import into repo |
| file → file   | `gfx --in S1 --out S2[.gz]`   | pure stream-to-stream; no git subprocess at all |

Stream files are `git fast-export` streams, **optionally gzip-compressed**
(gzippable on write, gzip-transparent on read). Two accompanying features
make the stream-file flows useful for producing share-safe snapshots without
a scratch clone:

1. **`.gitignore` enforcement** — a new builtin pass (`enforce-ignore`) that
   drops file-modify ops for paths the repository's own ignore rules say
   should never have been tracked.
2. **Collapse anonymization** — a new `redact` mode that maps *every*
   author/committer/tagger ident to a single name/email, composing with the
   existing timestamp modes for full metadata anonymization.

## Non-goals

- **No stdin/stdout endpoints in v1.** `-` is reserved syntax; v1 takes
  filesystem paths only. (Buffered rounds already hold the whole stream in
  memory, so true streaming I/O is a separate, later optimization — same
  posture as the existing driver.)
- **No multi-stream archives.** `gfx pack`/`gfx unpack` (plan-multistream-pack)
  already own fan-out/fan-in; this plan is strictly single-stream. Pack
  members stay raw (the archive compresses/encrypts as a whole).
- **No message/path/blob-content anonymization.** Collapse covers idents
  (+ existing time modes). `fast-export --anonymize`-style rewriting of
  messages, paths, and contents remains out of scope (a future message
  pass, cf. plan-redact-idents §4.8).
- **No new ignore-rule sources.** Rules come from an operator-supplied file
  and/or the stream's own `.gitignore` blobs. We do not read
  `$GIT_DIR/info/exclude`, global `core.excludesFile`, or working-tree
  files (none of those exist for stream inputs).
- **No behavior change to existing invocations.** `gfx --repo R` and
  `gfx pack/unpack` stay byte-for-byte what they are today (same posture as
  plan-remote-data C7).

## Constraints

C1. **Passes stay sans-IO and `no_std`.** All new I/O (file reads, gzip,
    directory creation) lives in the `gfx` facade / `gfx-cli` std side.
    The ignore matcher and the collapse policy are pure, deterministic,
    injectable — same pattern as `SharedMatcher` / `IdentPolicy`.
C2. **Determinism.** Identical inputs + config ⇒ identical output bytes,
    including gzip containers (mtime 0, no original-name field, fixed OS
    byte, pinned compression level; byte-stability then holds per pinned
    `flate2` version, documented).
C3. **Fail-closed validation.** Nonsensical endpoint combinations
    (`--out` alone, `--in` == `--out`, remotes flags without a repo
    endpoint) are usage errors raised *before* anything is read or
    written — same posture as pass-order validation (rewrite-cli.md).
C4. **Read-only when no repo is written.** repo → file and file → file
    never mutate a repository; the source repo of repo → file is only
    read, so the non-bare safety check must not block it.
C5. **Safety preserved when a repo *is* written.** file → repo performs
    the same bare-check / `--force` gate as today's rewrite, on the
    destination, before import.
C6. **Marks-space honesty.** New commit OIDs are only knowable after a
    `git fast-import` assigns them (R4). File outputs therefore carry
    mark-space maps, never fabricated OIDs, and the report says so.
C7. **Credential/exec safety inherits.** Remote-data flags
    (`--save-remotes` et al.) keep their plan-remote-data semantics and
    only ever touch real repos; stream files carry no config.
C8. **Ignore enforcement never erases its own rules.** `.gitignore`
    blobs are rule carriers: the pass never drops them (mirroring
    strip-blobs' default `protect-glob` for `**/.gitignore`).

## Research findings (empirical, this codebase)

R1. **The pipeline is already endpoint-agnostic.** `driver.rs` calls
    `git::process::export_stream(&repo)` → `transform_stream(&input,
    &passes)` → `git::process::import_stream(&repo, &out.output, …)`. Those
    are the only three repo couplings in the round; everything between is
    `Vec<u8>` in / `Vec<u8>` out. The endpoint split is a driver-layer
    refactor, not a pipeline change.
R2. **Buffered rounds.** Export and output streams live fully in memory
    (documented v1 posture in `driver.rs`). File endpoints inherit this —
    fine for snapshots; a streaming-IO future optimization applies to all
    four modes at once.
R3. **Export flags are pinned and include `--show-original-ids` and
    `--all`** (`git.rs` `EXPORT_FLAGS`), so gfx-produced stream files carry
    `original-oid` lines and `refs/remotes/*` resets. Foreign streams may
    not — see D5.
R4. **Remap finalization is mode A.** `Remap::finalize_from_marks` folds
    fast-import's `--export-marks` output into the `old → new` commit map.
    Without an import there is no marks file, and computing new OIDs
    sans-IO would require rebuilding tree hashes through every stripped
    blob — reimplementing fast-import's tree builder. Rejected for v1
    (C6); `gfx-hash` exists (host-injected `Hasher`, sha1/sha256 features)
    but is not wired to remap, and wiring it would only fix the
    metadata-rewrite case, not the tree-mutation case.
R5. **gzip is already in the workspace.** `gfx-pack` depends on `flate2`
    (rust_backend/miniz) for its zip deflate; adding gzip framing is a
    feature-flag away and adds no new external dependency families.
R6. **Redact already has the policy seam.** `IdentPolicy` is a host-
    injected pure function `(role, ident) → ident`; builtins are an exact
    table and two pseudonymizers (`User N <userN@example.invalid>`, digest
    variant). A collapse mode is a third builtin, not a new mechanism. The
    report audits *injectivity* and surfaces `collision:` entries — a
    deliberate total collapse must declare itself non-injective so the
    audit doesn't light up with N_expected collisions (D7).
R7. **strip-blobs' path machinery is doublestar globs, not gitignore
    semantics.** Gitignore differs in five ways: basename matching for
    slash-free patterns, directory-only `foo/`, anchoring for
    slash-bearing patterns, `!` negation, and per-directory stacking with
    last-match-wins. Reusing `path-glob` for ignore enforcement would be
    silently wrong (e.g. `*.log` must match at every depth; `doc/*.html`
    must anchor). A dedicated matcher is required (D6).
R8. **`.gitignore` files ride the stream.** They are ordinary blobs
    modified by ordinary `M` ops, and fast-export emits commits in
    topo order with `from :mark` parentage — so per-commit ignore state
    is *recoverable* from the stream itself by propagating state along
    marks (D6, M4). This is what makes file → file enforcement possible
    with zero repo access.
R9. **Safety check guards import, not export.** `check_safety` refuses
    non-bare repos because import rewrites refs under a working tree.
    Export is read-only. The endpoint split must move the check to the
    *sink* side (C4/C5) — a small, well-contained change to `round()`.
R10. **Artifact location is `<gitdir>/gfx/`.** commit-map, ref-map,
    report, marks all live under the target repo's git dir. Stream sinks
    have no git dir — artifacts need a documented home (D4).

## Decision points

### D1 — Endpoint model

**Options.** (a) Two new flag pairs (`--in`/`--out`) composed with
`--repo`, validated into four modes; (b) a single `--source`/`--sink`
pair of `repo:PATH` / `stream:PATH` URIs; (c) new subcommands
(`gfx export`, `gfx import`, `gfx filter`).

**Analysis.** (c) fragments the CLI and duplicates the entire pass-flag
surface across subcommands; the registry model makes that expensive. (b)
is uniform but pushes mode validation to runtime string parsing and reads
worse in shell. (a) reuses the one flag users already know (`--repo`),
keeps validation structural (`clap`-style conflicts, cf. `args.rs`), and
maps 1:1 onto the four modes table above.

**Decision.** (a). `Source = Repo(PathBuf) | Stream(PathBuf)`, `Sink`
likewise, both in the `gfx` facade:

- `--repo R` alone → repo → repo (today, unchanged).
- `--repo R --out S` → repo → file.
- `--in S --repo R` → file → repo.
- `--in S --out S` → file → file.
- `--in` alone, `--out` alone, `--in == --out`, or `--in`/`--out` equal to
  a path inside `--repo`'s git dir → usage error, before any I/O (C3).

### D2 — gzip framing

**Options.** (a) extension-driven only (`.gz` ⇒ gzip); (b) magic-sniff on
read, extension-or-flag on write; (c) always require an explicit format
flag.

**Analysis.** (a) breaks on pipes-with-names and temp files; (c) is
hostile UX. (b) is how well-behaved unix tools behave: reads sniff the
`1f 8b` magic (never trust the name), writes default to `auto`
(`.gz` suffix ⇒ gzip, else raw) overridable with
`--out-compression auto|none|gzip`.

**Decision.** (b). Decode: sniff first two bytes; `1f 8b` ⇒ streaming
gunzip, else pass through. Encode: `GzBuilder` with empty filename,
mtime 0, OS byte 255, pinned level (default 6, flag `--out-gzip-level`
1–9) for C2 determinism. Helpers live in the `gfx` facade (std-gated),
shared by driver and CLI; `flate2` moves to a workspace dependency.

### D3 — Safety and remotes policies per mode

**Decision.** The safety check binds to the *sink* (R9):

| Mode        | Safety check                     | Remotes flags |
|-------------|----------------------------------|----------------|
| repo → repo | source (=sink), as today         | as today |
| repo → file | none (read-only)                 | `--save-remotes` allowed (captures from source repo); `--restore-remotes`/`--remote-refs` = usage error (no written repo) |
| file → repo | destination repo (bare/`--force`) | `--restore-remotes`/`--remote-refs` allowed against destination; `--save-remotes` = usage error (nothing pre-existing to save — the destination is fresh or force-overwritten) |
| file → file | none                             | all remotes flags = usage error |

`refs/remotes/*` *inside* streams (R3) are not filtered in v1: what the
stream carries is what the sink gets. Stream-side ref filtering
(e.g. `--remote-refs drop` stripping `reset refs/remotes/*` events from
an output stream) is a clean follow-up pass, noted here as future work.

### D4 — Artifacts for stream sinks

**Options.** (a) `<out>.gfx/` sibling directory; (b) `--artifacts <dir>`
flag, defaulting to (a); (c) no artifacts without a repo.

**Analysis.** The artifact surface (commit-map, ref-map, report) is a
documented contract; silently dropping it in file modes breaks the
filter-repo parity story. (a) alone is magic; (c) alone loses data.

**Decision.** (b): default `<out>.gfx/` (i.e. `out.feat.gz` →
`out.feat.gz.gfx/`), overridable with `--artifacts <dir>`. For stream
sinks the commit-map is written **in mark space** (C6): a `commit-marks`
file (`<old-oid> :<mark>`) plus a report note that finalization happens
at import. When the same stream is later imported via file → repo, the
driver folds import marks into the real `old → new` map exactly as
today. `--dry-run` keeps its meaning (no writes at all) in all modes.

### D5 — Foreign stream inputs

**Decision.** Stream inputs SHOULD carry `original-oid` lines
(gfx-produced ones do, R3). A stream without them is accepted but the
commit-map degrades to presence-only, and the report carries a
`no_original_ids` warning — same degradation remap already documents when
`original-oid` is absent. A stream that is not fast-export format fails
at the parser with the existing error surface. v1 does not validate
"beyond the parser" (no schema sniffing, no `--show-original-ids`
enforcement flag).

### D6 — `enforce-ignore`: rule sources and matching semantics

**Options for rule sources.** (a) operator-supplied rules file only
(`--enforce-ignore.rules <file>`); (b) in-stream `.gitignore` tracking
only; (c) both, composable.

**Options for matching.** (i) reuse strip-blobs' doublestar; (ii) a
dedicated no_std gitignore matcher crate (`gfx-ignore`); (iii) shell out
to `git check-ignore`.

**Analysis.** (iii) violates C1 (sans-IO passes) and is impossible for
file → file (there is no repo and no working tree to check against —
`check-ignore` answers working-tree questions). (i) is silently wrong
per R7. For sources: (a) alone can't see per-directory or per-era rule
changes; (b) alone can't enforce rules the history *should* have had
(e.g. "this repo never had a `.gitignore`, enforce today's"); (c) covers
both and composes naturally — external file = root-anchored rules present
from the first commit, in-stream tracking = the history's own evolving
rules.

**Decision.** (c) + (ii). New `no_std` crate `gfx-ignore` implementing
gitignore semantics over byte paths: slash-free patterns match basenames
at any depth; slash-bearing patterns anchor to the rule file's directory;
trailing `/` matches directories (hence everything beneath); leading `!`
negates; last matching pattern wins across the stacked rule set. Escape
handling (`\!`, `\#`, trailing-space) per gitignore(5). Documented v1
deviation: character-class edge cases in `fnmatch` corners follow
doublestar-compatible behavior, validated against `git check-ignore`
fixtures in tests. The pass drops `M` ops whose path is ignored
(drop-first, never synthesize — strip-blobs D1 applied verbatim), never
drops `.gitignore` carriers themselves (C8), keeps zero-op commits (with
a report count), and reports every drop with the winning rule.

State propagation (in-stream source, R8): each commit inherits its first
parent's ignore-rule state by mark, applies its own `.gitignore` `M`/`D`
ops, and judges its remaining ops against the resulting set — i.e. rules
of the commit's own tree. Non-first-parent state is ignored (merge
commits use the mainline's rules; documented). Memory: one persistent
(immutable, `Arc`-shared, copy-on-write) rule-set per live mark; bounded
by live marks, same order as remap's bookkeeping.

CLI shape:

| Flag | Meaning |
|---|---|
| `--enforce-ignore.rules <file>` | extra gitignore-format rule file, applied root-anchored from stream start (repeatable; host-read, injected — C1) |
| `--enforce-ignore.stream-rules` | also track `.gitignore` blobs carried by the stream itself (M4) |
| `--enforce-ignore.keep-empty` | drop zero-op commits left behind (default: keep, matching strip-blobs) |

At least one rule source is required, else usage error (a pass with no
rules is a no-op the user didn't mean).

### D7 — Collapse anonymization in `redact`

**Options.** (a) new `RedactMode::Collapse { name, email }` builtin;
(b) host-injected `IdentPolicy` only; (c) extending the exact-map table
with a catch-all.

**Analysis.** (b) already works today with zero changes but puts the
feature behind a library-only door — the ask is a CLI feature. (c)
abuses the map format. (a) is one more builtin beside the two existing
pseudonymizers, same wiring.

**Decision.** (a). All author/committer/tagger idents map to a single
`(name, email)`, default `Anonymous <anonymous@example.invalid>`
(matching the pseudonymizers' `example.invalid` convention), overridable
via `--redact.collapse-name` / `--redact.collapse-email`. The mode
declares itself **intentionally non-injective** (R6): the report's
injectivity audit is suppressed for collapse runs and replaced by an
`idents_collapsed=<n distinct originals>` total, so a successful collapse
reads as success, not as N collisions. Composes with all existing time
modes — `gfx --passes redact --redact.mode collapse --redact.time zero`
yields single-ident, zeroed-timestamp history: full metadata
anonymization in one round. Redact stays opt-in (registry `default`
override, plan-redact-idents D2) in all endpoint modes.

### D8 — Where the code lives

**Decision.**

- `gfx-core`: untouched (event model already suffices).
- `gfx-ignore` (new, `no_std`): matcher only. Path-in → match-out plus
  the winning rule for reports. No `Transform`.
- `gfx-strip-blobs` *(decision: no)* — enforcement is **not** folded into
  strip-blobs: selection semantics differ enough (R7) that a shared pass
  would grow a second, alien config surface. New builtin crate
  `gfx-enforce-ignore` (feature `enforce-ignore`) owning the `Transform`
  and the mark-keyed rule-state propagation.
- `gfx-redact`: `RedactMode::Collapse` + report/audit adjustment (D7).
- `gfx` facade: `Source`/`Sink` endpoint plumbing, gzip helpers (std),
  safety-check move to sink side (R9), artifact-dir resolution (D4).
- `gfx-cli`: `--in`/`--out`/`--out-compression`/`--artifacts`, mode
  validation (D1), new pass registration + flags (D6/D7), doc updates.

## Milestones

Each milestone lands green (tests + docs) and keeps existing invocations
byte-identical.

- [x] **M0 — Endpoint plumbing, raw streams.** `Source`/`Sink` in the
      facade; `--in`/`--out` + validation matrix (D1); safety check moved
      to the sink (R9); report/artifact shape for mark-space maps staged
      (`commit_map_finalized`, `no_original_ids` report warning; D5);
      Endpoint errors are CLI exit 2. Stream-sink artifact files
      (`<out>.gfx/` + `commit-marks`) deliberately wait for M1, which
      adds the marks-aware write path. Tests: `crates/gfx/tests/endpoints.rs`
      (facade, 8 tests), `crates/gfx-cli/tests/endpoints.rs` (CLI, 3).
- [x] **M1 — gzip.** D2 sniffing + deterministic encoding (flate2 default
      header: mtime 0, no name, OS 255; level pinned, default 6);
      `--out-compression` / `--out-gzip-level`; `flate2` is now a workspace
      dependency (`gfx` std-gated, `gfx-pack` moved onto it). Stream-sink
      artifact surface landed here: `<out>.gfx/` (or `--artifacts`) with
      `commit-map` (pre-finalization view), `ref-map`, `run-report.txt`,
      per-pass reports, and `commit-marks` (mark space; C6). Tests: magic
      sniffing vs. misleading names both directions, byte-determinism
      across runs, `.gz` round-trip through import (facade + CLI).
- [ ] **M2 — `gfx-ignore` matcher.** no_std crate, gitignore semantics
      per D6, property tests against `git check-ignore` fixtures (host
      side generates cases: temp repo, patterns × paths, compare verdict
      and winning rule), `bstr`-clean byte paths, fuzz target extended.
- [x] **M3 — `enforce-ignore` pass, external rules.** New
      `gfx-enforce-ignore` crate (drop-first M; kept-D validity via the
      vindex rewritten view; `C`/`R` judged both sides; zero-op commits
      kept and counted; C8 `.gitignore` carriers never dropped), wired as
      `PassSpec::EnforceIgnore` after strip-blobs / before redact, CLI
      `--enforce-ignore.rules <file>` (repeatable, host-read, opt-in —
      not in the default `--passes`), unused-flag guard, and
      `ignore-report.txt` artifacts. Tests: crate units + CLI E2E
      (in-place and repo→file→repo) pinning exact path sets and fsck.
- [x] **M4 — `--enforce-ignore.stream-rules`.** Mark-keyed per-commit
      rule-state propagation (D6/R8): each commit inherits its first
      parent's stream-rule state (`Arc`-shared, copy-on-write), applies
      its own `.gitignore` M/D ops (inline or blob-mark content; OID-
      sourced content counted as `rules_unresolved`), and is judged
      against the result layered under the external rules (operator
      intent wins ties — `Ruleset::combined`). Resets re-seat ref state.
      Own-tree semantics pinned: a mid-history `.gitignore` drops only
      after introduction (enforcing rules onto earlier history is what
      `--enforce-ignore.rules` is for). Tests: introduction/edit/delete,
      nested-dir scoping, branch inheritance, external composition, and
      CLI E2E incl. a no-repo file → file run.
- [x] **M5 — Collapse anonymization.** `IdentMode::Collapse { name,
      email }` (D7) with CLI `--redact.collapse[`-name`/`-email`]
      (default `Anonymous <anonymous@example.invalid>`); mutually
      exclusive with `--redact.map`/`--redact.pseudonymize`. The
      injectivity audit is suppressed for collapse runs and replaced by
      `idents_collapsed` (report summary reads `collapse=1 …`). Tests:
      crate-level leak scan + audit replacement + time-mode composition;
      CLI E2E in-place and file → file with a custom target identity;
      flag-conflict usage errors.
- [ ] **M6 — Docs + hardening.** `rewrite-cli.md` endpoints section
      (four-modes table, artifact locations, mark-space caveat);
      `docs/git-baseline.md` note if export flags are touched (they are
      not); E2E: repo → file → repo reproduces the in-place rewrite's
      refs exactly; fuzz: stream-file round-trips through gzip and
      enforce-ignore.

## Open questions

- O1. Should repo → file default to gzip when `--out` ends in `.gz`, or
  require explicit `--out-compression gzip`? (Current: D2's `auto` —
  extension wins. Revisit if surprising in practice.)
- O2. Mark-space `commit-marks` is a new artifact name; folding it into
  `commit-map` with a header marker was rejected as format-mixing, but a
  second pair of eyes on downstream consumers (`gfx-pack` manifests) is
  warranted before M0 lands.
- O3. Stream-side `refs/remotes/*` filtering (D3 future work) may deserve
  promotion to M4-adjacent if snapshot flows turn out to want it.
