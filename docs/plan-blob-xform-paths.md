# Plan: path-aware blob transforms — extension-gated, lazily-created blobs

| Field    | Value |
|----------|-------|
| Status   | Implemented (M0–M3) |
| Scope    | extend `gfx-blob-xform` with path rules: transform a blob only when it is used at a path matching a rule (e.g. `rustfmt` every `*.rs`), caching the result and creating the transformed blob once, at its first matching use |
| Depends  | [plan-blob-xform.md](plan-blob-xform.md) (implemented M0–M3: fallible-transform core, D1 retention, cmd adapter, driver stage); plan-multistream-pack.md D3 (pre-scan precedent) |
| Updated  | 2026-09-13 (M3 recipes + rustfmt E2E; see [rewrite-cli.md](rewrite-cli.md)) |

## 1. Summary

The base pass (plan-blob-xform.md) is deliberately **mode- and
path-blind**: standalone `blob` events carry no file name, so a whole-blob
transform like `crlf-to-lf` applies to every blob alike (its D5 hazard).
That rules out the canonical blob-xform use case — *"run `rustfmt` on
every `.rs` file in history"* — which must decide by **path**.

The path arrives only later, in `commit` events: an `M <mode> :<mark>
<path>` op is the first moment the stream binds a blob mark to a file
name. And a blob's path is not unique property of the blob: the same mark
can be referenced by many commits, under **different paths with different
extensions** (verified: one blob exported once, then referenced as both
`a.rs` and `d.txt` by later commits). So path-aware transformation cannot
happen at the `blob` event; it must happen **at the M-op site**, where
path *and* mode are known.

This plan adds **path rules** to `gfx-blob-xform`: an extension-keyed map
of transform chains (`.rs → rustfmt …`, `.py → black …`). The pass streams
unchanged in structure — original blob events always pass through — but
caches blob bytes as they go by. When a commit's M op references a cached
blob at a matching path, the pass runs that rule's chain on the cached
bytes (fail-open, same D1 semantics as the base pass), emits the result
as a **synthetic blob event immediately before the commit**, under a
freshly allocated mark, and rewrites the op to reference it. The
transformed blob is created **once per (blob, rule)** and reused by every
later matching use — the "cache a transformed blob, create it when first
used" model. Non-matching uses of the same blob keep the original mark
and see the original bytes.

## 2. Research findings (what makes this possible, and what constrains it)

All findings below were verified empirically against the system git
(macOS, Apple Git) and against the git-fast-import(1) documentation; the
experiments are reproducible in a scratch repo.

**R1 — fast-export interleaves blobs; paths bind late and non-uniquely.**
`git fast-export` does *not* emit all blobs first. Each blob is emitted
immediately before the first commit that references it, and blob/commit
marks come from **one shared mark space, allocated in emission order**
(observed stream: `blob :1`, `commit :2`, `blob :3`, `commit :4`, …).
A blob mark can be re-referenced by arbitrarily later commits under
different paths (observed: blob `:1` referenced as `a.rs` in commit `:2`
and as `d.txt` in commit `:8`). Consequences:

- The pass must buffer blob bytes from blob-event time until end of
  stream (a blob's *last* matching use is unknowable in streaming).
- Path-aware transformation happens at M-op sites, never at blob events.

**R2 — fast-import accepts blob commands anywhere before first use.**
Per git-fast-import(1), a `blob` is "not connected to any commit; this
connection must be formed in a subsequent `commit` command", and an M
op's dataref must be "a mark reference set by a **prior** `blob`
command". Verified: injecting a synthetic `blob` record immediately
before the first commit whose path matches, then rewriting that op (and
later matching ops) to the synthetic mark, imports cleanly; every
referencing path resolves to the transformed content.

**R3 — marks must be collision-free with the stream's future; there is no
error net.** git-fast-import(1) documents that "existing marks can be
moved to another object simply by reusing the same idnum" — mark
redefinition is *silent and sanctioned*. Verified consequences:

- Using a synthetic mark below the stream's eventual maximum: a later
  real `commit` redefines it; a still-later M op that should reference
  the synthetic blob then resolves to a commit object and the import dies
  mid-stream: `fatal: not a blob (actually a commit): M 100644 :4 d.txt`.
- A mark referenced before any definition fails fast (`fatal: mark :99
  not declared`) — ordering errors are at least loud.

Therefore synthetic marks must be allocated **above the stream's maximum
mark**, which requires knowing the maximum before emitting — a one-shot
pre-scan. The docs also "strongly encourage" dense marks 1..n (the marks
table is array-indexed), so synthetics should be allocated densely upward
from `max + 1`, not from some huge sparse base.

**R4 — the pre-scan is free: the driver already holds the whole stream.**
`PassDriver::round` exports the full stream into memory and
`transform_stream` parses **all** events into a `Vec<Event>` before
running any content stage. Computing `max_mark` is one cheap scan over
data already materialized; the driver injects it into the pass as a
`mark_base` before the stage runs. The pack driver shares the same
`transform_stream` path, and each repo's stream is independent there, so
each repo gets its own base — no cross-repo coordination is needed for
correctness (contrast plan-multistream-pack.md D3, where ordinal
pseudonyms *must* be shared archive-wide and needed a true pre-pass;
content-keyed transform caches have no such requirement).

**R5 — the driver's rewrite detection already does the right thing with
synthetic blobs, and forbids the alternative.** The canonical-diff
detection (plan-blob-xform.md M1) snapshots pre-pass event bytes by mark
and flags a mark as rewritten when its post-pass bytes differ, with
blob→commit propagation. A synthetic blob's mark is absent from the
snapshot ⇒ flagged as changed ⇒ every commit referencing it is correctly
flagged rewritten. Conversely this detection keys on marks, so the
alternative allocation scheme — renumbering *all* marks to make room —
would flag every event in the stream as rewritten and corrupt the
commit-map artifacts. **Allocated-above-max is the only compatible
scheme.**

**R6 — superseded originals are harmless.** The original blob event must
pass through (non-matching uses need it). If *every* use of a blob was
matching, the original becomes unreferenced; verified that this imports
as a `dangling blob`, which is invisible to refs and collected by `git
gc`. v1 accepts this; suppressing originals would require a second
streaming pass (out of scope, see open questions).

**R7 — memory model matches precedent.** The blob cache is O(sum of blob
bytes) ≈ repository content size — exactly what git-filter-repo pays for
the same job (it holds all blob contents in memory and does path-aware
rewriting in commit callbacks, its blob callbacks being equally
path-blind), and what this driver already pays (full stream + parsed
events, whose `Event::Blob` payloads inline every blob). No new
complexity class; a documented bound, not a regression.

**R8 — formatters fit the cmd adapter; failure is a feature.**
`rustfmt` reads stdin and writes stdout with `--emit stdout`; edition and
style-edition flags select the grammar/style. Rust's formatting stability
guarantee says a newer rustfmt cannot change output that a previous
version successfully formatted (same style edition), but configuration
options can change between versions — so the command is pinned
(version + flags) by the operator under the existing purity contract
(plan-blob-xform.md G4). Crucially, rustfmt exits non-zero on syntax it
cannot parse — which historical code often contains — and D1 fail-open
retention turns that into "format everything rustfmt can handle, carry
the rest untouched". `clang-format --assume-filename=x.cpp`,
`black -`, `gofmt` all read stdin/write stdout and slot into the same
adapter unchanged.

**R9 — mode-awareness is strictly better at the M-op site.** The base
pass's D5 hazard (whole-blob transforms can rewrite symlink *targets*,
because standalone blobs are mode-blind) does not apply here: the M op
carries the mode, so path rules skip `Symlink`/`Gitlink` payloads by
default — a `.rs` symlink survives even under a `.rs` rule.
`include_special_modes` opts back in.

## 3. Goals and non-goals

### Goals

- G1: Extension-gated transforms: a rule maps a path extension (`rs`,
  `py`, …) to a transform chain (built-ins and/or `--cmd`, reusing the
  base pass's `BlobTransform` machinery and adapters unchanged).
- G2: Create-once semantics: the transformed blob is produced at the
  first matching use, emitted as a synthetic blob before that commit, and
  reused by every later matching use of the same blob under the same
  rule; per-blob rule execution happens at most once per (blob, rule).
- G3: Original-preserving: the original blob event always passes through
  unaltered; non-matching uses of the same blob observe the original
  bytes. No event is ever dropped or reordered (synthetic blobs are only
  inserted, immediately before their referencing commit).
- G4: Fail-open per (blob, rule): transform error ⇒ the op keeps the
  original mark, counted as retained (plan-blob-xform.md D1 lifted to
  path rules).
- G5: Correctness under composition: synthetic marks never collide with
  stream marks (R3); rewrite detection, remap, and the marks-file
  finalization stay exact (R5); strip-blobs downstream can still strip
  synthetic blobs by size like any blob.
- G6: Mode-aware by default at M-op sites (R9); special modes skipped
  unless `include_special_modes`.
- G7: `no_std` mechanism in `gfx-blob-xform`; command execution stays in
  the `std` host (`gfx-cli::cmd::CmdTransform` reused as-is).

### Non-goals

- Glob/path-prefix matchers (`src/**.rs`, basename rules like
  `Makefile`): follow-up. Extension matching is the v1 domain; the rule
  key type is designed to grow (open questions).
- Suppressing superseded original blobs (R6 accepts dangling blobs).
- Cross-repo shared transform caches in pack (content-hash-keyed reuse
  is a perf follow-up, not a correctness need — R4).
- Cache eviction / disk spill for the blob cache (R7 documents the
  bound; v1 holds everything, matching filter-repo's operating point).
- Multi-file or project-context transforms (formatters that need
  sibling files); transforms remain per-blob pure functions.
- Transforming `Note` ops by path (notes carry no path).

## 4. Decisions

- **D1 (fail-open, inherited):** a rule-chain error on a blob retains the
  original mark at that op and counts it. Exactly plan-blob-xform.md D1,
  applied per (blob, rule) at M-op sites.
- **D2 (originals always pass through):** path rules never alter or drop
  a standalone `blob` event. The original must survive for non-matching
  uses, and whether any non-matching use exists is unknowable in
  streaming (R1). Superseded originals dangle (R6).
- **D3 (synthetic marks above stream max, driver-injected):** the pass
  allocates synthetic marks from `mark_base = stream_max_mark + 1`,
  counting up. The driver computes the max over the already-parsed events
  and injects the base before the stage runs (R4). Renumbering existing
  marks is rejected (R5); baseless allocation is rejected (R3). When the
  pass runs outside the driver (`transform_stream` used directly, tests),
  the caller injects the base the same way; a missing base with non-empty
  path rules is a **config error**, never a guess.
- **D4 (create at first matching use, cache by (mark, rule)):** the
  transformed cache maps `(original_mark, rule_id) → synthetic_mark`.
  First miss runs the chain on cached original bytes, allocates the
  synthetic mark, inserts the blob event before the commit; later hits
  only rewrite the op. The original-bytes cache maps `mark → bytes` for
  every blob (needed until end of stream, R1); the transformed-bytes are
  not retained (only the mark is reused).
- **D5 (one extension domain, per-extension chains):** v1 matches the
  final path component's bytes after the last `.` (case-sensitive,
  byte-exact; a path with no `.`, or ending in `.`, matches nothing).
  Each extension's chain runs in argv order, same chain semantics as the
  base pass. A path matches at most one extension, so multi-rule
  conflicts cannot occur in v1 (they return with globs — open questions).
- **D6 (mode-aware at M-op sites):** M ops with `Symlink`/`Gitlink`
  modes are skipped by default even when the extension matches;
  `include_special_modes` opts in (R9). Whole-blob transforms keep their
  documented mode-blindness — the two stages are independent knobs.
- **D7 (inline ops transform in place):** an `M … inline` op whose path
  matches a rule has its data rewritten inline (no synthetic blob, no
  mark machinery), with the same fail-open and mode rules. Consistent
  with the base pass's `include_inline` behavior, but gated on the path
  rule, not the whole-blob chain.
- **D8 (whole-blob stage runs before path rules):** when both are
  configured, the whole-blob chain transforms blob events first; the
  bytes cached for path rules are the post-whole-blob bytes. Mirrors the
  driver's D7 philosophy (downstream stages judge post-transform
  content). Configuring both for overlapping content is unusual but
  well-defined.
- **D9 (counts-only report, per rule):** report gains per-rule counters:
  ops examined, ops rewritten, blobs created (synthetic count),
  retained-failed, retained-guard (per-rule size guards as in the base
  pass), bytes in/out. No path- or blob-level artifacts (marks are
  stream-local; tree diffs already reveal what changed).
- **D10 (no cross-repo sharing in pack):** each repo's stream gets its
  own `mark_base` and its own caches (R4). Sharing a content-keyed
  transform cache across parallel repos is a possible perf follow-up and
  is explicitly not required for determinism.

## 5. Design

### 5.1 Crate additions (`gfx-blob-xform`, `#![no_std]`)

```rust
/// One path rule: extension → transform chain (G1).
pub struct PathRule {
    /// Extension bytes, without the dot (`b"rs"`). Matched against the
    /// final path component after the last `.` (D5).
    pub extension: BString,
    /// Chain, in order. Same handles as the whole-blob stage.
    pub transforms: Vec<SharedBlobTransform>,
    /// Per-rule size guards (same semantics as the base pass).
    pub skip_larger_than: Option<u64>,
    pub max_output_bytes: Option<u64>,
}

pub struct BlobXformConfig {
    // … existing whole-blob fields …
    /// Path rules (G1). Empty ⇒ the pass behaves exactly as today.
    pub path_rules: Vec<PathRule>,
    /// Synthetic mark base: stream max mark + 1 (D3). Required iff
    /// `path_rules` is non-empty; injected by the driver.
    pub mark_base: Option<u64>,
}

/// Internal state (D4):
///   originals:   BTreeMap<Mark, Data>            // every blob seen
///   transformed: BTreeMap<(Mark, rule_ix), Mark> // create-once cache
///   next_mark:   u64                             // from mark_base
```

`apply` changes, minimal and local:

- `Event::Blob`: whole-blob stage as today; if `path_rules` non-empty,
  also cache the (post-whole-blob, D8) bytes under the mark. Event passes
  through unaltered in structure (D2).
- `Event::Commit`: for each `FileOp::Modify`:
  - mode guard (D6), then extension match (D5) against the op's path;
  - no match ⇒ untouched;
  - match + `FileSource::Inline` ⇒ rewrite inline (D7);
  - match + `FileSource::DataRef::Mark(m)` ⇒ probe `transformed`; hit ⇒
    rewrite op to the cached synthetic mark; miss ⇒ look up `originals`,
    run the rule chain (D1 fail-open), allocate `next_mark`, push
    `Event::Blob { mark: synthetic, original_oid: None, data }` into
    `out` **before** the commit, cache, rewrite the op. (A mark with no
    cached original cannot occur in a well-formed fast-export stream —
    blobs precede use — but the miss arm treats it as retain-and-count,
    keeping the pass total over adversarial fuzz input.)
- `original_oid` on synthetic blobs is `None`: the synthetic has no
  source identity, and the field is informational.

The pass otherwise keeps its invariants: no drops, no reordering beyond
insertion, same `Transform` protocol — no driver-protocol change.

### 5.2 Driver injection (crates/gfx/src/driver.rs)

In `transform_stream`, after parsing `events` and before staging passes:
scan all events for the maximum mark (blobs, commits, tags; one pass over
already-materialized data, R4). When constructing the blob-xform stage
with non-empty `path_rules`, set `mark_base = max + 1`. Pack flows
through the same function per repo stream (R4, D10). The canonical-diff
detection needs no change (R5) — a synthetic mark is absent from the
pre-image and therefore flags its referencing commits as rewritten, which
is the truth.

### 5.3 CLI surface

Dynamic keys under `--blob-xform.ext.<EXT>.…`, parsed by the factory out
of `ArgMap` (prefix/suffix scan; `<EXT>` = the literal extension bytes,
validated as `[A-Za-z0-9]+` in v1):

| Flag | Meaning |
|------|---------|
| `--blob-xform.ext.<EXT>.cmd <shell>` | append a command stage to EXT's chain (repeatable; argv order within the extension) |
| `--blob-xform.ext.<EXT>.crlf-to-lf` / `.trim-trailing-whitespace` / `.ensure-final-newline` | append a builtin to EXT's chain |
| `--blob-xform.ext.<EXT>.skip-larger-than <size>` | per-rule guard |
| `--blob-xform.ext.<EXT>.max-output-bytes <size>` | per-rule output bound (also the cmd capture bound) |

Example (the motivating one):

```
gfx --repo r.git --passes blob-xform,remap \
    --blob-xform.ext.rs.cmd 'rustfmt --edition 2021 --emit stdout'
```

Usage errors: an `ext` key with no stages for that extension;
`ext` flags while the blob-xform pass is not selected (existing stance);
unknown `ext` sub-key. `include_special_modes` / `include_inline` stay
global to the pass.

### 5.4 Report

Per-rule lines fold into the existing `detail()` string, e.g.:

```
blob-xform: blobs=3 altered=3 … | rule[rs]: ops=12 rewritten=11 created=4 retained=1 (failed=1 guard=0) bytes=9102->8731
```

`created` counts synthetic blobs; `created ≤ rewritten` always (create-once
reuse, G2). Counters partition per rule (examined = rewritten + retained).

## 6. Testing

- **Contract (crate):** first-use creation (synthetic blob appears exactly
  once, immediately before the first matching commit; second matching use
  reuses the mark, transform ran once — count via a counting test
  transform); multi-path blob (`:1` as `a.rs` + `d.txt`: only the `.rs`
  op rewritten, original blob intact); multi-extension blob (`x.rs` and
  `y.py` ⇒ two synthetics, one per rule); fail-open retention keeps the
  original mark; symlink/gitlink skipped by default and transformed under
  `include_special_modes`; inline M op rewritten in place; mark with no
  cached original retained; missing `mark_base` with rules ⇒ config
  error; zero-alterations ⇒ output event sequence equals input (G3
  invariant, reused from the base fuzz target).
- **Driver:** max-mark injection; rewrite detection with synthetics
  (commits referencing synthetic marks appear in the commit-map as
  rewritten; commits touching only non-matching paths do not); remap
  finalization against the marks file unchanged.
- **E2E:** real repo with `.rs` + `.txt` history sharing one blob across
  paths; a `sh -c` stand-in formatter (`tr`, plus a content-gating script
  that fails on some blobs); verify transformed-at-matching-paths only,
  original-at-others, fsck clean, commit-map exact, `created` counts.
  A rustfmt E2E runs when a pinned rustfmt is on PATH (feature-gated
  ignore otherwise) — it exists to pin the recipe, not the machinery.
- **Pack:** per-repo mark bases under `--jobs 1` vs `--jobs 4` ⇒
  byte-identical archives (extends the existing determinism test);
  synthetic blobs strippable by a downstream strip-blobs stage.
- **Fuzz:** extend `blob_xform_roundtrip` with rotating path-rule
  configs; invariants: no panics; every synthetic mark ≥ base and
  defined before use (scan the output stream); zero alterations ⇒
  input-equality; counter partition per rule.

## 7. Milestones

| Milestone | Contents |
|-----------|----------|
| M0 | `PathRule`, config fields, pass machinery (caches, allocator, M-op rewriting, inline), report; crate contract tests |
| M1 | Driver `mark_base` injection + detection test; CLI dynamic-key factory + usage errors; E2E with shell stand-ins; rewrite-cli.md surface |
| M2 | Pack per-repo bases + `--jobs` determinism extension; fuzz target extension + smoke mirror |
| M3 | Hardening: rustfmt/clang-format recipes in docs (pinned-version guidance), R6 dangling-blob note in user docs, optional rustfmt E2E |

## 8. Open questions

- **Globs and basenames:** rule keys grow from extensions to a matcher
  enum (`Ext`, `Glob`, `Basename`). Multi-match semantics then need a
  decision: first-match-wins (predictable, order = argv) vs chain-all
  (consistent with the chain metaphor). Leaning first-match-wins.
- **Case sensitivity / multi-dot extensions:** `.RS`, `.tar.gz`. Leaning:
  stay case-sensitive byte-exact in v1, document; add a
  `case-insensitive` rule knob only if asked.
- **Superseded-original suppression:** a driver-mediated second pass
  (stream twice: first to compute the set of marks with ≥1 non-matching
  use, then to drop originals lacking one) would eliminate dangling
  blobs. Costs a second export/parse; the garbage is gc-collectable
  anyway. Leaning: not worth it; revisit if pack users report bloat.
- **Cache eviction / spill:** evicting an original's bytes is only safe
  when no future use can match a *different* rule — knowable only when
  there is exactly one rule and the blob was already transformed. A
  spill-to-tempdir cache is the general answer. Both are perf work,
  gated on real repos outgrowing the R7 bound.
- **Cross-repo shared cache in pack:** key by `(content_hash, rule)` →
  transformed bytes behind the existing `Send + Sync` handles; saves
  re-running formatters on blobs shared across repos. Determinism is
  unaffected (content-keyed). Perf follow-up.
- **Should `created` synthetics participate in `--dry-run` reporting of
  stream size?** They inflate the output stream by `created ×
  transformed_size`; the report's bytes counters already capture this,
  but the dry-run summary may want an explicit line.
