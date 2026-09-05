# Plan: pass-driver (`gfx rewrite`) + first content pass (`gfx-strip-blobs`)

| Field    | Value |
|----------|-------|
| Status   | Draft — pre-implementation |
| Scope    | `filter-repo`-style multi-pass invocation (host driver) + builtin: retroactive removal of large / generated files |
| Depends  | plan-fast-export.md §5 (architecture), §6 (builtin framework), §7 (`gfx-remap`), §9 (facade) |
| Updated  | 2025-08-31 |

---

## 1. Summary

Two deliverables and two shared foundations, one dependency arc:

1. **Pass-driver** — a `std`-gated host driver (new `gfx-cli` bin + reusable library
   bits in the `gfx` facade) that reproduces the *invocation shape* of
   `git filter-repo`: point it at a repo, name an arbitrary sequence of passes
   (stream transforms), and it runs `git fast-export` → pipeline of passes →
   `git fast-import` → marks folding → ref updates, with remap always composing
   last and its `CommitMap`/`RefMap` artifacts written out.
2. **First content pass** — a new `no_std` builtin crate `gfx-strip-blobs` that
   retroactively removes files from history, selected by **size threshold** and
   **"generated code" signals** (path patterns + content sniffing). This is the
   built-in composition of filter-repo's `--strip-blobs-bigger-than`,
   `--path*` filters, and a deterministic "looks generated" heuristic — the
   motivating rewrite for the whole project.

Both follow the established rules: the builtin is sans-IO, deterministic, and
`no_std`; everything that touches `git`, the filesystem, or clocks lives behind
`std` in the driver.

---

## 2. Goals and non-goals

### Goals

1. Arbitrary pass sequences from the CLI: `gfx rewrite --passes strip-blobs,remap`
   (order = pipeline order, first named runs first). Library users compose the same
   passes via `Pipeline::builder()`.
2. Remap is *always available and always last-class*: the driver appends `remap`
   automatically (unless already named), folds the downstream `export-marks` file
   via `Remap::finalize_from_marks`, and writes `commit-map`, `ref-map`, and a
   pass report — filter-repo's artifact surface, gfx naming.
3. `gfx-strip-blobs` removes historical file content by size and generated-ness
   with **drop-first semantics** (decision D1, §5.1): selected ops are dropped,
   absence propagates through the delta model, and the pass never synthesizes
   counter-ops. Emits a **StripReport** (blobs/paths removed, bytes saved,
   per-ref effect, documented divergences) suitable for `--dry-run`.
4. A shared **virtual index** crate, `gfx-vindex` (decision D3): the one
   `no_std` replay implementation of fast-import's branch-index semantics,
   used by the strip pass, the test-suite simulator, and future path-aware
   builtins.
5. The **CLI is a library** (decision D4): `gfx-cli` exposes a pass registry
   and a `rewrite_binary!` macro that wraps any chosen set of passes into a
   customized binary; every pass crate ships a helper/example binary built on
   that macro as its own CLI.
6. Safety rails copied in spirit from filter-repo: refuse to rewrite a repo that
   isn't a fresh clone without `--force`; `--dry-run` does export → passes →
   report, no import, no ref mutation.
7. Determinism (P6) and identity-noop (P4/P3) properties extend to the new pass:
   with nothing selected for stripping, output is byte-identical input.

### Non-goals (v1)

- **No empty-commit pruning** in `gfx-strip-blobs` v1 (filter-repo `--prune-empty`).
  Pruning changes parentage (`from` must be rewired to the nearest surviving
  ancestor), which we deliberately defer — see §6 (Deferred, item 1). Without pruning, parentage
  is untouched and remap composes unchanged.
- **No message-hash rewriting** in the driver's default sequence (plan §7.4
  defers it to a second pass consuming a finished `CommitMap`; the driver's
  multi-round support in §4.4 is the hook it will use).
- No blob-callback scripting layer (Python/Rust fn registry) in v1; the
  "generated" predicate is extensible via an injected pure-fn config knob (§5.2),
  not a general callback host.
- No incremental/marks-resumable rewrites (`--state-branch`-like resume).
- No partial-history rewrite (`--refs` selection) — v1 always rewrites all refs
  (`fast-export --all`).
- **No synthesized ops** in `gfx-strip-blobs` (decision D1): no `M`→`D`
  conversion, no tombstone `D`s. Where dropping an op makes a path revert to
  its last surviving content (possible under blob selection via `C`/`R`,
  §5.6), that divergence is reported, not papered over.

---

## 3. Background: what `git filter-repo` actually does on invocation

Behavioral reference for the driver (verified against filter-repo's docs/source
behavior, not something we re-implement wholesale):

1. **Sanity checks** — repo must be a fresh clone (`git clone --mirror` /
   `--bare` with no local modifications) unless `--force`.
2. **One export** — `git fast-export --show-original-ids --signed-tags=strip
   --tag-of-filtered-object=rewrite --fake-missing-tagger --reference-excluded-parents
   --use-done-feature --all` (flag set varies by filter selection).
3. **Filters as in-process callbacks** over the parsed stream, in a fixed
   composition order; commit-map fixes for messages happen in a *second* phase.
4. **One import** — `git fast-import` with `export-marks`; then ref updates from
   the ref-map, reflog expiry, `git gc`.
5. **Artifacts** — `.git/filter-repo/` containing `commit-map`, `ref-map`,
   `suboptimal-issues`, etc.

gfx v1 mirrors the shape (export → passes → import → fold marks → update refs →
artifacts) but keeps pass composition explicit and user-ordered, with remap as
the mandatory final stage. We do **not** mirror filter-repo's fixed internal
filter ordering: our contract is "pipeline order is user-defined, remap runs
after every content/path pass" (plan §6 rule 1), enforced by the driver.

---

## 4. Deliverable 1: pass-driver

### 4.1 Placement

```
crates/gfx-cli/           # CLI *library* (std only): pass registry, arg model,
                          # repo safety checks, artifact writing, rewrite_binary! macro;
                          # src/bin/gfx.rs — the default binary via rewrite_binary!
crates/gfx/src/driver.rs  # std-gated library core: PassSpec → Pipeline, export/import plumbing
```

Rationale: the *driver logic* (pass spec → pipeline → artifacts) is reusable
from Rust (tests, SDK embedding) and belongs in the facade; the *CLI* is a
library so any subset of passes can be compiled into a purpose-built binary
(decision D4). Neither is in the `no_std` graph. (The default binary lives in
`gfx-cli` rather than `gfx`: `gfx-cli` depends on the facade, so the reverse
edge would be a cycle.)

### 4.2 Pass specification

CLI shape (long-form flags win over cleverness for v1):

```
gfx rewrite [--repo <path>] [--force] [--dry-run] [--out-dir <dir>]
            [--passes <spec>]            # default: "strip-blobs,remap"
            [--strip-larger-than <size>] # 1M, 512K, bytes; feeds strip-blobs config
            [--strip-path-glob <glob>]…  # repeatable
            [--strip-path-regex <re>]…   # repeatable
            [--strip-content-signals]…   # named signal sets, §5.2
```

`--passes` grammar (v1): comma-separated pass names; builtins ship named
configuration via flags (above) or a config file (`--config gfx-rewrite.toml`
with a `[passes.strip-blobs]` table). A pass name not compiled in is a hard
error listing available passes — never silently skipped. The driver *validates
ordering constraints*: every content/path pass must precede `remap`; violation
is an error, not a reordering (explicitness over magic, consistent with plan
§6 guidance).

Library shape:

```rust
// gfx (facade, feature = "std")
pub struct PassDriver { /* … */ }
impl PassDriver {
    pub fn new(repo: impl AsRef<Path>) -> Result<Self, Error>;
    pub fn with_passes(self, passes: Vec<PassSpec>) -> Self;   // PassSpec::StripBlobs(cfg), PassSpec::Remap(cfg)
    pub fn dry_run(&mut self) -> Result<RunReport, Error>;     // export → passes → report; no import
    pub fn run(&mut self) -> Result<RunReport, Error>;         // full round
}
```

`RunReport` aggregates per-pass reports (`StripReport`, `MapStats`, `RefMap`s)
plus the finalized `CommitMap` path/contents.

#### Pass registry and `rewrite_binary!` (decision D4)

Passes are discovered through a registry, not a hardcoded match — this is what
lets a macro build a binary around any pass subset:

```rust
// gfx-cli
pub trait PassFactory: Send + Sync {
    fn name(&self) -> &'static str;
    /// Declare this pass's flags. In a composed binary the registry
    /// namespaces them as `--<pass>.<flag>`; a single-pass helper binary
    /// exposes them flat.
    fn arg_spec(&self) -> Vec<ArgSpec>;
    fn build(&self, args: &ArgMap) -> Result<Box<dyn Transform>, Error>;
}

/// Generates `fn main()`: build a registry from exactly these factories,
/// parse args, validate ordering (§4.2), run the driver, write artifacts.
gfx_cli::rewrite_binary! {
    /// Rewrite history: strip large/generated blobs, then remap.
    binary: my-rewriter,
    passes: [gfx_strip_blobs::pass_factory, gfx_remap::pass_factory],
}
```

Rules:

- The default `gfx` binary is itself `rewrite_binary!` over every
  compiled-in pass — dogfooding, zero special-casing.
- **Every pass crate ships a helper/example binary** (`examples/<pass>.rs`,
  built with the macro over just that pass). It is simultaneously the pass's
  CLI documentation, a usable single-purpose tool, and the conformance vehicle
  for its flag surface (acceptance A7).
- A pass name not present in the registry is a hard error listing available
  passes — never silently skipped (existing rule, now registry-enforced).

### 4.3 One round, end to end

```
safety check ──▶ git fast-export --show-original-ids --all --use-done-feature
                    │  (+ --signed-tags=strip --reencode=yes pinning; baseline doc records flags)
                    ▼
             Parser ──▶ Pipeline [pass₁ … passₙ, remap] ──▶ Writer
                    │                                    │
                    │                              Report artifacts (pre-import)
                    ▼
             git fast-import --force --export-marks=<tmp> (feature done enforced)
                    │
                    ▼
             Remap::finalize_from_marks(marks)   // Mode A, plan §7.2
                    │
                    ▼
             ref updates from RefMap (delete nothing; set tips; --replace-refs deferred)
                    │
                    ▼
             artifacts: commit-map, ref-map, run report; advise `git reflog expire --expire=now --all && git gc --prune=now` (print, don't run)
```

Notes:

- The parser must consume the *done* feature and the writer must emit it —
  already in the grammar (plan §3.1).
- fast-export flag pinning goes in `docs/git-baseline.md` like every
  version-sensitive corner. `--show-original-ids` is mandatory (remap depends
  on it; blob-level `original-oid` is what the strip pass keys its blob
  registry on, §5.1).
- Marks: fast-export's own `import-marks`/`export-marks` features are passed
  through untouched; the strip pass never renumbers marks (plan §6 rule 3).

### 4.4 Multi-round support (for future message-rewrite et al.)

`Transform::reset` already exists for deterministic multi-pass rewrites (plan
§4.1 rule on reset semantics). The driver gains `run_rounds(n)` / re-export
between rounds, used when a pass needs a *finished* map from a previous round
(message-hash rewriting). v1 ships the round API with exactly one round as the
only tested configuration; a second round arrives with `message-rewrite`.

### 4.5 Acceptance (driver)

| # | Test |
|---|---|
| A1 | Fresh-clone check trips on a dirty repo without `--force`; `--dry-run` never mutates refs/objects |
| A2 | Identity sequence (`--passes remap` on an unmodified export) reproduces byte-identical import stream (P4, end-to-end) |
| A3 | `strip-blobs,remap` on a fixture repo: import succeeds, `git fsck --strict` clean, `commit-map` complete, unchanged subgraph hashes preserved |
| A4 | Unknown pass name / wrong order (`remap,strip-blobs`) → error, no side effects |
| A5 | SHA-256 repo end-to-end mirror of A3 |
| A6 | Run report artifacts are complete and deterministic across two identical runs |
| A7 | `rewrite_binary!` with a single pass produces a working binary accepting that pass's flags; each per-pass helper binary passes its flag conformance checks |

---

## 5. Deliverable 2: `gfx-strip-blobs` — builtin

New `no_std` crate `crates/gfx-strip-blobs/` (facade feature `strip-blobs`),
plus the shared sibling `crates/gfx-vindex/` (decision D3). Both depend on
`gfx-core` only; `gfx-strip-blobs` additionally depends on `gfx-vindex`. The
facade gains features `strip-blobs` and `vindex` (the latter re-exported for
hosts that want the replay machinery alone).

### 5.1 Semantics — drop-first (decision D1)

A fast-export stream encodes each commit as **deltas against the branch's
virtual index**, which is why "remove file X from all history" sounds like it
needs presence tracking and synthesized counter-ops (`M`→`D`). Decision D1
(resolved open question 1) rejects that: **the pass drops ops and never
synthesizes any.** Absence propagates on its own:

- every path in any tree traces back to some stream op (`M`, `C`, `R`) or to
  inheritance from a parent tree whose contents trace back likewise;
- dropping every op that would create or carry selected content means no
  surviving op can introduce it;
- a commit that doesn't touch a selected path inherits its parent's rewritten
  tree — which already lacks it — and the walk bottoms out at root commits,
  whose trees are built entirely from their own (filtered) ops.

The deliberate, documented consequence: under **blob selection**, dropping the
`M` that changed path `P` makes `P` revert to its last *surviving* content
rather than to a tombstone. Path selection never reverts (all ops on a
selected path are dropped, so the path is absent everywhere). The strip
guarantee is about content, not about curating tree states; divergences are
report entries (§5.6), not surprises.

Per-op decisions:

| Situation | Action |
|---|---|
| `M` of a selected path (path selection), unprotected | drop the op |
| `M` whose data is a selected blob or selected inline payload (blob selection), at an unprotected path | drop the op |
| `D` of a selected path | drop (normalize) |
| `D` of an unselected path | keep iff the path is live in the **rewritten view** (below); drop otherwise — deletes of paths erased by our own drops are normalized away |
| `C from to`, `to` selected | drop (a copy would reintroduce content at a selected path) |
| `C from to`, `from` currently holds a selected blob (resolved via the original-view index), `to` kept | drop; report the content loss at `to` |
| `R from to`, `from` selected or holding a selected blob | drop; endpoints revert to last surviving content; reported |
| `R from to`, `to` selected | drop; reported if `to` reverts to surviving content |
| `filedeleteall` | pass through; both index views reset for that ref |
| anything else | pass through; views updated |

Normalization note: because the pass never synthesizes ops and drops
never-live `D`s, the stream can never contain a delete of an absent path —
the fast-import delete-of-absent corner (`docs/git-baseline.md` "verify"
note) cannot be triggered by this pass.

Blob identity across the stream: blobs are defined *before* use (fast-export
walk order) — except `M … inline`, where the data is in the op itself. The pass
therefore keeps a **blob registry**: `mark → BlobVerdict` (size + generated
verdict), populated from `Event::Blob` (with `original-oid` when available,
also `oid → verdict`), consulted by `FileSource::DataRef` ops; `inline` data is
judged at the op site. Verdicts for dataref'd blobs are always resolvable at
first use because fast-export never references a mark before defining it
(pinned behavior, baseline doc "verify" note).

Where the virtual index still earns its keep (via `gfx-vindex`, decision D3):
(a) resolving `C`/`R` *source* content to a blob verdict — the stream gives
paths, not datarefs, for copies/renames; (b) the **rewritten view** that
decides kept-`D` validity; (c) the independent absence simulator (property
S5); (d) future path-aware builtins. One replay implementation, tested once,
shared by every consumer.

### 5.2 Selection — size threshold + generated signals

A blob/path is **selected** iff any configured predicate matches (OR of
predicates; every predicate is deterministic):

1. **Size**: `blob_size > threshold` (strictly greater; `threshold = 0` selects
   everything — the config rejects negative). Applies to blob payloads and
   inline data. Gitlinks (mode `160000`) are never content-judged; symlink
   targets are tiny but still judged as blobs (harmless).
2. **Path globs**: `BString` glob match on the full path
   (`**/Cargo.lock`, `*.min.js`, `vendor/**`). Implementation: a tiny
   dependency-free glob matcher over bytes (`no_std`) — no regex crate in the
   builtin.
3. **Path regexes**: host-supplied `regex`-matched patterns are *pre-compiled
   by the host* into the config (the `regex` crate stays out of `no_std`;
   the config accepts an injected matcher trait, below). v1 CLI supports globs
   only; the regex knob exists at the library level.
4. **Content signals** (judged on full payload, bounded by a scan cap —
   default 64 KiB prefix, configurable):
   - Minification fingerprints: very long single lines with low whitespace
     ratio (`.map`-less bundles), `//# sourceMappingURL=` absence/presence
     ratios — keep the *specific* rules in one documented table so the
     heuristic is reviewable, not folk wisdom.
   - Lockfile/registry fingerprints: starts-with markers for
     `Cargo.lock`, `package-lock.json`, `yarn.lock`, `poetry.lock`, `Gemfile.lock`,
     `Podfile.lock`, `composer.lock`, `gradle.lockfile` (by path *or* content).
   - "Generated code" banner scan: case-insensitive ASCII/UTF-8 search for
     `do not edit`, `autogenerated`, `auto-generated`, `generated by`,
     `@generated`, `@nolint`, `code generated` within the scan cap (mirrors
     GitHub Linguist's generated-detection markers, subset documented in-crate).
   - Compact-word heuristic (Linguist-style, final fallback, off by default):
     tokenized lines with high `ratio = tokens / line-length` dominance —
     shipped only if the table above proves insufficient on fixtures; flag it
     as experimental in docs.

Predicate injection (library-level extensibility without a callback zoo):

```rust
pub trait BlobPredicate {
    fn judge(&self, path: Option<&BString>, data: &[u8]) -> bool;
}
// StripBlobsConfig { …, extra_predicates: Vec<Box<dyn BlobPredicate>> }
```

Pure functions of the observed bytes; determinism (P6) is preserved because
hosts must supply stateless predicates (documented contract; test kit includes
a determinism check with a stateful predicate proving the pass doesn't cache
verdicts across `reset()`).

### 5.3 Configuration

```rust
pub struct StripBlobsConfig {
    pub size_threshold: Option<u64>,          // bytes; None = no size rule
    pub path_globs: Vec<BString>,             // full-path globs (bytes; no UTF-8 assumption)
    pub path_matchers: Vec<alloc::boxed::Box<dyn PathMatcher>>, // host-compiled regexes
    pub content_signals: ContentSignals,      // on/off per signal + scan_cap
    pub extra_predicates: Vec<Box<dyn BlobPredicate>>,
    pub protect_globs: Vec<BString>,          // never strip (e.g. `**/.gitattributes`)
    pub strip_symlinks_too: bool,             // default false: a symlink whose target
                                              // string matches signals is stripped only if this is set
    pub report_limit: usize,                  // cap per-report listing (default 1000 entries)
}

pub struct StripReport { /* per-mark/oid verdicts, per-path removals, bytes_saved, per-ref op counts */ }
```

`protect_globs` exists because stripping `.gitattributes`/`.gitignore` content
by size would be surprising; defaults include the dotfiles. The report is
bounded (`report_limit`) so a repo with a million stripped blobs can't blow up
host memory — totals are always exact, listings are capped.

### 5.4 State machine (v1)

```
            ┌───────────────────────────────────────────────────────┐
 Blob ─────▶│ registry: mark/oid → {size, verdict}; inline data     │
 Commit ───▶│ judged at the op site                                 │──▶ events out
            │ gfx-vindex per ref, two views: original (verdict      │
            │ resolution for C/R sources) + rewritten (kept-D       │
            │ validity)                                             │
            │ decisions: drop / keep / normalize per §5.1 table     │
            └───────────────────────────────────────────────────────┘
 finish(): emit StripReport (bounded); reset() restores fresh state
```

Memory posture (plan §5.6): the registry and the two per-ref index views are
`BTreeMap`/`BTreeSet` — bounded by distinct paths/blobs, not by stream length.
Blob payloads are already owned by `Event::Blob` (v1 event model), so judging
adds no copies. The driver's `Limits` (plan §4) caps individual blob size for
parser safety; the strip pass's own threshold is orthogonal and may exceed it
(a blob beyond parser limits already fails earlier — document the interaction).

### 5.5 Interaction with `remap`

- Strip runs **before** remap (driver enforces). Remap's canonical digest
  (plan decision 1) sees the *post-strip* content and flags affected commits
  rewritten by itself — no side channel needed.
- Commits whose only change was a stripped file still occur (no pruning in v1,
  §2); they become empty-parent-diff commits and are rewritten like any other.
  Their `original-oid` linkage keeps the commit-map meaningful.
- Because v1 does not prune, no `from` rewiring occurs here; parentage rewrite
  is remap's job alone. The deferred `prune_empty` (§6, Deferred item 1) is what will need
  ancestor-walking — deliberately not smuggled into this pass.

### 5.6 Edge cases (must-have fixture coverage)

| Case | Expected |
|---|---|
| `M 160000` gitlink at a "large" path | never content-judged; path glob may still select it |
| Symlink whose target is a stripped blob's path | symlink op untouched (target text is not the blob) |
| Same blob at two paths, one protected | verdict is per (blob, path-at-op) pair; protected path keeps its op |
| `C`/`R` under blob selection (source holds a selected blob) | op dropped; endpoints revert to last surviving content; each divergence is a report entry |
| `D` of a path our own drops erased | dropped (kept `D`s must target live paths in the rewritten view) |
| `M 040000` tree-replace | path globs apply to the directory path; content predicates are skipped (tree contents aren't visible in the stream) — documented limitation |
| Notes (`N`) on stripped content | note blobs judged like any blob; commit refs untouched |
| Path with C-quoted bytes / non-UTF-8 | byte-exact glob matching on raw `BString` post-unquote |
| `data delim` blobs | normalized to raw `data <n>` at parse time (plan §5.2) — strip logic sees uniform `Data` |
| Sub-half-of-threshold blob at a globbed path | selected (path predicate ORs size predicate) |
| Blob selected, later commit re-adds it inline | re-judged at op site, stripped again |
| Empty commit after stripping (introduction-only) | kept as-is in v1 (no pruning); report flags count of now-empty commits |

### 5.7 Properties & tests

| # | Property |
|---|---|
| S1 | Nothing selected ⇒ byte-identical output (P4 analog; includes untouched virtual-index bookkeeping) |
| S2 | For any fixture repo: after strip+remap+import, `git log --all -- <stripped-path>` is empty and `git fsck --strict` passes |
| S3 | Determinism: two runs byte-identical (P6), including with an injected stateful predicate (reset correctness) |
| S4 | Orphan guarantee: no surviving op (`M`/`N`) references a selected blob's mark; every kept `D` targets a path live in the rewritten view |
| S5 | Absence guarantee: for every ref, replaying the rewritten ops in `gfx-vindex` yields no tree containing a selected path or selected blob — the simulator is driven from the git docs' index semantics, not from pass internals |
| S6 | Report truthfulness: `bytes_saved` equals sum of stripped `Data::len()` across the stream, verified against fixtures |
| S7 | `cargo-mutants` on the verdict/index logic (plan §10.4 analog) |

Test kit reuse: the plan §6 builtin test kit (contract tests every transform
must pass) plus `test_kit`-driven golden streams for §5.6.

---

## 6. Deferred (explicitly)

1. **`prune_empty`** (filter-repo `--prune-empty=always|auto|never`): requires
   walking to the nearest surviving ancestor and rewriting `from` — a
   parentage-coupled feature that belongs with remap-grade machinery or its own
   follow-up pass. Driver surfaces `--prune-empty=never` (only supported value)
   so the CLI shape is future-stable.
2. **`--replace-refs`** (filter-repo's `replace/` ref generation for old→new
   reachability): artifact-generating, needs `CommitMap`; trivial once the
   driver round-trip is stable.
3. **Content-derived tree/hash mode integration** (plan §7.2 Mode B): strip
   verdicts feed it naturally; no coupling in v1.
4. **Anonymize / path-filter / message-rewrite builtins**: roadmap rows already
   exist (plan §6); the pass-spec grammar and the registry grow with each, and
   `prune_empty`/`path-filter` build directly on `gfx-vindex` (D3) — that is
   why the index is a shared crate rather than strip-pass internals.

---

## 7. Milestones

| Milestone | Deliverable | Acceptance |
|---|---|---|
| **P0** Pass-driver core | `gfx-cli` library (registry, arg model, safety) + `rewrite_binary!` macro; default `gfx` binary; `gfx::driver::PassDriver`; one-round export→identity-pipeline→import; artifacts | A1, A2, A4, A6, A7 |
| **P1** Virtual index + strip builtin | `gfx-vindex` crate (replay + simulator harness); `gfx-strip-blobs` crate; size + glob predicates; drop-semantics decisions; report; helper binary `examples/strip-blobs.rs` | S1, S3, S4, S7; contract kit green |
| **P2** Composition | strip+remap end-to-end via CLI; content signals; protect globs; edge-case fixtures | A3, A5, S2, S5, S6 |
| **P3** Polish | `--config` TOML surface, report formatting, docs; fuzz target for the glob matcher | fuzz smoke green; docs complete |

---

## 8. Risks & open questions

**Risks**

- *`gfx-vindex` divergence from real fast-import index semantics* (e.g. subtle
  `filedeleteall`/`N` interplay) → S5's independent simulator run is written
  **from the git docs, not from our pass code**, so agreement is a real check;
  `t9300` cases involving deletes feed the fixtures. One implementation serves
  the pass and the tests, so a divergence is fixed once.
- *Revert divergences confuse users* (blob selection makes a path fall back
  to older content where the original had the stripped blob) → every
  divergence is a `StripReport` entry; dry-run surfaces before/after; crate
  docs state the drop-first consequence up front.
- *Generated-heuristic false positives* (a hand-written file that says
  "generated by…") → signal table is documented and per-signal toggleable;
  `protect_globs` and dry-run reports give users an exit; heuristics are
  conservative by default (banner + fingerprints on; Linguist-style ratio
  heuristic off).
- *Glob matcher correctness on byte paths* → dedicated fuzz target (P3), plus
  quoted/non-UTF-8 fixtures from the existing corpus.
- *Driver flag drift across git versions* → same baseline-pinning policy as
  plan §11.

**Resolved decisions** (this plan)

1. **D1 — drop-first.** The strip pass never synthesizes ops (was open
   question 1). Kept `D`s are validated against the rewritten view; never-live
   `D`s are normalized away; blob-selection `C`/`R` reverts are documented
   divergences with report entries.
2. **D2 — pass name stays `strip-blobs`** (was open question 2).
3. **D3 — shared virtual index crate.** `gfx-vindex`, `no_std`, depends on
   `gfx-core` only; consumed by the strip pass (original + rewritten views),
   the S5 simulator, and future path-aware builtins.
4. **D4 — CLI as a library.** `gfx-cli` is a library with a pass registry and
   `rewrite_binary!`; every pass crate ships a helper/example binary built
   with the macro; the default `gfx` binary is the macro over all passes.

**Open questions**: none outstanding.
