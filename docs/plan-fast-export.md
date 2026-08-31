# Plan: `gfx` — a sans-IO, `no_std` implementation of the `git fast-export` protocol

| Field    | Value |
|----------|-------|
| Status   | Draft — pre-implementation |
| Scope    | Workspace-wide architecture + first delivery milestones |
| Author   | — |
| Updated  | 2025-08-31 (decisions 1-4 resolved)

---

## 1. Summary

`gfx` implements the **`git fast-export` / `git fast-import` stream protocol** as a Rust
library that is:

- **sans-IO** — all protocol logic is a state machine over explicit input/output buffers.
  The library never opens a file, spawns `git`, reads a clock, or touches a socket. The
  *host* owns all I/O (sync, async, or none at all).
- **`no_std`** — the core crates compile with `#![no_std]` + `alloc`. No `std::io`, no
  `std::process`, no OS clocks. Determinism is a hard property of the core.
- **Usable with or without builtins** — the stream parser/serializer/exporter are
  independently useful. *Builtins* (stream-to-stream transforms, conceptually the role
  `git filter-repo` plays as a filter between fast-export and fast-import) are optional,
  feature-gated pipeline stages. With zero builtins the pipeline is an identity.

The first builtin is **commit-hash remapping**: tracking `original OID → mark → new OID`,
rewriting parentage (`from` / `merge` / `reset` / tag targets), and producing a
commit-map compatible in spirit with filter-repo's `--map-file`.

**Interpretation note.** "Implement the `git fast-export` protocol" is taken to mean the
full wire grammar (parse *and* emit), plus the export side (generating a stream from an
abstract repository snapshot) and the import-side surface (consuming a stream). Wiring
that to a real repository lives in a thin, `std`-gated facade.

---

## 2. Goals and non-goals

### Goals

1. Byte-exact **parse → emit round-trip** of canonical fast-export streams (git-emitted
   streams re-serialize unchanged).
2. A typed **event model** (`Event`) covering the full fast-import grammar, with
   lenient/strict parsing modes.
3. A **pipeline** of `Transform`s (builtins) that is composable, order-preserving, and
   optional.
4. Builtin #1, `remap`: commit-hash mapping + parentage rewriting, with marks-file
   finalization so the `old → new` OID map can be completed after a downstream
   `git fast-import` run.
5. A sans-IO **exporter**: `abstract repo snapshot → stream`, reproducing
   `git fast-export` behavior (marks, changed-paths, tag policies, `original-oid`).
6. A `std` facade (feature-gated) with drivers that spawn `git fast-export` /
   `git fast-import` for integration testing and convenience — not part of the core.
7. Fuzz + property-test coverage of every parser byte path.

### Non-goals

- No pack writing / object database (real import stays delegated to `git fast-import`).
- No re-implementation of rename/copy detection (`-M`/`-C` results are *host-supplied*).
- No `filter-repo`-equivalent callback scripting layer (Python or otherwise) in v1 —
  filter-repo informs the builtin *roadmap*, not the v1 API.
- No async runtime dependency anywhere; async adapters belong to hosts.
- No credentials, network, or subprocess handling inside `no_std` crates.

---

## 3. Background: the protocol

`git fast-export` serializes history into a command stream that `git fast-import`
consumes to rebuild objects and refs at high speed. The grammar (from
`Documentation/git-fast-import.adoc`, mirrored by `git-fast-export.adoc`):

### 3.1 Command summary

| Command | Shape (abridged) | Notes |
|---|---|---|
| `blob` | `blob` `mark?` `data` | payloads via `data <n>` (raw), `data literal <n>`, `data delim <s>` (version-dependent) |
| `commit <ref>` | `mark?` `original-oid?` (`author`? `committer`? `encoding`?) `data` `from?` `merge*` file-ops | file-ops mutate the branch's virtual index |
| file-ops | `M <mode> <dataref|inline> <path>`, `D <path>`, `C <a> <b>`, `R <a> <b>`, `filedeleteall`, `N <dataref> <committish>` | modes `100644 100755 120000 160000` (+ `040000` tree-replace, version-dependent) |
| `tag <name>` | `from?` `original-oid?` `tagger?` `data` | `mark` only with `--mark-tags` (newer git) |
| `reset <ref>` | `from?` | `reset` without `from` deletes a ref |
| `checkpoint` | — | import-side sync point |
| `progress <bytes>` | — | passthrough |
| `feature <name>[=<arg>]` | `date-format`, `import-marks[-if-exists]`, `export-marks`, `relative-marks`, `force`, `object-format`, `done`, … | pre-import negotiation |
| `option <arg>` | e.g. `quiet`, `max-pack-size` | passed to fast-import |
| `done` | — | with `feature done` / `--use-done-feature` |
| `alias` | `mark` `data` | mark aliasing (newer git — verify version) |
| `get-mark`, `cat-blob`, `ls` | — | import-side *requests*; see §5.4 |
| `# comment` | — | tolerated at command boundaries by fast-import; never emitted by fast-export |
| `original-oid <oid>` | inside commit/tag (blob coverage varies by git version — verify) | present with `--show-original-ids` |

### 3.2 Details that drive the design

- **Marks** (`:1`, `:2`, …) are a single counter shared by blobs and commits, assigned by
  fast-export in walk order. Marks exist precisely so rewriters never need to know OIDs.
- **Idents** are `name <email> when`; `when` defaults to `raw` format
  (`<epoch> <±HHMM>`). Names/emails may be non-UTF-8 → paths and idents must be byte
  strings.
- **Paths** are raw bytes; when they contain special characters fast-export emits them
  C-style quoted (`"` with `\` escapes). Parser must unquote; writer must re-quote.
- **`data <n>`** payloads are binary and length-delimited — the parser must be
  incremental and cannot assume line-oriented framing mid-payload.
- **Ordering**: parents precede children (topological). This is what makes streaming
  hash remapping tractable (§9).
- **SHA-256 repos** exist: `feature object-format=sha256`; OIDs are 64 hex chars. The
  object format is stream state from the first `feature` line onward.
- **`original-oid` on blobs** (verified against git): with `--show-original-ids`,
  fast-export emits `original-oid` inside `blob` blocks too, not just commits/tags.
- **Block framing** (verified byte-for-byte against git): fast-export emits exactly one
  `\n` separator after each top-level command block (after the last `data` payload of a
  blob; after the last file-op of a commit; after a tag's message; after a `reset` *that
  carries a `from`* — a bare `reset` has none). Payloads keep their exact byte length;
  the separator is not counted in `data <n>`.

### 3.3 Authoritative references

- `git-fast-import(1)`, `git-fast-export(1)` (pinned to a documented git version, see §11).
- git source: `builtin/fast-import.c`, `builtin/fast-export.c`.
- `t9300-fast-import-tests.sh` — the de-facto conformance suite; mine it for fixtures.

---

## 4. Design principles

### 4.1 Sans-IO contract

The core exposes **pull-based state machines**. Hosts feed bytes, pull events, push
events, and drain bytes. Concretely:

```
host (owns ALL I/O: files, git subprocess, sockets, async runtimes)
  │ bytes in                                 ▲ bytes out
  ▼                                          │
Parser ──Event──▶ Pipeline [Transform; N] ──Event──▶ Writer ──▶ host buffer
(gfx-core)        (0..=N, optional)                  (gfx-core)
```

Rules:

1. No syscalls, no clocks, no randomness, no environment reads in `no_std` crates.
   Same input ⇒ same output, bit-for-bit.
2. Every fallible step returns `Result<_, gfx_core::Error>`; no panics on any input
   (verified by fuzzing, §11).
3. All blocking/timeout/retry policy belongs to the host. The parser never "waits".
4. Transform buffering is explicit: a transform may emit 0..N events per input event and
   must flush residuals in `finish()`.

### 4.2 `no_std` rules

- Crates `gfx-core`, `gfx-remap` (and any future builtin crate) are
  `#![no_std] extern crate alloc;`.
- Collections: `alloc::collections::BTreeMap`/`BTreeSet` only — **iteration order is
  deterministic**, which the remap builtin's reproducibility guarantee relies on.
- Byte strings: `bstr::BString` (no_std + `alloc` feature) for paths, refnames, ident
  parts, raw timestamps. No `String::from_utf8` assumptions anywhere near protocol data.
- Errors: `gfx_core::Error` implementing `core::error::Error` (MSRV ≥ 1.81). No
  `std::io::Error` in core; the facade maps at the boundary.
- Hashing: an injected `Hasher` trait (§9.5); bundled SHA-1/SHA-256 via RustCrypto
  `sha1`/`sha2` crates (both `no_std`) behind features.
- CI proves it: `cargo check --target x86_64-unknown-none` (plus one
  `thumbv*-none-eabi`) for every core crate, per feature, via `cargo-hack`.

---

## 5. Architecture

### 5.1 Workspace layout

```
gfx/
├── crates/
│   ├── gfx-core/        # no_std+alloc: Event, Parser, Writer, Transform, Pipeline, Error, Limits
│   ├── gfx-hash/        # no_std: Hasher trait; features: sha1 (RustCrypto), sha256
│   ├── gfx-remap/       # no_std builtin #1: commit-hash remap (depends on gfx-core, gfx-hash trait)
│   └── gfx/             # facade: prelude, pipeline builder; features:
│                        #   std        — Read/Write adapters, git subprocess drivers
│                        #   remap      — re-exports gfx-remap
│                        #   hash-sha1 / hash-sha256 — bundled hashers
├── fuzz/                # cargo-fuzz targets (parser robustness, round-trip props)
├── fixtures/            # golden streams generated by pinned git (see §11.3)
└── docs/
```

Rationale: builtin crates stay tiny and depend on the smallest surface; users can depend
on `gfx-core` alone (zero builtins compiled in); the facade keeps `std` and process
code out of the core dependency graph. Alternative (single crate + features) was
rejected: it would make "no builtins" a compile-flag promise rather than a structural one.

Dependency graph (arrows = "depends on"):

```
gfx (facade) ──▶ gfx-core ◀── gfx-remap ──▶ gfx-hash (trait only)
     │                            │
     └──▶ gfx-hash (bundled impls, optional)
```

### 5.2 Event model (sketch)

```rust
// gfx-core/src/event.rs
pub type Mark = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Blob   { mark: Option<Mark>, data: Data },
    Commit(Commit),
    Tag(Tag),
    Reset  { ref_name: BString, from: Option<Committish> },
    Checkpoint,
    Progress { bytestring: BString },
    Feature  { name: BString, arg: Option<BString> },
    Option   { arg: BString },
    Done,
    Alias    { mark: Mark, target: Committish },      // newer git
    GetMark  { mark: Mark },                           // import-side request
    CatBlob  { dataref: DataRef },                     // import-side request
    Ls       { dataref: Option<DataRef>, path: Option<BString> },
    Comment  { text: BString },                        // only if Options::keep_comments
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub ref_name: BString,
    pub mark: Option<Mark>,
    pub original_oid: Option<Oid>,
    pub author: Option<Ident>,       // None = implicit (committer) — fast-import rule
    pub committer: Option<Ident>,
    pub encoding: Option<BString>,
    pub message: Data,
    pub from: Option<Committish>,
    pub merges: Vec<Committish>,
    pub ops: Vec<FileOp>,            // order-significant; fast-import applies in order
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileOp {
    Modify { mode: Mode, path: BString, source: FileSource }, // includes inline data + tree replace
    Delete { path: BString },
    Copy   { from: BString, to: BString },
    Rename { from: BString, to: BString },
    DeleteAll,
    Note   { data: FileSource, commit: Committish },          // `N` (notemodify)
}

pub enum FileSource { Mark(Mark), Oid(Oid), Inline(Data) }
pub enum Committish { Mark(Mark), Oid(Oid) }   // Oid form: excluded-parent refs, import streams, tags
pub enum Data      { Literal(Vec<u8>) }        // delim form normalized at parse time (§5.6)
pub enum Mode      { Regular, Exec, Symlink, Gitlink, Dir }
pub enum Oid       { Sha1([u8; 20]), Sha256([u8; 32]) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub name: BString,
    pub email: BString,
    pub time: Timestamp,             // raw text preserved + parsed view
}
pub struct Timestamp { pub raw: BString, pub epoch: i64, pub tz_offset_min: i16 }
```

Design choices:

- **Owned events v1.** `Event` owns its payloads; parse APIs are lifetime-free. A
  zero-copy `EventRef<'a>` companion is a tracked future optimization (§13), not v1.
- **`Data::Literal`** — `data delim`/`data literal` forms normalize to raw
  `data <n>` on write. Byte-exact round-trip is defined against *canonical git-emitted*
  streams (§11.2, property P2), which never use the delim form.
- Import-side requests (`GetMark`, `CatBlob`, `Ls`) are surfaced as events; the host
  answers through the `Writer` (§5.4).

### 5.3 Parser (sketch)

```rust
pub struct Parser { /* internal state machine + staging buffer; no I/O */ }

impl Parser {
    pub fn new(opts: ParseOptions) -> Self;

    /// Append raw bytes. Never blocks, never truncates mid-token.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error>;

    /// Pull the next complete event; `Ok(None)` = more input needed.
    pub fn next_event(&mut self) -> Result<Option<Event>, Error>;

    /// EOF: fails if a partial command or unterminated `data` remains.
    pub fn finish(&mut self) -> Result<(), Error>;
}

pub struct ParseOptions {
    pub mode: Mode,                 // Lenient (default) | Strict
    pub keep_comments: bool,        // default false (skip like fast-import)
    pub limits: Limits,             // max_data (default 1 GiB), max_merges, max_ops, …
    pub object_format: ObjectFormat,// Sha1 | Sha256 | Auto (from `feature object-format`)
}
```

- The state machine tracks exactly one pending construct at a time
  (`CommandHeader → headers → data(n) → file-ops…`), so `feed` chunk sizes are
  irrelevant to output.
- `Error` taxonomy (non-exhaustive): `UnknownCommand`, `UnexpectedToken`,
  `MalformedIdent`, `MalformedDataLen`, `DataTooLarge`, `BadMode`, `BadMark`,
  `BadRefName`, `ObjectFormatMismatch`, `TruncatedStream`, `Unsupported { feature }`.
- Strict mode enforces fast-import's documented validations (ident grammar, ref-name
  rules, mode set, OID length vs object format). Lenient mode keeps raw text and
  defers — required to round-trip foreign streams that git itself would accept
  permissively (`raw-permissive` dates, etc.).
- A push convenience lives on the facade: `feed_all(&mut parser, impl Read)` — *outside*
  core.

### 5.4 Writer (sketch)

```rust
/// Canonical emission, one event per call, into a host-owned buffer.
pub fn write_event(ev: &Event, out: &mut Vec<u8>) -> Result<(), Error>;

pub struct Writer { out: Vec<u8> }   // sugar: push events, drain chunks
impl Writer {
    pub fn write(&mut self, ev: &Event) -> Result<(), Error>;
    pub fn take(&mut self) -> Vec<u8>;
}
```

- Canonical form: `data <n>` (never delim), C-quoted paths only when required
  (mirroring `quote_c_style` rules), raw timestamps, marks as `:<decimal>`,
  commands separated by single `\n`. `write(parse(bytes)) == bytes` holds for any
  canonical input (property P2).
- Import-side responses: `write_event(&Event::Blob{..})`-adjacent helpers emit
  `cat-blob` replies (`<oid> <size>\n<payload>\n`) and `ls` stanzas on the caller's
  buffer — the host routes them to fd 3 / the protocol channel itself.

### 5.5 Pipeline and `Transform` trait

```rust
pub trait Transform {
    fn name(&self) -> &'static str;
    /// 1 event in → 0..N events out (order-preserving).
    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error>;
    /// Flush buffered events at end of stream.
    fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error>;
    /// Reset for a fresh pass (enables deterministic multi-pass hosts).
    fn reset(&mut self);
}

pub struct Pipeline { transforms: Vec<Box<dyn Transform>> }
impl Pipeline {
    pub fn builder() -> PipelineBuilder;              // .push(t) / .remap(cfg) w/ feature
    pub fn apply(&mut self, ev: Event, out: &mut Vec<Event>) -> Result<(), Error>;
    pub fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error>;
}
```

- **Zero builtins is a first-class mode**: `Pipeline::builder().build()` is an identity.
  Users may also skip the pipeline entirely and use `Parser`/`Writer` directly.
- Builtins are opt-in *dependencies*: the facade's `remap` feature (or a direct
  `gfx-remap` dependency). Nothing in `gfx-core` knows any builtin exists.
- Contract tests in `gfx-core` (`transform_test_kit`) that every builtin must pass:
  order preservation, no silent drops, `finish` idempotence after flush, determinism.

### 5.6 Memory & streaming posture

The parser stages at most one construct; `Data` payloads are owned copies, bounded by
`Limits::max_data`. Hosts control chunk sizes. A chunked `Data` variant
(`DataStart/DataChunk/DataEnd`) is deliberately deferred (§13) — it complicates every
transform's state machine and no v1 consumer needs it; the enum's shape admits it
non-breakingly later if telemetry justifies it.

---

## 6. Builtin framework

Builtins are sans-IO stream transforms with three lifecycle rules:

1. **Composable & ordered.** Pipeline order is user-defined. Documented guidance:
   *content/path-mangling builtins before `remap`* (remap must observe the final
   content so its map is meaningful), *mark-consuming builtins after exporters*.
2. **Feature-gated, not core.** Each builtin is its own `no_std` crate + a facade
   feature. "Library usable with or without builtins" is structural (§5.1).
3. **Deterministic.** No clocks/randomness; `BTreeMap` ordering; stable mark handling
   (builtins never renumber existing marks).

Roadmap (v1 ships only the first two rows; the rest is directional):

| Priority | Builtin | Role |
|---|---|---|
| 1 | `gfx-remap` | commit-hash remapping (§7) |
| 2 | `gfx-strip-signatures` (tiny) | drop `gpgsig`-style payloads / signed-object policies (mirrors `--signed-tags=strip`) |
| later | `path-filter` | include/exclude path sets (`filedeleteall`-based pruning) |
| later | `message-rewrite` | text substitution consuming a finished remap commit-map |
| later | `anonymize` | stable pseudonymization (mirrors `--anonymize`) |
| later | `filter-repo` parity layer | accrete the filter-repo feature set as builtins |

---

## 7. Builtin #1: `gfx-remap` — commit-hash remapping

### 7.1 Semantics

The builtin watches every commit/tag/reset and maintains the mapping machinery a
rewriter needs, then rewrites the stream so references follow the *new* lineage:

```
old OID ──(original-oid / import-marks)──▶ mark :N ──(new content)──▶ new OID
```

Concretely, per event:

| Input | Action |
|---|---|
| `commit` with `original-oid` | record `old_oid → mark` |
| `commit` without `original-oid` | record `mark` only (map stays mark-keyed) |
| `from`/`merge`/`reset.from`/`tag.from` as **Oid** | if that OID is mapped/rewritten → emit `Committish::Mark(m)`; if unchanged → keep Oid verbatim (identity) |
| refs whose tip commit was rewritten | emit/adjust `reset` events so the branch tip points at the rewritten lineage |
| `tag` of a rewritten object | retarget per config |
| unchanged commits (identity above them) | **pass through untouched** — unchanged subgraphs keep their hashes, matching filter-repo's preservation property |

Outputs of the builtin (what "remapping hashes" delivers):

1. **A rewritten stream** whose parentage is internally consistent with marks, ready for
   `git fast-import` to materialize new OIDs.
2. **A `CommitMap`**: `old_oid → Option<new_oid>` (`None` until finalized).
3. **A `RefMap`**: `ref_name → old_tip / new_tip(mark)` for ref updates.

### 7.2 Hash finalization — two modes

- **Mode A — marks-only (v1).** New OIDs are materialized by the downstream
  `git fast-import`, which can `feature export-marks=<file>`. The host (facade) reads the
  marks file and calls:

  ```rust
  impl Remap {
      pub fn commit_map(&self) -> impl Iterator<Item = (&Oid, Option<Oid>)>;
      pub fn finalize_from_marks(&mut self, marks: &MarkFile) -> Result<MapStats, Error>;
  }
  ```

  `MarkFile` parse/serialize (the `:1 <hex>` line format) lives in `gfx-core` (decision 3) —
  it is
  pure text processing, `no_std`-friendly, and doubles as
  `import-marks`/`export-marks` support.

- **Mode B — in-process hashing (stretch, M6).** For hosts that want the new OID without
  running fast-import: build each commit's canonical object bytes
  (`tree`, parents→mapped OIDs, author/committer, encoding, message) and hash
  `sha1("commit <len>\0" + body)` via the injected `Hasher`. Requires a **virtual tree
  builder** applying `FileOp`s to reconstruct tree OIDs (tree objects hash without zlib —
  only pack writing needs deflate, which stays out of scope). Behind
  `RemapConfig::hash_mode = InProcess(HasherKey)`.

### 7.3 Configuration

```rust
pub struct RemapConfig {
    pub object_format: ObjectFormat,
    pub hash_mode: HashMode,                    // MarksOnly (v1) | InProcess (stretch)
    pub original_oid_policy: OriginalOidPolicy, // Keep | Drop | ReplaceWithNew
    pub identity_is_noop: bool,                 // if the final map is identity,
                                                // emit byte-identical output (default true)
    pub track_message_oids: bool,               // harvest old-OIDs mentioned in messages
                                                // (feeds a later message-rewrite builtin)
}
```

`identity_is_noop` gives a strong, cheap property: with no content-changing builtin
upstream, `remap(export(repo)) == export(repo)` byte-for-byte (property P4).

### 7.4 Message-hash rewriting (explicitly deferred)

Rewriting OIDs *inside commit messages* cannot be done in one streaming pass in general
(messages may reference descendants or unrelated commits). Decision: `gfx-remap` v1 only
*harvests* referenced OIDs (`track_message_oids`); the follow-up `message-rewrite`
builtin consumes the finished `CommitMap` in a **second pass** over a re-export (host
drives; `Transform::reset` exists for exactly this). This mirrors how filter-repo must
order its own hash-substitution work and avoids unbounded message buffering.

### 7.5 State machine (v1)

```
            ┌───────────────────────────────────────────────────────┐
 Event ────▶│ collect: mark→old (original-oid)                      │
            │ rewrite: from/merge/reset/tag targets (oid → mark)    │──▶ events out
            │ track:   rewritten? per mark (canonical digest baseline) │
            └───────────────────────────────────────────────────────┘
 finish(): emit trailing `reset`s for remapped tips; emit RefMap summary
```

Internals: `BTreeMap<Mark, Option<Oid>>` (mark → original), `BTreeMap<Oid, Mark>`,
`BTreeSet<Mark>` (rewritten set — **canonical digest** (decision 1): remap hashes each
commit's canonical digest itself and flags it rewritten when the digest differs from the
`original-oid`-derived baseline; keeps builtins decoupled, no shared side-channel),
marks-file reader/writer via `gfx_core::MarkFile` (decision 3).

---

## 8. Export side: generating streams (sans-IO)

`gfx-core::export::Exporter` produces `Event`s from a host-driven repository snapshot.
The host walks its object store (gitoxide, libgit2, a subprocess, a test fixture —
anything) in **topological commit order** and drives:

```rust
pub enum RepoInput<'a> {
    Refs(&'a [(BString, Oid)]),                 // ref tips to export
    BeginCommit { oid: Oid, parents: &'a [Oid], },
    CommitMeta { author: Ident, committer: Ident, encoding: Option<BString>,
                 message: &'a [u8], original_oid: bool, /* … */ },
    /// changed paths vs first parent (host computes diff; or `full_tree` mode)
    FileChange { mode: Mode, path: &'a [u8], content: BlobRef<'a> },
    FileDelete { path: &'a [u8] },
    /// host-supplied rename/copy pairs (we do NOT detect; this is -M/-C)
    Renames(&'a [(BString, BString)]),
    BlobChunk(&'a [u8]),                        // streamed into `data`
    Tag { name: BString, target: Oid, tagger: Option<Ident>, message: &'a [u8], /* … */ },
    EndCommit, End,
}

pub struct Exporter { /* mark table (oid→mark), dedup set, options */ }
impl Exporter {
    pub fn apply(&mut self, input: RepoInput<'_>, out: &mut Vec<Event>) -> Result<(), Error>;
    pub fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error>;
}

pub struct ExportOptions {
    pub mark_tags: bool,              // `--mark-tags`
    pub show_original_ids: bool,      // `--show-original-ids`
    pub signed_tag_policy: SignedPolicy,   // abort|strip|warn… (host sees warnings via Result/log hook)
    pub full_tree: bool,
    pub export_marks: bool,           // expose mark table at finish()
    /* … */
}
```

Exporter responsibilities: mark assignment in fast-export's order (shared blob/commit
counter), blob dedup via the mark table, `reset` emission for branch tips, tag framing,
`feature`/`done` framing, and exposing the final mark table (feeding `gfx-remap` /
marks-file output). Acceptance target: byte-exact parity with pinned-git `git fast-export`
over the fixture corpus (§11.3), with documented, versioned deltas if any.

---

## 9. Public API surface (facade)

```rust
// gfx (facade) — the only crate most users touch
pub use gfx_core::{Event, Parser, Writer, Pipeline, Transform, Error, …};
#[cfg(feature = "remap")]  pub use gfx_remap::{Remap, RemapConfig, CommitMap};
pub use gfx_core::MarkFile;

/// Stream → stream in one call (still sans-IO: buffers in, buffers out).
pub fn rewrite(input: &[u8], pipeline: &mut Pipeline) -> Result<Vec<u8>, Error>;

#[cfg(feature = "std")]
pub mod git {
    /// Spawn `git fast-export` on a repo path; returns an iterator of `Event`s (parsing on a thread or in-band).
    pub fn export(repo: &Path, args: ExportArgs) -> impl Iterator<Item = Result<Event, Error>>;
    /// Feed a stream to `git fast-import` (adds `feature done`, captures marks/refs report).
    pub fn import(repo: &Path, events: impl Iterator<Item = Event>) -> Result<ImportReport, Error>;
}
```

Everything under `git` is `std`-gated, test-oriented, and never required — the
`no_std` story stands alone.

---

## 10. Testing & CI strategy

### 10.1 Property tests (in-suite, deterministic)

| # | Property |
|---|---|
| P1 | `parse(write(e)) == e` for arbitrary `e` (`arbitrary`-generated `Event`s) |
| P2 | `write(parse(bytes)) == bytes` for canonical fixture streams |
| P3 | identity pipeline: `bytes == rewrite(bytes, [])` |
| P4 | remap identity-noop: unchanged input stream passes through byte-identical |
| P5 | parentage closure: every `from`/`merge` in remapped output resolves to a mapped/unchanged target; downstream `git fsck --strict` passes |
| P6 | determinism: two runs over the same input are byte-identical (catches HashMap leakage) |
| P7 | parser never panics on arbitrary bytes (fuzz target, `cargo-fuzz`, long-running in CI nightly) |

### 10.2 Golden fixtures

- `fixtures/gen` — a script building synthetic repos (cranky cases: non-UTF-8 paths,
  CRLF messages, empty commits, merges/octopus, notes, submodules (gitlinks), symlinks,
  exec bits, tags-of-tags, SHA-256 repo, `data delim` streams, quoted paths) and
  capturing `git fast-export` output with a **pinned git version** committed alongside
  expected marks files.
- Fixture files are committed; regeneration is an explicit, reviewed act (version bump
  = corpus bump).

### 10.3 Integration (std facade, requires `git` in PATH)

- End-to-end: fixture repo → `git fast-export` → gfx pipeline (remap) →
  `git fast-import` into a fresh repo → `git fsck --strict` clean; refs match `RefMap`;
  `CommitMap` finalized from exported marks; unchanged subgraph hashes preserved.
- SHA-256 end-to-end mirror of the above.
- macOS is the dev host; any required guest-Linux coverage follows the global AGENTS.md
  rule — Homebrew QEMU with software emulation only, explicit generated args, ephemeral
  disks, bounded timeouts, and **fail-closed** if the emulator/image is unavailable
  (never substitute host results for Linux coverage).

### 10.4 CI gates

- `cargo build -p gfx-core -p gfx-remap --target x86_64-unknown-none` (+ one
  `thumbv7m-none-eabi`) — the `no_std` gate.
- `cargo hack check --each-feature --no-dev-deps` — feature-matrix hygiene.
- MSRV job (§12), clippy `-D warnings`, `miri` on parser unit tests, fuzz smoke
  (60s/target) on PRs, nightly long fuzz.
- `cargo-mutants` (or similar) on `gfx-remap` — mapping logic is exactly where subtle
  mutants should be killed.

---

## 11. Compatibility policy

- **Spec baseline**: git docs + source pinned in `docs/git-baseline.md` (initially:
  current stable at M0, recorded by hash). Version-sensitive corners are listed there
  with "verify" notes: `data delim/literal` intro version, `alias`, `--mark-tags`,
  `original-oid` coverage per object type, `--signed-commits` stream surface, `M 040000`
  tree-replace.
- Unknown `feature`/`option` names: lenient parser passes them through as events; strict
  parser errors with `Unsupported`. Never silently drop.
- `t9300`-derived corpus supplements our fixtures to catch drift early.

---

## 12. Milestones

| Milestone | Deliverable | Acceptance |
|---|---|---|
| Milestone | Deliverable | Acceptance | Status |
|---|---|---|---|
| **M0** Scaffold | Workspace per §5.1; `Error`, `Limits`, `BString` conventions; `no_std` CI gate; git baseline doc | `x86_64-unknown-none` builds green, all crates | ✅ done |
| **M1** Grammar core | `Event`, lenient `Parser` (blob/commit/reset/tag/data/marks/file-ops/progress/feature/option/done/original-oid), canonical `Writer` | P1/P2 on MVP subset; fixtures round-trip | ✅ done |
| **M2** Full grammar | C-style path (un)quoting; `data delim`; `alias`/`get-mark`/`cat-blob`/`ls`; SHA-256; strict mode; limits; fuzz targets live | P7 green; full fixture corpus P2; strict-mode test suite | ✅ done (fuzz targets pending) |
| **M3** Pipeline | `Transform`, `Pipeline`, test kit; facade crate with builder | P3; builtin test kit exercised by a toy builtin | ✅ done |
| **M4** `gfx-remap` v1 (Mode A) | Mapping, parentage rewrite, `reset` tip fixes, `MarkFile` I/O, `CommitMap`/`RefMap`, identity-noop | P4/P5/P6; end-to-end git integration green (incl. SHA-256) | ✅ core done; git-CI wiring pending |
| **M5** Exporter | `Exporter` + options; `std` facade `git::export`/`git::import` | Byte-exact parity vs pinned git on corpus; remap composes on exporter output | pending (write-side parity already proven byte-exact vs live git on the smoke corpus) |
| **M6** Stretch | Mode B in-process hashing (virtual tree builder + `Hasher`); `strip-signatures` builtin | Mode B map matches Mode A map on corpus | pending |

MSRV/edition: edition 2024, MSRV **1.85** (documented; bumped only in M-milestone PRs).

---

## 13. Risks & open questions

**Resolved decisions**

1. How do upstream content builtins flag "this commit changed" to `gfx-remap`?
   **Canonical digest** (M4): remap hashes a canonical digest of each commit itself,
   keeping builtins decoupled — no shared side-channel type in `gfx-core`.
2. `Event::Comment` capture granularity (if `keep_comments` lands): **line-level** —
   one `Event::Comment` per `#` line, text = the line's bytes.
3. `MarkFile` placement: **`gfx-core`** (M0) — `import-marks`/`export-marks` are
   protocol surface, not remap-specific. `gfx-remap` consumes it via the core type.
4. Naming: **dedicated split** — `Committish::Oid` for commit-ish targets
   (`from`/`merge`/`reset.from`/`tag.from`), `DataRef::Oid` for blob/content refs
   (`M` sources, `N` notes); no shared variant.

**Risks**

- *Undocumented/version-drifting grammar corners* → baseline pinning + fixture corpus +
  `t9300` mining (§10.2, §11).
- *Memory profile of owned `Data` events on huge blobs* → limits now; chunked-data
  variant is a designed-for extension if telemetry demands it (§5.6).
- *Byte-exact exporter parity may fight git's quirks* → parity is scoped to the pinned
  corpus with documented deltas, not a universal promise.
- *`dyn Transform` dynamic dispatch cost* — negligible vs parsing; revisit only with
  profiles (generic `Pipeline<T>` alternative kept in mind).

**Open questions**: none outstanding — all four M0/M4 questions resolved above.

---

## 14. References

- `git-fast-export(1)`, `git-fast-import(1)` — protocol grammar.
- git source: `builtin/fast-export.c`, `builtin/fast-import.c`;
  `t/t9300-fast-import-tests.sh`.
- `git filter-repo` — design doc & `--map-file`/commit-map semantics (behavioral
  reference for `gfx-remap`).
- Sans-IO pattern: <https://sans-io.readthedocs.io/> (practice notes from HTTP/2, QUIC
  implementations).
- Crates: `bstr` (no_std byte strings), `sha1`/`sha2` (RustCrypto, no_std), `arbitrary`
  + `cargo-fuzz`.
