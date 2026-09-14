# Plan: `gfx-blob-xform` — generic fallible blob rewriting

| Field    | Value |
|----------|-------|
| Status   | Implemented (M0–M3) |
| Scope    | builtin pass: run a fallible `Vec<u8>`/`String` transform over every blob; alter on success, retain original on failure |
| Depends  | plan-fast-export.md §5 (architecture), §6 (builtin framework); plan-pass-driver-strip-blobs.md §4 (driver, registry), §5.2 (injected-predicate pattern); plan-redact-idents.md (injected `IdentPolicy` pattern); plan-multistream-pack.md M4 (Send/Sync shared handles) |
| Updated  | 2026-09-13 (M3 hardening; see [rewrite-cli.md](rewrite-cli.md) for the user-facing surface) |

---

## 1. Summary

One deliverable — a fourth `no_std` builtin, `gfx-blob-xform` (pass name
`blob-xform`) — that rewrites the *payload bytes* of every blob in a
fast-export stream through a **fallible, pure, per-blob transform**:

```
let Ok(new) = transform.apply(&old) else { keep old };   // D1
```

If the transform succeeds, the blob's `data` is replaced; if it fails, the
original bytes flow through untouched and the failure is counted, not
raised. The crate supplies the machinery (coverage, failure semantics,
no-op elision, size guards, reporting) plus a small set of built-in
transforms (`crlf-to-lf`, `trim-trailing-whitespace`, `ensure-final-newline`);
hosts inject arbitrary `Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, _>>` (and a
`String` adapter over UTF-8) through the established shared-handle pattern —
the same shape as strip-blobs' injected predicates and redact's
`IdentPolicy`, upgraded to `Arc + Send + Sync` by multistream M4.

The defining design decision (D1) is the **fail-open** mirror of
strip-blobs' fail-closed drop-first rule: this pass exists for *best-effort
improvement* (normalization, re-encoding, format fixups), where a blob the
transform can't handle is data, not an error. Guaranteed removal stays with
strip-blobs; guaranteed field rewriting stays with redact. `blob-xform`
never drops, synthesizes, or reorders an event — marks, `original-oid`
lines, refs, and topology are untouched, and remap (always composing last)
owns the resulting commit-hash churn, exactly as for redact.

Motivating gap: today there is no way to touch blob *contents* at all —
strip-blobs deletes whole ops, redact rewrites idents/timestamps. The
recurring ask ("run this function over every file in history, fix what you
can, leave the rest") is filter-repo's `--blob-callback`, and it deserves a
first-class, deterministic, `no_std` home with explicit failure semantics.

## 2. Goals and non-goals

### Goals

- G1: Total blob coverage of the stream's two content sites: standalone
  `blob` events (`mark`, `original-oid`, `data`) and inline `data` in
  `M`/`N` file ops (`FileSource::Inline`).
- G2: Precise failure semantics (D1): per-blob `Result`; `Ok` ⇒ alter,
  `Err` ⇒ retain original bytes; the pass itself only fails on stream-level
  errors, never because of blob content.
- G3: No-op elision: output identical to input ⇒ emit the event
  byte-identically (identity transform ⇒ identity stream, P6 analog), and
  count it separately from "altered".
- G4: Determinism: pure functions of the input bytes only — no clocks, no
  RNG; identical stream + config ⇒ byte-identical output. Injected
  transforms carry the same purity contract as strip-blobs' injected
  predicates.
- G5: A text-first API (`String`/`&str`) layered on the bytes API with
  explicit decode-failure ⇒ retain semantics, so "line-oriented cleanup"
  transforms never mangle binary blobs by accident.
- G6: Reporting: examined / altered / unchanged / retained(failed) /
  retained(guard) counts plus in/out byte totals, in the run report's
  per-pass detail line.

### Non-goals

- N1: **Guaranteed transformation.** Fail-open is the point. If a secret
  *must* come out, that is strip-blobs (drop-first, fail-closed) or a
  dedicated scrub pass — not this.
- N2: **Path-aware decisions.** Blob events carry no path; path logic is
  strip-blobs' domain. The only path/mode information available is on
  inline `M`/`N` ops, used solely for the special-mode guard (D5).
- N3: **Tree/op restructuring** — no drops, no synthesized ops, no mark
  renumbering. Only `data` payloads change.
- N4: **A shell/subprocess surface in the `no_std` crate.** The external
  -command adapter (M2) is a `std`-gated host-side injection, keeping the
  builtin embeddable.

## 3. Decisions

- **D1 — Fail-open per blob, atomic to the original.** Each blob runs the
  configured transform chain; `Ok(bytes)` at the end ⇒ alter, any `Err` ⇒
  emit the **original** bytes (not the last good intermediate stage) and
  count a retention. Rationale: "alter if the pass succeeds" is the whole
  contract; partial chains produce blobs that match neither the source nor
  a documented output, and silently mixing stage depths across blobs is a
  determinism and auditability hazard. The pass's own `apply`/`finish`
  return `Err` only for stream-level failures.
- **D2 — Machinery in the crate, transforms injected.** The crate owns
  event plumbing and reporting; transforms are values of a
  `BlobTransform` trait object behind a `SharedBlobTransform`
  (`Arc<dyn BlobTransform + Send + Sync>`) newtype — clone-cheap,
  thread-shareable (multistream M4 fans passes out across workers). Three
  built-ins ship in-crate (`crlf-to-lf`, `trim-trailing-whitespace`,
  `ensure-final-newline`); everything else is host-injected, including the
  CLI's `std`-gated external-command adapter (M2).
- **D3 — Text is an adapter, not a mode.** `TextTransform` wraps any
  `Fn(&str) -> Result<String, _>`: UTF-8 decode (fail ⇒ retain), run,
  re-encode. Byte transforms and text transforms compose freely in one
  chain because the chain element is always bytes-in/bytes-out. BOM,
  non-UTF-8, and invalid-UTF-8 inputs thus fall out as ordinary
  retentions, not special cases.
- **D4 — Guards are retentions, not errors.** Optional input selector
  `skip-larger-than <n>` (leave big blobs alone, e.g. binaries) and output
  guard `max-output-bytes <n>` (a transform that inflates pathologically
  loses its work). Both count as `retained(guard)` — distinct from
  `retained(failed)` — so the report separates "couldn't" from "chose
  not to".
- **D5 — Mode-blindness is documented, and inline ops guard special
  modes.** Standalone `blob` events carry no file mode, and fast-export
  emits blobs *before* the commits that reference their marks, so a
  streaming pass cannot know whether a blob is a symlink target (whose
  trailing bytes are semantically load-bearing). Consequences: (a) the
  pass applies built-ins to all standalone blobs and documents that
  whitespace/line-ending transforms can, in principle, alter symlink
  targets — same blindness as filter-repo's `--blob-callback`;
  (b) for inline `M`/`N` data (where mode *is* present), blobs with
  `Symlink`/`Gitlink` modes are skipped by default, opt-out knob
  `include-special-modes`.
- **D6 — `original-oid` is preserved verbatim.** After alteration the line
  no longer matches the payload — exactly like a commit's `original-oid`
  after remap, and that is its job: it records the pre-transform identity
  for downstream audit/mark-folding. Streams already carry these lines
  end-to-end (`--show-original-ids` export → fast-import), so nothing new
  is introduced on the import path.
- **D7 — Fixed stage order: blob-xform before strip-blobs.** The driver
  runs content stages in a fixed sequence (blob-xform → strip → redact →
  remap), as it already did for strip/redact — `--passes` order selects
  *which* passes run, not their relative order. Blob-xform runs first so
  size-based stripping judges *post-transform* sizes (a shrink can save a
  blob from the knife — usually the desired reading); relative to redact
  the passes are orthogonal (disjoint fields).

## 4. Design

### 4.1 Crate shape (`gfx-blob-xform`, `#![no_std]`)

```rust
/// A fallible, pure, per-blob byte transform.
pub trait BlobTransform {
    fn name(&self) -> &'static str;
    /// Ok(new bytes) to alter; Err(()) to retain the original.
    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()>;
}

/// Clone-cheap, thread-shareable handle (strip-blobs SharedMatcher shape,
/// Arc + Send + Sync per multistream M4).
pub struct SharedBlobTransform(pub Arc<dyn BlobTransform + Send + Sync>);

/// D3: `Fn(&str) -> Result<String, _>` with UTF-8 decode-fail ⇒ retain.
pub struct TextTransform<F> { pub name: &'static str, pub f: F }

pub struct BlobXformConfig {
    /// Applied in order; any stage Err ⇒ retain original (D1).
    pub transforms: Vec<SharedBlobTransform>,
    /// D4 guards.
    pub skip_larger_than: Option<u64>,
    pub max_output_bytes: Option<u64>,
    /// D5: transform inline `M`/`N` data at all, and whether to include
    /// Symlink/Gitlink modes when doing so.
    pub include_inline: bool,          // default true
    pub include_special_modes: bool,   // default false
}

pub struct BlobXform { /* config + counters */ }
impl Transform for BlobXform { /* apply/finish/reset per the contract */ }

pub struct BlobXformReport {
    pub blobs_examined: u64,
    pub altered: u64,
    pub unchanged: u64,        // transform Ok but output == input (G3)
    pub retained_failed: u64,  // transform Err (incl. UTF-8 decode)
    pub retained_guard: u64,   // D4 size guards / D5 special modes
    pub bytes_in: u64,
    pub bytes_out: u64,
}
```

`apply` matches on the event: `Event::Blob` ⇒ transform `data` in place;
`Event::Commit`/`Tag` walk ops and rewrite `FileSource::Inline` payloads
(subject to D5); everything else forwards untouched. `reset` clears
counters only (there is no cross-event state — the pass is deliberately
stateless per blob, which is what makes per-blob failure isolation trivial
and the multistream fan-out safe beyond the `Send + Sync` handles).

### 4.2 Built-in transforms (initial set)

| Name | Bytes or text | Failure cases |
|------|---------------|---------------|
| `crlf-to-lf` | bytes (CRLF/CR → LF) | never fails; no-op ⇒ unchanged |
| `trim-trailing-whitespace` | text | non-UTF-8 ⇒ retain |
| `ensure-final-newline` | text | non-UTF-8 ⇒ retain; empty blob stays empty |

Deliberately minimal: the built-ins prove the machinery; real workloads
arrive via injection. Each built-in is idempotent (apply∘apply == apply),
which the property tests pin.

### 4.3 CLI surface (`rewrite`/`pack --passes`)

```
--passes blob-xform \
  --blob-xform.crlf-to-lf            # built-in, chainable, repeatable flags
  --blob-xform.trim-trailing-whitespace
  --blob-xform.ensure-final-newline
  --blob-xform.skip-larger-than 1MiB # D4
  --blob-xform.max-output-bytes 16MiB
  --blob-xform.cmd 'upx --best'      # M2, std-gated: per-blob subprocess;
                                     # exit != 0 ⇒ retain; stdout = new bytes
```

Flags append transforms in argv order (chain order = flag order).
`blob-xform` with no transform flags is a usage error ("nothing to do"),
mirroring how strip-blobs requires at least one selector. Like `redact`,
the pass is registered but never a default — content rewriting is opt-in.

### 4.4 Report

Pass detail line, same shape as the other builtins:

```
- blob-xform: blobs=12043 altered=317 unchanged=11580 retained=146 (failed=141 guard=5) bytes=48112033->47998510
```

## 5. Testing

- **Unit (test kit):** the `Transform` contract suite; each built-in's
  table of cases (CRLF mix, lone CR, empty blob, already-clean, binary
  with invalid UTF-8 ⇒ retained, NUL-heavy blob under text transforms ⇒
  retained); D1 atomicity (a chain whose second stage fails emits the
  *original* bytes); D4 guards; D5 symlink-mode skip on inline ops.
- **Stream round-trips:** identity stream when all transforms fail;
  no-op elision (unchanged blobs produce byte-identical events, marks and
  `original-oid` intact); inline + standalone coverage in one stream.
- **Property:** arbitrary `&[u8]` under every built-in and under arbitrary
  chains — never panics; built-ins idempotent; retained-on-failure means
  output bytes == input bytes exactly.
- **Fuzz:** `fuzz_targets/blob_xform_roundtrip.rs`, modeled on
  `strip_roundtrip.rs`: arbitrary streams through rotating configs
  (built-ins × guards × inline knobs), asserting the contract suite's
  invariants hold for garbage input.
- **E2E (M1/M2):** repo with mixed text/binary/CRLF history → `rewrite
  --passes blob-xform,remap` → fast-import → fsck; `git diff` of
  before/after trees shows exactly the intended hunks; multistream pack
  with `--jobs 1` vs `--jobs 4` stays byte-identical (D-determinism under
  fan-out, the M4 test extended with this pass).

## 6. Milestones

- **M0 — crate + trait + built-ins.** `gfx-blob-xform` `no_std` crate,
  `BlobTransform`/`SharedBlobTransform`/`TextTransform`, three built-ins,
  full unit + property coverage. *Exit:* contract suite green; no_std
  check in CI.
- **M1 — driver/registry/CLI wiring.** `PassSpec::BlobXform`, registry
  registration (never-default), flag parsing with chain-order semantics,
  report detail line, E2E round-trip through fast-export/fast-import.
  *Exit:* the §5 E2E test green; `rewrite-cli.md` section.
- **M2 — external-command adapter.** `std`-gated `--blob-xform.cmd`
  implemented as host injection from the facade/CLI (subprocess per blob,
  stdin = blob, stdout = replacement, non-zero exit ⇒ retain; bounded
  output capture feeding D4's guard). Documented as deterministic-only
  ("the command is your purity contract"). *Exit:* E2E with a real filter
  program; non-zero-exit retention test.
- **M3 — hardening.** Fuzz target, multistream `--jobs` determinism test,
  docs (`rewrite-cli.md`, pack-cli.md cross-refs), hazard write-up for D5
  symlink mode-blindness. *Exit:* fuzz target compiles and runs a clean
  smoke corpus; all suites green.

## 7. Open questions

- Q1: Should the run report (or an optional artifact file) list *which*
  blobs were retained — by mark/`original-oid` (standalone blobs have no
  path)? Cheap to add later behind a flag; the counts-only default keeps
  the artifact-free profile of the other passes. Leaning: counts now,
  `--blob-xform.report-retained <file>` if asked for.
- Q2: Is per-transform (vs. whole-chain) accounting worth it when chains
  are long? Adds a `Vec<u64>` of counters keyed by stage; defer until a
  real chain > 2 exists.
- Q3: A `skip-binary` heuristic knob (NUL-in-first-8k, git's own rule) as
  sugar over text transforms? It duplicates what D3 already guarantees;
  only add if users find the retained counts noisy.
