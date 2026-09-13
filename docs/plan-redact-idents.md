# Plan: `gfx-redact` — commit-metadata redaction (idents + timestamps)

| Field    | Value |
|----------|-------|
| Status   | Approved — implementing (M0–M3) |
| Scope    | builtin pass: rewrite author/committer/tagger identities and timestamps for share-safe history |
| Depends  | plan-fast-export.md §5 (architecture), §6 (builtin framework), §7 (`gfx-remap`); plan-pass-driver-strip-blobs.md §4 (driver, registry), §5.5 (remap interaction note) |
| Updated  | 2025-09-05 |

---

## 1. Summary

One deliverable — a third `no_std` builtin, `gfx-redact` (pass name `redact`) —
that rewrites the *people and times* inside a fast-export stream:

1. **Ident redaction** — `author`, `committer`, and `tagger` name/email fields
   are replaced under a deterministic policy: an exact mapping table
   (`--redact.map`), the built-in seeded **pseudonymizer** (every distinct
   ident becomes `User-N <user-N@example.invalid>`), or a host-injected
   `IdentPolicy` (the strip pass's injected-matcher pattern, applied to idents).
2. **Timestamp redaction** — commit/tag times under explicit modes:
   `preserve` (default), `zero`, `shift` (constant offset), `bucket`
   (floor to day/week/month), `fuzz` (seeded bounded jitter) — with **timezone
   offsets zeroed by default**, because `±HHMM` leaks geography.

The defining design decision (D1 below, scoped to this document) is the
mirror image of the strip pass's drop-first rule: redact **rewrites fields in
place and never restructures anything** — no op is dropped, no op is synthesized, marks,
`original-oid` lines, ref names, and commit topology are untouched. The only
guarantee it makes about hashes is a negative one: any commit whose fields the
policy changed gets a different hash, and remap (already always composing
last) owns that bookkeeping.

Motivating gap: every existing tool leaves timestamps intact.
`git fast-export --anonymize` replaces names/emails/paths/messages/contents
but **explicitly preserves commit timestamps** (git-fast-export(1),
"ANONYMIZING"); `git filter-repo`'s `--mailmap` and `--name-callback` /
`--email-callback` rewrite idents only. Sharing a repo with anonymized names
but real dates still leaks working hours, time zones (via the offset bytes),
activity patterns, and a re-dating correlation attack surface. This plan
closes that with explicit, documented, deterministic time modes.

## 2. Goals and non-goals

### Goals

- G1: Byte-precise rewriting of `author`/`committer`/`tagger` idents in commit
  and tag events — same (name, email) always maps to the same replacement
  within a run (structural consistency, like fast-export `--anonymize`'s
  "two instances of the same string are replaced equivalently").
- G2: Explicit timestamp modes with *documented* order/interval consequences —
  the user chooses what history-wide information survives.
- G3: Zero timezone offsets by default (`keep-tz` opt-out), since offsets are
  geographic metadata.
- G4: Determinism above all: no clocks, no RNG — every "random-looking"
  transformation is a pure function of `(seed, original bytes)`; identical
  input + config ⇒ byte-identical output (P6 analog).
- G5: A **mapping artifact** (`redact-map.txt`) so the operator can audit —
  and later reverse — the redaction, written outside the stream with a
  sensitivity warning.
- G6: The **leak-scan property**: after redaction, no original ident bytes
  survive anywhere in the emitted stream (property R4 is a grep, in test form).
- G7: Compose with the existing driver: a content pass that slots into the
  registry, validates ordering (`…,redact,remap`), and rides the same
  safety check / dry-run / artifacts machinery.

### Non-goals (v1)

- N1: **Message rewriting** — sign-off trailers (`Signed-off-by:`),
  `Co-authored-by:`, quoted names, and `Date:` lines inside commit/tag
  messages are untouched (they are message-rewrite pass territory,
  plan-fast-export.md §7.4). Documented as a residual leak (§8); the CLI
  guide's sharing checklist says so in plain text.
- N2: **Ref-name redaction** (`refs/heads/alice/fix` leaks identity).
  Deferred with path/refname anonymization; docs advise renaming refs first.
- N3: **Full `--anonymize`** (blob contents, tree shapes, paths) — a future
  pass; this one keeps all content real on purpose (that is what makes it a
  *redactor* rather than an anonymizer).
- N4: Cryptographically secure anonymity. `fuzz` and hash-derived pseudonyms
  are deterministic obfuscation, not defense against a determined analyst with
  side information (§8, R-risk). The strong defaults (ordinal pseudonyms,
  zeroed tz, zero/shift/bucket times) reduce leakage structurally instead.
- N5: Per-commit/per-ref time policies (e.g., "keep times on `main`, zero on
  `experiment/*`") — deferred; v1 modes are history-wide.
- N6: GPG signatures — already stripped by the driver's pinned
  `--signed-tags=strip`; the pass assumes a re-signed world (out of scope).

## 3. Background: where metadata lives, and what tooling does today

### 3.1 The leak model

A fast-export stream carries people-and-time metadata in exactly these
places:

| Stream location | Leaks | v1 redact handles |
|---|---|---|
| `author` / `committer` ident lines | legal name, email, employer, identity graph | yes (§4.3) |
| `tagger` ident line | same, for annotated tags | yes (§4.3) |
| ident `when` field: `<epoch> <±HHMM>` | activity hours, intervals, **UTC offset = geography** | yes (§4.4) |
| commit/tag message payloads | sign-offs, mentions, prose self-identification | no — message-rewrite pass (N1) |
| ref names | usernames in branch/remote names | no — ref renaming (N2) |
| `encoding` header (`GBK`, `Big5`, …) | locale hints | no; documented residual (rare; driver's `--reencode=yes` normalizes message bytes upstream) |
| path strings (`src/alice/…`) | usernames in paths | no — out of scope (N3) |

Correlation attacks worth naming in docs (they justify the time modes):
a pseudonymized repo with preserved timestamps lets an analyst match the
commit-time fingerprint (interval pattern, hour-of-day histogram, tz offset)
against a known repo or a public mailing-list identity and re-attach real
names to pseudonyms. Zeroing tz and bucketing/zeroing times is what blunts
that; preserving times verbatim does not.

### 3.2 What the reference tools do (verified)

- **`git fast-export --anonymize`** (git-fast-export(1), ANONYMIZING):
  replaces "all refnames, paths, blob contents, commit and tag messages,
  names, and email addresses … Two instances of the same string will be
  replaced equivalently", keeps tree *shape*, and — key for us —
  "the commit timestamps" are explicitly retained. `--anonymize-map=<from>[:<to>]`
  pins chosen tokens. It is a bug-reproduction anonymizer, not a
  share-safe redactor: real dates survive by design.
- **`git filter-repo`**: no longer implements anonymize itself (its
  `sanity_check_args` merely greps `git fast-export -h` for
  `--anonymize-map` capability). Its ident options — `--mailmap <file>`,
  `--name-callback`, `--email-callback` (Python snippets over bytes) —
  rewrite names/emails and **do not touch timestamps**. There is no
  first-class "redact dates" mode; users hand-roll a commit callback.
- So: names are solved upstream; *time/zone redaction with documented
  semantics* is the actual gap, and it is pure stream rewriting — ideal
  builtin material.

### 3.3 Prior art in-repo

The strip pass established the patterns this plan reuses: host-injected
pure predicates (`BlobPredicate`/`PathMatcher` with the `Shared*` newtypes),
per-entity registries bounded by distinct entities, exact totals + capped
listings in reports, and a driver-side artifact file. Redact applies them to
idents and times, with one new wrinkle: an **injectivity audit** (§4.3) —
two distinct original idents must never silently collapse into one
replacement.

## 4. Deliverable: `gfx-redact` — builtin

New `no_std` crate `crates/gfx-redact/` (facade feature `redact`,
`dep:gfx-redact` optional). Depends on `gfx-core` only — no `gfx-vindex`
dependency: redact never inspects tree state, so the virtual index is not
needed (deliberate contrast with strip; recorded in case a reviewer expects
symmetry). The facade re-exports `pub use gfx_redact;` behind the feature.

### 4.1 Placement

```
crates/gfx-redact/         # no_std builtin: ident + timestamp rewriting
crates/gfx/src/driver.rs   # PassSpec::Redact wiring (content stage, before remap)
crates/gfx-cli/src/passes.rs  # RedactFactory: flag surface (§5)
crates/gfx-cli/src/config.rs  # [redact] table in the TOML config file
```

### 4.2 Semantics — rewrite fields in place, never restructure (decision D1)

Decision IDs in this plan are scoped to this document; the strip plan's D1
(drop-first) is a different decision and is cited by name when referenced.

The strip plan's D1 rule was *drop, never synthesize*. Redact's D1 is the
dual: **rewrite, never restructure.** Concretely, per event:

| Event | Action |
|---|---|
| `Commit` | rewrite `author`/`committer` idents (present ones only) and their `Timestamp`s per policy; every other field — `mark`, `original_oid`, `from`, `merges`, `ops`, `encoding`, `message` — passes through untouched |
| `Tag` | rewrite `tagger` ident + its `Timestamp` per policy; everything else untouched |
| `Blob`, `Reset`, `Checkpoint`, `Progress`, `Feature`, `Option`, `Done`, `Alias`, `GetMark`, `CatBlob`, `Ls`, `Comment` | pass through untouched |

What this never does: drop an op, synthesize an op, add or remove an ident
field (a commit with no `author` line stays without one — fast-import
inherits from committer; redact does not "fix" that), renumber marks,
alter `original-oid`, emit trailing resets (remap's job, plan-fast-export
§7.5), or touch topology.

**Per-commit identity-noop:** a commit whose idents and time the policy
leaves unchanged (table miss + `preserve` time) must serialize byte-identical
to input — the pass edits `Timestamp.raw` only when a mode actually applies.
This makes `redact` composable without forcing a whole-repo rewrite when the
table intentionally pins some idents (e.g. bot accounts `--anonymize-map`-style).

**Canonicalization rule (only for altered fields):** when the pass changes
epoch or offset it regenerates `Timestamp.raw` as
`"<decimal-epoch> <±HHMM>"` from the parsed `epoch: i64` /
`tz_offset_min: i16` (the parser guarantees these are populated for raw-format
idents; `epoch = 0` with unparsable `raw` marks the lenient-parse corner —
§4.9). Unaltered fields keep their original raw bytes, preserving
byte-identity. Raw bytes are rebuilt with the pass's own formatter (core's
`push_decimal` is unsigned; negative epochs — pre-1970 commits — must
serialize with a leading `-`; edge case, §4.9).

### 4.3 Ident mapping — three mechanisms, one audit

Input to the mapper is the parsed `Ident { name: BString, email: BString,
time: Timestamp }` plus a role tag; output is a replacement `Ident` (with
`time` handled per §4.4).

```rust
pub enum IdentRole { Author, Committer, Tagger }

/// Host-injected policy (library-level knob, the strip pass's injected
/// matcher pattern applied to idents). Contract: a pure function of
/// (role, ident); determinism (P6) is the documented requirement, and the
/// pass *audits* injectivity (below) rather than trusting it.
pub trait IdentPolicy {
    fn rewrite(&self, role: IdentRole, ident: &Ident) -> Ident;
}

pub enum IdentMode {
    /// No ident change (times may still change).
    Preserve,
    /// Exact rows first-match-wins; `name: None` / `email: None` are
    /// wildcards (mailmap-flavored, minus the reverse-mapping column —
    /// filter-repo's `--mailmap` remains the richer upstream format).
    Table(Vec<RedactRow>),
    /// Built-in deterministic pseudonyms for every ident.
    Pseudonymize(PseudonymStyle),
    /// Host-compiled policy (regex rename, org mailmap, role-aware rules).
    Injected(SharedPolicy),
}

pub struct RedactRow {
    pub name: Option<BString>,   // None = wildcard
    pub email: Option<BString>,  // None = wildcard
    pub new_name: BString,
    pub new_email: BString,
}

pub enum PseudonymStyle {
    /// First-seen ordinal: `User 1 <user1@example.invalid>`, `User 2 …`.
    Ordinal,
    /// Digest-derived: `user-<8 hex> <user-8hex@example.invalid>`.
    Hash,
}
```

Matching and stability rules:

- The map key is the **(name, email) pair, byte-exact** (`BString`s; no
  UTF-8 assumption). A table row matches when both non-`None` fields equal;
  first matching row wins; no match ⇒ ident passes through unchanged (table
  mode is a *selective* redactor, like `--anonymize-map`).
- **Same input ⇒ same output** within a run, enforced by caching the
  resolved mapping in a `BTreeMap<(name, email), Ident>` consulted before the
  policy re-runs — this is what makes author and committer of the same
  person, and the same person across 10k commits, agree byte-for-byte
  (goal G1). The cache is also the audit ledger (below) and the mapping
  artifact source (§4.8).
- **Pseudonym `Ordinal`** (default): assignment order = first occurrence in
  stream order. Deterministic for a given repo + flag set. Two properties on
  purpose: (a) replacements derive *nothing* from input bytes — no
  dictionary attack can recover `alice@…` from `User 3 <user3@…>`;
  (b) two independently-redacted repos of the same project do *not* correlate
  the same person (the number is per-repo) — the anonymity-preserving choice.
  Trade-off documented: the same human may appear as `User 3` in one repo and
  `User 7` in another; the mapping artifact is the join key, and it never
  leaves the operator's machine.
- **Pseudonym `Hash`** (opt-in): stable across repos, at the cost of
  brute-forceability (small candidate name/email sets can be hashed and
  compared) and cross-repo correlation. Documented as the convenience option,
  not the safe one (§8).
- Domain: `.invalid` (RFC 2606) — unresolvable by construction, and an
  unmistakable "this is synthetic" marker in any clone.
- **Injectivity audit (the new wrinkle):** while populating the ledger, the
  pass records `replacement → original-set`; if a *table row or host policy*
  maps two distinct originals to the same (new_name, new_email), that is
  reported as a `collision` entry in the redact report (not an error —
  merging identities is occasionally the goal, e.g. coalescing
  `Alice <a@work>` / `Alice <a@home>`; it must be *visible*, never silent).
  Built-in modes are injective by construction; the audit exists for
  `Table`/`Injected`.

Role handling: the same policy runs for all three roles by default; a
host `IdentPolicy` may treat roles differently (e.g. redact `Author`,
preserve `Committer`). There is deliberately no built-in role-splitting flag
in v1 — the trait is the extension point (N5-adjacent).

### 4.4 Timestamp modes

Applies to the `time` field of every ident the pass touches — and to every
commit/tag time when `time_mode != preserve`, even in `IdentMode::Preserve`
(time and identity redaction are independent axes; redacting names but not
dates is a legitimate half-measure and the flags reflect that).

| Mode | Rewrites to | Ordering | Intervals | tz |
|---|---|---|---|---|
| `preserve` (default) | untouched (raw bytes kept; identity-noop possible) | kept | kept | kept unless tz-redaction fires |
| `zero` | `0 +0000` for every commit/tag | destroyed (log falls back to topology) | destroyed | zeroed |
| `shift <secs>` | `epoch + secs` (i64 checked; overflow ⇒ `Error::TimestampOutOfRange`, §4.9) | preserved exactly | preserved exactly (leaks the interval fingerprint — documented) | zeroed unless `keep-tz` |
| `bucket <day\|week\|month>` | `floor(epoch, boundary)` in **UTC**, days are 86400-aligned, weeks Monday-aligned, months calendar-floored (deterministic, no DST/local-time logic — bucketing in a *kept* tz would re-leak the tz it hides) | coarse order kept; ties within a bucket | destroyed within bucket | zeroed |
| `fuzz <jitter-secs>` | `epoch + (H(seed, role, raw-when) mod (2*jitter+1)) − jitter` — pure function of the seed and the original raw bytes | *not* guaranteed monotone (documented) | approximately preserved (jitter-scale) | zeroed unless `keep-tz` |

Rules:

- **tz zeroing is the default for every mode except `preserve`+`keep-tz`**;
  `keep-tz` is honored only with `preserve`/`shift` (zero/bucket/fuzz ignore
  it rather than half-apply). Goal G3.
- `fuzz`'s `H` is a keyed non-crypto digest over `(seed_be, role_tag,
  original_raw_bytes)` — deterministic, allocation-light, and honest about
  what it is: obfuscation with a retained seed, not cryptography (N4, §8).
  The seed lives in the mapping artifact (§4.8) — losing it makes `fuzz`
  irreversible, which is the point.
- Epochs are `i64`; every arithmetic path is `checked_add`/`checked_sub` and
  overflow deterministically errors rather than wraps (a silently wrong date
  is worse than a failed run).
- Canonical raw regeneration (§4.2) applies in every non-`preserve` mode, so
  `raw` is always `"<epoch> +0000"`-shaped afterwards (property R7).
- Author and committer times use the same mode in v1 (split per-role time
  config is deferred with N5).

### 4.5 What this pass does not touch (and why, again)

- **Messages** (N1): sign-offs and mentions are the most common *real*
  identity leak in practice after idents themselves; they are also the one
  place where rewriting needs language-aware machinery (replacement lengths,
  quoted emails, trailers). Belongs to the message-rewrite builtin
  (plan-fast-export.md §7.4), which will consume redact's ledger as input —
  that is why the ledger keeps *original ident → replacement* and not just
  counts.
- **Ref names** (N2): `refs/heads/alice/big-refactor` defeats everything
  above. Renaming refs is a driver-level concern (affects `ref-map` and the
  reset targets) and ships separately; the CLI guide's checklist tells
  operators to rename refs (or export only `main`) before sharing.
- **Paths / blob contents** (N3): real on purpose.
- **`encoding` header**: passes through. `--reencode=yes` at export already
  normalized message bytes to UTF-8, so a non-UTF-8 `encoding` header is rare
  in driver-fed streams; when present it is a locale hint — documented
  residual (§8), not worth a special case.

### 4.6 State machine (v1)

```
            ┌────────────────────────────────────────────────────┐
 Blob ─────▶│ pass-through                                       │
 Commit ───▶│ ident ledger: (name,email) → replacement Ident     │──▶ events out
 Tag ──────▶│ collision ledger: replacement → originals          │
            │ time transform: mode × (seed, raw) → new Timestamp │
            └────────────────────────────────────────────────────┘
 finish(): nothing appended; report() carries totals, collision
 entries, and (bounded) mapping entries
```

Memory posture (plan-fast-export §5.6): both ledgers are `BTreeMap`s bounded
by *distinct idents* — realistically tens, pathologically thousands; the
strip registry's rationale applies verbatim. No blob payloads flow through
the pass, so there is nothing size-shaped to cap except the report listing
(`report_limit`, strip pattern). `reset()` restores fresh state (ledger
contents included — the strip pass's "verdicts are not cached across reset"
test has a direct analog here: the call-counting policy proves re-derivation).

### 4.7 Interaction with `remap` and `strip-blobs`

- **Ordering**: redact is a content pass — driver validation requires it
  before `remap` and after nothing in particular (it and `strip-blobs` are
  independent: strip decides *which ops exist*, redact decides *what the
  surviving commits' metadata says*). Canonical default spec when both are
  named explicitly: `strip-blobs,redact,remap`.
- **Hashes**: every commit whose author/committer/time changed gets a new
  hash; commits pinned by the policy (table hits that map to themselves,
  `preserve` on an untouched ident) keep theirs. `original-oid` lines are
  preserved verbatim, so remap's old-oid bookkeeping is complete; the
  rewritten-flag bookkeeping still rides the §5.5 note in
  plan-pass-driver-strip-blobs.md (remap v1 keys rewrittenness off
  `original-oid` presence / host flagging, so `commits_rewritten` may read
  low until the canonical-digest follow-up lands) — the driver's ref-map
  remains authoritative for what actually moved.
- **Ref tips**: remap emits trailing resets-to-mark at finish for rewritten
  lineages (plan-fast-export §7.5); redact adds nothing to that machinery.
- **Registration**: redact is *available but not default* — see Q1 (§8): the
  registry learns a `in_default()` factory attribute so the composed binary's
  implicit `--passes` stays `strip-blobs,remap` and redaction only ever runs
  when explicitly requested. Silently redacting on a bare `gfx --repo x.git`
  run would be the worst kind of surprise.

### 4.8 The mapping artifact — and its sensitivity

On a real run, the driver writes `<gitdir>/gfx/redact-map.txt`:

```
# gfx redact mapping — SENSITIVE: this file re-identifies the anonymized repo.
# Keep it out of the repository, out of backups you share, and out of git.
# style: ordinal  time-mode: shift(+31536000)  tz: zeroed  seed: 0x9E3779B9
User 1 <user1@example.invalid>   <-  Alice <alice@example.com>   [author+committer, 412 commits]
User 2 <user2@example.invalid>   <-  Bob <bob@example.org>       [tagger, 3 tags]
...
time-shift: every epoch +31536000; 17 commits kept original times (pinned rows)
```

Deterministic contents (same run config on clones ⇒ byte-identical file,
A6 pattern). The header *is* the sensitivity warning — the artifact is the
de-anonymization key for ordinal pseudonyms (which derive nothing from
input bytes, so the map is the only bridge back).

- `--dry-run` does **not** write the file; the report surfaces totals and the
  first `report_limit` mapping entries in memory so the operator can inspect
  before committing to a destructive run.
- The report's bounded listing rule (strip §5.3) applies: totals exact,
  listing capped (`map_report_limit`, default 1000).
- Future consumption: the message-rewrite pass reads this ledger to rewrite
  `Signed-off-by:` trailers consistently with ident redaction (N1) — the
  artifact format is therefore protocol between passes, not just operator
  convenience; its shape is pinned by a round-trip test (R9).

### 4.9 Edge cases (must-have fixture coverage)

| Case | Expected |
|---|---|
| Commit with no `author` line (fast-import inherits committer) | no ident synthesized; committer (if present) still redacted; D1 rewrite-only rule |
| Tag with no `tagger` (raw stream; driver's `--fake-missing-tagger` normally supplies one) | tag passes through unredacted; the fake `fake-missing-tagger` ident, when present, is mapped like any ident (ordinal pseudonym) — noted in the map |
| Empty name (`<a@b>`) or empty email (`Name <>`) | valid map key (bytes are just empty); pseudonymizer assigns an ordinal like any ident; table wildcards match |
| Non-UTF-8 name/email bytes | byte-exact key matching (`BString`); replacements are whatever bytes the row/policy supplies — no re-encoding |
| Negative epoch (pre-1970) | `shift` arithmetic on `i64`; canonical raw regeneration emits a leading `-` (pass-local formatter; core's `push_decimal` is unsigned — do not reuse it here) |
| `shift` overflow / underflow | `Error::TimestampOutOfRange` (new core variant, §5.2) — deterministic failure, never a wrap |
| Unparsable `when` raw (lenient-parse corner: `epoch == 0` + raw unparseable) | `preserve`: raw untouched (byte-identity); any other mode: regenerate from parsed fields (`0 +0000` post-zero) — the lenient corner cannot smuggle original bytes past a redacting mode (part of R4) |
| author and committer identical | one ledger entry; replacement byte-equal on both roles (cache guarantees) |
| Ident appears on multiple refs / roles | one ordinal, one map entry; commit/tag usage counts kept separately in the report |
| Table row maps two originals to one replacement | allowed, reported as a `collision` ledger entry (§4.3 audit) — never silent |
| Replacement contains original name/email bytes (operator error, e.g. row maps `Alice <a@x>` → `Alice(a@x) <x@y>`) | redact still runs; report entry flagged `suspicious-replacement` (deterministic substring check); the leak-scan property (R4) is what enforces the *test* side |
| `reset` events, notes (`N`) op, `refs/notes/*` commits | reset: untouched (no idents); notes ops: untouched (blobs); `refs/notes/*` commits: redacted like any commit |
| `data delim` messages | already normalized to raw `data <n>` at parse time (plan-fast-export §5.2); irrelevant to ident lines |
| SHA-256 stream | nothing ident-specific depends on the object format; fixture mirrors the strip suite |

### 4.10 Properties & tests

| # | Property |
|---|---|
| R1 | Empty policy with `keep-tz` (`preserve` + no rows) ⇒ byte-identical output (P4 analog), including untouched ledger bookkeeping; without `keep-tz` the empty policy still zeroes offsets (decision D3: always-on tz zeroing) |
| R2 | Determinism: two runs byte-identical; with an injected policy; `reset()` re-derives (call-counting policy, strip S3 analog) |
| R3 | Injectivity of built-in modes: distinct original idents ⇒ distinct replacements across a synthetic corpus; collision entries exist **only** where table/policy rows demand them |
| R4 | **Leak scan**: for a corpus with known idents/times, the serialized output contains none of the original name/email byte-strings, no original `±HHMM` offsets (non-`keep-tz`), and no original `epoch` raw bytes in `zero`/`bucket`/`fuzz` modes |
| R5 | Mapping closure: every ident in the output is in the ledger's image; every ledger entry round-trips through the artifact format (R9's parser) |
| R6 | Documented ordering semantics per mode: `shift`/`bucket` monotone-preserving (bucket: ties collapsed), `zero` collapses all, `fuzz` within jitter bounds — each fixture-tested |
| R7 | Canonical raw: every altered `Timestamp.raw` matches `^-?\d+ [+-]\d{4}$` (unaltered fields byte-identical) |
| R8 | End-to-end (driver): redact+remap on a fixture repo — import succeeds, `git fsck --strict` clean, `git log --format='%an %ae %ad'` shows no original identity/date, ref tips bound to the rewritten lineages |
| R9 | Report/artifact truthfulness: counts match the stream; `redact-map.txt` parses back (the future message-rewrite contract) and is byte-identical across two identical runs (A6 analog) |
| R10 | `cargo-mutants` on the ledger/mapping/time-transform logic; fuzz target: arbitrary streams through parse → redact → write without panic (strip_roundtrip analog with redact in the pipeline) |

Test kit reuse: plan-fast-export §5.5 contract tests via `test-kit`, strip
suite's structure (identity, edge table, driver e2e) as the template.

## 5. CLI surface

### 5.1 Flags (namespaced in composed binaries, flat in the helper binary)

```
gfx rewrite --passes strip-blobs,redact,remap \
    --redact.pseudonymize \
    --redact.time-mode shift --redact.time-shift 31536000 \
    [--redact.map <toml>] \
    [--redact.pseudonym-style ordinal|hash] \
    [--redact.time-mode preserve|zero|shift|bucket|fuzz] \
    [--redact.time-bucket day|week|month] \
    [--redact.time-jitter <seconds>] \
    [--redact.seed <n>] \
    [--redact.keep-tz]
```

Rules:

- `--redact.map` and `--redact.pseudonymize` are mutually exclusive
  (table wins *or* generate-all; mixing is ambiguity, not composition) —
  usage error when both given. Injected policies are library-level only,
  mirroring the strip pass's regex knob.
- `--redact.time-mode fuzz` requires `--redact.seed` (no default seed: a
  silently-fixed seed in the binary would be a shared constant across every
  user's repos); `--redact.seed` with non-fuzz modes is an error.
- `--redact.time-shift <secs>` / `--redact.time-jitter <secs>` are
  i64-checked decimal (suffixed forms `1d`/`2w` accepted — parsed to seconds
  by the same size-parser family; document `d`=86400, `w`=604800).
- **Unused-flag guard (safety rule):** any `--redact.*` flag given while
  `redact` is *not* named in `--passes` is a usage error. Silently ignoring
  redaction flags would leave the operator believing history was redacted —
  the one failure mode this pass must never have. (Generalizing the guard to
  all namespaced flags is a nice-to-have; redact is where it is mandatory.)
- `--redact.keep-tz` honored only with `preserve`/`shift` (§4.4).

### 5.2 Config file (`--config`)

```toml
[redact]
pseudonymize = true
time-mode = "shift"
time-shift = "365d"
# or table mode:
# map = "idents.toml"
```

Table rows live in the separate `--redact.map` file (TOML array-of-tables —
a whole `[[row]]` set inside `--config` would make the main config
sensitive; a side file keeps `--config` shareable). New error path:
unknown `[redact]` keys are usage errors (config.rs already validates
per-pass keys — redact's flag kinds plug in).

### 5.3 Core change: one new error variant

`gfx-core::Error::TimestampOutOfRange { token: String }` — input-derived,
deterministic, needed by §4.4's checked arithmetic (a Transform has no other
honest way to fail). It joins the taxonomy with its own Display arm and a
parser-side test that absurd-but-parseable raw epochs (e.g. `i64::MAX - 1`
then shifted) surface it from the pass, not from a panic.

### 5.4 Driver wiring

- `PassSpec::Redact(RedactConfig)` (feature `redact`), content stage before
  remap; `RunReport.passes` gains the redact summary line
  (`idents_redacted=N collisions=M times_altered=K tz_zeroed=…`).
- `write_artifacts` gains `redact-map.txt` (real runs only, §4.8).
- Registry: `PassFactory::in_default(&self) -> bool` (default `true`,
  `false` for redact) — `default_spec()` filters on it; composed binary's
  macro call-site unchanged (Q1).

## 6. Deferred (explicitly)

1. **Message-rewrite builtin** (N1) — consumes redact's ledger; sign-off and
   mention scrubbing with length-aware message surgery; the largest remaining
   leak and its own plan-sized piece.
2. **Ref-name redaction / full anonymize** (N2, N3) — refname + path token
   mapping (fast-export `--anonymize`'s "split into tokens at slash
   boundaries" is the prior art to match), blob-content replacement;
   `gfx-anonymize` as a separate pass so redact stays precise.
3. **Per-ref/per-path policies** (N5) — role-split time modes, ref-scoped
   tables.
4. **Reversal tooling** — a `gfx unredact` that replays a mapping artifact
   onto a redacted clone (useful for vetting before publishing); trivially
   a table-mode redact run in reverse once R9's round-trip format is stable.
5. **Signature preservation** — re-signing rewritten commits/tags (needs the
   content-digest mode B machinery, plan-fast-export §7.2 Mode B).

## 7. Milestones

| Milestone | Deliverable | Acceptance |
|---|---|---|
| **M0** Core redaction | `gfx-redact` crate: `Table` mode + `preserve` times, ledger + audit, `redact-map.txt` artifact in driver, R1/R2/R3/R5/R9 | identity + table fixtures green; artifact round-trip test |
| **M1** Time modes + pseudonyms | `zero`/`shift`/`bucket`/`fuzz`, tz zeroing, `Ordinal`/`Hash` pseudonyms, `Error::TimestampOutOfRange`, R4/R6/R7 | leak-scan property green; ordering fixtures |
| **M2** CLI + composition | flags (§5.1 rules incl. unused-flag guard), config table, driver `PassSpec::Redact`, injected `IdentPolicy` conformance, e2e fixture incl. sha256 mirror, R8 | end-to-end redact+remap on a real repo, `git log` fields verified redacted |
| **M3** Polish | fuzz targets (R10), mutants, `rewrite-cli.md` redact section + pre-sharing checklist, plan status flip | fuzz smoke green; docs complete |

## 8. Risks & open questions

### Risks

| Risk | Mitigation |
|---|---|
| Residual identity leaks via messages, ref names, paths, `encoding` (§4.5) | documented in CLI guide as a mandatory pre-sharing checklist; ledger format ready for the message pass |
| Mapping artifact itself leaks (it *is* the de-anonymization key) | never in the stream, never in dry-run, header warning, docs; artifact lives in `<gitdir>/gfx/` beside other local-only state |
| `fuzz`/`shift` reversible with side info (seed + intervals preserved) | documented semantics table (§4.4); `zero`/`bucket` offered as the strong options; seed never defaulted |
| Hash-style pseudonyms brute-forced from candidate lists | `Ordinal` default derives nothing from input bytes; `Hash` opt-in with warning |
| Silent flag-dropping makes users *believe* they redacted | unused-flag guard is a hard usage error for `--redact.*` (§5.1) |
| Host `IdentPolicy` non-determinism or collisions | documented pure-function contract; pass-side collision audit + report entries; determinism fixture with an injected policy (R2) |
| `--fake-missing-tagger` pseudo-ident gets pseudonymized into a "real-looking" user | documented; operators pin it to itself via map row if they want the marker visible |

### Resolved decisions (2026-09-12, all recommendations accepted)

- **D2 — default pass list (was Q1):** redact is registered in the composed
  binary's registry but *not* in the default `--passes`, via a new
  `PassFactory::in_default()` (default `true`, redact overrides `false`).
  `default_spec()` filters on it, so a bare `gfx --repo x.git` run never
  redacts; `--passes redact` remains discoverable.
- **D3 — default time mode (was Q2):** `preserve` + always-on tz zeroing.
  `--redact.time-mode zero` is the documented choice for sharing outside the
  org. Under `preserve`, tz zeroing fires unless `--redact.keep-tz` (then the
  run is a true byte-identity no-op when no ident rows hit).
- **D4 — pseudonym style (was Q3):** `Ordinal` is the default
  (`--redact.pseudonym-style hash` opts into cross-repo-stable digests).
- **D5 — pass name (was Q4):** `redact`; `anonymize` stays reserved for the
  future full-anonymization pass (N3).
