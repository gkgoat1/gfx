# Plan: `gfx pack` / `gfx unpack` — multistream archives of rewritten repositories

| Field    | Value |
|----------|-------|
| Status   | Implemented (M0–M5) |
| Scope    | New std driver crate `gfx-pack` + two `gfx` subcommands: fan-out export → passes → hash remap → zip (optionally encrypted), and the exact reverse |
| Depends  | plan-fast-export.md §5–§7 (architecture, builtins, remap), plan-pass-driver-strip-blobs.md §4 (driver, registry), plan-redact-idents.md (redact pass), rewrite-cli.md (user-facing pass surface) |
| Updated  | 2026-09-13 (M5 hardening — see [pack-cli.md](pack-cli.md) for the user-facing surface) |

---

## 1. Summary

One deliverable — a **multistream driver** that runs the existing single-repo
round as a fan-out/fan-in pair:

- **`gfx pack`** — point it at N repositories and one pass spec; it runs
  `git fast-export` on each, pushes every stream through the same pass
  pipeline (`redact`, `strip-blobs`, … with `remap` auto-appended last, as
  today), and writes a single **`.gfxpack` archive**: a zip containing one
  transformed stream per repo plus manifest, commit-maps, ref-maps, and
  reports. Optionally the whole archive is age-encrypted (`.gfxpack.age`).
- **`gfx unpack`** — the exact reverse: decrypt if needed, verify manifest
  and checksums, create N fresh repositories, `git fast-import` each stream,
  finalize each commit-map from fast-import's exported marks
  (`Remap::finalize_from_marks`), verify tips, and drop per-repo artifacts
  into each destination's `<gitdir>/gfx/`.

The defining constraint (D1) is that *multistream is fan-out/fan-in, never a
merge*: each repo gets an independent, self-contained stream with its own
marks namespace; the archive is the only coupling. The pass framework is
reused unchanged — a single-repo `gfx rewrite` invocation must lift to a
multistream `gfx pack` by changing only the repo arguments (D2).

Motivating use: producing a share-safe snapshot of a whole org's history —
redact idents/timestamps uniformly, strip generated blobs, rewrite hashes —
as one encrypted artifact a recipient can materialize back into real repos.

## 2. Goals and non-goals

### Goals

1. `gfx pack --repo a:pathA --repo b:pathB --passes redact,strip-blobs …`
   exports, transforms, and archives N repos in one invocation. Per-repo
   failures are isolated and reported; the archive is all-or-nothing (D7).
2. `gfx unpack --archive out.gfxpack` materializes every stream into a fresh
   repo and reproduces the full filter-repo-style artifact surface
   (`commit-map`, `ref-map`, report) *per repo*.
3. Byte-reproducible archives: identical inputs + config ⇒ identical zip
   bytes (normalized entry order and timestamps, no wall-clock unless asked
   for — D4).
4. Whole-archive age encryption as a post-zip step, both directions (D5).
5. Bounded-memory fan-out: streams are spooled to per-repo temp files; the
   zip is assembled single-threaded from spools in manifest order (D6).
6. End-to-end verification: per-stream SHA-256 in the manifest, and per-ref
   expected tips checked after import (D8).

### Non-goals

- **No merging** of repos into one history (no prefix/graft/subtree
  stitching, no cross-repo OID rewriting — e.g. submodule pointers are
  carried verbatim and stay dangling across repos).
- No incremental archive updates (append/remove entry). Archives are
  write-once, immutable.
- No new pass semantics: every stream-level behavior belongs to the existing
  builtins; this plan only adds fan-out plumbing.
- No pack-file writing on unpack — import stays delegated to
  `git fast-import`, per the workspace-wide rule.
- No streaming/random-access encryption format; decryption materializes the
  zip to a temp file first (D5).

## 3. Decisions

### D1 — Fan-out/fan-in, never a merge

Each repo is exported, transformed, and imported as a fully independent
fast-export stream: its own marks starting at 1, its own `original-oid`
space, its own commit-map. No event ever crosses repo boundaries. The
archive format is a container of N independent streams, not a multiplexed
wire — unpacking any single entry with plain `git fast-import` must work.

*Consequence:* repos may be packed/unpacked in parallel and in any order,
and a corrupt entry can only doom its own repo.

### D2 — One uniform pass spec, lifted verbatim from `gfx rewrite`

`--passes` and all namespaced pass flags (`--redact.map`,
`--strip-blobs.larger-than`, …) are exactly the `gfx rewrite` surface,
applied identically to every repo; `remap` is auto-appended last per stream
and pass-order validation is unchanged. `--config` TOML works as today.
Per-repo pass overrides are deliberately out of scope — uniformity is what
makes an archive auditable ("every repo in this file had exactly this done
to it", recorded in the manifest).

### D3 — Shared identity/time policy across the fan-out

Unlike the stream plumbing, the **redact policy is one instance for the
whole run**: a single seeded pseudonymizer and a single timestamp policy,
so the same person becomes `User-7` in *every* stream and `shift`/`fuzz`
offsets are consistent across repos. Without this, per-repo instances would
re-roll `User-1` independently and cross-repo identity correlation (the
useful kind) would break. `--per-repo-idents` opts out for maximal
unlinkability. The shared ident map is recorded once at archive level
(`maps/_idents`) — note this means the archive, not any single repo, is the
unit of identity disclosure.

### D4 — Archive format: zip + manifest, byte-reproducible

Layout (names are repo slugs from `--repo name:path`):

```
manifest.toml
streams/<name>.fi            # transformed fast-export stream
maps/<name>/commit-map       # old-oid → mark (pack-time side)
maps/<name>/ref-map
maps/_idents                 # shared redact ident map (D3), if redact ran
reports/<name>/report.txt    # per-repo pass report
```

- `manifest.toml` records: format version, the full pass spec + normalized
  flags (the audit record of D2), per-repo: name, stream entry path,
  SHA-256 of the *uncompressed* stream, event/commit counts, and per-ref
  expected post-rewrite tips as `oid → mark` pairs (D8).
- Reproducibility: entries written in manifest order, zip timestamps fixed
  to the DOS epoch (unless `--stamp-time`), no absolute source paths by
  default (`--record-source-paths` opts in; source hints land in
  `meta/source-hints.toml`).

### D5 — Encryption is whole-archive, post-zip age

`.gfxpack.age` = age(rage) over the complete `.gfxpack` file. Never
per-entry zip crypto: it leaks entry names/sizes and has weak interop.
Whole-file encryption hides everything, at the cost of decrypting to a temp
file before reading — accepted for v1. Flags: `--encrypt <recipient>`
(repeatable), `--encrypt-passphrase` (scrypt; secret from prompt or
`GFX_PACK_PASSPHRASE`, never argv). Decryption is auto-detected by the
`.age` suffix with identities from `--identity <file>`.

### D6 — Spool-then-assemble; assembly is single-threaded

Workers export → pipeline → spool one temp file per repo (bounding memory —
a deliberate deviation from `gfx rewrite`'s buffered rounds, since N repos
do not fit the in-memory posture). A coordinator then writes the zip from
spools in manifest order, so archive bytes are independent of completion
order. `--jobs N` (default: available parallelism) bounds the worker pool;
gfx core stays sans-IO and deterministic, threads only wrap subprocess and
file plumbing.

### D7 — Pack is all-or-nothing; unpack is per-repo fail-fast

Pack writes to `<out>.tmp` and renames on success — a failed repo fails the
run (no partial archive), with the failing repo/pass/stage in the error.
Unpack defaults to fail-fast but leaves already-imported repos in place
(their streams are independent per D1) and prints a resume hint;
`--keep-going` attempts every repo and reports a per-repo status table.

### D8 — The commit-map is finalized across the archive boundary

Pack has no import step, so each `commit-map` in the archive carries the
old-oid → mark side only. Unpack's `git fast-import --export-marks`
supplies the mark → new-oid side, `Remap::finalize_from_marks` completes
the map, and finalized artifacts are written into each *destination repo's*
`gfx/` dir — never back into the immutable archive. Unpack then asserts
each manifest ref tip's mark resolves to the imported tip, catching
corruption and nondeterminism beyond checksums.

## 4. CLI surface

```
gfx pack \
    --repo alpha:/srv/repos/alpha.git --repo beta:/srv/repos/beta.git \
    --passes redact,strip-blobs \
    --redact.map idents.toml --redact.time bucket:week \
    --strip-blobs.larger-than 1M \
    --out org-history.gfxpack \
    [--encrypt age1…] [--encrypt-passphrase] \
    [--jobs N] [--dry-run] [--record-source-paths] [--config file.toml]

gfx unpack \
    --archive org-history.gfxpack[.age] \
    [--identity key.txt] \
    [--dest-root ./out]                # default: ./<name> per repo
    [--repo alpha:./elsewhere/alpha]   # explicit overrides win
    [--verify-only] [--keep-going] [--force] [--dry-run]
```

- Repo names must be unique and slug-safe (`[A-Za-z0-9._-]+`); they become
  zip paths and default dest dirs. Collisions and invalid names are usage
  errors before anything is touched.
- `--dry-run` (pack): full export → passes → report, no archive written —
  the multistream form of the existing dry-run guarantee.
- `--verify-only` (unpack): manifest well-formedness, format version,
  checksums, and decryptability; no repo creation.

## 5. Safety model

- **Pack sources are read-only** — export never modifies a repo, so the
  fresh-clone check does not apply; a non-repo path is an error.
- **Unpack inherits the rewrite safety posture**: destination must not
  exist or must be an empty dir without `--force`; bare repos by default
  (`git init --bare`), `--worktree` opts into non-bare.
- Decrypted plaintext zip lives in a 0700 temp dir and is removed on
  success *and* on error (drop-guard, best-effort on kill).
- Secrets (passphrase, identities, the `_idents` map) are never echoed to
  logs; reports refer to repos by slug only.

## 6. Milestones

- **M0 — `gfx-pack` format crate (std).** Manifest serde model, zip
  writer/reader, per-stream SHA-256, canned-stream round-trip tests
  (pack bytes → read back → byte-equal streams). No git yet.
- **M1 — `gfx pack` driver.** Fan-out: per-repo export through the existing
  `gfx::driver` pipeline builder → spool → manifest → atomic zip.
  `--dry-run`, slug validation, fail-fast. Integration test: two small
  fixture repos → archive → entries verified.
- **M2 — `gfx unpack` driver.** Fan-in: verify (D8) → create repos →
  `fast-import --export-marks` → finalize maps → tip assertions →
  artifacts. `--verify-only`, `--keep-going`, `--dest-root`. Round-trip
  test: source repos → pack → unpack → `git fsck` clean + ref tips match
  the finalized maps.
- **M3 — Encryption.** age wrap/unwrap both directions, passphrase and
  recipient paths, temp-plaintext hygiene. Tests cover wrong-key and
  truncated-archive failures.
- **M4 — Parallelism + ergonomics.** `--jobs`, progress output, determinism
  check (`pack` twice → identical bytes), `--record-source-paths`.
- **M5 — Hardening.** Manifest parser fuzzing (it is the one
  attacker-controlled parse surface introduced here; the streams themselves
  route through the already-fuzzed gfx-core parser), property tests over
  randomized multi-repo shapes (empty repos, tag-only repos, detached tips,
  repos with zero commits after stripping).

## 7. Testing strategy

1. **Unit (M0):** manifest round-trip, slug validation, checksum mismatch
   detection, reproducibility (fixed timestamps, sorted entries).
2. **Integration:** fixture repos with known nasty shapes (octopus merges,
   annotated tags, symlinks, generated blobs) → pack with
   `redact,strip-blobs` → assert: stream entries parse with the strict
   gfx-core parser, `_idents` is consistent across streams (same source
   ident ⇒ same pseudonym in every repo), redaction leaked no original
   idents.
3. **Round-trip property:** pack → unpack → `fast-export` the result →
   re-imported history's ref tips equal the finalized commit-map new side;
   unpacking a second time yields identical OIDs (import determinism).
4. **Failure injection:** kill mid-pack ⇒ no archive, no tmp litter;
   corrupt one stream entry ⇒ checksum fails, `--verify-only` reports the
   repo, sibling repos still unpack under `--keep-going`.
