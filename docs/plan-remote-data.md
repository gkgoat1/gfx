# Plan: save & restore remote data across rewrites and packs

|          |                                                              |
|----------|--------------------------------------------------------------|
| Status   | Research complete; design ready for implementation            |
| Created  | 2026-09-14                                                   |
| Updated  | 2026-09-14                                                   |
| Depends on | [plan-pass-driver.md](plan-pass-driver.md), [plan-pack-v2.md](plan-pack-v2.md), [rewrite-cli.md](rewrite-cli.md) |

## Goal

"Remote data" — the repository-local configuration and refs that connect a
repo to its servers — must survive gfx's two destructive flows **when the
operator opts in**:

1. **In-repo transforms** (`gfx --repo …`): the rewrite mutates
   `refs/remotes/*` semantically (they get rewritten along with history and
   end up claiming the *rewritten* history is the remote's history — proven
   below). `.git/config` survives untouched, but there is no snapshot for
   audit or recovery, and no policy for the tracking refs.
2. **Pack create → unpack** (`gfx-pack`): unpack reconstitutes repos with a
   **fresh `git init`** (`unpack.rs:275`), so *all* remote configuration —
   remote URLs, push URLs, fetch refspecs, mirror flags, branch tracking —
   is silently lost. Only object data and refs travel.

The feature: opt-in **capture** of remote data before the destructive step
and opt-in **restore** after it, with tamper-evidence in packs and
fail-closed handling of URLs that carry credentials.

## Non-goals

- Saving working-tree state, hooks, `info/`, `gc` settings, or any other
  config not on the allowlist.
- Contacting remotes (no `git fetch`/`ls-remote`) — capture and restore are
  purely local.
- Restoring LFS objects, submodule working copies, or credentials
  themselves (helpers are excluded on purpose, see D2).

## Constraints

C1. **Credential safety.** Remote URLs can embed credentials
    (`https://user:token@host/…`). A pack archive may leave the machine —
    writing credentials into it must be fail-closed with an explicit
    operator override, consistent with the repo's secret-handling posture
    (cf. `docs/pre-sharing` checklist, redact pass).
C2. **No command injection.** Several config keys cause git to *execute
    commands* (`credential.helper`, `remote.*.uploadpack`,
    `remote.*.receivepack`, filter drivers). Restoring attacker-controlled
    values for these = arbitrary code execution on the next fetch. The
    capture format must be an explicit **allowlist** of non-executable keys.
C3. **Determinism (D6 of pack-v2).** Capture must be byte-stable for a
    given repo state so `--jobs N` vs `--jobs 1` archives stay identical.
C4. **Tamper-evidence.** A restored remote URL decides where later fetches
    and pushes go. Pack-carried remote data needs the same sha256 pinning
    streams get.
C5. **Format robustness.** Config values can contain newlines and other
    hostile bytes; line-based `git config --get-regexp` output is not
    parse-safe. Use NUL-terminated capture (`git config --list -z`).
C6. **Zip/tar parity.** Both archive backends expose the same
    member-name API (`contains`/`extract`); the design must hold for both.
C7. **No behavior change without opt-in.** Default flows are byte-for-byte
    what they are today.

## Research findings (empirical, this machine)

R1. **Config survives in-repo rewrites.** The driver pipes fast-export →
    passes → fast-import; none of that touches `.git/config`. Verified: a
    mirror clone's `remote.origin.url`, `remote.origin.mirror`,
    `remote.origin.fetch`, `branch.*.remote/merge`, `lfs.*` are all intact
    after a rewriting `gfx --passes blob-xform,remap` run.
R2. **`fast-export --all` includes `refs/remotes/*`** as `reset` records.
    gfx's pinned `EXPORT_FLAGS` use `--all` (`git.rs:87`), so
    remote-tracking refs ride the stream both in-repo and in packs.
R3. **In-repo rewrite rewrites remote-tracking refs along.** Verified:
    `refs/remotes/origin/main` at pre-rewrite tip `d1f8011` pointed at the
    rewritten tip `5eca042` after the rewrite. The repo then believes the
    rewritten history *is* origin's history: `git status` can claim
    "up to date with origin/main" while origin still has the old history.
    The next fetch force-updates the ref (self-healing), but until then the
    state is misleading — and a careless `push --force-with-lease` chain
    reasons from a lie.
R4. **Pack round-trip loses all remote data.** `unpack_repo` does
    `git init` + import; nothing carries `.git/config`. Verified by code
    read (unpack.rs:275 `git::init`) — and streams carry `refs/remotes/*`
    (R2), so an unpacked repo also inherits the *rewritten* tracking refs
    (R3's misleading state, baked in).
R5. **Sidecar-member precedent exists.** Redact maps travel as
    `maps/<repo>/redact-map.txt` archive members, extracted optionally via
    `zip.contains()` (unpack.rs:193). The manifest is deterministic
    hand-rolled TOML with per-repo `sha256` for streams; adding an optional
    per-repo key is a contained parser change.
R6. **Key catalog** (what `git config --local` can hold for remotes):
    - data keys (safe): `remote.<n>.url`, `.pushurl` (multi), `.fetch`
      (multi), `.mirror`, `.prune`, `.prunetags`, `.tagopt`, `.promisor`,
      `.partialclonefilter`, `.proxy`, `.serveroption` (multi),
      `.skipdefaultupdate`, `.followremotehead`;
      `branch.<n>.remote`, `.merge`, `.pushremote`, `.rebase`,
      `.description`; `lfs.url`, `lfs.<n>.url`.
    - executable keys (must NOT travel): `credential.helper`,
      `remote.<n>.uploadpack`, `remote.<n>.receivepack`, any `filter.*`,
      `diff.*.command`, etc.
    - everything else: out of scope (v1).
R7. **`-z` capture is the robust one.** `git config --list --local -z`
    emits `key\nvalue\0` entries; values keep embedded newlines verbatim.
    `git config --get-regexp` (newline-terminated) corrupts multi-line
    values. NUL bytes cannot appear in keys or values (git rejects them),
    so NUL framing is injective.

## Decision points

### D1 — What gets captured

**Options.** (a) whole `.git/config` file verbatim; (b) `remote.*` only;
(c) allowlist: the R6 "data keys" — `remote.*` data keys + branch tracking
keys + LFS endpoint URLs.

**Analysis.** (a) violates C2 (config carries executable keys) and C1
(may carry `credential.helper` with embedded helpers, user.name/email the
operator may not want shared). (b) misses branch tracking and LFS
endpoints — the things you actually need to resume work after unpacking.
(c) is fail-closed by construction.

**Decision: (c).** The allowlist is a code-level table, not config:
extension requires a code change and review (fail-closed).

### D2 — Executable keys never travel

Even with an allowlist, call it out as its own decision:
`credential.helper`, `uploadpack`, `receivepack`, and anything outside the
R6 data-key list are dropped at capture time, with a `skipped=N` count in
the report so the operator sees what did not travel. Rationale: an archive
(or a snapshot file copied with a repo) must never become a code-execution
vector when restored. This also means *credential helpers don't restore* —
documented; the operator's global config usually provides them.

### D3 — Credentials in URLs: fail-closed in packs, warn in-repo

A URL is treated as credential-bearing when its authority contains
userinfo **with a password** (`user:pass@`, any scheme) or **any**
userinfo on `http(s)` (bare-token URLs like `https://TOKEN@host` are a
common CI pattern). A bare username on `ssh://` (`ssh://git@host`) and
scp-like syntax (`git@host:path`) are identities, not credentials — not
flagged (implementation finding: flagging them fails closed on the most
common ssh URL shape, unacceptable noise). Audit rendering redacts any
userinfo regardless. When a captured URL is credential-bearing:

- **pack create**: error out and refuse to write the archive, unless
  `--pack.allow-credential-urls` is passed (recorded in `flags_audit`).
  The archive may be shared; embedding live tokens in it must be a
  deliberate, audited act. (Recommending `--pack.age-recipients` alongside
  in the error message.)
- **in-repo snapshot**: the snapshot lands in the repo's own
  `gfx/` artifacts dir — same trust domain as the config it came from —
  so warn (report line) but proceed.

### D4 — Capture format and storage

**Format:** raw `git config --list --local -z` bytes, filtered to the
allowlist, in original file order (stable per repo state ⇒ C3 holds
without sorting). NUL framing per R7.

**In-repo:** snapshot to the artifacts dir the driver already manages:
`<repo>/gfx/remote-state.bin` (exact `-z` bytes) plus a redacted
human-readable `remote-state.txt` (URLs shown with userinfo stripped) for
the audit trail.

**Pack:** archive member `remotes/<repo>.config` (mirroring the
`maps/<repo>/redact-map.txt` precedent), plus `remotes-sha256 = <hex>` on
the manifest's `[[repo]]` entry (C4 — same pinning streams get). Archives
without the member unpack exactly as today (parser: optional key).

### D5 — Restore semantics

**Unpack (`--unpack.restore-remotes`):** after import and ref fixups, for
each captured entry: `git config --unset-all <key>` (ignore missing) then
`git config --add <key> <value>` — preserving multi-valued key order.
Fresh `git init` repos have no remotes, so there is nothing to merge with;
the unset/add form keeps the operation idempotent if the same archive is
unpacked over an existing directory twice. Then **delete `refs/remotes/*`**
that rode the stream (R2/R4): on a fresh repo they are meaningless (they
name rewritten commits as "what the server has") and the first fetch
repopulates them. Report `restored=<keys>` and `remote-refs-dropped=N`.

**In-repo (`--restore-remotes`):** config already survived (R1), so
restore is *add-missing only*: keys present in the snapshot but absent
locally are added; present-but-different values are **reported as drift,
never overwritten** (fail-safe; the live repo's own choices win).

### D6 — Remote-tracking ref policy on in-repo rewrite

**Options.** (a) `rewrite` (today's behavior: refs/remotes ride the stream
and end up naming rewritten commits — R3's misleading state); (b) `drop`
(delete post-import; fetch repopulates); (c) `pin` (restore pre-rewrite
OIDs captured pre-export — keeps pre-rewrite objects reachable, which is
**wrong when the rewrite's purpose was redaction**, but useful for
forensic/disaster-recovery rewrites).

**Decision:** flag `--remote-refs <rewrite|drop|pin>`, default `rewrite`
(C7 — no behavior change without opt-in). `drop` is the documented
recommendation for any rewrite whose old objects should become
collectable; `pin` requires the same operator judgment as keeping a backup
and says so in its help text. (Default choice revisited before 1.0 — see
open questions.)

### D7 — Where the code lives

A new module `gfx::remotes` in the `gfx` crate (std; shells `git config`
via the existing `git::run` plumbing), split pure/impure:

- pure: allowlist table, `-z` frame parser/serializer, userinfo detector,
  drift planner (snapshot × live → ops), redacted renderer;
- impure: `capture(repo) -> RemoteState`, `restore(repo, &RemoteState)`.

The pack crates depend on `gfx` already, so both flows share one
implementation; the pure core is unit-testable without git. No new crate:
the surface is one module, two entry points.

### D8 — Reporting and audit

- in-repo driver prints a non-pass line after the pass summaries:
  `remotes: saved=<keys> restored=<keys> drift=<keys> remote-refs=<policy>:<n>`.
- pack manifest gains `save-remotes = true` in `[flags]` when enabled
  (flags table already records operator intent);
  `flags_audit` records `pack.save-remotes`, `pack.allow-credential-urls`,
  `unpack.restore-remotes` like all other flags.
- unpack report: per repo `remotes: restored=<keys> dropped-refs=N` or
  `remotes: none saved`.

## Design sketch

```text
in-repo:   export ──► (snapshot: gfx/remote-state.bin[+.txt])
            │ passes … import … ref fixups
            └─► (--restore-remotes: add-missing config keys, report drift)
                (--remote-refs: rewrite|drop|pin over refs/remotes/*)

pack:      validate ──► export spool ──► (capture remotes ──► member
            remotes/<repo>.config + manifest remotes-sha256) ──► transform
            ──► … ──► archive
unpack:    verify ──► init+import ──► (--unpack.restore-remotes:
            verify remotes-sha256, unset/add keys, drop refs/remotes/*)
```

## Milestones

Each ends green (`cargo test --workspace`) and commits separately.

1. **M0 — `gfx::remotes` module.** Allowlist table; `-z` parser/serializer
   (round-trip property: parse(serialize(x)) == x for arbitrary values
   incl. newlines, quotes, `=`); userinfo detection (incl. `user@host`
   without password, IPv6 literals, missing scheme); drift planner;
   redacted renderer. Capture/restore against temp repos.
   *Tests:* unit for all pure pieces; capture/restore round-trip via
   `git config`; executable-key exclusion (`credential.helper` present in
   config, absent from capture, counted skipped).
2. **M1 — pack create.** `--pack.save-remotes` flag → per-repo capture at
   export time → `remotes/<repo>.config` member + `remotes-sha256`
   manifest key; fail-closed credential guard + `--pack.allow-credential-urls`;
   `[flags]` and `flags_audit` entries. *Tests:* member present and
   byte-stable across `--jobs 1` vs `--jobs 4` (extends the existing
   determinism test); guard refuses credential URLs without the override;
   archives without the flag are byte-identical to today (C7).
3. **M2 — unpack restore.** `--unpack.restore-remotes`: hash verify →
   unset/add apply → drop `refs/remotes/*`; absent member ⇒ `none saved`,
   not an error. *Tests:* round-trip — mirror-source repo with url,
   pushurl, multi-value fetch, mirror flag, branch tracking → pack →
   unpack → `git config --local -z` matches the allowlisted snapshot
   exactly and `for-each-ref refs/remotes` is empty; tampered member ⇒
   Checksum error; executable keys that were hand-injected into an archive
   member are rejected at restore (defense in depth: restore re-filters
   through the allowlist, never trusting the member).
4. **M3 — in-repo driver.** `--save-remotes` (snapshot to `gfx/`
   artifacts), `--restore-remotes` (add-missing + drift report),
   `--remote-refs <rewrite|drop|pin>` (default `rewrite`).
   *Tests:* mirror clone with tracking refs → rewrite →
   `drop` leaves `refs/remotes` empty and fsck-clean with old objects
   unreachable; `pin` restores pre-rewrite OIDs (and the report warns they
   pin pre-rewrite objects); `rewrite` is today's bytes (C7); drift
   detection when config changed between save and restore.
5. **M4 — docs & hardening.** rewrite-cli.md flag tables + a "Remote data"
   section (what survives by default, what the flags do, credential
   guidance); pack docs; pre-sharing checklist gains "saved remotes may
   carry URLs — review `remotes/*` members before sharing"; zip-backend
   parity test; this plan → Implemented.

## Risks

- **Allowlist rot.** New git versions add `remote.*` keys; the allowlist
  ages. Mitigation: `skipped=N` reporting makes omissions visible; the
  table is one reviewed location.
- **False comfort from restore.** Restored URLs may be dead (server moved)
  — restore never validates reachability (non-goal); documented.
- **`pin` misuse.** `--remote-refs pin` after a redaction rewrite keeps
  the redacted content reachable. Mitigation: help text + report warning
  naming exactly this; redact docs cross-reference.
- **Manifest parser churn.** `remotes-sha256` is optional; older gfx
  versions reading newer manifests may reject unknown keys — acceptable
  (manifest is versioned internally; archives are produced/consumed by the
  same release in practice).

## Deferred

- Capturing `submodule.*` config (active submodules, URL overrides) —
  `.gitmodules` content travels in trees already; the config-side cache is
  rebuildable with `git submodule init`.
- `lfs.*` beyond endpoint URLs (`locksverify`, transfer customizations).
- A standalone `gfx remotes export|import` subcommand for ad-hoc snapshot
  management (the in-repo flags cover the destructive-flow need).
- Server-side reachability validation on restore.
- Default-flip of `--remote-refs` from `rewrite` to `drop` (1.0 decision).

## Open questions

1. Should `--unpack.restore-remotes` also re-add `branch.*` tracking for
   branches that don't exist in the unpacked repo (e.g. stripped during
   transform)? Current design: apply verbatim (harmless noise); pruning to
   existing branches is friendlier but hides intent.
2. Is `drop` the right `--remote-refs` default for 1.0? It is the
   semantically honest post-rewrite state, but changes long-standing
   behavior.
3. Should pack capture include `remote.<n>.promisor`/partial-clone filters
   (captured today) when the pack itself may change object availability?
   Leaning: capture verbatim; the operator opted into saving server
   relationships.

## References

- `crates/gfx/src/driver.rs` (in-repo rewrite rounds, artifacts dir)
- `crates/gfx/src/git.rs` (`EXPORT_FLAGS` — `--all`; `git::run` plumbing)
- `crates/gfx-pack/src/pack.rs` / `unpack.rs` (fresh-init reconstitution,
  `maps/<repo>/redact-map.txt` sidecar precedent)
- `crates/gfx-pack/src/manifest.rs` (deterministic TOML, per-repo sha256)
- `git-config(1)` (`--list -z` framing), `git-fast-export(1)` (`--all`
  ref coverage), `git-fetch(1)` (remote-tracking ref semantics)
