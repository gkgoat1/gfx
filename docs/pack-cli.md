# `gfx pack` / `gfx unpack` — multistream archives

`gfx pack` runs the [`gfx rewrite`](rewrite-cli.md) pass pipeline over *N*
repositories at once and combines the results into a single deterministic
`.gfxpack` archive (optionally age-encrypted). `gfx unpack` reverses it:
verify, import into fresh repositories, and finalize every commit map.

Design + rationale: [`plan-multistream-pack.md`](plan-multistream-pack.md)
(decisions D1–D8). This file is the user-facing surface.

## Model (D1)

Multistream is **fan-out/fan-in, never a merge**: each repository is
exported, transformed, and archived as an independent, self-contained
fast-export stream (its own marks namespace). Any entry can be extracted
with plain `unzip` and imported with plain `git fast-import` — the archive
adds manifest, checksums, maps, and reports, not a new wire format.

## `gfx pack`

```sh
gfx pack \
    --repo alpha:/srv/repos/alpha.git --repo beta:/srv/repos/beta.git \
    --passes redact,strip-blobs \
    --redact.pseudonymize \
    --strip-blobs.larger-than 1M \
    --out org-history.gfxpack
```

- `--repo <name>:<path>` (repeatable, at least one). The name is a slug
  (`[A-Za-z0-9._-]+`) used for zip paths and default unpack destinations.
  Sources are **read-only** — pack never modifies them.
- `--passes` and every namespaced pass flag are exactly the `gfx rewrite`
  surface, applied uniformly to every repo (D2); `remap` is auto-appended
  last. `gfx pack --help` lists the full registry.
- `--dry-run` runs export → passes → report and writes nothing.
- `--record-source-paths` embeds `meta/source-hints.toml`; by default the
  archive contains no host paths (D4).

Determinism (D4): identical inputs + flags ⇒ identical archive bytes
(fixed entry order, DOS-epoch zip timestamps, no clocks).

### Shared identities (D3)

With `--redact.pseudonymize` (ordinal), the ordinal space is **shared
across the whole fan-out**: the same source ident becomes the same
`User N` in every stream, deterministically in repo order. The merged
mapping lands in `maps/_idents`; per-repo slices in
`maps/<name>/redact-map.txt`. Both re-identify the redacted history —
treat them as secrets. (`Hash` pseudonyms are digest-derived and need no
sharing.)

## Archive layout (D4)

```
manifest.toml            # passes + flags audit, per-repo sha256/size/ref-tips
streams/<name>.fi        # transformed fast-export stream
maps/<name>/commit-map   # old-oid → new-oid ('-' until unpack finalizes)
maps/<name>/ref-map
maps/<name>/redact-map.txt
maps/_idents             # merged redact map, if redact ran
reports/<name>/report.txt
```

## `gfx unpack` (M2)

Reverses the pack: manifest + checksum verification (`--verify-only`),
fresh bare repos (`git init --bare`), `git fast-import` per stream,
commit-map finalization from the import's marks, ref-tip assertions
against the manifest (D8), and per-repo artifacts under
`<gitdir>/gfx/`.
