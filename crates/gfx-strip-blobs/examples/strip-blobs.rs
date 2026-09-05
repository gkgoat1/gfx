//! Helper binary for the `strip-blobs` pass (plan §4.2 decision D4):
//! the pass's CLI documentation, a usable single-purpose tool, and the
//! conformance vehicle for its flag surface (acceptance A7).
//!
//! Exposed flat here (single-pass helper): `--larger-than`, `--path-glob`,
//! `--content-signals`, ... — in a composed binary the same flags are
//! namespaced as `--strip-blobs.<flag>`.

gfx_cli::rewrite_binary! {
    binary: "gfx-strip-blobs",
    about: "retroactively strip large / generated blobs from a repository's history",
    passes: [gfx_cli::passes::strip_blobs_factory()],
}
