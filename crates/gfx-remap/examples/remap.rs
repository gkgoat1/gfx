//! Helper binary for the `remap` pass (plan §4.2 decision D4).

gfx_cli::rewrite_binary! {
    binary: "gfx-remap",
    about: "rewrite a repository while tracking the old→new commit map",
    passes: [gfx_cli::passes::remap_factory()],
}
