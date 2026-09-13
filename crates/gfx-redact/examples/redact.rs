gfx_cli::rewrite_binary! {
    binary: "redact",
    about: "redact commit metadata (idents + timestamps) from a repo's history",
    passes: [gfx_cli::passes::redact_factory(), gfx_cli::passes::remap_factory()],
}
