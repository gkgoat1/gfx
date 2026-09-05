gfx_cli::rewrite_binary! {
    binary: "gfx",
    about: "git filter-repo-style history rewriter built on the gfx pass driver",
    passes: [gfx_cli::passes::strip_blobs_factory(), gfx_cli::passes::remap_factory()],
}
