//! The default `gfx` binary: all compiled-in passes, plus the multistream
//! subcommands (plan-multistream-pack.md). Dispatch: a leading `pack` (and
//! later `unpack`) routes to the archive driver; anything else is the
//! filter-repo-style rewrite surface, unchanged.

fn factories() -> Vec<Box<dyn gfx_cli::PassFactory>> {
    vec![
        Box::new(gfx_cli::passes::strip_blobs_factory()),
        Box::new(gfx_cli::passes::redact_factory()),
        Box::new(gfx_cli::passes::blob_xform_factory()),
        Box::new(gfx_cli::passes::remap_factory()),
    ]
}

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let sub = argv.first().map(|a| a.to_string_lossy().into_owned());
    let code = match sub.as_deref() {
        Some("pack") => gfx_cli::run_pack_cli_to(
            &mut std::io::stdout(),
            "pack repositories into one multistream archive",
            factories(),
            argv.into_iter().skip(1),
        ),
        Some("unpack") => gfx_cli::run_unpack_cli_to(&mut std::io::stdout(), argv.into_iter().skip(1)),
        _ => gfx_cli::run_rewrite_cli_to(
            &mut std::io::stdout(),
            "gfx",
            "git filter-repo-style history rewriter built on the gfx pass driver",
            factories(),
            argv,
        ),
    };
    std::process::exit(code);
}
