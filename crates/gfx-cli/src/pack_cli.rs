//! `gfx pack` subcommand (plan-multistream-pack.md §4): fan-out N
//! repositories through one uniform pass pipeline into a single archive.
//!
//! The pass-flag surface is lifted verbatim from `gfx rewrite` (decision
//! D2): the registry resolves `--passes` and every namespaced pass flag the
//! same way, and the same ordering contract and redact unused-flag guard
//! apply (`cli::resolve_passes_checked`). Pack-only globals live here.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use crate::args::{parse_argv, ArgMap, ArgSpec};
use crate::cli::{exit_code_for, resolve_passes_checked, EXIT_OK};
use crate::error::CliError;
use crate::registry::PassRegistry;
use gfx_pack::{PackOptions, PackRepo};

/// Pack-specific global flags; pass flags come from the registry.
fn pack_globals() -> Vec<ArgSpec> {
    vec![
        ArgSpec::multi("repo", "repository to pack, as <name>:<path> (repeatable, at least one)"),
        ArgSpec::value("out", None, "archive destination (.gfxpack); required unless --dry-run"),
        ArgSpec::value("passes", None, "comma-separated pass names, pipeline order (default: registry order)"),
        ArgSpec::flag("dry-run", "export, run passes, report — no archive written"),
        ArgSpec::value("config", None, "TOML config file with pass flag defaults (CLI flags override)"),
        ArgSpec::flag("record-source-paths", "record original source paths in meta/source-hints.toml"),
        ArgSpec::flag("help", "print this help and exit"),
    ]
}

const PACK_SYNOPSIS: &str = "usage: gfx pack --repo <name>:<path> [--repo <name>:<path>]... \
    [--out <archive.gfxpack>] [--passes <spec>] [--dry-run] [--record-source-paths] \
    [--config <file>] [--pass.<flag> <value>]...";

/// Parse and run `gfx pack`; report text (and usage on `--help`) goes to
/// `out`, diagnostics to stderr. Returns the process exit code.
pub fn run_pack_cli_to(
    out: &mut dyn Write,
    about: &str,
    factories: Vec<Box<dyn crate::registry::PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> i32 {
    match try_run_pack(out, about, factories, argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gfx pack: {e}");
            exit_code_for(&e)
        }
    }
}

fn try_run_pack(
    out: &mut dyn Write,
    about: &str,
    factories: Vec<Box<dyn crate::registry::PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<i32, CliError> {
    let registry = PassRegistry::new(factories)?;
    let globals = pack_globals();
    let specs = registry.all_args(&globals);
    let argv: Vec<OsString> = argv.into_iter().collect();

    let mut map = parse_argv(&specs, &argv)?;

    if map.flag("help") {
        write!(
            out,
            "{}",
            registry.usage_with_synopsis(&format!("gfx pack — {about}"), PACK_SYNOPSIS, &globals)
        )
        .map_err(CliError::Io)?;
        return Ok(EXIT_OK);
    }

    if let Some(cfg_path) = map.value("config").map(str::to_string) {
        crate::config::apply_config_file(&registry, std::path::Path::new(&cfg_path), &mut map)?;
    }

    // Pass validation happens before any repository is touched (A4).
    let passes = resolve_passes_checked(&registry, &map)?;

    let mut repos = Vec::new();
    for raw in map.multi("repo") {
        let (name, path) = raw.split_once(':').ok_or_else(|| {
            CliError::FlagConflict(format!(
                "--repo {raw:?}: want <name>:<path> (e.g. alpha:/srv/repos/alpha.git)"
            ))
        })?;
        repos.push(PackRepo {
            name: name.to_string(),
            path: PathBuf::from(path),
        });
    }

    let dry_run = map.flag("dry-run");
    let out_path = map.value("out").map(PathBuf::from);
    if !dry_run && out_path.is_none() {
        return Err(CliError::FlagConflict(
            "--out is required unless --dry-run".into(),
        ));
    }

    let report = gfx_pack::pack(&PackOptions {
        repos,
        passes,
        flags_audit: flags_audit(&map),
        out: out_path.unwrap_or_default(),
        dry_run,
        record_source_paths: map.flag("record-source-paths"),
    })?;

    write!(out, "{}", report.to_text()).map_err(CliError::Io)?;
    if let Some(archive) = &report.archive {
        writeln!(out, "archive: {}", archive.display()).map_err(CliError::Io)?;
    }
    Ok(EXIT_OK)
}

/// The D2 audit record persisted in the manifest: every explicitly-set flag
/// that shaped the run, namespaced, sorted. Multi-value flags are joined
/// with commas. Host paths (`repo`, `out`) are excluded — the archive must
/// not leak the pack host's layout unless `--record-source-paths` (D4).
fn flags_audit(map: &ArgMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for key in map.keys() {
        // `present` is exactly "explicitly set": defaults fill `values`
        // without marking it (see `parse_argv`).
        if !map.flag(key) || matches!(key, "config" | "help" | "repo" | "out") {
            continue;
        }
        let multi = map.multi(key);
        let value = if !multi.is_empty() {
            multi.join(",")
        } else {
            "true".to_string()
        };
        out.insert(key.to_string(), value);
    }
    out
}
