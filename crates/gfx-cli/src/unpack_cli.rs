//! `gfx unpack` subcommand (plan-multistream-pack.md §4): the reverse of
//! `gfx pack` — verify an archive and materialize every stream back into a
//! real repository. Takes no pass flags: the pipeline that produced the
//! archive is recorded in its manifest and is not re-run here.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use crate::args::{parse_argv, ArgSpec};
use crate::cli::{exit_code_for, EXIT_FAILURE, EXIT_OK};
use crate::error::CliError;
use gfx_pack::UnpackOptions;

/// Unpack-specific global flags.
fn unpack_globals() -> Vec<ArgSpec> {
    vec![
        ArgSpec::value("archive", None, "the .gfxpack archive to read"),
        ArgSpec::multi("repo", "per-repo destination override, as <name>:<path> (repeatable)"),
        ArgSpec::value("dest-root", None, "parent directory for default per-repo destinations (default: .)"),
        ArgSpec::flag("verify-only", "verify manifest and checksums only; create nothing"),
        ArgSpec::flag("dry-run", "alias for --verify-only"),
        ArgSpec::flag("keep-going", "attempt every repo even when some fail; report per-repo status"),
        ArgSpec::flag("force", "allow importing into an existing non-empty destination"),
        ArgSpec::flag("worktree", "create non-bare repositories (default: bare)"),
        ArgSpec::flag("help", "print this help and exit"),
    ]
}

const UNPACK_USAGE: &str = "gfx unpack — materialize a multistream archive back into repositories\n\n\
usage: gfx unpack --archive <file.gfxpack> [--dest-root <dir>] [--repo <name>:<path>]... \
[--verify-only] [--keep-going] [--force] [--worktree]\n\n\
flags:\n";

/// Parse and run `gfx unpack`; report text (and usage on `--help`) goes to
/// `out`, diagnostics to stderr. Returns the process exit code.
pub fn run_unpack_cli_to(out: &mut dyn Write, argv: impl IntoIterator<Item = OsString>) -> i32 {
    match try_run_unpack(out, argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gfx unpack: {e}");
            exit_code_for(&e)
        }
    }
}

fn try_run_unpack(out: &mut dyn Write, argv: impl IntoIterator<Item = OsString>) -> Result<i32, CliError> {
    let globals = unpack_globals();
    let specs: Vec<crate::args::CliArg> = globals
        .iter()
        .map(|s| crate::args::CliArg {
            key: s.flag.to_string(),
            spec: s.clone(),
        })
        .collect();
    let argv: Vec<OsString> = argv.into_iter().collect();
    let map = parse_argv(&specs, &argv)?;

    if map.flag("help") {
        write!(out, "{UNPACK_USAGE}").map_err(CliError::Io)?;
        for g in &globals {
            writeln!(out, "  --{:<28} {}", g.flag, g.help).map_err(CliError::Io)?;
        }
        return Ok(EXIT_OK);
    }

    let archive = map.value("archive").map(PathBuf::from).ok_or_else(|| {
        CliError::MissingValue {
            flag: "archive".into(),
        }
    })?;
    let mut repo_overrides = Vec::new();
    for raw in map.multi("repo") {
        let (name, path) = raw.split_once(':').ok_or_else(|| {
            CliError::FlagConflict(format!("--repo {raw:?}: want <name>:<path>"))
        })?;
        repo_overrides.push((name.to_string(), PathBuf::from(path)));
    }

    let report = gfx_pack::unpack(&UnpackOptions {
        archive,
        dest_root: map.value("dest-root").map(PathBuf::from),
        repo_overrides,
        verify_only: map.flag("verify-only") || map.flag("dry-run"),
        keep_going: map.flag("keep-going"),
        force: map.flag("force"),
        worktree: map.flag("worktree"),
    })?;

    write!(out, "{}", report.to_text()).map_err(CliError::Io)?;
    Ok(if report.ok() { EXIT_OK } else { EXIT_FAILURE })
}
