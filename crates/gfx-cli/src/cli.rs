



//! The generated-`main` entry point: parse args → resolve passes → drive
//! the round → print the report. [`crate::rewrite_binary!`] is a thin wrap
//! over [`run_rewrite_cli_to`]; tests call the function directly (A7).


extern crate std;

use std::ffi::OsString;
use std::io::Write;

use crate::args::{parse_argv, ArgMap, ArgSpec};
use crate::error::CliError;
use crate::registry::PassRegistry;
use gfx::driver::{PassDriver, Sink, Source};

/// Global flags every generated binary accepts.
pub fn global_args() -> Vec<ArgSpec> {
    vec![
        ArgSpec::value("repo", Some("."), "repository to rewrite"),
        ArgSpec::value(
            "in",
            None,
            "read the fast-export stream from this file instead of exporting --repo \
             (plan-stream-files.md; combine with --repo to import, with --out to filter)",
        ),
        ArgSpec::value(
            "out",
            None,
            "write the transformed stream to this file instead of importing \
             (combine with --repo to export, with --in to filter)",
        ),
        ArgSpec::value(
            "artifacts",
            None,
            "artifact directory for stream sinks (default <out>.gfx/; meaningless with a repo sink)",
        ),
        ArgSpec::flag("force", "override the fresh-clone safety check"),
        ArgSpec::flag(
            "save-remotes",
            "snapshot the repo's allowlisted remote data (URLs, fetch specs, branch \
             tracking) to gfx/remote-state.{bin,txt} before rewriting (plan-remote-data.md)",
        ),
        ArgSpec::flag(
            "restore-remotes",
            "after the rewrite, re-add any remote-data keys that went missing and report \
             drift (normally a no-op: the rewrite never touches config)",
        ),
        ArgSpec::value(
            "remote-refs",
            Some("rewrite"),
            "refs/remotes/* policy after the rewrite: rewrite (default, status quo), \
             drop (delete; next fetch repopulates), pin (restore pre-rewrite OIDs — \
             keeps pre-rewrite objects reachable; hostile to redaction)",
        ),
        ArgSpec::flag("dry-run", "export, run passes, report — no import, no ref changes"),
        ArgSpec::value(
            "passes",
            None,
            "comma-separated pass names, pipeline order (default: registry order)",
        ),
        ArgSpec::value(
            "config",
            None,
            "TOML config file with pass flag defaults (CLI flags override)",
        ),
        ArgSpec::flag("help", "print this help and exit"),
    ]
}

/// Outcome of a CLI run: process exit code.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;

/// Parse and run; report text (and usage on `--help`) goes to `out`,
/// diagnostics to stderr. Returns the process exit code.
pub fn run_rewrite_cli_to(
    out: &mut dyn Write,
    binary: &str,
    about: &str,
    factories: Vec<Box<dyn PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> i32 {
    match try_run(out, binary, about, factories, argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{binary}: {e}");
            exit_code_for(&e)
        }
    }
}

/// Usage errors (exit 2) vs. failures (exit 1), shared by the `rewrite`,
/// `pack`, and `unpack` CLI surfaces.
pub(crate) fn exit_code_for(e: &CliError) -> i32 {
    match e {
        CliError::UnknownFlag { .. }
        | CliError::AmbiguousFlag { .. }
        | CliError::MissingValue { .. }
        | CliError::BadSize { .. }
        | CliError::UnexpectedPositional(_)
        | CliError::UnknownPass { .. }
        | CliError::PassOrder(_)
        | CliError::BadConfig { .. }
        | CliError::FlagConflict(_) => EXIT_USAGE,
        // Endpoint validation failures are usage errors (C3).
        CliError::Driver(gfx::driver::DriverError::Endpoint(_)) => EXIT_USAGE,
        CliError::Pack(gfx_pack::PackError::Usage(_)) => EXIT_USAGE,
        _ => EXIT_FAILURE,
    }
}

/// Resolve `--passes` against the registry, then validate — the redact
/// unused-flag guard (plan-redact-idents.md §5.1) and the ordering contract
/// (remap last, at most once) — *before* any repository is touched (A4).
/// Shared by the rewrite and pack drivers.
pub fn resolve_passes_checked(
    registry: &PassRegistry,
    map: &crate::args::ArgMap,
) -> Result<Vec<gfx::driver::PassSpec>, CliError> {
    let passes_spec = map
        .value("passes")
        .map(str::to_string)
        .unwrap_or_else(|| registry.default_spec());
    let passes = registry.resolve(&passes_spec, map)?;

    // Unused-flag guard: pass flags given for a pass not named in --passes
    // are a usage error — silently ignoring them would leave the operator
    // believing history was redacted.
    for key in map.keys().map(|k| k.to_string()).collect::<Vec<_>>() {
        if key.starts_with("redact.") && !passes.iter().any(|p| p.name() == "redact") {
            return Err(CliError::FlagConflict(format!(
                "--{key} given but the redact pass is not in --passes; redaction must never be silently skipped"
            )));
        }
        if key.starts_with("blob-xform.")
            && !passes.iter().any(|p| p.name() == "blob-xform")
        {
            return Err(CliError::FlagConflict(format!(
                "--{key} given but the blob-xform pass is not in --passes; content rewriting must never be silently skipped"
            )));
        }
        if key.starts_with("enforce-ignore.")
            && !passes.iter().any(|p| p.name() == "enforce-ignore")
        {
            return Err(CliError::FlagConflict(format!(
                "--{key} given but the enforce-ignore pass is not in --passes; ignored-path enforcement must never be silently skipped"
            )));
        }
    }

    let mut remap_seen = false;
    for (i, p) in passes.iter().enumerate() {
        if p.is_remap() {
            if remap_seen {
                return Err(CliError::PassOrder("remap named more than once".into()));
            }
            if i + 1 != passes.len() {
                return Err(CliError::PassOrder(
                    "remap must be the last pass (content passes must precede it)".into(),
                ));
            }
            remap_seen = true;
        }
    }
    Ok(passes)
}

/// Resolve `--repo`/`--in`/`--out` into driver endpoints
/// (plan-stream-files.md D1). All nonsensical combinations are usage
/// errors here, before any file or repository is touched (C3):
///
/// | flags               | mode          |
/// |---------------------|---------------|
/// | `--repo R`          | repo → repo   |
/// | `--repo R --out S`  | repo → file   |
/// | `--in S --repo R`   | file → repo   |
/// | `--in S1 --out S2`  | file → file   |
/// | `--in` / `--out` alone | usage error |
fn build_driver(map: &ArgMap) -> Result<PassDriver, CliError> {
    let repo = map.value("repo");
    let in_path = map.value("in");
    let out_path = map.value("out");
    // `--repo` counts as given only when the user actually passed it (the
    // ArgMap fills its "." default otherwise).
    let repo_given = map.flag("repo");

    // Mode validation (usage errors, exit 2).
    if in_path.is_some() && out_path.is_none() && !repo_given {
        return Err(CliError::FlagConflict(
            "--in alone is ambiguous: pass --repo <dest> to import the stream, or --out <file> to filter it"
                .into(),
        ));
    }
    if out_path.is_some() && in_path.is_none() && !repo_given {
        return Err(CliError::FlagConflict(
            "--out alone is ambiguous: pass --repo <src> to export it, or --in <file> to filter a stream"
                .into(),
        ));
    }
    if let (Some(a), Some(b)) = (in_path, out_path) {
        if a == b {
            return Err(CliError::FlagConflict(
                "--in and --out name the same file".into(),
            ));
        }
    }

    let mut driver = match (in_path, out_path) {
        (None, None) => PassDriver::new(std::path::Path::new(repo.unwrap_or(".")))?,
        (None, Some(o)) => PassDriver::with_endpoints(
            Source::Repo(std::path::PathBuf::from(repo.unwrap_or("."))),
            Sink::Stream(std::path::PathBuf::from(o)),
        )?,
        (Some(i), None) => PassDriver::with_endpoints(
            Source::Stream(std::path::PathBuf::from(i)),
            Sink::Repo(std::path::PathBuf::from(repo.unwrap_or("."))),
        )?,
        (Some(i), Some(o)) => PassDriver::with_endpoints(
            Source::Stream(std::path::PathBuf::from(i)),
            Sink::Stream(std::path::PathBuf::from(o)),
        )?,
    };
    if let Some(dir) = map.value("artifacts") {
        driver = driver.with_artifacts_dir(std::path::PathBuf::from(dir))?;
    }
    Ok(driver)
}

fn try_run(
    out: &mut dyn Write,
    binary: &str,
    about: &str,
    factories: Vec<Box<dyn PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<i32, CliError> {
    let registry = PassRegistry::new(factories)?;
    let globals = global_args();
    let specs = registry.all_args(&globals);
    let argv: Vec<OsString> = argv.into_iter().collect();

    let mut map = parse_argv(&specs, &argv)?;

    if map.flag("help") {
        write!(out, "{}", registry.usage(binary, about, &globals))
            .map_err(CliError::Io)?;
        return Ok(EXIT_OK);
    }

    if let Some(cfg_path) = map.value("config").map(str::to_string) {
        crate::config::apply_config_file(&registry, std::path::Path::new(&cfg_path), &mut map)?;
    }

    let passes = resolve_passes_checked(&registry, &map)?;

    let remote_refs = gfx::driver::RemoteRefsPolicy::parse(map.value("remote-refs").unwrap_or("rewrite"))
        .ok_or_else(|| {
            CliError::FlagConflict(format!(
                "bad --remote-refs {:?} (want rewrite|drop|pin)",
                map.value("remote-refs").unwrap_or("")
            ))
        })?;
    let mut driver = build_driver(&map)?
        .with_passes(passes)?
        .force(map.flag("force"))
        .with_remote_data(
            map.flag("save-remotes"),
            map.flag("restore-remotes"),
            remote_refs,
        );

    let report = if map.flag("dry-run") {
        driver.dry_run()?
    } else {
        driver.run()?
    };

    write!(out, "{}", report.to_text()).map_err(CliError::Io)?;
    if let Some(dir) = &report.artifacts_dir {
        writeln!(out, "artifacts: {}", dir.display()).map_err(CliError::Io)?;
    }
    Ok(EXIT_OK)
}

use crate::registry::PassFactory;
