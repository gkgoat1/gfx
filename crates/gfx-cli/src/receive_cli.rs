//! `gfx receive` subcommand (plan-transfer.md): fetch a `.gfxpack` archive
//! with a transfer tool (wormhole/sendme) into a temporary directory, then
//! materialize it via the exact `gfx unpack` pipeline (D2). Every flag this
//! module does not own is forwarded verbatim to the unpack CLI.

use std::ffi::OsString;
use std::io::Write;

use crate::cli::{exit_code_for, EXIT_FAILURE, EXIT_OK};
use crate::error::CliError;
use crate::transfer::{extract_transfer_args, receive_argv, resolve_transport, TempDir};
use crate::unpack_cli::run_unpack_cli_to;

const RECEIVE_USAGE: &str = "gfx receive — fetch a transferred archive and materialize its repositories\n\n\
usage: gfx receive <code> [--via wormhole|sendme|auto] [unpack flags...]\n\n\
transfer flags:\n\
  <code>      the transfer code (wormhole) or ticket (sendme) the sender printed\n\
  --via       transfer tool: wormhole (default when installed), sendme, or auto\n\n\
All other flags are forwarded to `gfx unpack` (e.g. --dest-root, --force,\n\
--worktree, --restore-remotes, --identity). The archive lands in a temporary\n\
directory and is deleted after unpack.\n";

/// Parse and run `gfx receive`. Returns the process exit code.
pub fn run_receive_cli_to(out: &mut dyn Write, argv: impl IntoIterator<Item = OsString>) -> i32 {
    match try_run_receive(out, argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gfx receive: {e}");
            exit_code_for(&e)
        }
    }
}

fn try_run_receive(out: &mut dyn Write, argv: impl IntoIterator<Item = OsString>) -> Result<i32, CliError> {
    let args = extract_transfer_args(argv.into_iter().collect())?;
    if args.help {
        write!(out, "{RECEIVE_USAGE}")?;
        return Ok(EXIT_OK);
    }
    if args.code.is_some() {
        return Err(CliError::FlagConflict(
            "gfx receive takes the code positionally: gfx receive <code>".to_string(),
        ));
    }
    let code = match args.positionals.as_slice() {
        [code] => code.clone(),
        [] => {
            return Err(CliError::FlagConflict(
                "gfx receive needs the transfer code the sender printed: gfx receive <code>"
                    .to_string(),
            ))
        }
        extra => {
            return Err(CliError::UnexpectedPositional(extra[1].clone()));
        }
    };
    let forwarded = args.forwarded;
    if forwarded.iter().any(|a| {
        let s = a.to_string_lossy();
        s == "--archive" || s.starts_with("--archive=")
    }) {
        return Err(CliError::FlagConflict(
            "gfx receive chooses the archive path; drop --archive".to_string(),
        ));
    }

    let kind = resolve_transport(args.via, std::env::var_os("PATH").as_deref())?;
    let tmp = TempDir::new()?;
    let archive = tmp.path().join("archive.gfxpack");

    let (argv, cwd) = receive_argv(kind, &code, &archive);
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    writeln!(out, "gfx receive: fetching with {} ...", kind.label())?;
    let status = cmd.status().map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to start {}: {e}", kind.binary()),
        ))
    })?;
    if !status.success() {
        eprintln!("gfx receive: {} exited with {status}", kind.binary());
        return Ok(EXIT_FAILURE);
    }

    // sendme names the output after the source (archive.gfxpack, R3); if the
    // name ever drifts, accept any single landed file ending in .gfxpack*.
    let archive = if archive.is_file() {
        archive
    } else {
        let mut found: Vec<_> = std::fs::read_dir(tmp.path())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.file_name()
                        .map(|n| n.to_string_lossy().starts_with("archive.gfxpack"))
                        .unwrap_or(false)
            })
            .collect();
        match found.len() {
            1 => found.remove(0),
            _ => {
                return Err(CliError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "transfer reported success but no archive landed in {}",
                        tmp.path().display()
                    ),
                )))
            }
        }
    };

    let mut unpack_argv = forwarded;
    unpack_argv.push(OsString::from("--archive"));
    unpack_argv.push(archive.as_os_str().to_os_string());
    Ok(run_unpack_cli_to(out, unpack_argv))
}
