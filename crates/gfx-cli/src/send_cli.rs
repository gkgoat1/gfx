//! `gfx send` subcommand (plan-transfer.md): pack repositories into a
//! temporary `.gfxpack` archive via the exact `gfx pack` pipeline (D2), hand
//! the archive to a transfer tool (wormhole/sendme), surface the transfer
//! code, and clean up. Every flag this module does not own is forwarded
//! verbatim to the pack CLI.

use std::ffi::OsString;
use std::io::Write;

use crate::cli::{exit_code_for, EXIT_FAILURE, EXIT_OK};
use crate::error::CliError;
use crate::pack_cli::run_pack_cli_to;
use crate::registry::PassFactory;
use crate::transfer::{
    extract_code, extract_transfer_args, resolve_transport, send_argv, TempDir, TransportKind,
};

const SEND_USAGE: &str = "gfx send — pack repositories and transfer the archive to another machine\n\n\
usage: gfx send [--repo <name>:<path>]... [--via wormhole|sendme|auto] [--code <code>] \
[pack flags...]\n\n\
transfer flags:\n\
  --via       transfer tool: wormhole (default when installed), sendme, or auto\n\
  --code      pin the wormhole code instead of allocating one\n\n\
All other flags are forwarded to `gfx pack` (e.g. --passes, --redact.collapse,\n\
--save-remotes, --encrypt-passphrase). With no --repo, the current directory is\n\
sent as one repo named by its folder name.\n\n\
The transfer code grants the archive to whoever holds it; both transports are\n\
end-to-end encrypted. Add pack's --encrypt* flags for at-rest protection on the\n\
receiving side.\n";

/// Parse and run `gfx send`. Returns the process exit code.
pub fn run_send_cli_to(
    out: &mut dyn Write,
    factories: Vec<Box<dyn PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> i32 {
    match try_run_send(out, factories, argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gfx send: {e}");
            exit_code_for(&e)
        }
    }
}

fn try_run_send(
    out: &mut dyn Write,
    factories: Vec<Box<dyn PassFactory>>,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<i32, CliError> {
    let args = extract_transfer_args(argv.into_iter().collect())?;
    if args.help {
        write!(out, "{SEND_USAGE}")?;
        return Ok(EXIT_OK);
    }
    if !args.positionals.is_empty() {
        return Err(CliError::UnexpectedPositional(args.positionals[0].clone()));
    }
    let mut forwarded = args.forwarded;
    reject_forwarded(&forwarded, "--out")?;
    if !has_flag(&forwarded, "--repo") {
        let cwd = std::env::current_dir()?;
        let name = cwd
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                CliError::FlagConflict(
                    "no --repo given and the current directory has no usable name".to_string(),
                )
            })?;
        forwarded.push(OsString::from("--repo"));
        forwarded.push(OsString::from(format!("{name}:{}", cwd.display())));
    }

    let kind = resolve_transport(args.via, std::env::var_os("PATH").as_deref())?;
    let tmp = TempDir::new()?;
    let archive = tmp.path().join("archive.gfxpack");

    // Pack: forwarded argv + our archive destination (D2).
    let mut pack_argv = forwarded;
    pack_argv.push(OsString::from("--out"));
    pack_argv.push(archive.as_os_str().to_os_string());
    let code = run_pack_cli_to(out, "pack repositories for transfer", factories, pack_argv);
    if code != EXIT_OK {
        return Ok(code);
    }
    if !archive.is_file() {
        return Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("pack reported success but {} is missing", archive.display()),
        )));
    }

    writeln!(
        out,
        "gfx send: handing {} to {}",
        archive.display(),
        kind.label()
    )?;
    let send_code = run_sender(out, kind, &archive, args.code.as_deref())?;
    Ok(send_code)
}

/// Spawn the transport sender, tee its output to stderr, surface the
/// transfer code on `out` as soon as the tool prints it (D4), and wait.
fn run_sender(
    out: &mut dyn Write,
    kind: TransportKind,
    archive: &std::path::Path,
    code: Option<&str>,
) -> Result<i32, CliError> {
    let argv = send_argv(kind, archive, code)?;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to start {}: {e}", kind.binary()),
        ))
    })?;

    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    let mut join = Vec::new();
    let streams: Vec<Box<dyn std::io::Read + Send>> = vec![
        Box::new(child.stdout.take().expect("stdout piped")),
        Box::new(child.stderr.take().expect("stderr piped")),
    ];
    for stream in streams {
        let tx = tx.clone();
        join.push(std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stream);
            use std::io::BufRead;
            for line in reader.lines() {
                let Ok(line) = line else { break };
                eprintln!("{}", line);
                let _ = tx.send(Some(line));
            }
            let _ = tx.send(None); // stream closed
        }));
    }
    drop(tx);

    // First extracted code wins; the channel closes when both streams end.
    let mut found: Option<String> = None;
    let mut open = join.len();
    while open > 0 {
        match rx.recv() {
            Ok(Some(line)) => {
                if found.is_none() {
                    if let Some(code) = extract_code(kind, &line) {
                        found = Some(code.to_string());
                    }
                }
            }
            Ok(None) => open -= 1,
            Err(_) => break,
        }
        if found.is_some() {
            break;
        }
    }
    if let Some(code) = &found {
        writeln!(out, "gfx send: transfer code: {code}")?;
        if kind == TransportKind::Sendme {
            writeln!(
                out,
                "gfx send: sendme serve mode — keep this process running until the receiver \
                 finishes; Ctrl-C ends it"
            )?;
        }
        out.flush().ok();
    }

    let status = child.wait().map_err(CliError::Io)?;
    for j in join {
        j.join().ok();
    }
    if status.success() {
        writeln!(out, "gfx send: transfer complete; temporary archive removed")?;
        Ok(EXIT_OK)
    } else {
        eprintln!("gfx send: {} exited with {status}", kind.binary());
        Ok(EXIT_FAILURE)
    }
}

fn has_flag(argv: &[OsString], flag: &str) -> bool {
    argv.iter().any(|a| {
        let s = a.to_string_lossy();
        s == flag || s.strip_prefix(flag).is_some_and(|r| r.starts_with('='))
    })
}

fn reject_forwarded(argv: &[OsString], flag: &str) -> Result<(), CliError> {
    if has_flag(argv, flag) {
        return Err(CliError::FlagConflict(format!(
            "gfx send chooses the archive path; drop {flag}"
        )));
    }
    Ok(())
}

