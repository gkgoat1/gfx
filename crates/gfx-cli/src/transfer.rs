//! Transfer transport core (plan-transfer.md): external CLI tools move one
//! `.gfxpack` archive between machines. gfx never embeds a transfer protocol
//! (D1); each transport is PATH discovery + argv construction + output
//! parsing, so the pieces are unit-testable without touching a network.
//!
//! - `wormhole` (magic-wormhole): `send` prints `Wormhole code is: <code>`
//!   on stderr and exits when the receiver finishes; `receive --accept-file
//!   -o <path> <code>` is fully non-interactive (R1, R2).
//! - `sendme` (iroh): `send` prints a `blob…` ticket and then *serves until
//!   Ctrl-C* (R3); `receive <ticket>` writes into its working directory, so
//!   callers run it with `cwd` set to the transfer temp dir.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::CliError;

/// A supported transfer tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// magic-wormhole (`wormhole` binary).
    Wormhole,
    /// iroh's sendme (`sendme`).
    Sendme,
}

impl TransportKind {
    /// Binary looked up on PATH.
    pub fn binary(self) -> &'static str {
        match self {
            TransportKind::Wormhole => "wormhole",
            TransportKind::Sendme => "sendme",
        }
    }

    /// Install hint printed when the binary is missing (C1).
    pub fn install_hint(self) -> &'static str {
        match self {
            TransportKind::Wormhole => "brew install magic-wormhole",
            TransportKind::Sendme => "cargo install sendme",
        }
    }

    /// Human-facing name for reports.
    pub fn label(self) -> &'static str {
        match self {
            TransportKind::Wormhole => "magic-wormhole",
            TransportKind::Sendme => "sendme (iroh)",
        }
    }
}

/// `--via` selection: a pinned transport or `auto` (first PATH hit in the
/// order wormhole, sendme — D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Auto,
    Pinned(TransportKind),
}

impl Via {
    /// Parse the `--via` value.
    pub fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "auto" => Ok(Via::Auto),
            "wormhole" => Ok(Via::Pinned(TransportKind::Wormhole)),
            "sendme" | "iroh" => Ok(Via::Pinned(TransportKind::Sendme)),
            other => Err(CliError::FlagConflict(format!(
                "unknown --via {other:?}; expected wormhole, sendme, or auto"
            ))),
        }
    }
}

/// True when `binary` is an executable file reachable via `path_env`
/// (a PATH-style colon-separated list). Pure: the caller supplies the PATH
/// string so tests never mutate process env.
pub fn on_path(path_env: Option<&OsStr>, binary: &str) -> Option<PathBuf> {
    let path_env = path_env?;
    for dir in std::env::split_paths(path_env) {
        let candidate = dir.join(binary);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Resolve `--via` against a PATH string, failing closed with install hints
/// when nothing (or the pinned tool) is available (C1).
pub fn resolve_transport(via: Via, path_env: Option<&OsStr>) -> Result<TransportKind, CliError> {
    match via {
        Via::Pinned(kind) => {
            if on_path(path_env, kind.binary()).is_some() {
                Ok(kind)
            } else {
                Err(CliError::FlagConflict(format!(
                    "--via {}: `{}` not found on PATH; install it with: {}",
                    kind.binary(),
                    kind.binary(),
                    kind.install_hint()
                )))
            }
        }
        Via::Auto => [TransportKind::Wormhole, TransportKind::Sendme]
            .into_iter()
            .find(|k| on_path(path_env, k.binary()).is_some())
            .ok_or_else(|| {
                CliError::FlagConflict(format!(
                    "no transfer tool found on PATH; install one: `{}` (provides `wormhole`), or `{}`",
                    TransportKind::Wormhole.install_hint(),
                    TransportKind::Sendme.install_hint()
                ))
            }),
    }
}

/// Sender argv for `kind`, transferring `archive`. `code` pins a wormhole
/// code; sendme cannot pin (usage error, D3).
pub fn send_argv(
    kind: TransportKind,
    archive: &Path,
    code: Option<&str>,
) -> Result<Vec<OsString>, CliError> {
    match kind {
        TransportKind::Wormhole => {
            let mut argv = vec![OsString::from("wormhole"), OsString::from("send")];
            if let Some(code) = code {
                argv.push(OsString::from("--code"));
                argv.push(OsString::from(code));
            }
            argv.push(archive.as_os_str().to_os_string());
            Ok(argv)
        }
        TransportKind::Sendme => {
            if code.is_some() {
                return Err(CliError::FlagConflict(
                    "--code cannot pin a sendme ticket (tickets are content-bound); \
                     drop --code or use --via wormhole"
                        .to_string(),
                ));
            }
            Ok(vec![
                OsString::from("sendme"),
                OsString::from("send"),
                archive.as_os_str().to_os_string(),
            ])
        }
    }
}

/// Receiver argv for `kind`. For sendme, `dest_dir` becomes the child's
/// working directory (sendme has no output flag, R3); for wormhole the
/// archive path is passed with `-o`.
pub fn receive_argv(kind: TransportKind, code: &str, archive: &Path) -> (Vec<OsString>, Option<PathBuf>) {
    match kind {
        TransportKind::Wormhole => (
            vec![
                OsString::from("wormhole"),
                OsString::from("receive"),
                OsString::from("--accept-file"),
                OsString::from("-o"),
                archive.as_os_str().to_os_string(),
                OsString::from(code),
            ],
            None,
        ),
        TransportKind::Sendme => (
            vec![
                OsString::from("sendme"),
                OsString::from("receive"),
                OsString::from(code),
            ],
            // Run inside the directory that must end up holding the file.
            archive.parent().map(Path::to_path_buf),
        ),
    }
}

/// Extract a wormhole code from one output line
/// (`Wormhole code is: 66-bottomless-allow`, R1).
pub fn extract_wormhole_code(line: &str) -> Option<&str> {
    let rest = line.split("Wormhole code is:").nth(1)?;
    let code = rest.trim();
    (!code.is_empty()).then_some(code)
}

/// Extract a sendme ticket from one output line. Accepts the wrapped form
/// (`sendme receive blob…`) and a bare `blob…` token (R3).
pub fn extract_sendme_ticket(line: &str) -> Option<&str> {
    if let Some(rest) = line.split("sendme receive").nth(1) {
        // The ticket must follow on the same line.
        let rest = rest.split(['\n', '\r']).next().unwrap_or("");
        let ticket = rest.split_whitespace().next().unwrap_or("");
        if !ticket.is_empty() {
            return Some(ticket);
        }
    }
    line.split_whitespace().find(|tok| {
        tok.len() >= 24 && tok.starts_with("blob") && tok.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// Extract the transfer code/ticket for `kind` from one tool output line.
pub fn extract_code(kind: TransportKind, line: &str) -> Option<&str> {
    match kind {
        TransportKind::Wormhole => extract_wormhole_code(line),
        TransportKind::Sendme => extract_sendme_ticket(line),
    }
}

/// The transfer temp directory guard: removed on normal drop (C3). A
/// SIGINT-killed process cannot run Drop; OS temp reaping collects
/// `gfx-transfer-*` strays.
pub struct TempDir(PathBuf);

impl TempDir {
    /// Fresh `$TMPDIR/gfx-transfer-<pid>-<n>` directory.
    pub fn new() -> std::io::Result<Self> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        for n in 0..1000u32 {
            let candidate = base.join(format!("gfx-transfer-{pid}-{n}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return Ok(TempDir(candidate)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a fresh gfx-transfer-* temp directory",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Extract this subcommand's own flags from raw argv. Only `--via`/`--code`
/// consume a following token, and they are recognized anywhere. Bare tokens
/// *before the first foreign `--flag`* are positionals (the receive code);
/// from the first foreign flag onward everything forwards verbatim, so the
/// values of pack/unpack flags (whose arity this module does not know) are
/// never misclassified (D2). `--help` is consumed by the caller, never
/// forwarded.
pub struct TransferArgs {
    pub via: Via,
    pub code: Option<String>,
    pub help: bool,
    pub positionals: Vec<String>,
    pub forwarded: Vec<OsString>,
}

pub fn extract_transfer_args(argv: Vec<OsString>) -> Result<TransferArgs, CliError> {
    let mut via = Via::Auto;
    let mut code: Option<String> = None;
    let mut help = false;
    let mut positionals = Vec::new();
    let mut forwarded = Vec::new();
    let mut seen_foreign_flag = false;
    let mut it = argv.into_iter();
    while let Some(tok) = it.next() {
        let s = tok.to_string_lossy();
        if s == "--via" {
            let value = it.next().ok_or(CliError::MissingValue {
                flag: "via".to_string(),
            })?;
            via = Via::parse(&value.to_string_lossy())?;
        } else if let Some(value) = s.strip_prefix("--via=") {
            via = Via::parse(value)?;
        } else if s == "--code" {
            let value = it.next().ok_or(CliError::MissingValue {
                flag: "code".to_string(),
            })?;
            code = Some(value.to_string_lossy().into_owned());
        } else if let Some(value) = s.strip_prefix("--code=") {
            code = Some(value.to_string());
        } else if s == "--help" || s == "-h" {
            // Handled by the caller's own usage text; never forwarded.
            help = true;
        } else if s.starts_with("--") {
            seen_foreign_flag = true;
            forwarded.push(tok);
        } else if seen_foreign_flag {
            // A foreign flag's value (or anything else after the flags
            // start) — never ours to interpret.
            forwarded.push(tok);
        } else {
            positionals.push(s.into_owned());
        }
    }
    Ok(TransferArgs {
        via,
        code,
        help,
        positionals,
        forwarded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via_parse_accepts_known_names() {
        assert_eq!(Via::parse("auto").unwrap(), Via::Auto);
        assert_eq!(Via::parse("wormhole").unwrap(), Via::Pinned(TransportKind::Wormhole));
        assert_eq!(Via::parse("sendme").unwrap(), Via::Pinned(TransportKind::Sendme));
        assert_eq!(Via::parse("iroh").unwrap(), Via::Pinned(TransportKind::Sendme));
        assert!(Via::parse("scp").is_err());
    }

    #[test]
    fn resolve_pinned_missing_fails_closed_with_hint() {
        let err = resolve_transport(Via::Pinned(TransportKind::Sendme), Some(OsStr::new("/nonexistent")))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sendme"), "{msg}");
        assert!(msg.contains("cargo install sendme"), "{msg}");
    }

    #[test]
    fn resolve_auto_lists_both_hints_when_nothing_found() {
        let err = resolve_transport(Via::Auto, Some(OsStr::new("/nonexistent"))).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("magic-wormhole"), "{msg}");
        assert!(msg.contains("sendme"), "{msg}");
    }

    #[test]
    fn resolve_auto_prefers_wormhole() {
        let dir = std::env::temp_dir().join(format!("gfx-transfer-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["wormhole", "sendme"] {
            let p = dir.join(if cfg!(windows) { format!("{binary}.exe", binary = name) } else { name.to_string() });
            std::fs::write(&p, b"#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let path = std::env::join_paths([dir.clone()]).unwrap();
        assert_eq!(
            resolve_transport(Via::Auto, Some(&path)).unwrap(),
            TransportKind::Wormhole
        );
        assert_eq!(
            resolve_transport(Via::Pinned(TransportKind::Sendme), Some(&path)).unwrap(),
            TransportKind::Sendme
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wormhole_send_argv_pins_code() {
        let argv = send_argv(TransportKind::Wormhole, Path::new("/t/a.gfxpack"), Some("7-x-y")).unwrap();
        let flat: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(flat, ["wormhole", "send", "--code", "7-x-y", "/t/a.gfxpack"]);
    }

    #[test]
    fn sendme_rejects_pinned_code() {
        assert!(send_argv(TransportKind::Sendme, Path::new("/t/a.gfxpack"), Some("x")).is_err());
        let argv = send_argv(TransportKind::Sendme, Path::new("/t/a.gfxpack"), None).unwrap();
        let flat: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(flat, ["sendme", "send", "/t/a.gfxpack"]);
    }

    #[test]
    fn receive_argv_shapes() {
        let (argv, cwd) = receive_argv(TransportKind::Wormhole, "1-a-b", Path::new("/t/archive.gfxpack"));
        let flat: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            flat,
            ["wormhole", "receive", "--accept-file", "-o", "/t/archive.gfxpack", "1-a-b"]
        );
        assert!(cwd.is_none());

        let (argv, cwd) = receive_argv(TransportKind::Sendme, "blobxyz", Path::new("/t/archive.gfxpack"));
        let flat: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(flat, ["sendme", "receive", "blobxyz"]);
        assert_eq!(cwd.as_deref(), Some(Path::new("/t")));
    }

    #[test]
    fn code_extraction() {
        assert_eq!(
            extract_wormhole_code("Wormhole code is: 66-bottomless-allow"),
            Some("66-bottomless-allow")
        );
        assert_eq!(extract_wormhole_code("Sending file"), None);
        assert_eq!(
            extract_sendme_ticket("to get this data, use sendme receive blobabc123"),
            Some("blobabc123")
        );
        // Wrapped form requires the ticket on the same line...
        assert_eq!(extract_sendme_ticket("run sendme receive"), None);
        // ...but a bare ticket token anywhere matches on its own.
        assert_eq!(
            extract_sendme_ticket("ticket: blobDEF456ghi789jkl012mno345"),
            Some("blobDEF456ghi789jkl012mno345")
        );
        assert_eq!(extract_sendme_ticket("nothing here"), None);
    }

    #[test]
    fn extract_transfer_args_separates_own_flags() {
        // --repo's value looks positional to us but follows a foreign flag.
        let args = extract_transfer_args(vec![
            OsString::from("--repo"),
            OsString::from("main:/tmp/x"),
            OsString::from("--via"),
            OsString::from("sendme"),
        ])
        .unwrap();
        assert_eq!(args.via, Via::Pinned(TransportKind::Sendme));
        assert!(args.positionals.is_empty());
        let fwd: Vec<String> = args.forwarded.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(fwd, ["--repo", "main:/tmp/x"]);
    }

    #[test]
    fn extract_transfer_args_receives_code_before_flags() {
        let args = extract_transfer_args(vec![
            OsString::from("7-a-b"),
            OsString::from("--dest-root"),
            OsString::from("/tmp/out"),
        ])
        .unwrap();
        assert_eq!(args.positionals, ["7-a-b"]);
        let fwd: Vec<String> = args.forwarded.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(fwd, ["--dest-root", "/tmp/out"]);
    }

    #[test]
    fn extract_transfer_args_flags() {
        let args = extract_transfer_args(vec![
            OsString::from("--via"),
            OsString::from("wormhole"),
            OsString::from("--code=7-a-b"),
            OsString::from("--repo"),
            OsString::from("main:/tmp/x"),
            OsString::from("--passes"),
            OsString::from("redact"),
            OsString::from("--redact.collapse"),
        ])
        .unwrap();
        assert_eq!(args.via, Via::Pinned(TransportKind::Wormhole));
        assert_eq!(args.code.as_deref(), Some("7-a-b"));
        assert!(args.positionals.is_empty());
        let fwd: Vec<String> = args.forwarded.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            fwd,
            ["--repo", "main:/tmp/x", "--passes", "redact", "--redact.collapse"]
        );
    }

    #[test]
    fn extract_transfer_args_collects_positionals() {
        let args = extract_transfer_args(vec![OsString::from("7-a-b"), OsString::from("--force")]).unwrap();
        assert_eq!(args.positionals, ["7-a-b"]);
        let fwd: Vec<String> = args.forwarded.iter().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(fwd, ["--force"]);
    }
}
