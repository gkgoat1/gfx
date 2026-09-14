//! External-command blob transform (plan-blob-xform.md §4.3, M2): each
//! blob is piped through a shell command — stdin = blob bytes, stdout =
//! replacement bytes, non-zero exit (or any spawn/I/O failure, or a
//! capture-limit overrun) ⇒ `Err(())` ⇒ the pass retains the original.
//!
//! This is the `std` host side of D2: the `no_std` builtin crate knows only
//! the [`BlobTransform`] trait; process spawning lives here.
//!
//! **The command is the purity contract** (G4): gfx cannot enforce that an
//! external program is deterministic. A command that consults clocks, RNG,
//! or the environment produces nondeterministic history rewrites — the
//! operator is responsible. stderr is swallowed; a command's diagnostics
//! never enter the stream, and its failure shows up only as retention
//! counts in the report. A command that never terminates hangs the run
//! (no per-blob timeout in v1) — same operational profile as
//! filter-repo's callbacks.

use std::io::{Read, Write};

use gfx::gfx_blob_xform::BlobTransform;

/// Default stdout capture bound when the pass has no explicit
/// `--blob-xform.max-output-bytes` (a runaway command must not OOM the
/// host; 64 MiB matches the strip pass's scan-cap order of magnitude).
pub const DEFAULT_CAPTURE_LIMIT: u64 = 64 * 1024 * 1024;

/// One per-blob shell command in the transform chain.
pub struct CmdTransform {
    /// The shell command line (run as `sh -c <cmd>`).
    pub cmd: String,
    /// stdout capture bound; overrun counts as command failure (⇒ retain).
    pub capture_limit: u64,
}

impl BlobTransform for CmdTransform {
    fn name(&self) -> &'static str {
        "<cmd>"
    }

    fn describe(&self) -> String {
        format!("cmd:{:?}", self.cmd)
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        run_shell(&self.cmd, blob, self.capture_limit)
    }
}

/// Pipe `input` through `sh -c <cmd>` with a bounded stdout capture.
///
/// Deadlock-free: a writer thread feeds stdin (closing it on completion or
/// EPIPE) while the calling thread drains stdout, so a child that blocks on
/// either pipe always makes progress. On capture overrun the child is
/// killed rather than left to fill memory.
fn run_shell(cmd: &str, input: &[u8], capture_limit: u64) -> Result<Vec<u8>, ()> {
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| ())?;

    let mut stdin = child.stdin.take().ok_or(())?;
    let mut stdout = child.stdout.take().ok_or(())?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // stdin drops here, closing the pipe (child sees EOF).
    });

    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let mut overflow = false;
    loop {
        match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() as u64 + n as u64 > capture_limit {
                    overflow = true;
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(_) => break,
        }
    }
    if overflow {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| ())?;
    let _ = writer.join();

    if overflow || !status.success() {
        return Err(());
    }
    Ok(out)
}
