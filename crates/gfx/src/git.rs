//! `std`-gated host adapters (plan §9). These are conveniences for hosts and
//! integration tests — the sans-IO core never requires them.

use alloc::vec::Vec;

extern crate std;
use gfx_core::{Error, Parser};

#[cfg(feature = "git")]
pub mod process {
    //! `git` subprocess drivers used by the pass driver (plan §4.3).
    //! Every function spawns `git` with explicit arguments and maps failures
    //! to [`GitError`] with captured stderr — never panics, never swallows
    //! diagnostics.

    extern crate std;

    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::fmt;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// A failed (or unspawnable) `git` invocation.
    #[derive(Debug)]
    pub struct GitError {
        pub command: String,
        pub status: Option<i32>,
        pub stderr: String,
    }

    impl fmt::Display for GitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "git {} failed", self.command)?;
            if let Some(s) = self.status {
                write!(f, " (exit {s})")?;
            }
            let err = self.stderr.trim();
            if !err.is_empty() {
                write!(f, ": {err}")?;
            }
            Ok(())
        }
    }

    impl std::error::Error for GitError {}

    fn spawn(repo: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(repo).args(args);
        cmd
    }

    fn fail(repo: &Path, args: &[&str], out: &std::process::Output) -> GitError {
        GitError {
            command: format!("-C {} {}", repo.display(), args.join(" ")),
            status: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run `git` in `repo`, requiring success; returns stdout bytes.
    pub fn run(repo: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
        let out = spawn(repo, args)
            .output()
            .map_err(|e| GitError {
                command: format!("-C {} {}", repo.display(), args.join(" ")),
                status: None,
                stderr: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(fail(repo, args, &out));
        }
        Ok(out.stdout)
    }

    /// Run `git`, returning trimmed stdout text.
    pub fn text(repo: &Path, args: &[&str]) -> Result<String, GitError> {
        let bytes = run(repo, args)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_string())
    }

    /// fast-export flags pinned for the rewrite round (plan §4.3). The set
    /// is version-sensitive and recorded in `docs/git-baseline.md`.
    pub const EXPORT_FLAGS: &[&str] = &[
        "fast-export",
        "--show-original-ids",
        "--signed-tags=strip",
        "--tag-of-filtered-object=rewrite",
        "--fake-missing-tagger",
        "--reference-excluded-parents",
        "--use-done-feature",
        "--all",
        "--reencode=yes",
    ];

    /// Capture a full `git fast-export` stream into memory. (v1 posture:
    /// buffered rounds, consistent with the sans-IO `rewrite` API. Streaming
    /// export→import is a future optimization.)
    pub fn export_stream(repo: &Path, extra_args: &[&str]) -> Result<Vec<u8>, GitError> {
        let mut args: Vec<&str> = Vec::with_capacity(EXPORT_FLAGS.len() + extra_args.len());
        args.extend_from_slice(EXPORT_FLAGS);
        args.extend_from_slice(extra_args);
        run(repo, &args)
    }

    /// Feed a complete stream to `git fast-import --force`, writing its
    /// marks file to `marks_path` (used to finalize the remap commit map,
    /// plan §7.2 mode A).
    pub fn import_stream(repo: &Path, stream: &[u8], marks_path: &Path) -> Result<(), GitError> {
        // `--export-marks=<path>` must be one argv token (Apple Git rejects
        // the split form), so the command is built directly rather than via
        // the generic arg-list helper.
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(repo)
            .arg("fast-import")
            .arg("--force")
            .arg("--quiet")
            .arg(format!("--export-marks={}", marks_path.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| GitError {
                command: format!("-C {} fast-import", repo.display()),
                status: None,
                stderr: e.to_string(),
            })?;
        // The stream is bounded by the parser's limits; a broken pipe here
        // means fast-import died early — its stderr carries the real error.
        let write = child.stdin.take().expect("piped stdin").write_all(stream);
        let _ = write;
        let out = child
            .wait_with_output()
            .map_err(|e| GitError {
                command: format!("-C {} fast-import", repo.display()),
                status: None,
                stderr: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(GitError {
                command: format!("-C {} fast-import --force --quiet", repo.display()),
                status: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(())
    }

    /// Absolute path of the repo's git dir. (Absolute matters: `git -C`
    /// chdirs the subprocess, so any path argument we hand to `fast-import`
    /// must not be relative to *our* cwd.)
    pub fn git_dir(repo: &Path) -> Result<PathBuf, GitError> {
        let rel = text(repo, &["rev-parse", "--git-dir"])?;
        let p = Path::new(&rel);
        let joined = if p.is_absolute() {
            p.to_path_buf()
        } else {
            repo.join(p)
        };
        std::fs::canonicalize(joined).map_err(|e| GitError {
            command: format!("rev-parse --git-dir ({})", repo.display()),
            status: None,
            stderr: e.to_string(),
        })
    }

    /// All refs as `(objectname, refname)` pairs, sorted by refname.
    pub fn refs(repo: &Path) -> Result<Vec<(String, String)>, GitError> {
        let out = run(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])?;
        let mut v: Vec<(String, String)> = String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|l| {
                let (oid, name) = l.split_once(' ')?;
                Some((oid.into(), name.into()))
            })
            .collect();
        v.sort();
        Ok(v)
    }

    /// `git fsck --strict` — the acceptance gate for rewritten repos.
    pub fn fsck(repo: &Path) -> Result<(), GitError> {
        run(repo, &["fsck", "--strict"]).map(|_| ())
    }

    /// The repo's object format (`sha1` / `sha256`), from
    /// `git rev-parse --object-format`. Unknown formats are an error —
    /// remap's OID handling is format-sensitive.
    pub fn object_format(repo: &Path) -> Result<gfx_core::ObjectFormat, GitError> {
        match text(repo, &["rev-parse", "--object-format"])?.as_str() {
            "sha1" => Ok(gfx_core::ObjectFormat::Sha1),
            "sha256" => Ok(gfx_core::ObjectFormat::Sha256),
            other => Err(GitError {
                command: format!("-C {} rev-parse --object-format", repo.display()),
                status: None,
                stderr: format!("unknown object format {other:?}"),
            }),
        }
    }

    pub fn is_bare(repo: &Path) -> Result<bool, GitError> {
        Ok(text(repo, &["rev-parse", "--is-bare-repository"])? == "true")
    }

    /// `git status --porcelain` output (empty when clean).
    pub fn status_porcelain(repo: &Path) -> Result<String, GitError> {
        text(repo, &["status", "--porcelain"])
    }
}

/// Feed all bytes from a reader into the parser (core stays `no_std`; this
/// adapter lives on the facade).
pub fn feed_all(parser: &mut Parser, mut reader: impl std::io::Read) -> Result<(), Error> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(io_error)?;
        if n == 0 {
            return Ok(());
        }
        parser.feed(&buf[..n]);
    }
}

fn io_error(e: std::io::Error) -> Error {
    let _ = e;
    Error::Internal("host i/o error (see host logs)")
}

/// Stream → stream in one call: parse `input`, push it through `pipeline`,
/// and serialize. Buffers in, buffers out — still sans-IO (plan §9).
pub fn rewrite(input: &[u8], pipeline: &mut gfx_core::Pipeline) -> Result<Vec<u8>, Error> {
    let mut parser = Parser::new(gfx_core::ParseOptions::default());
    parser.feed(input);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event()? {
        pipeline.apply(ev, &mut events)?;
    }
    let mut final_events = Vec::new();
    parser.finish(&mut final_events)?;
    for ev in final_events {
        pipeline.apply(ev, &mut events)?;
    }
    pipeline.finish(&mut events)?;
    let mut writer = gfx_core::Writer::new();
    for ev in &events {
        writer.write(ev)?;
    }
    Ok(writer.take())
}
