//! CLI-level stream-endpoint tests (plan-stream-files.md M0): the four
//! `--in`/`--out`/`--repo` combinations through the real rewrite surface,
//! and the usage errors for nonsensical flag sets (C3).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-cli-endpoints-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn factories() -> Vec<Box<dyn gfx_cli::PassFactory>> {
    vec![
        Box::new(gfx_cli::passes::strip_blobs_factory()),
        Box::new(gfx_cli::passes::remap_factory()),
    ]
}

fn git(repo: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    String::from_utf8(git(repo, args)).unwrap().trim().to_string()
}

fn refs_snapshot(repo: &Path) -> String {
    git_text(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
}

/// Small bare repo: two commits (one holding a >8-byte blob) and a tag.
fn make_source_bare(tag: &str) -> PathBuf {
    let base = tmpdir(tag);
    let work = base.join("work");
    let bare = base.join("bare.git");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    std::fs::write(work.join("big.bin"), b"0123456789abcdef\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    std::fs::write(work.join("small.txt"), b"tiny\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "two"]);
    git(&base, &["clone", "-q", "--bare", "work", "bare.git"]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

fn run_cli(args: &[&str]) -> (i32, String) {
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(&mut out, "test-gfx", "about", factories(), os(args));
    (code, String::from_utf8_lossy(&out).into_owned())
}

#[test]
fn cli_repo_to_file_then_file_to_repo() {
    let bare = make_source_bare("cli-r2f");
    let base = bare.parent().unwrap().to_path_buf();
    let stream = base.join("out.feat");

    // repo → file, stripping the big blob.
    let (code, report) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--out", stream.to_str().unwrap(),
        "--strip-blobs.larger-than", "8",
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert!(stream.exists());
    let bytes = std::fs::read(&stream).unwrap();
    assert!(bytes.windows(7).any(|w| w == b"commit "), "real stream bytes");
    // The >8-byte blob's only op (big.bin in commit 1) is dropped; the
    // tiny blob's op (small.txt in commit 2) survives.
    assert_eq!(
        bytes.windows(10).filter(|w| *w == b"M 100644 :").count(),
        1,
        "strip-blobs drops the filemodify op for selected content"
    );
    // Source repo untouched.
    assert!(refs_snapshot(&bare).contains("refs/heads/main"));

    // file → repo: import the stripped stream into a fresh bare repo.
    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let (code, report) = run_cli(&[
        "--in", stream.to_str().unwrap(),
        "--repo", dest.to_str().unwrap(),
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert_eq!(git_text(&dest, &["show", "HEAD:small.txt"]), "tiny");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&dest)
            .args(["show", "HEAD:big.bin"])
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(false),
        "stripped path must not exist in the destination"
    );
    assert!(dest.join("gfx").join("commit-map").exists());
    assert!(dest.join("gfx").join("run-report.txt").exists());
}

#[test]
fn cli_file_to_file_and_dry_run() {
    let bare = make_source_bare("cli-f2f");
    let base = bare.parent().unwrap().to_path_buf();
    let stream = base.join("s.feat");
    let (code, _) = run_cli(&["--repo", bare.to_str().unwrap(), "--out", stream.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK);

    let out = base.join("filtered.feat");
    let (code, report) = run_cli(&[
        "--in", stream.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--strip-blobs.larger-than", "8",
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    let bytes = std::fs::read(&out).unwrap();
    // The big blob's only referencing op (commit 1's `M`) is gone.
    assert_eq!(bytes.windows(10).filter(|w| *w == b"M 100644 :").count(), 1);

    // --dry-run against a stream source writes nothing.
    let dry_out = base.join("dry.feat");
    let (code, report) = run_cli(&[
        "--in", stream.to_str().unwrap(),
        "--out", dry_out.to_str().unwrap(),
        "--dry-run",
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert!(report.contains("mode: dry-run"));
    assert!(!dry_out.exists(), "dry-run must not write the stream file");
}

#[test]
fn cli_endpoint_flag_validation() {
    // --in alone is ambiguous → usage error.
    let (code, _) = run_cli(&["--in", "/tmp/whatever.feat"]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // --out alone is ambiguous → usage error.
    let (code, _) = run_cli(&["--out", "/tmp/whatever.feat"]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // --in == --out → usage error.
    let (code, _) = run_cli(&["--in", "/tmp/x.feat", "--out", "/tmp/x.feat"]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // --save-remotes with a stream source → usage error.
    let base = tmpdir("cli-val");
    let s1 = base.join("a.feat");
    let s2 = base.join("b.feat");
    std::fs::write(&s1, b"").unwrap();
    let (code, _) = run_cli(&[
        "--in", s1.to_str().unwrap(),
        "--out", s2.to_str().unwrap(),
        "--save-remotes",
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // --remote-refs with a stream sink → usage error.
    let (code, _) = run_cli(&[
        "--in", s1.to_str().unwrap(),
        "--out", s2.to_str().unwrap(),
        "--remote-refs", "drop",
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);
}

#[test]
fn cli_gzip_round_trip() {
    let bare = make_source_bare("cli-gz");
    let base = bare.parent().unwrap().to_path_buf();
    let stream = base.join("out.feat.gz");

    // repo → file, auto-compressed by the .gz suffix.
    let (code, report) = run_cli(&["--repo", bare.to_str().unwrap(), "--out", stream.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    let bytes = std::fs::read(&stream).unwrap();
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "auto + .gz ⇒ gzip container");
    assert!(base.join("out.feat.gz.gfx").join("commit-marks").exists());

    // file(.gz, sniffed) → repo.
    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let (code, report) = run_cli(&["--in", stream.to_str().unwrap(), "--repo", dest.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert_eq!(refs_snapshot(&dest), refs_snapshot(&bare));

    // Bad flag values are usage errors.
    let (code, _) = run_cli(&["--repo", bare.to_str().unwrap(), "--out", "/tmp/x.feat", "--out-compression", "bzip2"]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);
    let (code, _) = run_cli(&["--repo", bare.to_str().unwrap(), "--out", "/tmp/x.feat", "--out-gzip-level", "42"]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);
}
