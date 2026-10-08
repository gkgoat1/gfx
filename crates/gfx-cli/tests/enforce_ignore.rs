//! E2E for the `enforce-ignore` pass (plan-stream-files.md M3): external
//! rules drop ignored paths from all of history, carriers survive, and
//! the pass composes through the stream endpoints.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-cli-ignore-{tag}-{}-{n}", std::process::id()));
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
        Box::new(gfx_cli::passes::enforce_ignore_factory()),
        Box::new(gfx_cli::passes::remap_factory()),
    ]
}

fn run_cli(args: &[&str]) -> (i32, String) {
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(&mut out, "test-gfx", "about", factories(), os(args));
    (code, String::from_utf8_lossy(&out).into_owned())
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

/// Every path in every commit of every ref.
fn all_paths(repo: &Path) -> Vec<String> {
    let out = git(repo, &["log", "--all", "--name-only", "--pretty=format:"]);
    let mut v: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Repo with ignored junk committed over two commits, plus a .gitignore
/// that arrived too late (the motivating case).
fn make_repo(tag: &str) -> (PathBuf, PathBuf) {
    let base = tmpdir(tag);
    let work = base.join("work");
    let bare = base.join("bare.git");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    let id = ["-c", "user.email=t@t", "-c", "user.name=T"];

    std::fs::write(work.join("debug.log"), b"log1\n").unwrap();
    std::fs::create_dir_all(work.join("build"));
    std::fs::write(work.join("build/out.o"), b"obj1\n").unwrap();
    std::fs::write(work.join("keep.txt"), b"keep\n").unwrap();
    git(&work, &["add", "-f", "."]); // -f: tracked despite being ignorable
    git(&work, &[&id[..], &["commit", "-qm", "one"][..]].concat());

    std::fs::write(work.join("debug.log"), b"log2\n").unwrap();
    std::fs::write(work.join(".gitignore"), b"*.log\nbuild/\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &[&id[..], &["commit", "-qm", "two"][..]].concat());

    git(&base, &["clone", "-q", "--bare", "work", "bare.git"]);
    let _ = std::fs::remove_dir_all(&work);
    (base, bare)
}

#[test]
fn e2e_enforce_ignore_in_place() {
    let (base, bare) = make_repo("inplace");
    let rules = base.join("rules.gitignore");
    std::fs::write(&rules, "*.log\nbuild/\n").unwrap();

    let (code, report) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--passes", "enforce-ignore",
        "--enforce-ignore.rules", rules.to_str().unwrap(),
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert!(report.contains("ops_dropped=3"), "{report}");

    let paths = all_paths(&bare);
    assert_eq!(paths, vec![".gitignore".to_string(), "keep.txt".to_string()], "junk gone from all of history: {paths:?}");
    // C8: the late .gitignore survived even though it was committed history.
    assert!(base.join("bare.git/gfx/ignore-report.txt").exists());
    let rep = std::fs::read_to_string(base.join("bare.git/gfx/ignore-report.txt")).unwrap();
    assert!(rep.contains("debug.log") && rep.contains("build/out.o"), "{rep}");
    gfx::git::process::fsck(&bare).expect("fsck --strict");
}

#[test]
fn e2e_enforce_ignore_via_stream_files() {
    let (base, bare) = make_repo("stream");
    let rules = base.join("rules.gitignore");
    std::fs::write(&rules, "*.log\nbuild/\n").unwrap();

    // repo → file (enforce at export) → file → repo.
    let stream = base.join("clean.feat");
    let (code, report) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--out", stream.to_str().unwrap(),
        "--passes", "enforce-ignore",
        "--enforce-ignore.rules", rules.to_str().unwrap(),
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");

    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let (code, report) = run_cli(&["--in", stream.to_str().unwrap(), "--repo", dest.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    let paths = all_paths(&dest);
    assert_eq!(paths, vec![".gitignore".to_string(), "keep.txt".to_string()]);
    gfx::git::process::fsck(&dest).expect("fsck --strict");
}

#[test]
fn enforce_ignore_requires_a_rule_source() {
    let (_base, bare) = make_repo("norules");
    let (code, _) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--passes", "enforce-ignore",
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // And its flags may not ride along when the pass is not named.
    let base2 = tmpdir("guard");
    let rules = base2.join("r");
    std::fs::write(&rules, "*.log\n").unwrap();
    let (code, _) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--dry-run",
        "--enforce-ignore.rules", rules.to_str().unwrap(),
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE, "unused-flag guard");
}
