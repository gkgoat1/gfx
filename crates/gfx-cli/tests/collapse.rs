//! E2E for `redact --redact.collapse` (plan-stream-files.md M5): every
//! ident in history becomes one, composing with time modes — including
//! over the stream endpoints (file → file with no repo).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-cli-collapse-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn factories() -> Vec<Box<dyn gfx_cli::PassFactory>> {
    vec![
        Box::new(gfx_cli::passes::redact_factory()),
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

fn git_text(repo: &Path, args: &[&str]) -> String {
    String::from_utf8(git(repo, args)).unwrap().trim().to_string()
}

/// Repo with three authors across commits and a tag.
fn make_repo(tag: &str) -> (PathBuf, PathBuf) {
    let base = tmpdir(tag);
    let work = base.join("work");
    let bare = base.join("bare.git");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    for (i, who) in ["alice", "bob", "carol"].iter().enumerate() {
        std::fs::write(work.join(format!("f{i}.txt")), format!("{who}\n")).unwrap();
        git(&work, &["add", "."]);
        git(&work, &[
            "-c", &format!("user.email={who}@example.com"),
            "-c", &format!("user.name={who}"),
            "commit", "-qm", &format!("c{i}"),
        ]);
    }
    git(&work, &["-c", "user.email=tag@x.io", "-c", "user.name=Tagr", "tag", "-a", "-m", "v", "v1"]);
    git(&base, &["clone", "-q", "--bare", "work", "bare.git"]);
    let _ = std::fs::remove_dir_all(&work);
    (base, bare)
}

#[test]
fn e2e_collapse_all_idents_to_one() {
    let (_base, bare) = make_repo("collapse");
    let (code, report) = run_cli(&[
        "--repo", bare.to_str().unwrap(),
        "--passes", "redact",
        "--redact.collapse",
        "--redact.time-mode", "zero",
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    assert!(report.contains("collapse=1"), "{report}");
    assert!(!report.contains("collisions="), "{report}");

    // Every ident in history is the one pair; times are zeroed.
    let log = git_text(&bare, &["log", "--all", "--format=%an <%ae> | %cn <%ce> | %at %ct"]);
    for line in log.lines() {
        assert!(
            line.starts_with("Anonymous <anonymous@example.invalid> | Anonymous <anonymous@example.invalid> | 0 0"),
            "collapsed + zeroed: {line}"
        );
    }
    let tag = git_text(&bare, &["cat-file", "tag", "v1"]);
    assert!(tag.contains("tagger Anonymous <anonymous@example.invalid> 0 +0000"), "{tag}");
    gfx::git::process::fsck(&bare).expect("fsck --strict");
}

#[test]
fn e2e_collapse_custom_identity_over_file_to_file() {
    let (base, bare) = make_repo("collapse-f2f");
    let stream = base.join("s.feat");
    let (code, _) = run_cli(&["--repo", bare.to_str().unwrap(), "--out", stream.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK);

    let out = base.join("anon.feat");
    let (code, report) = run_cli(&[
        "--in", stream.to_str().unwrap(),
        "--out", out.to_str().unwrap(),
        "--passes", "redact",
        "--redact.collapse",
        "--redact.collapse-name", "Redacted",
        "--redact.collapse-email", "nobody@example.invalid",
    ]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");

    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let (code, report) = run_cli(&["--in", out.to_str().unwrap(), "--repo", dest.to_str().unwrap()]);
    assert_eq!(code, gfx_cli::EXIT_OK, "{report}");
    let log = git_text(&dest, &["log", "--all", "--format=%an <%ae>"]);
    assert!(log.lines().all(|l| l == "Redacted <nobody@example.invalid>"), "{log}");
    gfx::git::process::fsck(&dest).expect("fsck --strict");
}

#[test]
fn collapse_flag_conflicts_are_usage_errors() {
    let (_base, bare) = make_repo("collapse-val");
    // collapse + pseudonymize
    let (code, _) = run_cli(&[
        "--repo", bare.to_str().unwrap(), "--passes", "redact",
        "--redact.collapse", "--redact.pseudonymize",
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);
    // collapse-name without collapse
    let (code, _) = run_cli(&[
        "--repo", bare.to_str().unwrap(), "--passes", "redact",
        "--redact.collapse-name", "X",
    ]);
    assert_eq!(code, gfx_cli::EXIT_USAGE);
}
