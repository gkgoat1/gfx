//! E2E for `gfx send` / `gfx receive` (plan-transfer.md M1/M2): the
//! transports are mock binaries on a prepended PATH — a POSIX shell script
//! that emulates wormhole's code line and file delivery — so the loopback
//! exercises the real pack/unpack pipeline without touching a network.
//! PATH mutation is process-global, so these tests serialize on a mutex.

#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

static COUNTER: AtomicU64 = AtomicU64::new(0);
static PATH_LOCK: Mutex<()> = Mutex::new(());

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-cli-transfer-{tag}-{}-{n}", std::process::id()));
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
        Box::new(gfx_cli::passes::redact_factory()),
        Box::new(gfx_cli::passes::enforce_ignore_factory()),
        Box::new(gfx_cli::passes::remap_factory()),
    ]
}

fn git(repo: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// A repo with two commits (two authors) and one tag.
fn make_repo(root: &Path, name: &str) -> PathBuf {
    let repo = root.join(name);
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    std::fs::write(repo.join("a.txt"), "alpha\n").unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &["-c", "user.name=Alice", "-c", "user.email=alice@example.com", "commit", "-qm", "one"],
    );
    std::fs::write(repo.join("b.txt"), "bravo\n").unwrap();
    git(&repo, &["add", "."]);
    git(
        &repo,
        &["-c", "user.name=Bob", "-c", "user.email=bob@example.com", "commit", "-qm", "two"],
    );
    git(&repo, &["tag", "v1"]);
    repo
}

/// Mock `wormhole`: `send [--code C] <file>` copies the file to
/// `$MOCK_DROP/<code>` and prints the code line on stderr like the real
/// tool (R1); `receive --accept-file -o <out> <code>` copies it back.
const MOCK_WORMHOLE: &str = r#"#!/bin/sh
set -eu
cmd="$1"; shift
case "$cmd" in
  send)
    code="9-mock-transfer"
    file=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --code) code="$2"; shift 2 ;;
        *) file="$1"; shift ;;
      esac
    done
    cp "$file" "$MOCK_DROP/$code"
    echo "Wormhole code is: $code" >&2
    echo "On the other computer, please run: wormhole receive $code" >&2
    ;;
  receive)
    out=""
    code=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --accept-file) shift ;;
        -o) out="$2"; shift 2 ;;
        *) code="$1"; shift ;;
      esac
    done
    cp "$MOCK_DROP/$code" "$out"
    ;;
  *) echo "mock wormhole: bad cmd" >&2; exit 1 ;;
esac
"#;

/// Mock `sendme`: `send <file>` copies to `$MOCK_DROP/sendme-ticket` and
/// prints a ticket; `receive <ticket>` runs with cwd = the destination dir
/// and writes `archive.gfxpack` there (R3).
const MOCK_SENDME: &str = r#"#!/bin/sh
set -eu
cmd="$1"; shift
case "$cmd" in
  send)
    cp "$1" "$MOCK_DROP/blobmockticket0000000000000000"
    echo "content added"
    echo "run sendme receive blobmockticket0000000000000000"
    ;;
  receive)
    cp "$MOCK_DROP/$1" ./archive.gfxpack
    ;;
  *) echo "mock sendme: bad cmd" >&2; exit 1 ;;
esac
"#;

struct MockEnv {
    _guard: MutexGuard<'static, ()>,
    bin: PathBuf,
    drop: PathBuf,
    orig_path: OsString,
}

/// Install mock transports on PATH (prepended) with a drop directory.
fn install_mocks(tag: &str, which: &[(&str, &str)]) -> MockEnv {
    let guard = PATH_LOCK.lock().unwrap();
    let root = tmpdir(tag);
    let bin = root.join("bin");
    let drop = root.join("drop");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&drop).unwrap();
    for (name, script) in which {
        let p = bin.join(name);
        std::fs::write(&p, script).unwrap();
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        std::fs::set_permissions(&p, perms).unwrap();
    }
    let orig_path = std::env::var_os("PATH").unwrap_or_default();
    let mut new_path = std::ffi::OsString::from(&bin);
    new_path.push(":");
    new_path.push(&orig_path);
    std::env::set_var("PATH", &new_path);
    std::env::set_var("MOCK_DROP", &drop);
    MockEnv {
        _guard: guard,
        bin,
        drop,
        orig_path,
    }
}

impl Drop for MockEnv {
    fn drop(&mut self) {
        std::env::set_var("PATH", &self.orig_path);
        std::env::remove_var("MOCK_DROP");
        if let Some(parent) = self.bin.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn send(args: &[&str]) -> (i32, String) {
    let mut out = Vec::new();
    let code = gfx_cli::run_send_cli_to(&mut out, factories(), os(args));
    (code, String::from_utf8_lossy(&out).into_owned())
}

fn receive(args: &[&str]) -> (i32, String) {
    let mut out = Vec::new();
    let code = gfx_cli::run_receive_cli_to(&mut out, os(args));
    (code, String::from_utf8_lossy(&out).into_owned())
}

fn refs(repo: &Path) -> String {
    String::from_utf8_lossy(&git(repo, &["for-each-ref", "--format=%(refname) %(objectname)"]))
        .into_owned()
}

#[test]
fn loopback_wormhole_send_receive() {
    let mock = install_mocks("wh", &[("wormhole", MOCK_WORMHOLE)]);
    let work = tmpdir("wh-work");
    let src = make_repo(&work, "src");
    let dest = work.join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    let (code, out) = send(&["--repo", &format!("main:{}", src.display()), "--via", "wormhole"]);
    assert_eq!(code, 0, "send failed:\n{out}");
    assert!(out.contains("gfx send: transfer code: 9-mock-transfer"), "code not surfaced:\n{out}");
    assert!(mock.drop.join("9-mock-transfer").is_file(), "mock never got the archive");

    let (code, out) = receive(&["9-mock-transfer", "--via", "wormhole", "--dest-root", &dest.display().to_string()]);
    assert_eq!(code, 0, "receive failed:\n{out}");
    let landed = dest.join("main");
    assert!(landed.join("HEAD").is_file() || landerefs(&landed), "no repo at {}", landed.display());
    assert_eq!(refs(&landed), refs(&src), "refs did not survive the loopback");
    let fsck = Command::new("git").arg("-C").arg(&landed).args(["fsck", "--strict"]).output().unwrap();
    assert!(fsck.status.success(), "fsck: {}", String::from_utf8_lossy(&fsck.stderr));

    // Temp hygiene (C3): no gfx-transfer-* dirs left by this process.
    let strays: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(&format!("gfx-transfer-{}-", std::process::id()))
        })
        .collect();
    assert!(strays.is_empty(), "temp litter: {strays:?}");
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn loopback_sendme_and_redact_in_flight() {
    let _mock = install_mocks("sm", &[("sendme", MOCK_SENDME)]);
    let work = tmpdir("sm-work");
    let src = make_repo(&work, "src");
    let dest = work.join("dest");
    std::fs::create_dir_all(&dest).unwrap();

    // Pack flags forward through send: anonymize in flight (plan §1).
    let (code, out) = send(&[
        "--via", "sendme",
        "--repo", &format!("main:{}", src.display()),
        "--passes", "redact",
        "--redact.collapse",
        "--redact.time-mode", "zero",
    ]);
    assert_eq!(code, 0, "send failed:\n{out}");
    assert!(
        out.contains("gfx send: transfer code: blobmockticket0000000000000000"),
        "ticket not surfaced:\n{out}"
    );

    let (code, out) = receive(&[
        "blobmockticket0000000000000000",
        "--via", "sendme",
        "--dest-root", &dest.display().to_string(),
    ]);
    assert_eq!(code, 0, "receive failed:\n{out}");
    let landed = dest.join("main");
    let idents = String::from_utf8_lossy(&git(&landed, &["log", "--all", "--format=%an <%ae> %at"])).into_owned();
    assert!(idents.contains("Anonymous <anonymous@example.invalid> 0"), "not anonymized:\n{idents}");
    assert!(!idents.contains("alice@example.com"), "source ident leaked:\n{idents}");
    std::fs::remove_dir_all(&work).ok();
}

#[test]
fn usage_errors_exit_2() {
    // No transports on PATH at all → C1 fail-closed with both hints.
    // Scoped guard: install_mocks below takes the same lock.
    {
        let _guard = PATH_LOCK.lock().unwrap();
        let orig = std::env::var_os("PATH").unwrap_or_default();
        std::env::set_var("PATH", "/nonexistent");
        let (code, out) = receive(&["1-x-y"]);
        std::env::set_var("PATH", &orig);
        assert_eq!(code, 2);
        assert!(out.is_empty());
    }

    // Missing code positional.
    let mock = install_mocks("usage", &[("wormhole", MOCK_WORMHOLE)]);
    let (code, _) = receive(&[]);
    assert_eq!(code, 2);
    // Extra positional.
    let (code, _) = receive(&["a", "b"]);
    assert_eq!(code, 2);
    // --out is send's own choice.
    let (code, _) = send(&["--out", "/tmp/whatever"]);
    assert_eq!(code, 2);
    // Unknown --via.
    let (code, _) = send(&["--via", "scp"]);
    assert_eq!(code, 2);
    drop(mock);
}

/// Helper: a directory looks like a git repo (bare or not).
fn landerefs(p: &Path) -> bool {
    p.join(".git").exists() || p.join("objects").is_dir()
}
