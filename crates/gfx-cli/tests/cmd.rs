//! External-command blob transform tests (plan-blob-xform.md M2): the
//! adapter itself, its factory wiring (argv-order interleaving with the
//! built-ins), and a real-repo E2E through the pass driver.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::driver::{PassDriver, PassSpec};
use gfx::gfx_blob_xform::{BlobTransform, BlobXformConfig, SharedBlobTransform};
use gfx_cli::args::parse_argv;
use gfx_cli::cmd::{CmdTransform, DEFAULT_CAPTURE_LIMIT};
use gfx_cli::passes::blob_xform_factory;
use gfx_cli::registry::PassRegistry;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-cmd-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().expect("spawn git");
    assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

fn cmd(c: &str) -> CmdTransform {
    CmdTransform { cmd: c.to_string(), capture_limit: DEFAULT_CAPTURE_LIMIT }
}

// ---------------------------------------------------------------------------
// The adapter

#[test]
fn cmd_transform_pipes_blob_through_command() {
    assert_eq!(cmd("tr a-z A-Z").apply(b"hello\n").as_deref(), Ok(&b"HELLO\n"[..]));
    assert_eq!(cmd("cat").apply(b"\x00\xffbinary").as_deref(), Ok(&b"\x00\xffbinary"[..]));
    assert_eq!(cmd("cmd:").describe(), "cmd:\"cmd:\"");
}

#[test]
fn cmd_transform_nonzero_exit_and_overrun_retain() {
    assert!(cmd("false").apply(b"data").is_err(), "non-zero exit ⇒ retain");
    assert!(cmd("exit 3").apply(b"data").is_err());
    assert!(cmd("does-not-exist-xyz").apply(b"data").is_err(), "spawn failure ⇒ retain");
    // Emit more than the capture limit.
    let t = CmdTransform { cmd: "yes X | head -c 100000".into(), capture_limit: 1024 };
    assert!(t.apply(b"seed").is_err(), "capture overrun ⇒ retain");
}

#[test]
fn cmd_transform_is_send_sync_and_deterministic() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CmdTransform>();
    let t = cmd("tr a-z A-Z");
    let a = t.apply(b"same input").unwrap();
    let b = t.apply(b"same input").unwrap();
    assert_eq!(a, b, "deterministic command ⇒ deterministic transform");
}

// ---------------------------------------------------------------------------
// Factory wiring — cmd stages interleave with built-ins in argv order

#[test]
fn factory_interleaves_cmd_with_builtins_in_argv_order() {
    let reg = PassRegistry::new(vec![blob_xform_factory()]).unwrap();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let argv: Vec<std::ffi::OsString> = [
        "--passes", "blob-xform",
        "--blob-xform.crlf-to-lf",
        "--blob-xform.cmd", "tr a-z A-Z",
        "--blob-xform.ensure-final-newline",
        "--blob-xform.cmd", "cat",
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let map = parse_argv(&specs, &argv).unwrap();
    let passes = reg.resolve("blob-xform", &map).unwrap();
    match &passes[0] {
        PassSpec::BlobXform(cfg) => {
            let names: Vec<String> = cfg.transforms.iter().map(|t| t.0.describe()).collect();
            assert_eq!(
                names,
                [
                    "crlf-to-lf",
                    "cmd:\"tr a-z A-Z\"",
                    "ensure-final-newline",
                    "cmd:\"cat\""
                ],
                "chain order = argv order"
            );
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// E2E — a real filter program over real history

#[test]
fn cmd_transform_end_to_end_uppercase() {
    let base = tmpdir("e2e");
    let work = base.join("work");
    let bare = base.join("bare.git");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    let id = ["-c", "user.email=t@t", "-c", "user.name=T"];
    std::fs::write(work.join("a.txt"), b"hello world\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &[&id[..], &["commit", "-qm", "greeting"][..]].concat());
    // A blob the command rejects: `tr` succeeds on anything, so use a
    // command that fails on this content to prove retention mid-history.
    std::fs::write(work.join("keep.txt"), b"KEEPME\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &[&id[..], &["commit", "-qm", "keep"][..]].concat());
    git(&base, &["clone", "-q", "--bare", "work", "bare.git"]);
    let _ = std::fs::remove_dir_all(&work);

    let head_before = String::from_utf8(git(&bare, &["rev-parse", "HEAD"])).unwrap();

    // Uppercase everything EXCEPT blobs containing KEEPME. The command
    // must buffer stdin before gating (a plain `grep -q … | tr …` would
    // consume the blob in the gate and leave tr nothing) — exactly the
    // shape an operator writes with a scratch file.
    let transform = CmdTransform {
        cmd: "f=$(mktemp); cat > $f; \
              if grep -q KEEPME $f; then rm -f $f; exit 1; \
              else tr a-z A-Z < $f; rm -f $f; fi"
            .into(),
        capture_limit: DEFAULT_CAPTURE_LIMIT,
    };
    let cfg = BlobXformConfig {
        transforms: vec![SharedBlobTransform(std::sync::Arc::new(transform))],
        ..BlobXformConfig::default()
    };
    let mut d = PassDriver::new(&bare)
        .unwrap()
        .with_passes(vec![
            PassSpec::BlobXform(cfg),
            PassSpec::Remap(gfx::gfx_remap::RemapConfig::default()),
        ])
        .unwrap();
    let report = d.run().unwrap();

    gfx::git::process::fsck(&bare).expect("fsck --strict");
    assert_eq!(git(&bare, &["show", "HEAD:a.txt"]), b"HELLO WORLD\n");
    assert_eq!(git(&bare, &["show", "HEAD:keep.txt"]), b"KEEPME\n", "failed blob retained");
    assert_ne!(
        head_before,
        String::from_utf8(git(&bare, &["rev-parse", "HEAD"])).unwrap(),
        "history rewrote"
    );
    let detail = &report.passes[0].detail;
    assert!(detail.contains("altered=1"), "{detail}");
    assert!(detail.contains("failed=1"), "{detail}");

    let _ = std::fs::remove_dir_all(&base);
}
