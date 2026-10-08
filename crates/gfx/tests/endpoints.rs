//! Stream-file endpoint tests (plan-stream-files.md M0): the four
//! source/sink combinations, sink-side safety binding, validation errors,
//! and the foreign-stream (no `original-oid`) degradation.
//!
//! Requires `git` in PATH; each test works in its own temp directory.

#![cfg(all(feature = "git", feature = "remap"))]

use gfx::driver::{read_stream, DriverError, PassDriver, Sink, Source};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-endpoints-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
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

/// A small bare repo with two commits on `main` and a tag.
fn make_source_bare(tag: &str) -> PathBuf {
    let base = tmpdir(tag);
    let work = base.join("work");
    let bare = base.join("bare.git");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    std::fs::write(work.join("b.txt"), b"world\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "two"]);
    git(&work, &["tag", "v1"]);
    git(&base, &["clone", "-q", "--bare", "work", "bare.git"]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

fn refs_snapshot(repo: &Path) -> String {
    git_text(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
}

#[test]
fn repo_to_file_matches_plain_export() {
    let bare = make_source_bare("r2f");
    let out = bare.with_file_name("out.feat");

    let mut d = PassDriver::with_endpoints(
        Source::Repo(bare.clone()),
        Sink::Stream(out.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    let report = d.run().unwrap();
    assert!(report.identity, "identity passes must not change the stream");

    let expected = gfx::git::process::export_stream(&bare, &[]).unwrap();
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got, expected, "repo → file must be exactly export → passes");

    // The source repo is untouched (read-only source, C4).
    let refs_after = refs_snapshot(&bare);
    assert!(refs_after.contains("refs/heads/main"));
    assert!(!bare.join("gfx").exists(), "no artifacts in the source repo");
}

#[test]
fn repo_to_file_skips_the_safety_check_on_nonbare_source() {
    // C4: export is read-only, so a non-bare (even dirty) source is fine.
    let base = tmpdir("r2f-nb");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&base, &["init", "-q", "work"]);
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    git(&work, &["add", "."]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    std::fs::write(work.join("dirty.txt"), b"uncommitted\n").unwrap();

    let out = base.join("out.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Repo(work.clone()),
        Sink::Stream(out.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    let report = d.run().unwrap();
    assert!(report.identity);
    assert!(out.exists(), "stream file written without --force on a dirty non-bare source");
}

#[test]
fn file_to_repo_reproduces_the_in_place_rewrite() {
    let bare = make_source_bare("f2r");
    let base = bare.parent().unwrap().to_path_buf();

    // Export the stream, then import it into a fresh bare repo.
    let stream = base.join("stream.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Repo(bare.clone()),
        Sink::Stream(stream.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    d.run().unwrap();

    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let mut d = PassDriver::with_endpoints(
        Source::Stream(stream.clone()),
        Sink::Repo(dest.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    let report = d.run().unwrap();
    assert!(!report.dry_run);
    assert!(report.commit_map_finalized);
    assert!(!report.no_original_ids, "gfx-produced streams carry original-oid");

    // Identity passes ⇒ dest refs equal the source refs, exactly.
    assert_eq!(refs_snapshot(&dest), refs_snapshot(&bare));
    gfx::git::process::fsck(&dest).expect("fsck --strict");
    assert!(dest.join("gfx").join("commit-map").exists());
    assert!(dest.join("gfx").join("run-report.txt").exists());
}

#[test]
fn file_to_file_is_a_pure_filter() {
    let bare = make_source_bare("f2f");
    let base = bare.parent().unwrap().to_path_buf();

    let stream = base.join("stream.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Repo(bare.clone()),
        Sink::Stream(stream.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    d.run().unwrap();

    let out = base.join("filtered.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Stream(stream.clone()),
        Sink::Stream(out.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    let report = d.run().unwrap();
    assert!(report.identity);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(&stream).unwrap(),
        "file → file with identity passes copies the stream byte for byte"
    );
}

#[test]
fn nonbare_sink_is_refused_without_force() {
    // C5: importing into a non-bare repo keeps the safety gate.
    let bare = make_source_bare("f2r-safety");
    let base = bare.parent().unwrap().to_path_buf();
    let stream = base.join("stream.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Repo(bare.clone()),
        Sink::Stream(stream.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    d.run().unwrap();

    let dest = base.join("dest");
    git(&base, &["init", "-q", "dest"]);
    let mut d = PassDriver::with_endpoints(Source::Stream(stream), Sink::Repo(dest))
        .unwrap()
        .with_passes(vec![])
        .unwrap();
    match d.run() {
        Err(DriverError::Unsafe { .. }) => {}
        other => panic!("expected Unsafe, got {other:?}"),
    }
}

#[test]
fn endpoint_validation_rejects_nonsense() {
    let bare = make_source_bare("valid");

    // Same file in and out.
    let p = bare.parent().unwrap().join("x.feat");
    match PassDriver::with_endpoints(Source::Stream(p.clone()), Sink::Stream(p)) {
        Err(DriverError::Endpoint(_)) => {}
        other => panic!("expected Endpoint, got {other:?}"),
    }

    // Remotes flags against a stream source/sink (D3).
    let r = PassDriver::with_endpoints(
        Source::Stream(bare.parent().unwrap().join("in.feat")),
        Sink::Stream(bare.parent().unwrap().join("out.feat")),
    )
    .unwrap()
    .with_remote_data(true, false, gfx::driver::RemoteRefsPolicy::Rewrite)
    .run();
    match r {
        Err(DriverError::Endpoint(msg)) => assert!(msg.contains("--save-remotes")),
        other => panic!("expected Endpoint(save-remotes), got {other:?}"),
    }

    // A repo path that is not a repository.
    match PassDriver::with_endpoints(
        Source::Repo(bare.parent().unwrap().join("nope")),
        Sink::Stream(bare.parent().unwrap().join("out.feat")),
    ) {
        Err(DriverError::NotARepository { .. }) => {}
        other => panic!("expected NotARepository, got {other:?}"),
    }

    // --artifacts against a repo sink is meaningless (D4).
    let stream = bare.parent().unwrap().join("s.feat");
    let mut d = PassDriver::with_endpoints(
        Source::Repo(bare.clone()),
        Sink::Stream(stream.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    d.run().unwrap();
    let dest = bare.parent().unwrap().join("dest.git");
    git(bare.parent().unwrap(), &["init", "-q", "--bare", "dest.git"]);
    match PassDriver::with_endpoints(Source::Stream(stream), Sink::Repo(dest))
        .unwrap()
        .with_artifacts_dir("/tmp/anywhere")
    {
        Err(DriverError::Endpoint(msg)) => assert!(msg.contains("--artifacts")),
        other => panic!("expected Endpoint(artifacts), got {other:?}"),
    }
}

#[test]
fn foreign_stream_without_original_ids_warns_but_works() {
    // D5: a stream produced without --show-original-ids (here: plain
    // `git fast-export --all`) imports fine but degrades the commit map.
    let bare = make_source_bare("foreign");
    let base = bare.parent().unwrap().to_path_buf();
    let stream = base.join("foreign.feat");
    std::fs::write(&stream, git(&bare, &["fast-export", "--all"])).unwrap();

    let dest = base.join("dest.git");
    git(&base, &["init", "-q", "--bare", "dest.git"]);
    let mut d = PassDriver::with_endpoints(
        Source::Stream(stream),
        Sink::Repo(dest.clone()),
    )
    .unwrap()
    .with_passes(vec![])
    .unwrap();
    let report = d.run().unwrap();
    assert!(report.no_original_ids);
    assert!(
        report.commit_map.as_ref().map_or(true, |m| m.is_empty()),
        "no original-oid ⇒ no old→new entries"
    );
    assert!(
        report.to_text().contains("no original-oid"),
        "the report must say the map degraded"
    );
    assert_eq!(refs_snapshot(&dest), refs_snapshot(&bare));
    gfx::git::process::fsck(&dest).expect("fsck --strict");
}

#[test]
fn stream_read_is_verbatim_in_v1() {
    let base = tmpdir("read");
    let p = base.join("raw.feat");
    std::fs::write(&p, b"blob\nmark :1\ndata 4\nxyz\n").unwrap();
    assert_eq!(read_stream(&p).unwrap(), b"blob\nmark :1\ndata 4\nxyz\n");
}
