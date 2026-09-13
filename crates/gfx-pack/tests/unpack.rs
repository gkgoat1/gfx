//! Unpack driver integration tests (plan-multistream-pack.md M2): pack →
//! unpack round-trips with tip assertions (D8), tamper detection, and
//! per-repo failure isolation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::driver::PassSpec;
use gfx_pack::manifest::MANIFEST_ENTRY;
use gfx_pack::zip::{Method, ZipReader, ZipWriter};
use gfx_pack::{pack, unpack, PackOptions, PackRepo, RepoStatus, UnpackOptions};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-unpack-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A bare repo with two commits and a tag; optionally sha256; optionally
/// with a large blob in the tip commit.
fn make_repo(base: &Path, name: &str, sha256: bool, big: bool) -> PathBuf {
    let work = base.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).unwrap();
    if sha256 {
        git(&work, &["init", "-q", "--object-format=sha256"]);
    } else {
        git(&work, &["init", "-q"]);
    }
    let id = ["-c", "user.email=t@t", "-c", "user.name=T"];
    std::fs::write(work.join("a.txt"), format!("{name} one\n")).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &[&id[..], &["commit", "-qm", "one"][..]].concat());
    if big {
        std::fs::write(work.join("big.bin"), vec![b'x'; 200_000]).unwrap();
    } else {
        std::fs::write(work.join("b.txt"), format!("{name} two\n")).unwrap();
    }
    git(&work, &["add", "-A"]);
    git(&work, &[&id[..], &["commit", "-qm", "two"][..]].concat());
    git(&work, &["tag", "v1"]);
    let bare = base.join(format!("{name}.git"));
    git(base, &["clone", "-q", "--bare", &format!("{name}-work"), &format!("{name}.git")]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

fn refs_of(repo: &Path) -> BTreeMap<String, String> {
    git(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(oid, name)| (name.to_string(), oid.to_string()))
        .collect()
}

fn pack_archive(repos: Vec<PackRepo>, passes: Vec<PassSpec>, out: &Path) {
    pack(&PackOptions {
        repos,
        passes,
        flags_audit: Default::default(),
        out: out.to_path_buf(),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
    })
    .expect("pack");
}

fn default_unpack(archive: &Path, dest_root: &Path) -> UnpackOptions {
    UnpackOptions {
        archive: archive.to_path_buf(),
        dest_root: Some(dest_root.to_path_buf()),
        repo_overrides: vec![],
        verify_only: false,
        keep_going: false,
        force: false,
        worktree: false,
        identity_files: vec![],
        passphrase: None,
    }
}

/// Rebuild an archive applying `f` to each entry's bytes (tamper helper).
fn rebuild_archive(src: &Path, dst: &Path, mut f: impl FnMut(&str, Vec<u8>) -> Vec<u8>) {
    let mut r = ZipReader::open(std::fs::File::open(src).unwrap()).unwrap();
    let names: Vec<String> = r.entries().iter().map(|e| e.name.clone()).collect();
    let mut w = ZipWriter::new(Vec::new());
    for n in names {
        let data = r.extract(&n).unwrap();
        w.write_entry_bytes(&n, Method::Deflate, &f(&n, data)).unwrap();
    }
    std::fs::write(dst, w.finish().unwrap()).unwrap();
}

#[test]
fn roundtrip_identity_preserves_history() {
    let base = tmpdir("id");
    let a = make_repo(&base, "alpha", false, false);
    let b = make_repo(&base, "beta", false, false);
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![
            PackRepo { name: "alpha".into(), path: a.clone() },
            PackRepo { name: "beta".into(), path: b.clone() },
        ],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        &archive,
    );

    let dest = base.join("dest");
    let report = unpack(&default_unpack(&archive, &dest)).expect("unpack");
    assert!(report.ok(), "{}", report.to_text());

    // Identity pipeline: destinations have byte-identical refs to sources.
    assert_eq!(refs_of(&a), refs_of(&dest.join("alpha")));
    assert_eq!(refs_of(&b), refs_of(&dest.join("beta")));
    gfx::git::process::fsck(&dest.join("alpha")).expect("fsck");

    // Artifacts: finalized commit-map (old == new), ref-map, report.
    let cm = std::fs::read_to_string(dest.join("alpha").join("gfx/commit-map")).unwrap();
    for line in cm.lines() {
        let (old, new) = line.split_once(' ').unwrap();
        assert_eq!(old, new, "identity run: old == new");
    }
    let rm = std::fs::read_to_string(dest.join("alpha").join("gfx/ref-map")).unwrap();
    assert!(rm.contains("refs/heads/main"));
    assert!(rm.contains("refs/tags/v1"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn roundtrip_strip_finalizes_new_oids() {
    let base = tmpdir("strip");
    let a = make_repo(&base, "alpha", false, true); // has big.bin in tip
    let s = make_repo(&base, "sha", true, false); // sha256 repo
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![
            PackRepo { name: "alpha".into(), path: a.clone() },
            PackRepo { name: "sha".into(), path: s.clone() },
        ],
        vec![PassSpec::StripBlobs(gfx::gfx_strip_blobs::StripBlobsConfig {
            size_threshold: Some(100 * 1024),
            ..Default::default()
        })],
        &archive,
    );

    let dest = base.join("dest");
    let report = unpack(&default_unpack(&archive, &dest)).expect("unpack");
    assert!(report.ok(), "{}", report.to_text());
    let da = dest.join("alpha");
    let ds = dest.join("sha");

    // Object format survived the round-trip.
    assert_eq!(
        git(&ds, &["rev-parse", "--show-object-format"]).trim(),
        "sha256"
    );
    gfx::git::process::fsck(&da).expect("fsck alpha");
    gfx::git::process::fsck(&ds).expect("fsck sha");

    // Stripped content is gone from the materialized repo.
    let log = git(&da, &["log", "--all", "--oneline", "--", "big.bin"]);
    assert!(log.trim().is_empty(), "big.bin must not survive unpack");

    // The rewritten tip got a new OID, and the finalized commit-map in the
    // destination names exactly the ref tips the repo actually has (D8).
    let src_refs = refs_of(&a);
    let dst_refs = refs_of(&da);
    assert_eq!(src_refs.len(), dst_refs.len());
    let cm: BTreeMap<String, String> = std::fs::read_to_string(da.join("gfx/commit-map"))
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .collect();
    let mut saw_new = false;
    for (name, old_tip) in &src_refs {
        let new_tip = &dst_refs[name];
        if old_tip == new_tip {
            assert_eq!(cm[old_tip], *old_tip, "unchanged tip maps to itself");
        } else {
            saw_new = true;
            assert_eq!(cm[old_tip], *new_tip, "finalized map names the real new tip");
        }
    }
    assert!(saw_new, "strip must rewrite the tip commit");

    // sha256 repo is identity: refs unchanged.
    assert_eq!(refs_of(&s), refs_of(&ds));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn verify_only_happy_and_tampered() {
    let base = tmpdir("verify");
    let a = make_repo(&base, "alpha", false, false);
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![PackRepo { name: "alpha".into(), path: a }],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        &archive,
    );

    // Happy path: verifies, creates nothing.
    let dest = base.join("dest");
    let mut opts = default_unpack(&archive, &dest);
    opts.verify_only = true;
    let report = unpack(&opts).expect("verify-only");
    assert!(report.ok());
    assert!(report.repos.iter().all(|r| r.status == RepoStatus::Verified));
    assert!(!dest.exists(), "verify-only creates nothing");

    // Tamper: corrupt the recorded stream checksum in the manifest.
    let tampered = base.join("tampered.gfxpack");
    rebuild_archive(&archive, &tampered, |name, data| {
        if name == MANIFEST_ENTRY {
            let text = String::from_utf8(data).unwrap();
            // Flip the first recorded checksum's first hex digit in place,
            // keeping the manifest structurally valid.
            let marker = "sha256 = \"";
            let at = text.find(marker).unwrap() + marker.len();
            let (head, tail) = text.split_at(at);
            let digit = tail.chars().next().unwrap();
            let flipped = if digit == '0' { '1' } else { '0' };
            format!("{head}{flipped}{}", &tail[1..]).into_bytes()
        } else {
            data
        }
    });
    let mut opts = default_unpack(&tampered, &dest);
    opts.verify_only = true;
    let err = unpack(&opts).unwrap_err();
    assert!(
        matches!(err, gfx_pack::PackError::Checksum { .. }),
        "checksum tamper detected, got {err}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn keep_going_isolates_failures() {
    let base = tmpdir("kg");
    let a = make_repo(&base, "alpha", false, false);
    let b = make_repo(&base, "beta", false, false);
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![
            PackRepo { name: "alpha".into(), path: a },
            PackRepo { name: "beta".into(), path: b },
        ],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        &archive,
    );

    // Corrupt alpha's stream bytes (fresh zip, so the CRC is recomputed —
    // the failure surfaces at the manifest checksum).
    let tampered = base.join("tampered.gfxpack");
    rebuild_archive(&archive, &tampered, |name, mut data| {
        if name == "streams/alpha.fi" && !data.is_empty() {
            let n = data.len();
            data[n / 2] ^= 0xFF;
        }
        data
    });

    let dest = base.join("dest");
    let mut opts = default_unpack(&tampered, &dest);
    opts.keep_going = true;
    let report = unpack(&opts).expect("keep-going returns a report");
    assert!(!report.ok());
    let alpha = report.repos.iter().find(|r| r.name == "alpha").unwrap();
    let beta = report.repos.iter().find(|r| r.name == "beta").unwrap();
    assert!(matches!(alpha.status, RepoStatus::Failed(_)), "{alpha:?}");
    assert_eq!(beta.status, RepoStatus::Imported);
    // Sibling repo materialized fully despite the failure.
    gfx::git::process::fsck(&dest.join("beta")).expect("fsck beta");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn dest_safety_and_force() {
    let base = tmpdir("safety");
    let a = make_repo(&base, "alpha", false, false);
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![PackRepo { name: "alpha".into(), path: a }],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        &archive,
    );

    // Existing non-empty destination without --force: refused.
    let dest = base.join("dest");
    std::fs::create_dir_all(dest.join("alpha")).unwrap();
    std::fs::write(dest.join("alpha").join("occupied"), b"x").unwrap();
    let err = unpack(&default_unpack(&archive, &dest)).unwrap_err();
    assert!(matches!(err, gfx_pack::PackError::Usage(_)), "{err}");

    // With --force: imported.
    let mut opts = default_unpack(&archive, &dest);
    opts.force = true;
    let report = unpack(&opts).expect("forced unpack");
    assert!(report.ok(), "{}", report.to_text());
    gfx::git::process::fsck(&dest.join("alpha")).expect("fsck");

    // Override with an unknown repo name: usage error.
    let mut opts = default_unpack(&archive, &base.join("d2"));
    opts.repo_overrides = vec![("ghost".into(), base.join("d2/ghost"))];
    assert!(unpack(&opts).is_err());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn unpack_twice_is_deterministic() {
    // Import determinism (plan §7 testing 3): unpacking the same archive
    // twice yields identical OIDs.
    let base = tmpdir("twice");
    let a = make_repo(&base, "alpha", false, true);
    let archive = base.join("out.gfxpack");
    pack_archive(
        vec![PackRepo { name: "alpha".into(), path: a }],
        vec![PassSpec::StripBlobs(gfx::gfx_strip_blobs::StripBlobsConfig {
            size_threshold: Some(100 * 1024),
            ..Default::default()
        })],
        &archive,
    );
    let d1 = base.join("d1");
    let d2 = base.join("d2");
    assert!(unpack(&default_unpack(&archive, &d1)).unwrap().ok());
    assert!(unpack(&default_unpack(&archive, &d2)).unwrap().ok());
    assert_eq!(refs_of(&d1.join("alpha")), refs_of(&d2.join("alpha")));
    let _ = std::fs::remove_dir_all(&base);
}
