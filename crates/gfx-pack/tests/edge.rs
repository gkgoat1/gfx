//! Hardening tests (plan-multistream-pack.md M5): randomized multi-repo
//! round-trips over nasty shapes (empty repos, annotated tags, fully
//! stripped commits, sha256), and failure-injection hygiene (no partial
//! archives, no spool litter).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::driver::PassSpec;
use gfx_pack::{pack, unpack, PackOptions, PackRepo, UnpackOptions};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Tests in this binary run in threads sharing one temp dir; the litter
/// assertions in `failed_pack_leaves_no_archive_and_no_litter` count spool
/// dirs by pattern, so every test here serializes on one lock.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-edge-{tag}-{}-{n}", std::process::id()));
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

fn refs_of(repo: &Path) -> BTreeMap<String, String> {
    git(repo, &["for-each-ref", "--format=%(objectname) %(refname)"])
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(oid, name)| (name.to_string(), oid.to_string()))
        .collect()
}

fn opts(repos: Vec<PackRepo>, passes: Vec<PassSpec>, out: PathBuf) -> PackOptions {
    PackOptions {
        repos,
        passes,
        flags_audit: Default::default(),
        out,
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
        jobs: None,
        progress: false,
    }
}

fn unpack_to(archive: &Path, dest: &Path) -> gfx_pack::UnpackReport {
    unpack(&UnpackOptions {
        archive: archive.to_path_buf(),
        dest_root: Some(dest.to_path_buf()),
        ..Default::default()
    })
    .expect("unpack")
}

/// Deterministic xorshift PRNG — no rand dependency.
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Build one randomized bare repo. Returns its path.
fn random_repo(base: &Path, name: &str, rng: &mut Prng) -> PathBuf {
    let work = base.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).unwrap();
    let sha256 = rng.below(4) == 0;
    if sha256 {
        git(&work, &["init", "-q", "--object-format=sha256"]);
    } else {
        git(&work, &["init", "-q"]);
    }
    let id = ["-c", "user.email=t@t", "-c", "user.name=T"];
    let commits = rng.below(5); // 0–4 commits
    for c in 0..commits {
        if rng.below(3) == 0 {
            std::fs::write(work.join(format!("big{c}.bin")), vec![b'x'; 150_000]).unwrap();
        } else {
            std::fs::write(work.join(format!("f{c}.txt")), format!("{name} {c}\n")).unwrap();
        }
        git(&work, &["add", "-A"]);
        git(&work, &[&id[..], &["commit", "-qm", &format!("c{c}")][..]].concat());
    }
    if commits > 0 {
        match rng.below(3) {
            0 => {
                git(&work, &["tag", "v1"]);
            }
            1 => {
                git(&work, &[&id[..], &["tag", "-am", "annotated", "v1"][..]].concat());
            }
            _ => {}
        }
    }
    let bare = base.join(format!("{name}.git"));
    git(base, &["clone", "-q", "--bare", &format!("{name}-work"), &format!("{name}.git")]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

#[test]
fn randomized_multi_repo_round_trips() {
    let _guard = TEST_LOCK.lock().unwrap();
    for seed in [1u64, 7, 42, 1337] {
        let mut rng = Prng(seed << 32 | 0x9E3779B9);
        let base = tmpdir(&format!("prop{seed}"));
        let n = 1 + rng.below(3); // 1–3 repos
        let mut repos = Vec::new();
        let mut sources = Vec::new();
        for i in 0..n {
            let name = format!("r{i}");
            let path = random_repo(&base, &name, &mut rng);
            sources.push(path.clone());
            repos.push(PackRepo { name, path });
        }
        let passes = match rng.below(3) {
            0 => vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
            1 => vec![PassSpec::StripBlobs(gfx::gfx_strip_blobs::StripBlobsConfig {
                size_threshold: Some(100 * 1024),
                ..Default::default()
            })],
            _ => vec![PassSpec::Redact(gfx::gfx_redact::RedactConfig {
                ident_mode: gfx::gfx_redact::IdentMode::Pseudonymize(
                    gfx::gfx_redact::PseudonymStyle::Ordinal,
                ),
                ..Default::default()
            })],
        };
        let identity = matches!(&passes[0], PassSpec::Remap(_));
        let archive = base.join("out.gfxpack");
        pack(&opts(repos, passes, archive.clone())).expect("pack");
        let dest = base.join("dest");
        let report = unpack_to(&archive, &dest);
        assert!(report.ok(), "seed {seed}: {}", report.to_text());
        for (i, src) in sources.iter().enumerate() {
            let dst = dest.join(format!("r{i}"));
            gfx::git::process::fsck(&dst).unwrap_or_else(|e| panic!("seed {seed} r{i}: {e}"));
            let src_refs = refs_of(src);
            let dst_refs = refs_of(&dst);
            if identity {
                assert_eq!(src_refs, dst_refs, "seed {seed} r{i}: identity refs");
            } else {
                assert_eq!(
                    src_refs.len(),
                    dst_refs.len(),
                    "seed {seed} r{i}: same ref set"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[test]
fn empty_repo_round_trip() {
    let _guard = TEST_LOCK.lock().unwrap();
    let base = tmpdir("empty");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    let bare = base.join("empty.git");
    git(&base, &["clone", "-q", "--bare", "work", "empty.git"]);
    let _ = std::fs::remove_dir_all(&work);

    let archive = base.join("out.gfxpack");
    let report = pack(&opts(
        vec![PackRepo { name: "empty".into(), path: bare }],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        archive.clone(),
    ))
    .expect("pack empty repo");
    assert_eq!(report.repos[0].commits, 0);

    let dest = base.join("dest");
    let report = unpack_to(&archive, &dest);
    assert!(report.ok(), "{}", report.to_text());
    gfx::git::process::fsck(&dest.join("empty")).expect("fsck");
    assert!(refs_of(&dest.join("empty")).is_empty());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn annotated_tag_round_trip_preserves_tag_object() {
    let _guard = TEST_LOCK.lock().unwrap();
    let base = tmpdir("tag");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("a.txt"), b"one\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    git(
        &work,
        &["-c", "user.email=t@t", "-c", "user.name=T", "tag", "-am", "release notes", "v1"],
    );
    let bare = base.join("tag.git");
    git(&base, &["clone", "-q", "--bare", "work", "tag.git"]);
    let _ = std::fs::remove_dir_all(&work);
    let tag_msg = git(&bare, &["tag", "-l", "--format=%(contents)", "v1"]);
    assert!(tag_msg.contains("release notes"));

    let archive = base.join("out.gfxpack");
    pack(&opts(
        vec![PackRepo { name: "tag".into(), path: bare.clone() }],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        archive.clone(),
    ))
    .expect("pack");
    let dest = base.join("dest");
    assert!(unpack_to(&archive, &dest).ok());
    assert_eq!(refs_of(&bare), refs_of(&dest.join("tag")));
    let msg = git(&dest.join("tag"), &["tag", "-l", "--format=%(contents)", "v1"]);
    assert!(msg.contains("release notes"), "annotated tag object preserved");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn fully_stripped_commit_round_trip() {
    let _guard = TEST_LOCK.lock().unwrap();
    // The only file exceeds the threshold: the commit survives with zero
    // ops (D1 of the strip pass), and the round-trip must still work.
    let base = tmpdir("allstrip");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("big.bin"), vec![b'x'; 150_000]).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    let bare = base.join("allstrip.git");
    git(&base, &["clone", "-q", "--bare", "work", "allstrip.git"]);
    let _ = std::fs::remove_dir_all(&work);

    let archive = base.join("out.gfxpack");
    pack(&opts(
        vec![PackRepo { name: "allstrip".into(), path: bare }],
        vec![PassSpec::StripBlobs(gfx::gfx_strip_blobs::StripBlobsConfig {
            size_threshold: Some(100 * 1024),
            ..Default::default()
        })],
        archive.clone(),
    ))
    .expect("pack");
    let dest = base.join("dest");
    let report = unpack_to(&archive, &dest);
    assert!(report.ok(), "{}", report.to_text());
    let dst = dest.join("allstrip");
    gfx::git::process::fsck(&dst).expect("fsck");
    assert_eq!(git(&dst, &["rev-list", "--all", "--count"]).trim(), "1");
    assert!(git(&dst, &["log", "--all", "--oneline", "--", "big.bin"]).trim().is_empty());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn failed_pack_leaves_no_archive_and_no_litter() {
    let _guard = TEST_LOCK.lock().unwrap();
    let base = tmpdir("fail");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("a.txt"), b"one\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    let bare = base.join("ok.git");
    git(&base, &["clone", "-q", "--bare", "work", "ok.git"]);
    let _ = std::fs::remove_dir_all(&work);

    // Assembly fails: the output directory is read-only.
    let ro = base.join("readonly");
    std::fs::create_dir_all(&ro).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let out = ro.join("out.gfxpack");
    let spool_dirs = || -> std::collections::BTreeSet<String> {
        std::env::temp_dir()
            .read_dir()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("gfx-pack-run-"))
            .collect()
    };
    let before = spool_dirs();
    let result = pack(&opts(
        vec![PackRepo { name: "ok".into(), path: bare }],
        vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        out.clone(),
    ));
    #[cfg(unix)]
    {
        assert!(result.is_err(), "read-only output dir must fail");
        assert!(!out.exists(), "no archive");
        let partials: Vec<_> = std::fs::read_dir(&ro)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("partial"))
            .collect();
        assert!(partials.is_empty(), "no partial archives left behind: {partials:?}");
        // Spool dirs are drop-cleaned even on the error path: the failed
        // call added nothing to the set present before it ran.
        let after = spool_dirs();
        let leaked: Vec<_> = after.difference(&before).collect();
        assert!(leaked.is_empty(), "spool litter: {leaked:?}");
        // Restore writability so cleanup works.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (result, before, spool_dirs);
    }
    let _ = std::fs::remove_dir_all(&base);
}
