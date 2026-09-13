//! Pack driver integration tests (plan-multistream-pack.md M1): real repos
//! through the fan-out, archive structure + determinism, D3 shared idents.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::driver::PassSpec;
use gfx_pack::manifest::MANIFEST_ENTRY;
use gfx_pack::zip::ZipReader;
use gfx_pack::{pack, PackOptions, PackRepo};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-pack-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn git(dir: &Path, args: &[&str]) {
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
}

/// A bare repo with two commits. Author/committer names are explicit so
/// redact tests can control ident overlap across repos.
fn make_repo(base: &Path, name: &str, author: &str, committer: &str) -> PathBuf {
    let work = base.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("a.txt"), format!("{name} one\n")).unwrap();
    git(&work, &["add", "-A"]);
    let (an, ae) = author.split_once('|').unwrap();
    let (cn, ce) = committer.split_once('|').unwrap();
    git(
        &work,
        &[
            "-c",
            &format!("user.name={an}"),
            "-c",
            &format!("user.email={ae}"),
            "commit",
            "-qm",
            "one",
        ],
    );
    std::fs::write(work.join("b.txt"), format!("{name} two\n")).unwrap();
    git(&work, &["add", "-A"]);
    git(
        &work,
        &[
            "-c",
            &format!("user.name={cn}"),
            "-c",
            &format!("user.email={ce}"),
            "commit",
            "-qm",
            "two",
        ],
    );
    git(&work, &["tag", "v1"]);
    let bare = base.join(format!("{name}.git"));
    git(base, &["clone", "-q", "--bare", &format!("{name}-work"), &format!("{name}.git")]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

fn remap_only() -> Vec<PassSpec> {
    vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())]
}

fn redact_ordinal() -> PassSpec {
    PassSpec::Redact(gfx::gfx_redact::RedactConfig {
        ident_mode: gfx::gfx_redact::IdentMode::Pseudonymize(
            gfx::gfx_redact::PseudonymStyle::Ordinal,
        ),
        ..Default::default()
    })
}

fn open_archive(path: &Path) -> ZipReader<std::fs::File> {
    ZipReader::open(std::fs::File::open(path).unwrap()).expect("archive opens")
}

#[test]
fn pack_two_repos_structure_and_checksums() {
    let base = tmpdir("two");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    let b = make_repo(&base, "beta", "Bob|bob@y.com", "Bob|bob@y.com");
    let out = base.join("out.gfxpack");

    let report = pack(&PackOptions {
        repos: vec![
            PackRepo { name: "alpha".into(), path: a },
            PackRepo { name: "beta".into(), path: b },
        ],
        passes: remap_only(),
        flags_audit: Default::default(),
        out: out.clone(),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
    })
    .expect("pack");

    assert_eq!(report.repos.len(), 2);
    assert!(report.repos.iter().all(|r| r.identity), "remap-only is identity");
    assert!(report.archive_bytes > 0);

    let mut z = open_archive(&out);
    let manifest = gfx_pack::Manifest::parse(
        std::str::from_utf8(&z.extract(MANIFEST_ENTRY).unwrap()).unwrap(),
    )
    .expect("manifest parses");
    assert_eq!(manifest.passes, vec!["remap".to_string()]);
    assert_eq!(manifest.repos.len(), 2);

    for entry in &manifest.repos {
        // Checksum + size in the manifest match the archived stream.
        let stream = z.extract(&entry.stream).unwrap();
        assert_eq!(gfx_pack::sha256_hex(&stream), entry.sha256);
        assert_eq!(stream.len() as u64, entry.bytes);
        assert!(entry.commits >= 2);
        assert!(!entry.refs.is_empty(), "ref tips recorded for D8");
        // The stream itself parses with the strict core parser (D1).
        let mut p = gfx::core::Parser::new(gfx::core::ParseOptions::default());
        p.feed(&stream);
        let mut n = 0;
        while let Some(ev) = p.next_event().unwrap() {
            let _ = ev;
            n += 1;
        }
        assert!(n > 0);
        // Per-repo artifacts are archived.
        assert!(z.contains(&format!("maps/{}/commit-map", entry.name)));
        assert!(z.contains(&format!("maps/{}/ref-map", entry.name)));
        assert!(z.contains(&format!("reports/{}/report.txt", entry.name)));
        // No source paths without --record-source-paths.
        let cm = z.extract(&format!("maps/{}/commit-map", entry.name)).unwrap();
        let cm = String::from_utf8(cm).unwrap();
        assert!(!cm.contains(base.to_str().unwrap()));
    }
    assert!(!z.contains("meta/source-hints.toml"));

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn pack_is_byte_deterministic() {
    let base = tmpdir("det");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    let mk = |out: PathBuf| {
        pack(&PackOptions {
            repos: vec![PackRepo { name: "alpha".into(), path: a.clone() }],
            passes: vec![redact_ordinal()],
            flags_audit: Default::default(),
            out,
            dry_run: false,
            record_source_paths: false,
            encrypt: None,
        })
        .expect("pack")
    };
    let r1 = mk(base.join("one.gfxpack"));
    let r2 = mk(base.join("two.gfxpack"));
    assert_eq!(
        std::fs::read(base.join("one.gfxpack")).unwrap(),
        std::fs::read(base.join("two.gfxpack")).unwrap(),
        "identical inputs ⇒ identical archive bytes (D4)"
    );
    assert_eq!(r1.repos[0].sha256, r2.repos[0].sha256);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn redact_ordinals_are_shared_across_repos() {
    // D3: the same source ident must become the same pseudonym in every
    // stream of one pack run.
    let base = tmpdir("shared");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Carol|carol@z.com");
    let b = make_repo(&base, "beta", "Alice|alice@x.com", "Dave|dave@w.com");
    let out = base.join("out.gfxpack");

    pack(&PackOptions {
        repos: vec![
            PackRepo { name: "alpha".into(), path: a },
            PackRepo { name: "beta".into(), path: b },
        ],
        passes: vec![redact_ordinal()],
        flags_audit: Default::default(),
        out: out.clone(),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
    })
    .expect("pack");

    let mut z = open_archive(&out);
    let sa = String::from_utf8(z.extract("streams/alpha.fi").unwrap()).unwrap();
    let sb = String::from_utf8(z.extract("streams/beta.fi").unwrap()).unwrap();
    for s in [&sa, &sb] {
        assert!(!s.contains("alice@x.com"), "original ident redacted");
        assert!(!s.contains("carol@z.com"));
        assert!(!s.contains("dave@w.com"));
    }
    // Alice is first-seen in alpha ⇒ `user1@example.invalid` everywhere.
    assert!(sa.contains("user1@example.invalid"));
    assert!(sb.contains("user1@example.invalid"), "shared ordinal across repos");
    // Carol only appears in alpha; Dave only in beta — distinct pseudonyms.
    let carol_pseudo = (1..=6u32)
        .map(|i| format!("user{i}@example.invalid"))
        .find(|p| sa.contains(p.as_str()) && p != "user1@example.invalid")
        .expect("carol pseudonym present in alpha");
    assert!(!sb.contains(&carol_pseudo), "carol's ordinal not reused in beta");

    // Archive-level merged ident map exists and records the mapping.
    let idents = String::from_utf8(z.extract("maps/_idents").unwrap()).unwrap();
    assert!(idents.contains("alice@x.com"));
    assert!(idents.contains("user1@example.invalid"));

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn dry_run_writes_no_archive() {
    let base = tmpdir("dry");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    let out = base.join("out.gfxpack");
    let report = pack(&PackOptions {
        repos: vec![PackRepo { name: "alpha".into(), path: a }],
        passes: remap_only(),
        flags_audit: Default::default(),
        out: out.clone(),
        dry_run: true,
        record_source_paths: false,
        encrypt: None,
    })
    .expect("dry-run pack");
    assert!(report.archive.is_none());
    assert!(!out.exists(), "dry-run writes nothing");
    assert!(report.repos[0].commits >= 2);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn usage_errors_are_caught_early() {
    let base = tmpdir("usage");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    let mk = |repos: Vec<PackRepo>| PackOptions {
        repos,
        passes: remap_only(),
        flags_audit: Default::default(),
        out: base.join("x.gfxpack"),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
    };
    // Duplicate slug.
    assert!(pack(&mk(vec![
        PackRepo { name: "alpha".into(), path: a.clone() },
        PackRepo { name: "alpha".into(), path: a.clone() },
    ]))
    .is_err());
    // Bad slug.
    assert!(pack(&mk(vec![PackRepo { name: "../evil".into(), path: a.clone() }])).is_err());
    // Not a repo.
    assert!(pack(&mk(vec![PackRepo { name: "ghost".into(), path: base.join("nope") }])).is_err());
    // Empty repo set.
    assert!(pack(&mk(vec![])).is_err());
    // remap not last.
    assert!(pack(&PackOptions {
        passes: vec![remap_only()[0].clone(), redact_ordinal()],
        ..mk(vec![PackRepo { name: "alpha".into(), path: a.clone() }])
    })
    .is_err());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn strip_blobs_compose_in_pack() {
    let base = tmpdir("strip");
    let work = base.join("big-work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("small.txt"), b"tiny\n").unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    std::fs::write(&work.join("big.bin"), vec![b'x'; 100_000]).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "two"]);
    let bare = base.join("big.git");
    git(&base, &["clone", "-q", "--bare", "big-work", "big.git"]);
    let _ = std::fs::remove_dir_all(&work);

    let out = base.join("out.gfxpack");
    let report = pack(&PackOptions {
        repos: vec![PackRepo { name: "big".into(), path: bare }],
        passes: vec![PassSpec::StripBlobs(gfx::gfx_strip_blobs::StripBlobsConfig {
            size_threshold: Some(1_000),
            ..Default::default()
        })],
        flags_audit: Default::default(),
        out: out.clone(),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
    })
    .expect("pack");

    assert!(!report.repos[0].identity, "strip rewrote the stream");
    assert!(report.repos[0].rewritten > 0);
    let mut z = open_archive(&out);
    let stream = z.extract("streams/big.fi").unwrap();
    assert!(
        !stream.windows(7).any(|w| w == b"big.bin"),
        "stripped path absent from archived stream"
    );
    let _ = std::fs::remove_dir_all(&base);
}
