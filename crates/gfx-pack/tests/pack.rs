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
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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
            passes: vec![
                PassSpec::BlobXform(gfx::gfx_blob_xform::BlobXformConfig {
                    transforms: gfx::gfx_blob_xform::builtins::all(),
                    path_rules: vec![gfx::gfx_blob_xform::PathRule {
                        extension: b"txt".to_vec(),
                        transforms: vec![gfx::gfx_blob_xform::SharedBlobTransform(
                            std::sync::Arc::new(|b: &[u8]| -> Result<Vec<u8>, ()> {
                                Ok(b.iter().map(u8::to_ascii_uppercase).collect())
                            }),
                        )],
                        skip_larger_than: None,
                        max_output_bytes: None,
                    }],
                    ..Default::default()
                }),
                redact_ordinal(),
            ],
            flags_audit: Default::default(),
            out,
            dry_run: false,
            record_source_paths: false,
            encrypt: None,
            jobs: None,
            save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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
fn pack_is_deterministic_under_parallelism() {
    // D6: archive bytes are independent of worker count and completion
    // order. Four repos, a blob-xform (whole-blob + path rules) + redact
    // chain — transforms under fan-out, per-repo synthetic mark bases
    // (plan-blob-xform-paths.md D10), AND the shared-ordinal pre-scan —
    // jobs 1 vs 4 ⇒ byte-identical archives.
    let base = tmpdir("par");
    let repos: Vec<PackRepo> = ["r1", "r2", "r3", "r4"]
        .iter()
        .map(|n| PackRepo {
            name: n.to_string(),
            path: make_repo(&base, n, "Alice|alice@x.com", "Alice|alice@x.com"),
        })
        .collect();
    let mk = |jobs: Option<usize>, out: PathBuf| {
        pack(&PackOptions {
            repos: repos.clone(),
            passes: vec![
                PassSpec::BlobXform(gfx::gfx_blob_xform::BlobXformConfig {
                    transforms: gfx::gfx_blob_xform::builtins::all(),
                    path_rules: vec![gfx::gfx_blob_xform::PathRule {
                        extension: b"txt".to_vec(),
                        transforms: vec![gfx::gfx_blob_xform::SharedBlobTransform(
                            std::sync::Arc::new(|b: &[u8]| -> Result<Vec<u8>, ()> {
                                Ok(b.iter().map(u8::to_ascii_uppercase).collect())
                            }),
                        )],
                        skip_larger_than: None,
                        max_output_bytes: None,
                    }],
                    ..Default::default()
                }),
                redact_ordinal(),
            ],
            flags_audit: Default::default(),
            out,
            dry_run: false,
            record_source_paths: false,
            encrypt: None,
            jobs,
            save_remotes: false,
        allow_credential_urls: false,
        progress: false,
        })
        .expect("pack")
    };
    mk(Some(1), base.join("j1.gfxpack"));
    mk(Some(4), base.join("j4.gfxpack"));
    assert_eq!(
        std::fs::read(base.join("j1.gfxpack")).unwrap(),
        std::fs::read(base.join("j4.gfxpack")).unwrap(),
        "jobs=1 and jobs=4 produce identical archives"
    );
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
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
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

// ---------------------------------------------------------------------------
// Remote-data capture (plan-remote-data.md M1).

fn add_remote_config(repo: &Path) {
    git(repo, &["config", "remote.origin.url", "https://example.com/org/r.git"]);
    git(repo, &["config", "remote.origin.pushurl", "ssh://git@example.com/org/r.git"]);
    git(repo, &["config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"]);
    git(repo, &["config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*"]);
    git(repo, &["config", "branch.main.remote", "origin"]);
    git(repo, &["config", "branch.main.merge", "refs/heads/main"]);
    git(repo, &["config", "credential.helper", "store"]); // executable: must NOT travel
}

#[test]
fn pack_save_remotes_captures_allowlisted_config() {
    let base = tmpdir("rmt");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    add_remote_config(&a);
    let b = make_repo(&base, "beta", "Bob|bob@y.com", "Bob|bob@y.com"); // no remotes
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
        jobs: None,
        save_remotes: true,
        allow_credential_urls: false,
        progress: false,
    })
    .expect("pack");

    // Per-repo report.
    let rs = report.repos[0].remotes_saved.as_ref().expect("alpha captured");
    assert_eq!(rs.keys, 5, "url/pushurl/fetch + 2 branch keys (fetch counts once)");
    assert_eq!(rs.skipped, 1, "credential.helper dropped (D2)");
    // beta is a bare clone: clone itself recorded `remote.origin.url`
    // (a host path — saving remotes exposes it, like record-source-paths;
    // documented in M4). One key, nothing skipped.
    let rsb = report.repos[1].remotes_saved.as_ref().unwrap();
    assert_eq!(rsb.keys, 1, "bare clone's origin url: {rsb:?}");
    assert_eq!(rsb.skipped, 0);

    // Archive member: exact NUL-framed state, allowlisted only.
    let mut z = open_archive(&out);
    let member = z.extract("remotes/alpha.config").expect("member present");
    let state = gfx::remotes::RemoteState::parse_z(&member).unwrap();
    let keys: Vec<&str> = state.entries.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "remote.origin.url",
            "remote.origin.pushurl",
            "remote.origin.fetch",
            "remote.origin.fetch",
            "branch.main.remote",
            "branch.main.merge",
        ],
        "allowlisted, config order, multi-valued fetch preserved"
    );
    let beta_state =
        gfx::remotes::RemoteState::parse_z(&z.extract("remotes/beta.config").unwrap()).unwrap();
    assert_eq!(
        beta_state.entries.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        vec!["remote.origin.url"],
        "only the clone-recorded origin url"
    );

    // Manifest pins the member bytes (C4).
    let manifest = gfx_pack::manifest::Manifest::parse(
        std::str::from_utf8(&z.extract(MANIFEST_ENTRY).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest.repos[0].remotes_sha256.as_deref(),
        Some(gfx_pack::sha256_hex(&member).as_str()),
        "remotes-sha256 pins the member bytes"
    );
    assert!(manifest.repos[1].remotes_sha256.is_some());

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn pack_save_remotes_fails_closed_on_credential_urls() {
    let base = tmpdir("rmtc");
    let a = make_repo(&base, "alpha", "Alice|alice@x.com", "Alice|alice@x.com");
    git(&a, &["config", "remote.origin.url", "https://ci-user:sekret-token@example.com/r.git"]);

    let mk = |allow: bool| PackOptions {
        repos: vec![PackRepo { name: "alpha".into(), path: a.clone() }],
        passes: remap_only(),
        flags_audit: Default::default(),
        out: base.join(if allow { "ok.gfxpack" } else { "no.gfxpack" }),
        dry_run: false,
        record_source_paths: false,
        encrypt: None,
        jobs: None,
        save_remotes: true,
        allow_credential_urls: allow,
        progress: false,
    };

    let err = pack(&mk(false)).expect_err("credential URL must fail closed (D3)");
    let msg = err.to_string();
    assert!(msg.contains("credentials"), "{msg}");
    assert!(msg.contains("remote.origin.url"), "names the key, not the value: {msg}");
    assert!(!msg.contains("sekret-token"), "never echo the secret: {msg}");
    assert!(!base.join("no.gfxpack").exists(), "no partial archive");

    // Explicit override captures the URL verbatim (restore needs it).
    pack(&mk(true)).expect("override");
    let mut z = open_archive(&base.join("ok.gfxpack"));
    let member = z.extract("remotes/alpha.config").unwrap();
    let state = gfx::remotes::RemoteState::parse_z(&member).unwrap();
    assert_eq!(
        state.get_all("remote.origin.url"),
        vec!["https://ci-user:sekret-token@example.com/r.git"],
        "verbatim capture under the override"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn pack_save_remotes_deterministic_under_parallelism() {
    // D6 × plan-remote-data: capture happens in export workers; archives
    // must not depend on job count.
    let mk_repos = |tag: &str| -> (PathBuf, Vec<PackRepo>) {
        let base = tmpdir(tag);
        let names = ["r1", "r2", "r3", "r4"];
        let mut repos = Vec::new();
        for n in names {
            let p = make_repo(&base, n, "Alice|alice@x.com", "Alice|alice@x.com");
            add_remote_config(&p);
            repos.push(PackRepo { name: n.to_string(), path: p });
        }
        (base, repos)
    };
    let (base, repos) = mk_repos("rmtdet");
    let build = |jobs: usize, out: &str| -> Vec<u8> {
        pack(&PackOptions {
            repos: repos.clone(),
            passes: remap_only(),
            flags_audit: Default::default(),
            out: base.join(out),
            dry_run: false,
            record_source_paths: false,
            encrypt: None,
            jobs: Some(jobs),
            save_remotes: true,
            allow_credential_urls: false,
            progress: false,
        })
        .expect("pack");
        std::fs::read(base.join(out)).unwrap()
    };
    let one = build(1, "j1.gfxpack");
    let four = build(4, "j4.gfxpack");
    assert_eq!(one, four, "byte-identical archives across --jobs (D6)");
    let _ = std::fs::remove_dir_all(&base);
}
