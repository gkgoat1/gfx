//! Encryption integration tests (plan-multistream-pack.md M3): encrypted
//! archives round-trip through pack → decrypt → unpack; wrong keys and
//! truncation fail closed.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::driver::PassSpec;
use gfx_pack::{pack, unpack, EncryptSpec, PackOptions, PackRepo, SecretString, UnpackOptions};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmpdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("gfx-crypto-{tag}-{}-{n}", std::process::id()));
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

fn make_repo(base: &Path, name: &str) -> PathBuf {
    let work = base.join(format!("{name}-work"));
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    std::fs::write(work.join("a.txt"), format!("{name}\n")).unwrap();
    git(&work, &["add", "-A"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one"]);
    let bare = base.join(format!("{name}.git"));
    git(base, &["clone", "-q", "--bare", &format!("{name}-work"), &format!("{name}.git")]);
    let _ = std::fs::remove_dir_all(&work);
    bare
}

#[test]
fn encrypted_recipient_round_trip() {
    let base = tmpdir("age");
    let repo = make_repo(&base, "alpha");
    let id = gfx_pack::x25519::Identity::generate();
    let id_file = base.join("key.txt");
    std::fs::write(
        &id_file,
        format!(
            "# test key\n{}\n",
            gfx_pack::crypto::secrecy::ExposeSecret::expose_secret(&id.to_string())
        ),
    )
    .unwrap();

    let out = base.join("org.gfxpack");
    let report = pack(&PackOptions {
        repos: vec![PackRepo { name: "alpha".into(), path: repo }],
        passes: vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        flags_audit: Default::default(),
        out,
        dry_run: false,
        record_source_paths: false,
        encrypt: Some(EncryptSpec::Recipients(vec![id.to_public()])),
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
    })
    .expect("pack");

    // Destination gained .age and holds an age file, not a zip.
    let archive = report.archive.clone().unwrap();
    assert!(archive.to_string_lossy().ends_with(".age"), "{archive:?}");
    let head = std::fs::read(&archive).unwrap();
    assert!(head.starts_with(b"age-encryption.org/v1"), "age magic");
    assert!(!head.starts_with(b"PK"), "not a raw zip");

    // Without the identity: fail closed.
    let err = unpack(&UnpackOptions {
        archive: archive.clone(),
        dest_root: Some(base.join("d0")),
        ..Default::default()
    })
    .unwrap_err();
    assert!(format!("{err}").contains("--identity"), "{err}");

    // With the identity: full unpack.
    let dest = base.join("dest");
    let report = unpack(&UnpackOptions {
        archive,
        dest_root: Some(dest.clone()),
        identity_files: vec![id_file],
        ..Default::default()
    })
    .expect("decrypting unpack");
    assert!(report.ok(), "{}", report.to_text());
    gfx::git::process::fsck(&dest.join("alpha")).expect("fsck");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn encrypted_passphrase_round_trip_and_wrong_pass() {
    let base = tmpdir("pass");
    let repo = make_repo(&base, "alpha");
    let out = base.join("org.gfxpack");
    let report = pack(&PackOptions {
        repos: vec![PackRepo { name: "alpha".into(), path: repo }],
        passes: vec![PassSpec::Remap(gfx::gfx_remap::RemapConfig::default())],
        flags_audit: Default::default(),
        out,
        dry_run: false,
        record_source_paths: false,
        encrypt: Some(EncryptSpec::Passphrase(SecretString::from("hunter2"))),
        jobs: None,
        save_remotes: false,
        allow_credential_urls: false,
        progress: false,
    })
    .expect("pack");

    let archive = report.archive.clone().unwrap();
    // Wrong passphrase fails closed.
    assert!(unpack(&UnpackOptions {
        archive: archive.clone(),
        dest_root: Some(base.join("d0")),
        passphrase: Some(SecretString::from("hunter3")),
        ..Default::default()
    })
    .is_err());

    let dest = base.join("dest");
    let report = unpack(&UnpackOptions {
        archive,
        dest_root: Some(dest.clone()),
        passphrase: Some(SecretString::from("hunter2")),
        ..Default::default()
    })
    .expect("passphrase unpack");
    assert!(report.ok(), "{}", report.to_text());
    gfx::git::process::fsck(&dest.join("alpha")).expect("fsck");
    let _ = std::fs::remove_dir_all(&base);
}
