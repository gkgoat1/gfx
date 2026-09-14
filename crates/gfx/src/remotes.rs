//! Remote-data capture and restore (docs/plan-remote-data.md).
//!
//! "Remote data" is the repository-local configuration that connects a
//! repo to its servers: `remote.*` data keys, `branch.*` tracking keys,
//! and LFS endpoint URLs — captured with `git config --list --local -z`
//! (NUL-framed; R7), filtered through a fixed **allowlist** (D1), and
//! restorable after a rewrite or a pack unpack.
//!
//! Two safety properties are load-bearing:
//!
//! - **Executable keys never travel (D2).** `credential.helper`,
//!   `remote.*.uploadpack`/`receivepack`, and everything else outside the
//!   allowlist is dropped at capture; restore re-filters (defense in
//!   depth against hand-edited archives). The drop is reported via
//!   `skipped`.
//! - **Credentials in URLs are detected, never silently carried (D3).**
//!   `CaptureOutcome::credential_keys` names the offending keys (never
//!   the values); the pack flow fails closed on them, the in-repo flow
//!   warns. "Credential" = a password/token in userinfo (`user:pass@`),
//!   or any userinfo on `http(s)` (bare-token URLs); a bare username on
//!   `ssh://` is an identity, not flagged.

extern crate std;

use alloc::format;
use alloc::vec;
use std::fmt;
use std::path::Path;
use alloc::string::{String, ToString};
use std::vec::Vec;

use crate::git::process::{run, GitError};

/// Allowlisted `remote.<name>.<sub>` keys (plan R6). Data only — anything
/// that causes git to execute a command is deliberately absent.
const REMOTE_SUBKEYS: &[&str] = &[
    "url",
    "pushurl",
    "fetch",
    "mirror",
    "prune",
    "prunetags",
    "tagopt",
    "promisor",
    "partialclonefilter",
    "proxy",
    "serveroption",
    "skipdefaultupdate",
    "followremotehead",
];

/// Allowlisted `branch.<name>.<sub>` tracking keys (plan R6).
const BRANCH_SUBKEYS: &[&str] = &["remote", "merge", "pushremote", "rebase", "description"];

/// Is `key` on the capture allowlist (plan D1)?
///
/// `git config --list` lowercases the section and key-name segments and
/// preserves subsection case, so exact lowercase matching is correct.
pub fn is_allowed_key(key: &str) -> bool {
    if key == "lfs.url" {
        return true;
    }
    if let Some(rest) = key.strip_prefix("remote.") {
        return match rest.rsplit_once('.') {
            Some((name, sub)) => !name.is_empty() && REMOTE_SUBKEYS.contains(&sub),
            None => false,
        };
    }
    if let Some(rest) = key.strip_prefix("branch.") {
        return match rest.rsplit_once('.') {
            Some((name, sub)) => !name.is_empty() && BRANCH_SUBKEYS.contains(&sub),
            None => false,
        };
    }
    if let Some(rest) = key.strip_prefix("lfs.") {
        // lfs.<name>.url — endpoint URLs only, not locksverify &c.
        return rest.len() > ".url".len() && rest.ends_with(".url");
    }
    false
}

/// Is `key` in the remote-data domain at all (whether or not allowed)?
/// Used for the `skipped` count: we report remote-ish keys we dropped,
/// not the entire rest of the config (core.*, user.*, …).
fn is_remote_domain(key: &str) -> bool {
    key.starts_with("remote.")
        || key.starts_with("branch.")
        || key.starts_with("lfs.")
        || key.starts_with("credential.")
}

/// Is `key` URL-valued (worth a credential scan)?
fn is_url_valued(key: &str) -> bool {
    key.ends_with(".url") || key.ends_with(".pushurl") || key.ends_with(".proxy")
}

/// Does `url` embed a credential (plan D3)? True when the authority has
/// userinfo with a password (`user:pass@`) for any scheme, or ANY
/// userinfo on `http`/`https` (bare-token URLs: `https://TOKEN@host`).
/// A bare username on other schemes (`ssh://git@host`) and scp-like
/// syntax (`git@host:path`) are identities, not credentials.
pub fn contains_credential(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // RFC 3986: userinfo is everything before the LAST '@' in authority.
    let Some(at) = authority.rfind('@') else {
        return false;
    };
    let userinfo = &authority[..at];
    userinfo.contains(':') || scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
}

/// Render `url` with any userinfo replaced by `***` (audit-safe logging).
pub fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // RFC 3986: userinfo is everything before the LAST '@' in authority.
    match authority.rfind('@') {
        Some(at) => format!("{scheme}://***@{}{}", &authority[at + 1..], &rest[authority_end..]),
        None => url.to_string(),
    }
}

/// An ordered list of `(key, value)` config entries, in `git config
/// --list` (file) order — stable per repo state, so captures are
/// deterministic (plan C3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteState {
    pub entries: Vec<(String, String)>,
}

impl RemoteState {
    /// Parse NUL-framed `git config --list -z` output (`key\nvalue\0`).
    /// NUL cannot appear in git config keys or values, so framing is
    /// injective; values may contain newlines (R7).
    pub fn parse_z(bytes: &[u8]) -> Result<Self, RemoteDataError> {
        let mut entries = Vec::new();
        for frame in bytes.split(|b| *b == 0) {
            if frame.is_empty() {
                continue; // trailing frame after the final NUL
            }
            let s = std::str::from_utf8(frame)
                .map_err(|_| RemoteDataError::Malformed("config frame is not UTF-8".into()))?;
            let Some((k, v)) = s.split_once('\n') else {
                return Err(RemoteDataError::Malformed(format!(
                    "config frame lacks a key/value separator: {s:?}"
                )));
            };
            entries.push((k.to_string(), v.to_string()));
        }
        Ok(Self { entries })
    }

    /// Inverse of [`Self::parse_z`].
    pub fn serialize_z(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.entries {
            out.extend_from_slice(k.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(v.as_bytes());
            out.push(0);
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Values of `key`, in order (multi-valued keys appear repeatedly).
    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Human-readable rendering with URL userinfo redacted (D3 audit).
    pub fn render_text(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.entries {
            let shown = if is_url_valued(k) { redact_userinfo(v) } else { v.clone() };
            s.push_str(&format!("{k}={}\n", shown.replace('\n', "\\n")));
        }
        s
    }
}

/// Result of filtering a raw config dump through the allowlist.
#[derive(Clone, Debug, Default)]
pub struct CaptureOutcome {
    pub state: RemoteState,
    /// Remote-domain keys dropped by the allowlist (D2 — e.g.
    /// `credential.helper`, `remote.*.uploadpack`).
    pub skipped: u64,
    /// Allowlisted URL-valued keys whose value carries userinfo (D3).
    /// Key names only — never the values.
    pub credential_keys: Vec<String>,
}

/// Pure half of capture (unit-testable): filter a full local config dump.
pub fn filter_allowed(all: RemoteState) -> CaptureOutcome {
    let mut out = CaptureOutcome::default();
    for (k, v) in all.entries {
        if is_allowed_key(&k) {
            if is_url_valued(&k) && contains_credential(&v) {
                out.credential_keys.push(k.clone());
            }
            out.state.entries.push((k, v));
        } else if is_remote_domain(&k) {
            out.skipped += 1;
        }
    }
    out
}

/// Capture the repo's allowlisted remote data (D1, C5).
pub fn capture(repo: &Path) -> Result<CaptureOutcome, RemoteDataError> {
    let raw = run(repo, &["config", "--list", "--local", "-z"])?;
    Ok(filter_allowed(RemoteState::parse_z(&raw)?))
}

/// Capture `refs/remotes/*` as `(refname, oid)` pairs (for the
/// `--remote-refs pin` policy, plan D6).
pub fn capture_remote_refs(repo: &Path) -> Result<Vec<(String, String)>, RemoteDataError> {
    let out = run(
        repo,
        &["for-each-ref", "--format=%(refname) %(objectname)", "refs/remotes/"],
    )?;
    let text = String::from_utf8(out)
        .map_err(|_| RemoteDataError::Malformed("for-each-ref output is not UTF-8".into()))?;
    let mut refs = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((name, oid)) = line.split_once(' ') else {
            return Err(RemoteDataError::Malformed(format!(
                "for-each-ref line lacks a separator: {line:?}"
            )));
        };
        refs.push((name.to_string(), oid.to_string()));
    }
    Ok(refs)
}

/// How [`restore`] applies a captured state (plan D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreMode {
    /// Unset each captured key, then add each captured value in order —
    /// exact, idempotent (fresh unpack destinations; safe to repeat).
    Overwrite,
    /// Add only keys that are entirely absent locally; keys present with
    /// different values are reported as drift, never overwritten
    /// (in-repo restores, where the live repo's own choices win).
    AddMissing,
}

#[derive(Clone, Debug, Default)]
pub struct RestoreReport {
    /// Distinct keys written.
    pub keys_set: u64,
    /// Total `--add` operations.
    pub values_added: u64,
    /// Keys present locally with different values (AddMissing only).
    pub drift: Vec<String>,
    /// Allowlisted-but-dropped entries encountered in the input (defense
    /// in depth — should be zero for captures produced by [`capture`]).
    pub rejected: u64,
}

/// Apply `state` to `repo`'s local config. Re-filters through the
/// allowlist (defense in depth: archive members are attacker-editable).
pub fn restore(
    repo: &Path,
    state: &RemoteState,
    mode: RestoreMode,
) -> Result<RestoreReport, RemoteDataError> {
    let mut report = RestoreReport::default();
    // Group values by key, preserving first-seen key order.
    let mut order: Vec<String> = Vec::new();
    let mut values: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in &state.entries {
        if !is_allowed_key(k) {
            report.rejected += 1;
            continue;
        }
        match values.iter_mut().find(|(ek, _)| ek == k) {
            Some((_, vs)) => vs.push(v.clone()),
            None => {
                order.push(k.clone());
                values.push((k.clone(), vec![v.clone()]));
            }
        }
    }

    let live = match mode {
        RestoreMode::AddMissing => Some(capture(repo)?.state),
        RestoreMode::Overwrite => None,
    };

    for (k, vs) in &values {
        let write_values: &[String] = match mode {
            RestoreMode::Overwrite => {
                // Missing key ⇒ exit 5; ignore (fresh repos have nothing).
                let _ = run(repo, &["config", "--unset-all", k]);
                vs
            }
            RestoreMode::AddMissing => {
                let live = live.as_ref().expect("live captured for AddMissing");
                let existing = live.get_all(k);
                if existing.is_empty() {
                    vs
                } else {
                    if existing != vs.iter().map(String::as_str).collect::<Vec<_>>() {
                        report.drift.push(k.clone());
                    }
                    &[]
                }
            }
        };
        for v in write_values {
            run(repo, &["config", "--add", k, v])?;
            report.values_added += 1;
        }
        if !write_values.is_empty() {
            report.keys_set += 1;
        }
    }
    Ok(report)
}

/// Delete every `refs/remotes/*` ref (plan D5/D6 `drop`). Returns the
/// number dropped.
pub fn drop_remote_refs(repo: &Path) -> Result<u64, RemoteDataError> {
    let refs = capture_remote_refs(repo)?;
    for (name, _) in &refs {
        run(repo, &["update-ref", "-d", name])?;
    }
    Ok(refs.len() as u64)
}

/// Point `refs/remotes/*` back at captured pre-rewrite OIDs (plan D6
/// `pin`). Keeps pre-rewrite objects reachable — the operator's call.
pub fn pin_remote_refs(repo: &Path, saved: &[(String, String)]) -> Result<u64, RemoteDataError> {
    for (name, oid) in saved {
        run(repo, &["update-ref", name, oid])?;
    }
    Ok(saved.len() as u64)
}

/// Errors from remote-data capture/restore. Parse failures are `Malformed`;
/// subprocess failures pass through as `Git`.
#[derive(Debug)]
pub enum RemoteDataError {
    Malformed(String),
    Git(GitError),
}

impl fmt::Display for RemoteDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteDataError::Malformed(m) => write!(f, "remote data: {m}"),
            RemoteDataError::Git(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RemoteDataError {}

impl From<GitError> for RemoteDataError {
    fn from(e: GitError) -> Self {
        RemoteDataError::Git(e)
    }
}
