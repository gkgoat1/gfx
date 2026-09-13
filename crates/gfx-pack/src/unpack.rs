//! Unpack driver (plan-multistream-pack.md §3, M2): the exact reverse of
//! [`crate::pack`] — verify the manifest and per-stream checksums, create
//! fresh repositories, `git fast-import` each stream, finalize each commit
//! map from the import's marks (D8), assert ref tips, and drop per-repo
//! artifacts into each destination's `<gitdir>/gfx/`.
//!
//! The rewritten-vs-unchanged classification of commits is not
//! re-derivable from the archived stream alone (the passes' pre-images are
//! gone), so it travels in the archive: `maps/<name>/commit-map` marks
//! rewritten commits with a `-` new side (pack-time classification), and
//! unpack re-flags those marks before finalizing. The D8 tip assertions
//! keep the classification honest — a lying archive fails verification.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::core::{MarkFile, Oid, ParseOptions, Parser};
use gfx::git::process as git;
use gfx::gfx_remap::{Remap, RemapConfig};

use crate::manifest::{Manifest, RepoEntry, MANIFEST_ENTRY};
use crate::zip::ZipReader;
use crate::{PackError, Sha256};

/// Unpack invocation.
#[derive(Clone, Debug, Default)]
pub struct UnpackOptions {
    pub archive: PathBuf,
    /// Default parent directory for per-repo destinations (`./<name>`).
    /// Defaults to the current directory.
    pub dest_root: Option<PathBuf>,
    /// Explicit per-repo destinations, overriding `dest_root`.
    pub repo_overrides: Vec<(String, PathBuf)>,
    /// Verify manifest + checksums + decryptability only; create nothing.
    pub verify_only: bool,
    /// Attempt every repo even when some fail; report per-repo status (D7).
    pub keep_going: bool,
    /// Allow importing into an existing non-empty destination.
    pub force: bool,
    /// Create non-bare repositories (default: bare).
    pub worktree: bool,
    /// age identity files for recipient-encrypted archives (D5).
    pub identity_files: Vec<PathBuf>,
    /// Passphrase for passphrase-encrypted archives (CLI sources it from
    /// `GFX_PACK_PASSPHRASE`, never argv).
    pub passphrase: Option<age::secrecy::SecretString>,
}

/// Per-repo outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoStatus {
    /// Checksums verified (verify-only mode).
    Verified,
    /// Imported, tips asserted, artifacts written.
    Imported,
    /// This repo failed; `keep_going` continued with the rest.
    Failed(String),
}

/// Per-repo report entry.
#[derive(Clone, Debug)]
pub struct RepoUnpackReport {
    pub name: String,
    /// None in verify-only mode.
    pub dest: Option<PathBuf>,
    pub status: RepoStatus,
    pub commits: u64,
    pub refs_checked: usize,
}

/// What an unpack run did.
#[derive(Clone, Debug)]
pub struct UnpackReport {
    pub repos: Vec<RepoUnpackReport>,
    pub verify_only: bool,
}

impl UnpackReport {
    /// Every repo reached its terminal good state.
    pub fn ok(&self) -> bool {
        self.repos
            .iter()
            .all(|r| !matches!(r.status, RepoStatus::Failed(_)))
    }

    /// Deterministic report text (same discipline as `RunReport::to_text`).
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("gfx unpack report\n");
        s.push_str(&std::format!(
            "mode: {}\n",
            if self.verify_only { "verify-only" } else { "unpack" }
        ));
        s.push_str(&std::format!("repos: {}\n", self.repos.len()));
        for r in &self.repos {
            let status = match &r.status {
                RepoStatus::Verified => "verified".to_string(),
                RepoStatus::Imported => "imported".to_string(),
                RepoStatus::Failed(e) => std::format!("failed: {e}"),
            };
            s.push_str(&std::format!(
                "repo {}: {} commits={} refs-checked={}\n",
                r.name, status, r.commits, r.refs_checked
            ));
            if let Some(dest) = &r.dest {
                s.push_str(&std::format!("  dest: {}\n", dest.display()));
            }
        }
        s
    }
}

/// Temp spool directory, removed on drop (best-effort).
struct SpoolDir(PathBuf);

impl SpoolDir {
    fn new(tag: &str) -> Result<Self, PackError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(std::format!("gfx-pack-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        // Decrypted plaintext may land here (D5 safety model).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(SpoolDir(dir))
    }
}

impl Drop for SpoolDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Writer that spools to a file while hashing.
struct SpoolHasher {
    file: std::fs::File,
    hash: Sha256,
    written: u64,
}

impl Write for SpoolHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(buf)?;
        self.hash.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Everything extracted during the verify phase, kept for import.
struct Verified {
    spool: PathBuf,
    /// `maps/<name>/commit-map` text: the pack-time rewritten
    /// classification (`-` new sides).
    commit_map: String,
    redact_map: Option<Vec<u8>>,
}

/// Extract one repo's stream to a spool, verifying the manifest checksum
/// and size; pull the small per-repo maps into memory.
fn verify_one(
    zip: &mut ZipReader<std::fs::File>,
    entry: &RepoEntry,
    spools: &SpoolDir,
) -> Result<Verified, PackError> {
    let spool = spools.0.join(std::format!("stream-{}.fi", entry.name));
    let mut out = SpoolHasher {
        file: std::fs::File::create(&spool)?,
        hash: Sha256::new(),
        written: 0,
    };
    zip.extract_to(&entry.stream, &mut out)?;
    out.flush()?;
    if out.written != entry.bytes {
        return Err(PackError::Checksum { repo: entry.name.clone() });
    }
    if out.hash.finish_hex() != entry.sha256 {
        return Err(PackError::Checksum { repo: entry.name.clone() });
    }
    let commit_map = String::from_utf8(zip.extract(&std::format!("maps/{}/commit-map", entry.name))?)
        .map_err(|_| PackError::Manifest(std::format!("repo {:?}: commit-map is not UTF-8", entry.name)))?;
    let redact_entry = std::format!("maps/{}/redact-map.txt", entry.name);
    let redact_map = if zip.contains(&redact_entry) {
        Some(zip.extract(&redact_entry)?)
    } else {
        None
    };
    Ok(Verified {
        spool,
        commit_map,
        redact_map,
    })
}

/// Parse an archived commit-map, returning the old OIDs whose new side is
/// `-` (rewritten at pack time).
fn rewritten_old_oids(text: &str, entry: &RepoEntry) -> Result<Vec<Oid>, PackError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(old), Some(new), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(PackError::Manifest(std::format!(
                "repo {:?}: commit-map line {} malformed",
                entry.name,
                i + 1
            )));
        };
        if new == "-" {
            let oid = Oid::from_hex(old.as_bytes(), entry.object_format).ok_or_else(|| {
                PackError::Manifest(std::format!(
                    "repo {:?}: commit-map line {} has a bad old OID",
                    entry.name,
                    i + 1
                ))
            })?;
            out.push(oid);
        }
    }
    Ok(out)
}

/// Destination for one repo, applying safety rules.
fn prepare_dest(
    opts: &UnpackOptions,
    entry: &RepoEntry,
) -> Result<PathBuf, PackError> {
    let overrides: BTreeMap<&str, &PathBuf> = opts
        .repo_overrides
        .iter()
        .map(|(n, p)| (n.as_str(), p))
        .collect();
    let dest = match overrides.get(entry.name.as_str()) {
        Some(p) => (*p).clone(),
        None => opts
            .dest_root
            .clone()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(&entry.name),
    };
    let empty = match std::fs::read_dir(&dest) {
        Ok(mut it) => it.next().is_none(),
        Err(_) => true, // does not exist yet
    };
    if !empty && !opts.force {
        return Err(PackError::Usage(std::format!(
            "destination {} exists and is not empty; pass --force to override",
            dest.display()
        )));
    }
    Ok(dest)
}

/// Import one verified repo: init, remap re-run + re-flag, import,
/// finalize, assert tips (D8), write artifacts, fsck.
fn import_one(
    opts: &UnpackOptions,
    entry: &RepoEntry,
    verified: &Verified,
) -> Result<RepoUnpackReport, PackError> {
    let dest = prepare_dest(opts, entry)?;
    git::init(&dest, !opts.worktree, entry.object_format)?;
    let gitdir = git::git_dir(&dest)?;
    let gfx_dir = gitdir.join("gfx");
    std::fs::create_dir_all(&gfx_dir)?;
    let marks_path = gfx_dir.join("marks.out");

    let stream = std::fs::read(&verified.spool)?;

    // Rebuild old→mark tracking from the stream itself, then re-flag the
    // rewritten marks recorded by the archived commit-map (module docs).
    let mut remap = Remap::new(RemapConfig {
        object_format: entry.object_format,
        ..Default::default()
    });
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(&stream);
    let mut sink = Vec::new();
    while let Some(ev) = parser.next_event()? {
        gfx::core::Transform::apply(&mut remap, ev, &mut sink)?;
    }
    gfx::core::Transform::finish(&mut remap, &mut sink)?;
    for old in rewritten_old_oids(&verified.commit_map, entry)? {
        if let Some(mark) = remap.mark_for(&old) {
            remap.flag_mark_rewritten(mark);
        }
    }

    git::import_stream(&dest, &stream, &marks_path)?;
    let marks = MarkFile::parse(&std::fs::read(&marks_path)?)?;
    remap.finalize_from_marks(&marks);

    // D8: every recorded ref tip must resolve to what the import produced.
    let refs: BTreeMap<String, String> = git::refs(&dest)?
        .into_iter()
        .map(|(oid, name)| (name, oid))
        .collect();
    for tip in &entry.refs {
        let expected = match tip.mark {
            Some(m) => marks
                .get(m)
                .map(|o| o.to_hex().to_string())
                .ok_or_else(|| PackError::Manifest(std::format!(
                    "repo {:?}: ref {} mark :{m} missing from import marks",
                    entry.name, tip.name
                )))?,
            None => tip.old.clone(),
        };
        let actual = refs.get(&tip.name).ok_or_else(|| {
            PackError::Manifest(std::format!(
                "repo {:?}: ref {} missing after import",
                entry.name, tip.name
            ))
        })?;
        if *actual != expected {
            return Err(PackError::Manifest(std::format!(
                "repo {:?}: ref {} tip mismatch: expected {expected}, got {actual}",
                entry.name, tip.name
            )));
        }
    }

    // Artifacts (finalized where the archive's were pre-finalization).
    let mut commit_map = String::new();
    for (old, new) in remap.final_commit_map().iter() {
        let new = new.map_or_else(|| "-".to_string(), |n| n.to_hex().to_string());
        commit_map.push_str(&std::format!("{} {}\n", old.to_hex(), new));
    }
    std::fs::write(gfx_dir.join("commit-map"), commit_map)?;
    let mut ref_map = String::new();
    for tip in &entry.refs {
        let new = match tip.mark {
            Some(m) => marks
                .get(m)
                .map(|o| o.to_hex().to_string())
                .unwrap_or_else(|| "-".to_string()),
            None => tip.old.clone(),
        };
        ref_map.push_str(&std::format!("{} {} {}\n", tip.old, new, tip.name));
    }
    std::fs::write(gfx_dir.join("ref-map"), ref_map)?;
    if let Some(redact) = &verified.redact_map {
        std::fs::write(gfx_dir.join("redact-map.txt"), redact)?;
    }

    git::fsck(&dest)?;

    Ok(RepoUnpackReport {
        name: entry.name.clone(),
        dest: Some(dest),
        status: RepoStatus::Imported,
        commits: entry.commits,
        refs_checked: entry.refs.len(),
    })
}

/// Run an unpack. See module docs for the flow.
pub fn unpack(opts: &UnpackOptions) -> Result<UnpackReport, PackError> {
    // D5: an `.age` archive is decrypted whole into the (0700) spool dir
    // before the zip layer sees it; the spool dir is removed on drop.
    let spools = SpoolDir::new("unpack")?;
    let file = if opts.archive.extension().is_some_and(|e| e == "age") {
        let ciphertext = std::fs::read(&opts.archive)?;
        let mut identities = Vec::new();
        for f in &opts.identity_files {
            identities.extend(crate::crypto::parse_identity_file(&std::fs::read_to_string(f)?)?);
        }
        let plain = crate::crypto::decrypt_bytes(&ciphertext, opts.passphrase.clone(), &identities)?;
        let path = spools.0.join("archive.gfxpack");
        std::fs::write(&path, plain)?;
        std::fs::File::open(path)?
    } else {
        if !opts.identity_files.is_empty() || opts.passphrase.is_some() {
            return Err(PackError::Usage(
                "--identity / passphrase given but the archive is not .age-encrypted".into(),
            ));
        }
        std::fs::File::open(&opts.archive)?
    };
    let mut zip = ZipReader::open(file)?;
    let manifest_bytes = zip.extract(MANIFEST_ENTRY)?;
    let manifest_text = String::from_utf8(manifest_bytes)
        .map_err(|_| PackError::Manifest("manifest is not UTF-8".into()))?;
    let manifest = Manifest::parse(&manifest_text)?;

    // Overrides must name repos that exist — a typo here would silently
    // unpack to the default location.
    for (name, _) in &opts.repo_overrides {
        if !manifest.repos.iter().any(|r| &r.name == name) {
            return Err(PackError::Usage(std::format!(
                "--repo override {name:?} names no repo in the archive"
            )));
        }
    }

    let mut reports: Vec<RepoUnpackReport> = Vec::new();
    let mut verified: Vec<(&RepoEntry, Verified)> = Vec::new();
    for entry in &manifest.repos {
        match verify_one(&mut zip, entry, &spools) {
            Ok(v) => verified.push((entry, v)),
            Err(e) if opts.keep_going => {
                reports.push(RepoUnpackReport {
                    name: entry.name.clone(),
                    dest: None,
                    status: RepoStatus::Failed(e.to_string()),
                    commits: entry.commits,
                    refs_checked: 0,
                });
            }
            Err(e) => return Err(e),
        }
    }

    if opts.verify_only {
        for (entry, _) in &verified {
            reports.push(RepoUnpackReport {
                name: entry.name.clone(),
                dest: None,
                status: RepoStatus::Verified,
                commits: entry.commits,
                refs_checked: 0,
            });
        }
        sort_by_manifest(&manifest, &mut reports);
        return Ok(UnpackReport {
            repos: reports,
            verify_only: true,
        });
    }

    for (entry, v) in verified {
        match import_one(opts, entry, &v) {
            Ok(rep) => reports.push(rep),
            Err(e) if opts.keep_going => {
                reports.push(RepoUnpackReport {
                    name: entry.name.clone(),
                    dest: None,
                    status: RepoStatus::Failed(e.to_string()),
                    commits: entry.commits,
                    refs_checked: 0,
                });
            }
            Err(e) => return Err(e),
        }
    }
    sort_by_manifest(&manifest, &mut reports);
    Ok(UnpackReport {
        repos: reports,
        verify_only: false,
    })
}

/// Reports follow manifest (user) order, not completion order.
fn sort_by_manifest(manifest: &Manifest, reports: &mut [RepoUnpackReport]) {
    let order: BTreeMap<&str, usize> = manifest
        .repos
        .iter()
        .enumerate()
        .map(|(i, r)| (r.name.as_str(), i))
        .collect();
    reports.sort_by_key(|r| order.get(r.name.as_str()).copied().unwrap_or(usize::MAX));
}
