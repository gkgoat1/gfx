//! Pass driver (plan §4): `git filter-repo`-style invocation of an arbitrary
//! pass sequence over a real repository.
//!
//! One round (§4.3): safety check → `git fast-export` (pinned flags) →
//! parse → pass pipeline (content passes, then remap) → canonical writer →
//! `git fast-import --force --export-marks` → `Remap::finalize_from_marks` →
//! ref-map snapshot → artifacts under `<gitdir>/gfx/`.
//!
//! This module is the std side of the house: it owns every subprocess and
//! file touch. The passes themselves (gfx-core, gfx-remap) stay sans-IO and
//! `no_std`. v1 posture is buffered rounds: the whole export stream and
//! event list live in memory; streaming rounds are a future optimization.
//!
//! Ref binding during import relies on two pinned protocol facts: (1)
//! fast-export emits a bare `reset <ref>` before each ref's first commit,
//! detaching refs from their existing tips, and (2) remap emits trailing
//! resets-to-mark at `finish()` for tips whose lineage was rewritten (plan
//! §7.5). Unchanged tips rebind to their identical OIDs, which are present
//! because the round rewrites in place.
//!
//! Known v1 limitation: a ref pointing at *no* commit (empty branch) is
//! exported as a bare reset and therefore dropped by the round-trip — the
//! same outcome filter-repo has with its own empty-ref pruning.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::vec;

extern crate std;

use std::fmt;
use std::path::{Path, PathBuf};

use alloc::collections::{BTreeMap, BTreeSet};

use gfx_core::{
    write_event, Committish, DataRef, Error, Event, FileOp, FileSource, Mark, MarkFile, Parser,
    Pipeline, ParseOptions, Transform, Writer,
};

/// Errors from the driver layer. Subprocess failures keep their captured
/// stderr; core errors map unchanged at the boundary.
#[derive(Debug)]
pub enum DriverError {
    /// The path is not a git repository (no work tree, no git dir).
    NotARepository { path: PathBuf },
    /// The repo does not pass the safety check and `--force` was not given.
    Unsafe { reason: String },
    /// Invalid pass configuration (duplicates, unknown knobs).
    Config(String),
    /// Pass order violates the pipeline contract (content passes before
    /// remap; at most one remap, last). Never silently reordered.
    Order(String),
    Git(crate::git::process::GitError),
    Io(std::io::Error),
    Core(Error),
    /// Remote-data capture/restore failure (plan-remote-data.md).
    Remotes(crate::remotes::RemoteDataError),
    /// Endpoint configuration is nonsensical (plan-stream-files.md D1/D3).
    Endpoint(String),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::NotARepository { path } => {
                write!(f, "not a git repository: {}", path.display())
            }
            DriverError::Unsafe { reason } => {
                write!(f, "refusing to rewrite ({reason}); pass --force to override")
            }
            DriverError::Config(msg) => write!(f, "invalid pass configuration: {msg}"),
            DriverError::Order(msg) => write!(f, "invalid pass order: {msg}"),
            DriverError::Git(e) => write!(f, "{e}"),
            DriverError::Io(e) => write!(f, "i/o error: {e}"),
            DriverError::Core(e) => write!(f, "stream error: {e}"),
            DriverError::Remotes(e) => write!(f, "{e}"),
            DriverError::Endpoint(msg) => write!(f, "invalid endpoints: {msg}"),
        }
    }
}

impl std::error::Error for DriverError {}

impl From<crate::git::process::GitError> for DriverError {
    fn from(e: crate::git::process::GitError) -> Self {
        DriverError::Git(e)
    }
}

impl From<Error> for DriverError {
    fn from(e: Error) -> Self {
        DriverError::Core(e)
    }
}

impl From<crate::remotes::RemoteDataError> for DriverError {
    fn from(e: crate::remotes::RemoteDataError) -> Self {
        DriverError::Remotes(e)
    }
}

impl From<std::io::Error> for DriverError {
    fn from(e: std::io::Error) -> Self {
        DriverError::Io(e)
    }
}

/// One configured pass, in driver order. Content passes may rewrite stream
/// bytes; remap is the final stage that tracks the commit map.
///
/// v1 knows the builtins shipped with the facade; the pass *names and flag
/// surfaces* live in `gfx-cli`'s registry, which produces `PassSpec`s.
#[derive(Clone, Debug)]
pub enum PassSpec {
    /// Builtin #1 (plan §7): commit-hash remapping. The driver appends this
    /// automatically when the user did not name it.
    #[cfg(feature = "remap")]
    Remap(gfx_remap::RemapConfig),
    /// Builtin: retroactive removal of large/generated files (plan §5).
    #[cfg(feature = "strip-blobs")]
    StripBlobs(gfx_strip_blobs::StripBlobsConfig),
    /// Builtin: commit-metadata redaction (plan-redact-idents.md §4).
    #[cfg(feature = "redact")]
    Redact(gfx_redact::RedactConfig),
    /// Builtin: generic fallible blob rewriting (plan-blob-xform.md).
    #[cfg(feature = "blob-xform")]
    BlobXform(gfx_blob_xform::BlobXformConfig),
}

impl PassSpec {
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "remap")]
            PassSpec::Remap(_) => "remap",
            #[cfg(feature = "strip-blobs")]
            PassSpec::StripBlobs(_) => "strip-blobs",
            #[cfg(feature = "redact")]
            PassSpec::Redact(_) => "redact",
            #[cfg(feature = "blob-xform")]
            PassSpec::BlobXform(_) => "blob-xform",
        }
    }

    pub fn is_remap(&self) -> bool {
        #[cfg(feature = "remap")]
        {
            matches!(self, PassSpec::Remap(_))
        }
        #[cfg(not(feature = "remap"))]
        {
            false
        }
    }
}

/// Policy for `refs/remotes/*` across an in-repo rewrite
/// (plan-remote-data.md D6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RemoteRefsPolicy {
    /// Status quo (C7): tracking refs ride the export/import stream and
    /// end up naming rewritten commits — misleading until the next fetch
    /// force-updates them (research finding R3).
    #[default]
    Rewrite,
    /// Delete them post-import; the next fetch repopulates. Recommended
    /// when the old objects should become unreachable (redaction).
    Drop,
    /// Restore the pre-rewrite OIDs. Keeps pre-rewrite objects reachable
    /// — the operator's call, never the default.
    Pin,
}

impl RemoteRefsPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemoteRefsPolicy::Rewrite => "rewrite",
            RemoteRefsPolicy::Drop => "drop",
            RemoteRefsPolicy::Pin => "pin",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rewrite" => Some(RemoteRefsPolicy::Rewrite),
            "drop" => Some(RemoteRefsPolicy::Drop),
            "pin" => Some(RemoteRefsPolicy::Pin),
            _ => None,
        }
    }
}

/// Remote-data summary for the run report (plan-remote-data.md D8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemotesSummary {
    /// Allowlisted keys captured (0 when `--save-remotes` was off).
    pub saved_keys: u64,
    /// Remote-domain keys dropped by the allowlist (D2).
    pub skipped: u64,
    /// URL-valued keys carrying credentials (D3 — in-repo warns, never blocks).
    pub credential_keys: Vec<String>,
    /// Keys re-added by `--restore-remotes` (normally 0: the rewrite does
    /// not touch config — R1 — so a nonzero value means something external
    /// raced the run).
    pub restored_keys: u64,
    /// Keys whose live values differ from the snapshot; never overwritten.
    pub drift: Vec<String>,
    /// Applied refs/remotes policy and how many refs it touched.
    pub refs_policy: RemoteRefsPolicy,
    pub refs_affected: u64,
}

/// Per-pass summary for the run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassSummary {
    pub name: &'static str,
    pub detail: String,
}

/// What one driver round did. Deterministic: `to_text()` never embeds paths,
/// clocks, or environment values, so two identical runs on clones of the
/// same source produce identical text (acceptance A6).
#[derive(Clone, Debug)]
pub struct RunReport {
    pub dry_run: bool,
    pub passes: Vec<PassSummary>,
    pub input_bytes: usize,
    pub output_bytes: usize,
    /// Output stream is byte-identical to the export input.
    pub identity: bool,
    pub commits_observed: usize,
    pub commits_rewritten: usize,
    /// Finalized `old → new` commit map (populated by `run`; pre-finalization
    /// view from `dry_run`).
    #[cfg(feature = "remap")]
    pub commit_map: Option<gfx_remap::CommitMap>,
    /// `(old_tip, new_tip, refname)` before/after the round (run only).
    pub ref_map: Vec<(String, String, String)>,
    /// Directory the artifacts were written to (run only; deliberately NOT
    /// part of `to_text`).
    pub artifacts_dir: Option<PathBuf>,
    /// Remote-data capture/restore outcome; `Some` when any of
    /// `--save-remotes` / `--restore-remotes` / a non-default
    /// `--remote-refs` policy was requested (plan-remote-data.md D8).
    pub remotes: Option<RemotesSummary>,
    /// Stream source had no `original-oid` lines, so the commit map is a
    /// presence list, not a true old→new map (plan-stream-files.md D5).
    pub no_original_ids: bool,
    /// The commit map is mark-finalized (new OIDs assigned by the
    /// import). Always true today for repo sinks — the field exists so
    /// later mark-space outputs (stream sinks, plan-stream-files.md D4)
    /// can say `false` instead of lying about OIDs (C6).
    pub commit_map_finalized: bool,
}

impl RunReport {
    /// Human-readable, deterministic report text.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("gfx rewrite report\n");
        s.push_str(&format!(
            "mode: {}\n",
            if self.dry_run { "dry-run" } else { "rewrite" }
        ));
        s.push_str(&format!("input-bytes: {}\n", self.input_bytes));
        s.push_str(&format!("output-bytes: {}\n", self.output_bytes));
        s.push_str(&format!("identity: {}\n", self.identity));
        s.push_str(&format!("commits-observed: {}\n", self.commits_observed));
        s.push_str(&format!("commits-rewritten: {}\n", self.commits_rewritten));
        s.push_str(&format!(
            "commit-map-entries: {}\n",
            self.commit_map.as_ref().map_or(0, |m| m.len())
        ));
        s.push_str(&format!("ref-map-entries: {}\n", self.ref_map.len()));
        if self.no_original_ids {
            s.push_str("warning: input stream carries no original-oid lines; \
                the commit map is a presence list, not an old→new map\n");
        }
        s.push_str("passes:\n");
        for p in &self.passes {
            s.push_str(&format!("  - {}: {}\n", p.name, p.detail));
        }
        if let Some(r) = &self.remotes {
            s.push_str(&format!(
                "remotes: saved={} skipped={} restored={} drift={} remote-refs={}:{}\n",
                r.saved_keys,
                r.skipped,
                r.restored_keys,
                r.drift.len(),
                r.refs_policy.as_str(),
                r.refs_affected
            ));
            if !r.credential_keys.is_empty() {
                s.push_str(&format!(
                    "remotes-warning: URLs with credentials captured in keys: {}\n",
                    r.credential_keys.join(", ")
                ));
            }
            for k in &r.drift {
                s.push_str(&format!("remotes-drift: {k}\n"));
            }
        }
        s
    }
}

/// Where a round reads its fast-export stream from
/// (plan-stream-files.md D1). `Stream` is v1 endpoint plumbing only — the
/// import side arrives with compression (M1), which reuses the same
/// buffered read path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// `git fast-export` out of a repository (read-only).
    Repo(PathBuf),
    /// A fast-export stream file.
    Stream(PathBuf),
}

/// Where a round writes its transformed stream (plan-stream-files.md D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sink {
    /// `git fast-import` into a repository (the safety check binds here).
    Repo(PathBuf),
    /// A stream file (raw in v1; `.gz` lands with M1).
    Stream(PathBuf),
}

/// Read a stream file into memory (buffered rounds, R2). Bytes pass
/// through verbatim in v1 — gzip decode arrives with M1's magic sniff.
pub fn read_stream(path: &Path) -> Result<Vec<u8>, DriverError> {
    Ok(std::fs::read(path)?)
}

/// Write a stream file verbatim (buffered rounds, R2). The parent
/// directory must exist (no implicit creation — a typo'd path is an
/// error, not a tree of new directories).
pub fn write_stream(path: &Path, bytes: &[u8]) -> Result<(), DriverError> {
    Ok(std::fs::write(path, bytes)?)
}

/// The pass driver. Construct with [`PassDriver::new`] (repo → repo, as
/// today) or [`PassDriver::with_endpoints`] (any combination), configure
/// with [`PassDriver::with_passes`] / [`PassDriver::force`], then
/// [`PassDriver::run`] or [`PassDriver::dry_run`].
#[derive(Debug)]
pub struct PassDriver {
    source: Source,
    sink: Sink,
    passes: Vec<PassSpec>,
    force: bool,
    save_remotes: bool,
    restore_remotes: bool,
    remote_refs: RemoteRefsPolicy,
    /// Explicit artifact directory for stream sinks (D4). `None` =
    /// `<out>.gfx/` next to the output file.
    artifacts_dir: Option<PathBuf>,
}

impl PassDriver {
    /// Verify `repo` is a git repository and start a driver for it.
    pub fn new(repo: impl Into<PathBuf>) -> Result<Self, DriverError> {
        let repo = repo.into();
        crate::git::process::git_dir(&repo)
            .map_err(|_| DriverError::NotARepository { path: repo.clone() })?;
        Ok(PassDriver {
            source: Source::Repo(repo.clone()),
            sink: Sink::Repo(repo),
            passes: Vec::new(),
            force: false,
            save_remotes: false,
            restore_remotes: false,
            remote_refs: RemoteRefsPolicy::default(),
            artifacts_dir: None,
        })
    }

    /// Any source/sink combination (plan-stream-files.md D1). Repo
    /// endpoints are verified to be repositories; the combination is
    /// validated (C3: nonsense is a usage error before anything is read
    /// or written).
    pub fn with_endpoints(source: Source, sink: Sink) -> Result<Self, DriverError> {
        let mut repo_endpoints: Vec<PathBuf> = Vec::new();
        if let Source::Repo(p) = &source {
            repo_endpoints.push(p.clone());
        }
        if let Sink::Repo(p) = &sink {
            repo_endpoints.push(p.clone());
        }
        repo_endpoints.dedup();
        for repo in repo_endpoints {
            crate::git::process::git_dir(&repo)
                .map_err(|_| DriverError::NotARepository { path: repo })?;
        }
        let d = PassDriver {
            source,
            sink,
            passes: Vec::new(),
            force: false,
            save_remotes: false,
            restore_remotes: false,
            remote_refs: RemoteRefsPolicy::default(),
            artifacts_dir: None,
        };
        d.validate_endpoints()?;
        Ok(d)
    }

    /// Artifact directory override for stream sinks (plan-stream-files.md
    /// D4). Meaningless (and an error) for repo sinks, whose artifacts
    /// always live in `<gitdir>/gfx/`.
    pub fn with_artifacts_dir(mut self, dir: impl Into<PathBuf>) -> Result<Self, DriverError> {
        if matches!(self.sink, Sink::Repo(_)) {
            return Err(DriverError::Endpoint(
                "--artifacts is only meaningful with a stream sink (--out); \
                 repo sinks always write <gitdir>/gfx/"
                    .into(),
            ));
        }
        self.artifacts_dir = Some(dir.into());
        Ok(self)
    }

    /// C3/D1/D3 validation. Called at construction and again at run time
    /// (remotes options can change after `with_endpoints`).
    fn validate_endpoints(&self) -> Result<(), DriverError> {
        // Same-file source and sink would destroy the input mid-round.
        if let (Source::Stream(a), Sink::Stream(b)) = (&self.source, &self.sink) {
            if a == b {
                return Err(DriverError::Endpoint(
                    "--in and --out name the same file".into(),
                ));
            }
        }
        let has_source_repo = matches!(self.source, Source::Repo(_));
        let has_sink_repo = matches!(self.sink, Sink::Repo(_));
        // Remotes flags bind to whichever endpoint is a real repo (D3).
        if self.save_remotes && !has_source_repo {
            return Err(DriverError::Endpoint(
                "--save-remotes needs a repository source (there is nothing pre-existing to save from a stream)".into(),
            ));
        }
        if self.restore_remotes && !has_sink_repo {
            return Err(DriverError::Endpoint(
                "--restore-remotes needs a repository sink (a stream file has no config to restore into)".into(),
            ));
        }
        if self.remote_refs != RemoteRefsPolicy::Rewrite && !has_sink_repo {
            return Err(DriverError::Endpoint(
                "--remote-refs needs a repository sink (refs/remotes policy applies after an import)".into(),
            ));
        }
        Ok(())
    }

    /// Remote-data options (plan-remote-data.md): snapshot the allowlisted
    /// remote config to the artifacts dir (`save`), re-add any keys the
    /// run lost — normally none, config is untouched (R1) — and report
    /// drift (`restore`), and apply a `refs/remotes/*` policy after import.
    pub fn with_remote_data(
        mut self,
        save: bool,
        restore: bool,
        refs: RemoteRefsPolicy,
    ) -> Self {
        self.save_remotes = save;
        self.restore_remotes = restore;
        self.remote_refs = refs;
        self
    }

    /// Set the pass sequence. Order is pipeline order (first named runs
    /// first). The driver validates the contract and appends `remap`
    /// automatically when it was not named (plan §4.2): content/path passes
    /// must precede remap, at most one remap, and remap is always last.
    pub fn with_passes(mut self, passes: Vec<PassSpec>) -> Result<Self, DriverError> {
        let mut remap_seen = false;
        for (i, p) in passes.iter().enumerate() {
            if p.is_remap() {
                if remap_seen {
                    return Err(DriverError::Config("remap named more than once".into()));
                }
                if i + 1 != passes.len() {
                    return Err(DriverError::Order(
                        "remap must be the last pass (content passes must precede it)".into(),
                    ));
                }
                remap_seen = true;
            }
        }
        if !remap_seen {
            // Auto-append (plan §4.2): remap is the driver's final stage.
            let mut passes = passes;
            passes.push(PassSpec::Remap(gfx_remap::RemapConfig::default()));
            self.passes = passes;
        } else {
            self.passes = passes;
        }
        Ok(self)
    }

    /// Override the safety check (plan §4.2: a non-bare repository refuses
    /// to be rewritten in place unless forced; bare repositories pass).
    pub fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// The validated pass sequence (including the auto-appended remap).
    pub fn passes(&self) -> &[PassSpec] {
        &self.passes
    }

    /// The safety check binds to the *sink* (plan-stream-files.md D3,
    /// R9): it guards the import, not the export. Stream sinks write a
    /// file, which needs no repository safety gate.
    fn check_safety(&self) -> Result<(), DriverError> {
        let Sink::Repo(repo) = &self.sink else {
            return Ok(());
        };
        if self.force {
            return Ok(());
        }
        if crate::git::process::is_bare(repo)? {
            return Ok(());
        }
        let dirty = !crate::git::process::status_porcelain(repo)?.is_empty();
        Err(DriverError::Unsafe {
            reason: if dirty {
                "repository is non-bare and has uncommitted changes".into()
            } else {
                "repository is non-bare; a fresh `git clone --bare` is required".into()
            },
        })
    }

    /// Export → passes → report, without importing or touching refs (A1).
    pub fn dry_run(&mut self) -> Result<RunReport, DriverError> {
        self.round(false)
    }

    /// The full round (§4.3): safety check, export, passes, import, marks
    /// finalization, ref-map snapshot, artifacts.
    pub fn run(&mut self) -> Result<RunReport, DriverError> {
        self.validate_endpoints()?;
        self.check_safety()?;
        self.round(true)
    }

    fn round(&mut self, import: bool) -> Result<RunReport, DriverError> {
        // plan-remote-data.md: capture pre-rewrite remote state before
        // anything mutates the repo. Read-only, so dry runs capture too
        // (they report what a real run would save, but write nothing).
        let want_capture = self.save_remotes || self.restore_remotes;
        let captured = if want_capture {
            let Source::Repo(repo) = &self.source else {
                // validate_endpoints() rejects this; belt and braces.
                return Err(DriverError::Endpoint(
                    "--save-remotes/--restore-remotes need a repository source".into(),
                ));
            };
            Some(crate::remotes::capture(repo)?)
        } else {
            None
        };
        let saved_refs = if self.remote_refs == RemoteRefsPolicy::Pin {
            let Sink::Repo(repo) = &self.sink else {
                return Err(DriverError::Endpoint(
                    "--remote-refs pin needs a repository sink".into(),
                ));
            };
            crate::remotes::capture_remote_refs(repo)?
        } else {
            Vec::new()
        };

        let input = match &self.source {
            Source::Repo(repo) => crate::git::process::export_stream(repo, &[])?,
            Source::Stream(path) => read_stream(path)?,
        };
        let mut out = transform_stream(&input, &self.passes)?;

        let mut report = RunReport {
            dry_run: !import,
            passes: out.passes.clone(),
            input_bytes: out.input_bytes,
            output_bytes: out.output.len(),
            identity: out.identity,
            commits_observed: out.commits_observed,
            commits_rewritten: out.commits_rewritten,
            commit_map: out.commit_map.clone(),
            ref_map: Vec::new(),
            artifacts_dir: None,
            remotes: None,
            no_original_ids: out.no_original_ids,
            commit_map_finalized: false,
        };

        // Populate the capture side of the remotes summary (dry runs stop
        // here — they write nothing and touch no refs).
        if let Some(cap) = &captured {
            let mut keys: alloc::collections::BTreeSet<&str> = alloc::collections::BTreeSet::new();
            for (k, _) in &cap.state.entries {
                keys.insert(k.as_str());
            }
            report.remotes = Some(RemotesSummary {
                saved_keys: keys.len() as u64,
                skipped: cap.skipped,
                credential_keys: cap.credential_keys.clone(),
                refs_policy: self.remote_refs,
                ..RemotesSummary::default()
            });
        }

        if !import {
            return Ok(report);
        }

        // Stream sink (plan-stream-files.md): write the output bytes and
        // stop — no import, no ref-map, no artifacts (D4's artifact
        // surface lands with the marks-aware M1).
        if let Sink::Stream(path) = &self.sink {
            write_stream(path, &out.output)?;
            return Ok(report);
        }
        let Sink::Repo(sink_repo) = &self.sink else {
            unreachable!("stream sink returned above")
        };

        // Import, then finalize remap from fast-import's marks (mode A).
        let gitdir = crate::git::process::git_dir(sink_repo)?;
        let gfx_dir = gitdir.join("gfx");
        std::fs::create_dir_all(&gfx_dir)?;
        let marks_path = gfx_dir.join("marks.out");
        crate::git::process::import_stream(sink_repo, &out.output, &marks_path)?;
        report.commit_map_finalized = true;

        #[cfg(feature = "remap")]
        if let Some(r) = out.remap.as_mut() {
            let marks_bytes = std::fs::read(&marks_path)?;
            let marks = MarkFile::parse(&marks_bytes)?;
            r.finalize_from_marks(&marks);
            report.commit_map = Some(r.final_commit_map().clone());
        }

        // Ref-map: full before/after snapshot (complete even for refs only
        // bound by commit commands, which remap does not track).
        let before = crate::git::process::refs(sink_repo)?;
        let after = crate::git::process::refs(sink_repo)?;
        let after_map: std::collections::BTreeMap<&str, &str> =
            after.iter().map(|(o, n)| (n.as_str(), o.as_str())).collect();
        report.ref_map = before
            .iter()
            .map(|(old, name)| {
                let new = after_map.get(name.as_str()).copied().unwrap_or("deleted");
                (old.clone(), new.to_string(), name.clone())
            })
            .collect();

        // plan-remote-data.md: restore add-missing (config is untouched
        // by the rewrite — R1 — so a nonzero restored count means an
        // external actor raced the run), then apply the refs/remotes
        // policy. Both after the ref-map snapshot so it records the
        // state the passes produced.
        if let Some(cap) = &captured {
            if self.restore_remotes {
                let rr = crate::remotes::restore(
                    sink_repo,
                    &cap.state,
                    crate::remotes::RestoreMode::AddMissing,
                )?;
                let rem = report.remotes.as_mut().expect("set when captured");
                rem.restored_keys = rr.keys_set;
                rem.drift = rr.drift;
            }
        }
        match self.remote_refs {
            RemoteRefsPolicy::Rewrite => {}
            RemoteRefsPolicy::Drop => {
                let n = crate::remotes::drop_remote_refs(sink_repo)?;
                report
                    .remotes
                    .get_or_insert_with(|| RemotesSummary {
                        refs_policy: self.remote_refs,
                        ..RemotesSummary::default()
                    })
                    .refs_affected = n;
            }
            RemoteRefsPolicy::Pin => {
                let n = crate::remotes::pin_remote_refs(sink_repo, &saved_refs)?;
                report
                    .remotes
                    .get_or_insert_with(|| RemotesSummary {
                        refs_policy: self.remote_refs,
                        ..RemotesSummary::default()
                    })
                    .refs_affected = n;
            }
        }

        // Artifacts (plan §4.3). Deterministic contents (A6).
        write_artifacts(&gfx_dir, &report)?;
        // plan-remote-data.md D4: exact NUL-framed state + an audit-safe
        // (userinfo-redacted) rendering.
        if let Some(cap) = &captured {
            if self.save_remotes {
                std::fs::write(gfx_dir.join("remote-state.bin"), cap.state.serialize_z())?;
                std::fs::write(gfx_dir.join("remote-state.txt"), cap.state.render_text())?;
            }
        }
        #[cfg(feature = "strip-blobs")]
        if let Some(sr) = out.strip_report.as_ref() {
            std::fs::write(gfx_dir.join("strip-report.txt"), sr.to_text())?;
        }
        // The mapping artifact is SENSITIVE (plan §4.8): it re-identifies
        // the redacted repo. Written only on real runs, never in dry-run.
        #[cfg(feature = "redact")]
        if let Some(rr) = out.redact_report.as_ref() {
            std::fs::write(gfx_dir.join("redact-map.txt"), rr.to_text())?;
        }
        report.artifacts_dir = Some(gfx_dir);
        Ok(report)
    }
}

/// The transform half of a round: parse an export stream and push it
/// through a validated pass sequence, with no host side effects (no import,
/// no refs, no artifacts). Shared with the multistream pack driver
/// (plan-multistream-pack.md D2), which owns its own fan-out plumbing.
#[derive(Debug)]
pub struct TransformOutcome {
    /// Canonical output stream bytes.
    pub output: Vec<u8>,
    pub input_bytes: usize,
    /// Output stream is byte-identical to the export input.
    pub identity: bool,
    /// Per-pass summaries, in pipeline order.
    pub passes: Vec<PassSummary>,
    pub commits_observed: usize,
    pub commits_rewritten: usize,
    /// The input carried no `original-oid` lines (foreign stream;
    /// plan-stream-files.md D5). The commit map then degenerates to a
    /// presence list — hosts surface this, never silently.
    pub no_original_ids: bool,
    /// Pre-finalization `old → new` view (unchanged commits map to
    /// themselves; rewritten ones to `None` until the caller finalizes).
    #[cfg(feature = "remap")]
    pub commit_map: Option<gfx_remap::CommitMap>,
    /// The remap stage itself, so the caller can fold in a downstream
    /// import's marks (`Remap::finalize_from_marks`).
    #[cfg(feature = "remap")]
    pub remap: Option<gfx_remap::Remap>,
    #[cfg(feature = "strip-blobs")]
    pub strip_report: Option<gfx_strip_blobs::StripReport>,
    #[cfg(feature = "redact")]
    pub redact_report: Option<gfx_redact::RedactReport>,
    #[cfg(feature = "blob-xform")]
    pub blob_xform_report: Option<gfx_blob_xform::BlobXformReport>,
    /// Path rules the report's per-rule counters correspond to (D9).
    #[cfg(feature = "blob-xform")]
    pub blob_xform_rules: Vec<gfx_blob_xform::PathRule>,
}

/// Parse `input` and run `passes` over it in pipeline order. Assumes the
/// sequence already satisfies the ordering contract (content passes first,
/// at most one remap, last) — `PassDriver::with_passes` is the validator.
pub fn transform_stream(
    input: &[u8],
    passes: &[PassSpec],
) -> Result<TransformOutcome, DriverError> {
    // Stages in validated order: content passes feed the typed remap
    // stage, which is always last.
    let content = Pipeline::builder().build();
    #[cfg(feature = "remap")]
    let mut remap: Option<gfx_remap::Remap> = None;
    #[cfg(feature = "strip-blobs")]
    let mut strip: Option<gfx_strip_blobs::StripBlobs> = None;
    #[cfg(feature = "redact")]
    let mut redact: Option<gfx_redact::Redact> = None;
    #[cfg(feature = "blob-xform")]
    let mut blob_xform_cfg: Option<gfx_blob_xform::BlobXformConfig> = None;
    for p in passes {
        match p {
            #[cfg(feature = "remap")]
            PassSpec::Remap(cfg) => remap = Some(gfx_remap::Remap::new(cfg.clone())),
            #[cfg(feature = "strip-blobs")]
            PassSpec::StripBlobs(cfg) => {
                strip = Some(gfx_strip_blobs::StripBlobs::new(cfg.clone()))
            }
            #[cfg(feature = "redact")]
            PassSpec::Redact(cfg) => redact = Some(gfx_redact::Redact::new(cfg.clone())),
            #[cfg(feature = "blob-xform")]
            PassSpec::BlobXform(cfg) => {
                blob_xform_cfg = Some(cfg.clone());
            }
        }
    }
    let mut content = content;

    // Parse → content stages (strip first, then the custom pipeline) →
    // remap stage → canonical bytes.
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(input);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event()? {
        content.apply(ev, &mut events)?;
    }
    let mut tail = Vec::new();
    parser.finish(&mut tail)?;
    for ev in tail {
        content.apply(ev, &mut events)?;
    }
    content.finish(&mut events)?;

    // D3 (plan-blob-xform-paths.md): synthetic blob marks must live above
    // the stream's maximum mark (a colliding mark is silently redefined
    // by fast-import and fails the import mid-stream — R3). The stream is
    // fully parsed here, so the max is one cheap scan over materialized
    // data (R4); inject `max + 1` before the stage runs.
    #[cfg(feature = "blob-xform")]
    let mut blob_xform: Option<gfx_blob_xform::BlobXform> = None;
    #[cfg(feature = "blob-xform")]
    if let Some(mut cfg) = blob_xform_cfg {
        if !cfg.path_rules.is_empty() {
            let max_mark = events
                .iter()
                .filter_map(|ev| match ev {
                    Event::Commit(c) => c.mark,
                    Event::Tag(t) => t.mark,
                    Event::Blob { mark, .. } => *mark,
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            // Adversarial streams can carry mark u64::MAX; real streams
            // (sequential from 1) never get close.
            cfg.mark_base = Some(max_mark.checked_add(1).ok_or(gfx_core::Error::Internal(
                "stream marks exhaust u64; no room for synthetic blob marks",
            ))?);
        }
        blob_xform = Some(gfx_blob_xform::BlobXform::new(cfg));
    }

    // Snapshot commit/tag/blob events by mark before any content pass, for
    // the rewrite detection below (remap's canonical-digest contract, plan
    // §7 decision 1, implemented host-side: the driver diffs each mark's
    // event bytes across the whole content pipeline and flags what changed).
    // Blobs are included because a blob-only rewrite (blob-xform) changes
    // the hashes of every commit referencing it without touching the
    // commit's own event bytes.
    #[cfg(feature = "remap")]
    let mut pre_image: BTreeMap<Mark, Vec<u8>> = BTreeMap::new();
    #[cfg(feature = "remap")]
    for ev in &events {
        let m = match ev {
            Event::Commit(c) => c.mark,
            Event::Tag(t) => t.mark,
            Event::Blob { mark, .. } => *mark,
            _ => None,
        };
        if let Some(m) = m {
            let mut buf = Vec::new();
            write_event(ev, &mut buf)?;
            pre_image.insert(m, buf);
        }
    }

    // Blob-xform runs FIRST among the content stages (plan-blob-xform.md
    // D7): strip-blobs then judges post-transform sizes — a shrink can
    // save a blob from the knife, which is usually the desired reading.
    #[cfg(feature = "blob-xform")]
    let blob_xform_rules: Vec<gfx_blob_xform::PathRule> = passes
        .iter()
        .find_map(|p| match p {
            PassSpec::BlobXform(cfg) => Some(cfg.path_rules.clone()),
            _ => None,
        })
        .unwrap_or_default();
    #[cfg(feature = "blob-xform")]
    let mut blob_xform_report: Option<gfx_blob_xform::BlobXformReport> = None;
    #[cfg(feature = "blob-xform")]
    if let Some(x) = blob_xform.as_mut() {
        let mut next = Vec::new();
        for ev in events.drain(..) {
            x.apply(ev, &mut next)?;
        }
        x.finish(&mut next)?;
        events = next;
        blob_xform_report = Some(x.report().clone());
    }

    #[cfg(feature = "strip-blobs")]
    let mut strip_report = None;
    #[cfg(feature = "strip-blobs")]
    if let Some(s) = strip.as_mut() {
        let mut next = Vec::new();
        for ev in events.drain(..) {
            s.apply(ev, &mut next)?;
        }
        s.finish(&mut next)?;
        events = next;
        strip_report = Some(s.report().clone());
    }

    // Redact stage: rewrites surviving commits'/tags' metadata (plan
    // §4.7: strip decides which ops exist, redact decides what the
    // surviving commits' metadata says).
    #[cfg(feature = "redact")]
    let mut redact_report = None;
    #[cfg(feature = "redact")]
    if let Some(r) = redact.as_mut() {
        let mut next = Vec::new();
        for ev in events.drain(..) {
            r.apply(ev, &mut next)?;
        }
        r.finish(&mut next)?;
        events = next;
        redact_report = Some(r.report());
    }

    // Rewrite detection: a mark is rewritten iff its event bytes changed
    // across the content passes, any mark-referenced parent/target was
    // rewritten, or — for commits — any op sources a blob mark whose bytes
    // changed (plan-blob-xform.md: an altered blob rewrites the hash of
    // every commit whose tree contains it, without touching the commit's
    // own event bytes). Stream order is topological (parents precede
    // children, blobs precede the commits referencing them), so one forward
    // pass closes the set transitively. OID parents and OID-sourced blobs
    // belong to unchanged lineage (they keep their hashes by definition),
    // so only marks propagate.
    #[cfg(feature = "remap")]
    let rewritten_marks: BTreeSet<Mark> = {
        let mut all = BTreeSet::new();
        let mut rewritten_blobs: BTreeSet<Mark> = BTreeSet::new();
        for ev in &events {
            let (m, parents, forced) = match ev {
                Event::Blob { mark, .. } => {
                    if let Some(m) = mark {
                        let mut buf = Vec::new();
                        write_event(ev, &mut buf)?;
                        if pre_image.get(m) != Some(&buf) {
                            rewritten_blobs.insert(*m);
                        }
                    }
                    (None, Vec::new(), false)
                }
                Event::Commit(c) => {
                    let ps: Vec<Mark> = c
                        .from
                        .iter()
                        .chain(c.merges.iter())
                        .filter_map(|cm| match cm {
                            Committish::Mark(m) => Some(*m),
                            _ => None,
                        })
                        .collect();
                    let blob_hit = c.ops.iter().any(|op| match op {
                        FileOp::Modify {
                            source: FileSource::DataRef(DataRef::Mark(m)),
                            ..
                        } => rewritten_blobs.contains(m),
                        FileOp::Note {
                            data: FileSource::DataRef(DataRef::Mark(m)),
                            ..
                        } => rewritten_blobs.contains(m),
                        _ => false,
                    });
                    (c.mark, ps, blob_hit)
                }
                Event::Tag(t) => {
                    let ps = match &t.from {
                        Some(Committish::Mark(m)) => vec![*m],
                        _ => Vec::new(),
                    };
                    (t.mark, ps, false)
                }
                _ => (None, Vec::new(), false),
            };
            if let Some(m) = m {
                let mut buf = Vec::new();
                write_event(ev, &mut buf)?;
                if forced
                    || pre_image.get(&m) != Some(&buf)
                    || parents.iter().any(|p| all.contains(p))
                {
                    all.insert(m);
                }
            }
        }
        all
    };

    #[cfg(feature = "remap")]
    if let Some(r) = remap.as_mut() {
        let mut next = Vec::new();
        for ev in events.drain(..) {
            let m = match &ev {
                Event::Commit(c) => c.mark,
                Event::Tag(t) => t.mark,
                _ => None,
            };
            if let Some(m) = m.filter(|m| rewritten_marks.contains(m)) {
                r.flag_mark_rewritten(m);
            }
            r.apply(ev, &mut next)?;
        }
        r.finish(&mut next)?;
        events = next;
    }

    let mut writer = Writer::new();
    for ev in &events {
        writer.write(ev)?;
    }
    let output = writer.take();

    let mut out = TransformOutcome {
        identity: output == input,
        output,
        input_bytes: input.len(),
        passes: Vec::new(),
        commits_observed: 0,
        commits_rewritten: 0,
        no_original_ids: false,
        #[cfg(feature = "remap")]
        commit_map: None,
        #[cfg(feature = "remap")]
        remap: None,
        #[cfg(feature = "strip-blobs")]
        strip_report,
        #[cfg(feature = "redact")]
        redact_report,
        #[cfg(feature = "blob-xform")]
        blob_xform_report,
        #[cfg(feature = "blob-xform")]
        blob_xform_rules,
    };

    // Per-pass summaries + pre-finalization map (in pipeline order:
    // blob-xform → strip → redact → remap).
    #[cfg(feature = "blob-xform")]
    if let Some(r) = out.blob_xform_report.as_ref() {
        out.passes.push(PassSummary {
            name: "blob-xform",
            detail: r.detail_with_rules(&out.blob_xform_rules),
        });
    }
    #[cfg(feature = "strip-blobs")]
    if let Some(s) = strip.as_ref() {
        out.passes.push(PassSummary {
            name: "strip-blobs",
            detail: s.report().summary_text(),
        });
    }
    #[cfg(feature = "redact")]
    if let Some(r) = redact.as_ref() {
        out.passes.push(PassSummary {
            name: "redact",
            detail: r.report().summary_text(),
        });
    }
    #[cfg(feature = "remap")]
    if let Some(r) = remap.as_ref() {
        let st = r.stats();
        out.commits_observed = st.commits_observed;
        out.commits_rewritten = st.commits_rewritten;
        out.passes.push(PassSummary {
            name: "remap",
            detail: format!(
                "commits_observed={} commits_rewritten={} refs_rewritten={} message_oids_tracked={}",
                st.commits_observed,
                st.commits_rewritten,
                st.refs_rewritten,
                st.message_oids_tracked
            ),
        });
        out.commit_map = Some(r.commit_map());
        // D5: a stream with zero original-oid lines degenerates the map.
        out.no_original_ids = out.commits_observed > 0
            && out
                .commit_map
                .as_ref()
                .map_or(true, |m| m.is_empty());
    }
    #[cfg(feature = "remap")]
    {
        out.remap = remap;
    }
    Ok(out)
}

/// Serialize the run artifacts: `commit-map`, `ref-map`, `run-report.txt`.
fn write_artifacts(dir: &Path, report: &RunReport) -> Result<(), DriverError> {
    let mut commit_map = String::new();
    if let Some(m) = &report.commit_map {
        for (old, new) in m.iter() {
            let new = new.map_or_else(|| "-".to_string(), |n| n.to_hex().to_string());
            commit_map.push_str(&format!("{} {}\n", old.to_hex(), new));
        }
    }
    std::fs::write(dir.join("commit-map"), commit_map)?;

    let mut ref_map = String::new();
    for (old, new, name) in &report.ref_map {
        ref_map.push_str(&format!("{old} {new} {name}\n"));
    }
    std::fs::write(dir.join("ref-map"), ref_map)?;

    std::fs::write(dir.join("run-report.txt"), report.to_text())?;
    Ok(())
}
