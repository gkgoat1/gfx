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
        s.push_str("passes:\n");
        for p in &self.passes {
            s.push_str(&format!("  - {}: {}\n", p.name, p.detail));
        }
        s
    }
}

/// The pass driver. Construct with [`PassDriver::new`], configure with
/// [`PassDriver::with_passes`] / [`PassDriver::force`], then
/// [`PassDriver::run`] or [`PassDriver::dry_run`].
#[derive(Debug)]
pub struct PassDriver {
    repo: PathBuf,
    passes: Vec<PassSpec>,
    force: bool,
}

impl PassDriver {
    /// Verify `repo` is a git repository and start a driver for it.
    pub fn new(repo: impl Into<PathBuf>) -> Result<Self, DriverError> {
        let repo = repo.into();
        crate::git::process::git_dir(&repo)
            .map_err(|_| DriverError::NotARepository { path: repo.clone() })?;
        Ok(PassDriver {
            repo,
            passes: Vec::new(),
            force: false,
        })
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

    fn check_safety(&self) -> Result<(), DriverError> {
        if self.force {
            return Ok(());
        }
        if crate::git::process::is_bare(&self.repo)? {
            return Ok(());
        }
        let dirty = !crate::git::process::status_porcelain(&self.repo)?.is_empty();
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
        self.check_safety()?;
        self.round(true)
    }

    fn round(&mut self, import: bool) -> Result<RunReport, DriverError> {
        let input = crate::git::process::export_stream(&self.repo, &[])?;
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
        };

        if !import {
            return Ok(report);
        }

        // Import, then finalize remap from fast-import's marks (mode A).
        let gitdir = crate::git::process::git_dir(&self.repo)?;
        let gfx_dir = gitdir.join("gfx");
        std::fs::create_dir_all(&gfx_dir)?;
        let marks_path = gfx_dir.join("marks.out");
        crate::git::process::import_stream(&self.repo, &out.output, &marks_path)?;

        #[cfg(feature = "remap")]
        if let Some(r) = out.remap.as_mut() {
            let marks_bytes = std::fs::read(&marks_path)?;
            let marks = MarkFile::parse(&marks_bytes)?;
            r.finalize_from_marks(&marks);
            report.commit_map = Some(r.final_commit_map().clone());
        }

        // Ref-map: full before/after snapshot (complete even for refs only
        // bound by commit commands, which remap does not track).
        let before = crate::git::process::refs(&self.repo)?;
        let after = crate::git::process::refs(&self.repo)?;
        let after_map: std::collections::BTreeMap<&str, &str> =
            after.iter().map(|(o, n)| (n.as_str(), o.as_str())).collect();
        report.ref_map = before
            .iter()
            .map(|(old, name)| {
                let new = after_map.get(name.as_str()).copied().unwrap_or("deleted");
                (old.clone(), new.to_string(), name.clone())
            })
            .collect();

        // Artifacts (plan §4.3). Deterministic contents (A6).
        write_artifacts(&gfx_dir, &report)?;
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
    let mut blob_xform: Option<gfx_blob_xform::BlobXform> = None;
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
            cfg.mark_base = Some(max_mark + 1);
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
    #[cfg(feature = "blob-xform")]
    let blob_xform_rules: Vec<gfx_blob_xform::PathRule> = passes
        .iter()
        .find_map(|p| match p {
            PassSpec::BlobXform(cfg) => Some(cfg.path_rules.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let mut blob_xform_report = None;
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
