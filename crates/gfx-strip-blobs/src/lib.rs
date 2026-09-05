#![no_std]
#![forbid(unsafe_code)]
//! Builtin: retroactive removal of large / generated files (plan §5).
//!
//! Drop-first semantics (decision D1): the pass **drops ops and never
//! synthesizes any**. Selection is an OR of deterministic predicates — size
//! threshold, path globs, host-compiled path matchers, content signals, and
//! injected pure-fn predicates — protected by `protect_globs` (never strip
//! dotfiles like `.gitattributes` by default).
//!
//! Why the virtual index is involved even though we only drop: (a) `C`/`R`
//! *sources* must resolve to content so blob selection can catch copies of
//! selected blobs (the stream gives paths, not datarefs, for copies); (b)
//! kept `D`s must target paths that are live in the **rewritten view** —
//! deletes of paths erased by our own drops are normalized away; (c) the
//! pass reports the documented divergence of D1: under blob selection, a
//! path whose last surviving op was dropped reverts to older surviving
//! content rather than becoming a tombstone.
//!
//! With nothing selected the output is byte-identical input (property S1);
//! verdicts are cached per blob identity (marks/OIDs), never across
//! `reset()`.

extern crate alloc;

mod glob;
mod signals;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use gfx_core::{BString, DataRef, Error, Event, FileOp, FileSource, Mode};
use gfx_vindex::{BlobId, Entry, Index};

pub use glob::glob_match;
pub use signals::ContentSignals;

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Host-compiled path matcher (plan §5.2 knob 3): the `regex` crate stays
/// out of `no_std`; hosts pre-compile and inject. Shared by reference
/// (`Rc`) so the config stays cheaply clonable for `reset()`.
pub trait PathMatcher {
    fn matches(&self, path: &[u8]) -> bool;

    /// Debug output without requiring `Clone` bounds on implementations.
    fn describe(&self) -> String {
        String::from("<path-matcher>")
    }
}

/// Newtype for `Debug`/`Clone` on the shared matcher (orphan rule: we own
/// the newtype, not `Rc`).
#[derive(Clone)]
pub struct SharedMatcher(pub alloc::rc::Rc<dyn PathMatcher>);

impl core::fmt::Debug for SharedMatcher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0.describe())
    }
}

/// Host-injected pure predicate (plan §5.2 knob 5). Contract: a pure
/// function of `(path, bytes)` — stateful predicates break determinism (P6)
/// and are rejected by the test kit's stateful-predicate check.
pub trait BlobPredicate {
    fn judge(&self, path: Option<&BString>, data: &[u8]) -> bool;

    /// Debug output without requiring `Clone` bounds on implementations.
    fn describe(&self) -> String {
        String::from("<blob-predicate>")
    }
}

/// Newtype for `Debug`/`Clone` on the shared predicate (orphan rule).
#[derive(Clone)]
pub struct SharedPredicate(pub alloc::rc::Rc<dyn BlobPredicate>);

impl core::fmt::Debug for SharedPredicate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0.describe())
    }
}

/// Why a blob/path was selected (report surface, plan §5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    Size { bytes: u64 },
    PathGlob { glob: BString },
    PathMatcher,
    ContentSignal(signals::Signal),
    Injected,
}

impl Reason {
    #[allow(dead_code)]
    fn describe(&self) -> String {
        match self {
            Reason::Size { bytes } => format!("size>{bytes}"),
            Reason::PathGlob { glob } => {
                format!("path-glob:{}", String::from_utf8_lossy(glob.as_slice()))
            }
            Reason::PathMatcher => "path-matcher".into(),
            Reason::ContentSignal(s) => format!("signal:{s:?}"),
            Reason::Injected => "injected-predicate".into(),
        }
    }
}

/// Configuration (plan §5.3). `Clone` shares the injected matcher/predicate
/// boxes (they are treated as immutable shared state); `reset()` restores a
/// fresh transform while keeping the configuration.
#[derive(Clone, Debug, Default)]
pub struct StripBlobsConfig {
    /// Strip blobs strictly larger than this many bytes. `None` disables
    /// the size rule.
    pub size_threshold: Option<u64>,
    /// Full-path globs (bytes; `**` doublestar supported — see [`glob`]).
    pub path_globs: Vec<BString>,
    /// Host-compiled matchers (e.g. regexes), shared by reference.
    pub path_matchers: Vec<SharedMatcher>,
    /// Content-signal configuration (scan cap, per-signal toggles).
    pub content_signals: ContentSignals,
    /// Host-injected pure predicates, shared by reference.
    pub extra_predicates: Vec<SharedPredicate>,
    /// Paths matching these globs are never stripped (defaults include
    /// `.gitattributes` / `.gitignore` / `.gitmodules` at any depth).
    pub protect_globs: Vec<BString>,
    /// Also judge symlink payloads (targets) against content signals and
    /// extra predicates. Default false (plan §5.6: symlinks are tiny and
    /// stripping them is surprising).
    pub strip_symlinks_too: bool,
    /// Cap per-listing entries in the report; totals stay exact.
    pub report_limit: usize,
}

impl StripBlobsConfig {
    fn protect_globs_or_default(&self) -> Vec<BString> {
        if self.protect_globs.is_empty() {
            return [".gitattributes", ".gitignore", ".gitmodules"]
                .iter()
                .map(|g| {
                    let mut pat = Vec::with_capacity(g.len() + 7);
                    pat.extend_from_slice(b"**/");
                    pat.extend_from_slice(g.as_bytes());
                    BString::from(pat)
                })
                .collect();
        }
        self.protect_globs.clone()
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// One reported removal/divergence (bounded by `report_limit`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StripEntry {
    /// The op site: ref + path.
    pub ref_name: BString,
    pub path: BString,
    pub reason: Reason,
    /// Dropped payload size (0 for path-only or `C`/`R` drops).
    pub bytes: u64,
    /// A divergence under drop-first semantics (D1): the path will revert
    /// to older surviving content (blob-selected `C`/`R`/inline re-adds).
    pub divergent: bool,
}

/// Totals (always exact regardless of `report_limit`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StripTotals {
    /// Ops dropped (`M`/`C`/`R`/`D`).
    pub ops_dropped: u64,
    /// Content bytes no longer reachable from surviving `M`/`N` ops.
    pub bytes_saved: u64,
    pub paths_affected: u64,
    pub divergences: u64,
    /// Commits left with zero surviving ops after stripping.
    pub now_empty_commits: u64,
}

/// The pass report (`finish()` output, plan §5.4).
#[derive(Clone, Debug, Default)]
pub struct StripReport {
    pub totals: StripTotals,
    pub entries: Vec<StripEntry>,
    /// Truncated because of `report_limit`.
    pub truncated: bool,
}

impl StripReport {
    /// One-line deterministic summary for the driver's run report.
    pub fn summary_text(&self) -> String {
        format!(
            "ops_dropped={} bytes_saved={} paths_affected={} divergences={} now_empty_commits={}",
            self.totals.ops_dropped,
            self.totals.bytes_saved,
            self.totals.paths_affected,
            self.totals.divergences,
            self.totals.now_empty_commits
        )
    }
}

// ---------------------------------------------------------------------------
// The pass
// ---------------------------------------------------------------------------

/// Verdict for one blob identity.
#[derive(Clone, Debug)]
struct Verdict {
    selected: bool,
    reason: Reason,
    size: u64,
}

/// The strip-blobs transform.
#[derive(Debug)]
pub struct StripBlobs {
    cfg: StripBlobsConfig,
    /// Blob registry: mark/oid → verdict (plan §5.1).
    registry: BTreeMap<BlobId, Verdict>,
    /// Original view: what fast-import would see at each op (C/R source
    /// resolution). `inline_seq` mirrors the vindex counter.
    original: Index,
    /// Rewritten view: what the importer will see after our drops (kept-D
    /// validity).
    rewritten: Index,
    /// Blobs holding selected content, for rewritten-view bookkeeping: paths
    /// in the rewritten view whose entry is a *selected* blob (they only
    /// survive via inheritance semantics that cannot survive our drops, but
    /// tracking lets kept-D normalization be precise).
    selected_blobs: BTreeSet<BlobId>,
    report: StripReport,
    current_ref: Option<BString>,
    finished: bool,
}

impl StripBlobs {
    pub fn new(cfg: StripBlobsConfig) -> Self {
        StripBlobs {
            cfg,
            registry: BTreeMap::new(),
            original: Index::new(),
            rewritten: Index::new(),
            selected_blobs: BTreeSet::new(),
            report: StripReport::default(),
            current_ref: None,
            finished: false,
        }
    }

    pub fn config(&self) -> &StripBlobsConfig {
        &self.cfg
    }

    pub fn report(&self) -> &StripReport {
        &self.report
    }

    // -- selection ----------------------------------------------------------

    fn protected(&self, path: &[u8], protect: &[BString]) -> bool {
        protect.iter().any(|g| glob_match(g.as_slice(), path))
    }

    fn path_selected(&self, path: &[u8], protect: &[BString]) -> Option<Reason> {
        if self.protected(path, protect) {
            return None;
        }
        for g in &self.cfg.path_globs {
            if glob_match(g.as_slice(), path) {
                return Some(Reason::PathGlob { glob: g.clone() });
            }
        }
        for m in &self.cfg.path_matchers {
            if m.0.matches(path) {
                return Some(Reason::PathMatcher);
            }
        }
        None
    }

    /// Judge a payload against size + content signals + injected predicates.
    fn content_selected(&self, path: Option<&BString>, data: &[u8]) -> Option<Reason> {
        if let Some(t) = self.cfg.size_threshold {
            if (data.len() as u64) > t {
                return Some(Reason::Size { bytes: data.len() as u64 });
            }
        }
        if let Some(sig) = self.cfg.content_signals.judge(data) {
            return Some(Reason::ContentSignal(sig));
        }
        for p in &self.cfg.extra_predicates {
            if p.0.judge(path, data) {
                return Some(Reason::Injected);
            }
        }
        None
    }

    /// Full verdict for inline data at an op site (path + content rules).
    /// Protected paths are never judged (plan §5.6: same blob at two
    /// paths, one protected → protected path keeps its op).
    fn judge_inline(
        &self,
        mode: Mode,
        path: &BString,
        data: &[u8],
        protect: &[BString],
    ) -> Option<Reason> {
        if self.protected(path.as_slice(), protect) {
            return None;
        }
        if let Some(r) = self.path_selected(path.as_slice(), protect) {
            return Some(r);
        }
        if mode == Mode::Gitlink {
            return None; // never content-judged (plan §5.2)
        }
        if mode == Mode::Symlink && !self.cfg.strip_symlinks_too {
            return None;
        }
        self.content_selected(Some(path), data)
    }

    // -- report -------------------------------------------------------------

    fn record(&mut self, ref_name: &BString, path: &BString, reason: Reason, bytes: u64, divergent: bool) {
        self.report.totals.ops_dropped += 1;
        self.report.totals.bytes_saved += bytes;
        self.report.totals.paths_affected += 1;
        if divergent {
            self.report.totals.divergences += 1;
        }
        if self.report.entries.len() < self.cfg.report_limit.max(1) {
            self.report.entries.push(StripEntry {
                ref_name: ref_name.clone(),
                path: path.clone(),
                reason,
                bytes,
                divergent,
            });
        } else {
            self.report.truncated = true;
        }
    }

    /// Resolve the entry at `path` in the original view (pre-drop), if any.
    fn source_entry(&self, ref_name: &[u8], path: &[u8]) -> Option<Entry> {
        self.original.get(ref_name).and_then(|r| r.get(path).cloned())
    }

    /// Is the rewritten-view path live? (kept-D normalization)
    fn live_in_rewritten(&self, ref_name: &[u8], path: &[u8]) -> bool {
        self.rewritten
            .get(ref_name)
            .map(|r| r.get(path).is_some())
            .unwrap_or(false)
    }
}

impl gfx_core::Transform for StripBlobs {
    fn name(&self) -> &'static str {
        "strip-blobs"
    }

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.finished {
            out.push(event);
            return Ok(());
        }
        match event {
            Event::Blob { mark, original_oid, data } => {
                // Registry population (plan §5.1): judged once per identity.
                let size = data.len() as u64;
                let verdict = self.content_selected(None, data.as_slice()).map_or_else(
                    || Verdict {
                        selected: false,
                        reason: Reason::Size { bytes: 0 },
                        size,
                    },
                    |reason| Verdict {
                        selected: true,
                        reason,
                        size,
                    },
                );
                if let Some(m) = mark {
                    let id = BlobId::Mark(m);
                    if verdict.selected {
                        self.selected_blobs.insert(id.clone());
                    }
                    self.registry.insert(id, verdict.clone());
                }
                if let Some(oid) = original_oid {
                    let id = BlobId::Oid(oid);
                    if verdict.selected {
                        self.selected_blobs.insert(id.clone());
                    }
                    self.registry.entry(id).or_insert(verdict);
                }
                out.push(Event::Blob { mark, original_oid, data });
            }
            Event::Commit(c) => {
                let ref_name = c.ref_name.clone();
                self.current_ref = Some(ref_name.clone());

                let protect = self.cfg.protect_globs_or_default();
                let mut ops = Vec::with_capacity(c.ops.len());

                for op in &c.ops {
                    let mut drop: Option<(Reason, u64, bool)> = None;
                    match op {
                        FileOp::Modify { mode, path, source } => {
                            match source {
                                FileSource::Inline(data) => {
                                    if let Some(reason) =
                                        self.judge_inline(*mode, path, data.as_slice(), &protect)
                                    {
                                        drop = Some((reason, data.len() as u64, true));
                                    }
                                }
                                FileSource::DataRef(DataRef::Mark(m)) => {
                                    if let Some(reason) = self.path_selected(path.as_slice(), &protect) {
                                        drop = Some((reason, 0, false));
                                    } else if self.protected(path.as_slice(), &protect) {
                                        // protected: keep even a selected blob
                                    } else if *mode != Mode::Gitlink
                                        && self
                                            .registry
                                            .get(&BlobId::Mark(*m))
                                            .map(|v| v.selected)
                                            .unwrap_or(false)
                                    {
                                        let v = &self.registry[&BlobId::Mark(*m)];
                                        drop = Some((v.reason.clone(), v.size, true));
                                    }
                                }
                                FileSource::DataRef(DataRef::Oid(oid)) => {
                                    if let Some(reason) = self.path_selected(path.as_slice(), &protect) {
                                        drop = Some((reason, 0, false));
                                    } else if self.protected(path.as_slice(), &protect) {
                                        // protected: keep even a selected blob
                                    } else if *mode != Mode::Gitlink
                                        && self
                                            .registry
                                            .get(&BlobId::Oid(*oid))
                                            .map(|v| v.selected)
                                            .unwrap_or(false)
                                    {
                                        let v = &self.registry[&BlobId::Oid(*oid)];
                                        drop = Some((v.reason.clone(), v.size, true));
                                    }
                                }
                            }
                        }
                        FileOp::Delete { path } => {
                            // Normalize per §5.1: keep only deletes of paths
                            // live in the rewritten view. Selected-path
                            // deletes are dropped (the path must vanish);
                            // deletes of paths erased by our own drops are
                            // normalized away (not counted as strip ops).
                            if let Some(reason) = self.path_selected(path.as_slice(), &protect) {
                                drop = Some((reason, 0, false));
                            } else if !self.live_in_rewritten(ref_name.as_slice(), path.as_slice()) {
                                continue;
                            }
                        }
                        FileOp::Copy { from, to } => {
                            // `to` selected → a copy would reintroduce content
                            // at a selected path.
                            if let Some(reason) = self.path_selected(to.as_slice(), &protect) {
                                drop = Some((reason, 0, false));
                            } else if let Some(Entry::Blob { source }) =
                                self.source_entry(ref_name.as_slice(), from.as_slice())
                            {
                                if self.selected_blobs.contains(&source) {
                                    let reason = self
                                        .registry
                                        .get(&source)
                                        .map(|v| v.reason.clone())
                                        .unwrap_or(Reason::Injected);
                                    drop = Some((reason, 0, true));
                                }
                            }
                        }
                        FileOp::Rename { from, to } => {
                            if let Some(reason) = self
                                .path_selected(to.as_slice(), &protect)
                                .or_else(|| self.path_selected(from.as_slice(), &protect))
                            {
                                drop = Some((reason, 0, true));
                            } else if let Some(Entry::Blob { source }) =
                                self.source_entry(ref_name.as_slice(), from.as_slice())
                            {
                                if self.selected_blobs.contains(&source) {
                                    let reason = self
                                        .registry
                                        .get(&source)
                                        .map(|v| v.reason.clone())
                                        .unwrap_or(Reason::Injected);
                                    drop = Some((reason, 0, true));
                                }
                            }
                        }
                        FileOp::DeleteAll => {}
                        FileOp::Note { data, commit: _ } => {
                            // Note blobs are judged like any blob (§5.6);
                            // the note's commit ref is untouched.
                            match data {
                                FileSource::Inline(d) => {
                                    if let Some(reason) = self.content_selected(None, d.as_slice()) {
                                        drop = Some((reason, d.len() as u64, false));
                                    }
                                }
                                FileSource::DataRef(DataRef::Mark(m)) => {
                                    if self
                                        .registry
                                        .get(&BlobId::Mark(*m))
                                        .map(|v| v.selected)
                                        .unwrap_or(false)
                                    {
                                        let v = &self.registry[&BlobId::Mark(*m)];
                                        drop = Some((v.reason.clone(), v.size, false));
                                    }
                                }
                                FileSource::DataRef(DataRef::Oid(oid)) => {
                                    if self
                                        .registry
                                        .get(&BlobId::Oid(*oid))
                                        .map(|v| v.selected)
                                        .unwrap_or(false)
                                    {
                                        let v = &self.registry[&BlobId::Oid(*oid)];
                                        drop = Some((v.reason.clone(), v.size, false));
                                    }
                                }
                            }
                        }
                    }

                    match drop {
                        Some((reason, bytes, divergent)) => {
                            let path = match op {
                                FileOp::Modify { path, .. }
                                | FileOp::Delete { path }
                                | FileOp::Copy { to: path, .. }
                                | FileOp::Rename { to: path, .. } => path.clone(),
                                FileOp::Note { .. } => BString::from(b"<note>".to_vec()),
                                _ => unreachable!("DeleteAll never sets `drop`"),
                            };
                            self.record(&ref_name, &path, reason, bytes, divergent);
                        }
                        None => {
                            ops.push(op.clone());
                        }
                    }
                }

                // Replay both views: original sees every op, rewritten only
                // the survivors.
                self.original.apply_ops(ref_name.as_slice(), &c.ops);
                self.rewritten.apply_ops(ref_name.as_slice(), &ops);

                if ops.is_empty() && !c.ops.is_empty() {
                    self.report.totals.now_empty_commits += 1;
                }

                out.push(Event::Commit(gfx_core::Commit { ops, ..c }));
            }
            Event::Reset { ref_name, from } => {
                // Tip moves do not clear indices (fast-import semantics;
                // see gfx_vindex::Index::note_committish).
                self.original.note_committish(ref_name.as_slice(), from.as_ref());
                self.current_ref = Some(ref_name.clone());
                out.push(Event::Reset { ref_name, from });
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<Event>) -> Result<(), Error> {
        self.finished = true;
        // The report is the finish() output (plan §5.4); no stream events
        // are appended. Hosts read `report()` after the pipeline drains.
        Ok(())
    }

    fn reset(&mut self) {
        let cfg = self.cfg.clone();
        *self = StripBlobs::new(cfg);
    }
}
