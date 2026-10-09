#![no_std]
#![forbid(unsafe_code)]
//! `gfx-enforce-ignore` — builtin pass `enforce-ignore`
//! (plan-stream-files.md D6).
//!
//! Enforces gitignore rules retroactively: every `M` op whose path the
//! active ruleset ignores is **dropped** (drop-first, never synthesize —
//! the strip-blobs D1 rule applied verbatim), so the path never enters the
//! rewritten history. `D` ops for ignored paths are normalized against the
//! rewritten view (kept iff the path actually exists there), and `C`/`R`
//! ops touching an ignored path on either side are dropped.
//!
//! Rule sources (config, composable):
//!
//! - `external_rules` — gitignore-format bytes supplied by the host,
//!   applied root-anchored from stream start (M3);
//! - `stream_rules` — the stream's own `.gitignore` blobs, tracked
//!   per-commit (M4; this milestone parses but does not yet propagate).
//!
//! Guarantees and non-goals:
//!
//! - **`.gitignore` carriers are never dropped (C8).** A `M` op whose
//!   path basename is `.gitignore` always survives, even if a rule would
//!   match it — the rule source must not erase itself.
//! - Zero-op commits are **kept** (no prune-empty in v1 — remap does not
//!   splice parentage) and counted in the report.
//! - The pass is sans-IO and deterministic: rules come in as bytes, the
//!   verdict for a given (ruleset, path) pair never changes within a run.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use bstr::{BString, ByteSlice};
use gfx_core::{
    BString as CoreBString, Committish, DataRef, Error, Event, FileOp, FileSource, Mark, Mode,
    Transform,
};
use gfx_ignore::{rule_file, Ruleset};

/// Pass configuration.
#[derive(Clone, Debug, Default)]
pub struct EnforceIgnoreConfig {
    /// gitignore-format rule files applied root-anchored from stream
    /// start (outermost layer of the stack), as raw bytes.
    pub external_rules: Vec<BString>,
    /// Also track `.gitignore` blobs carried by the stream itself
    /// (M4). Requires no external rules; the stream provides them.
    pub stream_rules: bool,
    /// Cap per-listing entries in the report; totals stay exact.
    pub report_limit: usize,
}

impl EnforceIgnoreConfig {
    /// Resolve defaults (report limit).
    pub fn resolved(mut self) -> Self {
        if self.report_limit == 0 {
            self.report_limit = 1000;
        }
        self
    }
}

/// Why an op was dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    /// The deciding rule, rendered `dir:pattern` (negation prefixed).
    pub rule: String,
}

impl Reason {
    fn detail(&self) -> String {
        format!("ignored-by:{}", self.rule)
    }
}

/// One dropped op, for the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IgnoreEntry {
    /// Ref the commit was on.
    pub ref_name: CoreBString,
    /// Commit mark, when the stream gave one.
    pub mark: Option<Mark>,
    /// The path whose op was dropped.
    pub path: CoreBString,
    pub reason: Reason,
}

/// Exact totals (never truncated).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgnoreTotals {
    pub commits_observed: usize,
    /// Commits that had ops and lost all of them (kept, empty).
    pub now_empty_commits: usize,
    pub ops_dropped: usize,
    /// `D` ops normalized away (path absent in the rewritten view).
    pub deletes_normalized: usize,
    /// `.gitignore` rule-file updates picked up from the stream (M4).
    pub rule_files_tracked: usize,
    /// `.gitignore` modifications whose content the stream references by
    /// OID (incremental streams) — the bytes are not in the stream, so
    /// the rule update was skipped. Surfaced, never silent.
    pub rules_unresolved: usize,
}

/// Audit surface (plan D6): exact totals, bounded listings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgnoreReport {
    pub totals: IgnoreTotals,
    pub entries: Vec<IgnoreEntry>,
    /// Truncated because of `report_limit`.
    pub truncated: bool,
}

impl IgnoreReport {
    pub fn summary_text(&self) -> String {
        format!(
            "commits_observed={} ops_dropped={} deletes_normalized={} now_empty_commits={} rule_files_tracked={} rules_unresolved={}",
            self.totals.commits_observed,
            self.totals.ops_dropped,
            self.totals.deletes_normalized,
            self.totals.now_empty_commits,
            self.totals.rule_files_tracked,
            self.totals.rules_unresolved,
        )
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("{}\n", self.summary_text()));
        for e in &self.entries {
            s.push_str(&format!(
                "{} :{} {} — {}\n",
                String::from_utf8_lossy(&e.ref_name),
                e.mark.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
                String::from_utf8_lossy(&e.path),
                e.reason.detail(),
            ));
        }
        if self.truncated {
            s.push_str("# (listing truncated; totals above are exact)\n");
        }
        s
    }
}

/// A path whose basename is `.gitignore` carries rules — never drop it
/// (C8), even when a rule matches.
fn is_carrier(path: &[u8]) -> bool {
    let base = match path.rfind_byte(b'/') {
        Some(i) => &path[i + 1..],
        None => path,
    };
    base == b".gitignore"
}

/// The `enforce-ignore` transform.
pub struct EnforceIgnore {
    cfg: EnforceIgnoreConfig,
    /// Rules pinned from stream start: external files first, then any
    /// stream-tracked state layered on top per commit (M4).
    base: Ruleset,
    /// Rewritten-view index: which paths exist after our drops, per ref —
    /// drives `D` normalization and `C`/`R` source checks.
    rewritten: gfx_vindex::Index,
    /// M4 (stream_rules): commit mark → the ruleset of that commit's
    /// tree. `Arc`-shared: children inherit their first parent's ruleset
    /// by clone-of-`Arc`; a commit that edits `.gitignore` pays one copy.
    mark_rules: BTreeMap<Mark, Arc<Ruleset>>,
    /// Current ruleset per ref — covers markless commits and the common
    /// `from`-less "continue this branch" form.
    ref_rules: BTreeMap<Vec<u8>, Arc<Ruleset>>,
    /// M4: blob mark → payload. The stream carries blob bytes before the
    /// commits that reference them (topo order, R8); a `.gitignore`
    /// `M :mark` op resolves through this. Bounded by stream size, like
    /// the driver's buffered rounds.
    blobs: BTreeMap<Mark, Vec<u8>>,
    report: IgnoreReport,
    finished: bool,
}

impl EnforceIgnore {
    pub fn new(cfg: EnforceIgnoreConfig) -> Self {
        let cfg = cfg.resolved();
        let mut base = Ruleset::new();
        for bytes in &cfg.external_rules {
            base.push_file(gfx_ignore::BString::from(""), rule_file("", bytes).rules);
        }
        EnforceIgnore {
            cfg,
            base,
            rewritten: gfx_vindex::Index::new(),
            mark_rules: BTreeMap::new(),
            ref_rules: BTreeMap::new(),
            blobs: BTreeMap::new(),
            report: IgnoreReport::default(),
            finished: false,
        }
    }

    pub fn report(&self) -> &IgnoreReport {
        &self.report
    }

    /// The stream-rule state a commit starts from: its first parent's
    /// (M4, plan-stream-files.md D6 — merge commits use the mainline's
    /// rules), falling back to the ref's current state (the `from`-less
    /// continue-the-branch form) and finally to an empty stream state.
    /// External rules do not live here — they are layered on at judging
    /// time via [`Ruleset::combined`] (operator intent wins ties).
    fn parent_stream_rules(&self, c: &gfx_core::Commit) -> Arc<Ruleset> {
        match &c.from {
            Some(Committish::Mark(m)) => self
                .mark_rules
                .get(m)
                .cloned()
                .unwrap_or_else(|| Arc::new(Ruleset::new())),
            // An OID parent is outside the stream (incremental export):
            // its rules are unknowable here — the ref's current state is
            // the best approximation, else empty.
            Some(Committish::Oid(_)) | None => self
                .ref_rules
                .get(c.ref_name.as_slice())
                .cloned()
                .unwrap_or_else(|| Arc::new(Ruleset::new())),
        }
    }

    /// Apply a commit's own `.gitignore` ops to its inherited *stream*
    /// state (M4): the commit is judged against the rules of its own tree
    /// (stream state + the external layer). Carrier content comes from
    /// inline data or the blob cache; OID-sourced content is unresolvable
    /// (counted, never silent).
    ///
    /// Returns `(stream_state, judging_stack, tracked, unresolved)`.
    fn apply_rule_ops(
        &self,
        inherited: &Arc<Ruleset>,
        c: &gfx_core::Commit,
    ) -> (Arc<Ruleset>, Ruleset, usize, usize) {
        let mut tracked = 0usize;
        let mut unresolved = 0usize;
        let mut next: Option<Ruleset> = None;
        if self.cfg.stream_rules {
            for op in &c.ops {
                let dir: &[u8] = match op {
                    FileOp::Modify { path, .. } | FileOp::Delete { path }
                        if is_carrier(path.as_slice()) =>
                    {
                        match path.rfind_byte(b'/') {
                            Some(i) => &path[..i],
                            None => &[],
                        }
                    }
                    _ => continue,
                };
                let rs = next.get_or_insert_with(|| (**inherited).clone());
                match op {
                    FileOp::Modify { source, .. } => {
                        let bytes: Option<&[u8]> = match source {
                            FileSource::Inline(d) => Some(d.as_slice()),
                            FileSource::DataRef(DataRef::Mark(m)) => {
                                self.blobs.get(m).map(|v| v.as_slice())
                            }
                            FileSource::DataRef(DataRef::Oid(_)) => None,
                        };
                        match bytes {
                            Some(b) => {
                                rs.upsert_file(BString::from(dir), rule_file("", b).rules);
                                tracked += 1;
                            }
                            None => unresolved += 1,
                        }
                    }
                    FileOp::Delete { .. } => {
                        rs.remove_dir(dir);
                        tracked += 1;
                    }
                    _ => unreachable!("filtered above"),
                }
            }
        }
        let stream_state = match next {
            Some(rs) => Arc::new(rs),
            None => inherited.clone(),
        };
        let judging = stream_state.combined(&self.base);
        (stream_state, judging, tracked, unresolved)
    }

    fn record(&mut self, ref_name: &[u8], mark: Option<Mark>, path: &[u8], reason: Reason) {
        self.report.totals.ops_dropped += 1;
        if self.report.entries.len() < self.cfg.report_limit {
            self.report.entries.push(IgnoreEntry {
                ref_name: CoreBString::from(ref_name),
                mark,
                path: CoreBString::from(path),
                reason,
            });
        } else {
            self.report.truncated = true;
        }
    }
}

impl Transform for EnforceIgnore {
    fn name(&self) -> &'static str {
        "enforce-ignore"
    }

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.finished {
            out.push(event);
            return Ok(());
        }
        match event {
            Event::Blob { mark, original_oid, data } => {
                // M4: cache payloads so `.gitignore` `M :mark` ops resolve.
                if self.cfg.stream_rules {
                    if let Some(m) = mark {
                        self.blobs.insert(m, data.0.clone());
                    }
                }
                out.push(Event::Blob { mark, original_oid, data });
            }
            Event::Commit(c) => {
                self.report.totals.commits_observed += 1;
                let ref_name = c.ref_name.clone();

                // M4: inherit the first parent's stream-rule state, apply
                // this commit's own `.gitignore` edits, judge against the
                // result layered over the external rules (the rules of
                // the commit's own tree, D6; operator rules win ties).
                let inherited = self.parent_stream_rules(&c);
                let (stream_state, judging, tracked, unresolved) =
                    self.apply_rule_ops(&inherited, &c);
                self.report.totals.rule_files_tracked += tracked;
                self.report.totals.rules_unresolved += unresolved;
                if let Some(m) = c.mark {
                    self.mark_rules.insert(m, stream_state.clone());
                }
                self.ref_rules
                    .insert(ref_name.as_slice().to_vec(), stream_state.clone());
                let ruleset = &judging;

                let mut ops = Vec::with_capacity(c.ops.len());

                for op in &c.ops {
                    let mut drop: Option<Reason> = None;
                    match op {
                        FileOp::Modify { mode, path, .. } => {
                            if is_carrier(path.as_slice()) {
                                // C8: rule carriers survive.
                            } else {
                                let v = ruleset.judge_with_ancestors(
                                    path.as_slice(),
                                    *mode == Mode::Dir,
                                );
                                if v.ignored {
                                    let rule = v
                                        .decided_by
                                        .as_ref()
                                        .map(gfx_ignore::describe)
                                        .unwrap_or_else(|| "?".into());
                                    drop = Some(Reason { rule });
                                }
                            }
                        }
                        FileOp::Delete { path } => {
                            // Kept-D validity (strip-blobs §5.1): a delete
                            // of a path absent from the rewritten view —
                            // because we dropped its creation, an earlier
                            // pass did, or the stream was sloppy — is
                            // normalized away (never counted as an enforce
                            // drop). A live path keeps its delete, ignored
                            // or not: the delete removes it, which is the
                            // direction enforcement wants anyway.
                            let live = self
                                .rewritten
                                .get(ref_name.as_slice())
                                .and_then(|r| r.get(path.as_slice()))
                                .is_some();
                            if !live {
                                self.report.totals.deletes_normalized += 1;
                                continue;
                            }
                        }
                        FileOp::Copy { from, to } | FileOp::Rename { from, to }
                            if !is_carrier(from.as_slice()) && !is_carrier(to.as_slice()) =>
                        {
                            // A copy/rename *to* an ignored path would
                            // reintroduce ignored content; *from* an
                            // ignored path has no valid source (we dropped
                            // its creation). Carrier paths are never
                            // judged (C8) — a copy that creates one is
                            // kept (its content is not tracked as rules;
                            // documented M4 limitation).
                            let to_v = ruleset.judge_with_ancestors(to.as_slice(), false);
                            let from_v = ruleset.judge_with_ancestors(from.as_slice(), false);
                            if to_v.ignored || from_v.ignored {
                                let v = if to_v.ignored { &to_v } else { &from_v };
                                let rule = v
                                    .decided_by
                                    .as_ref()
                                    .map(gfx_ignore::describe)
                                    .unwrap_or_else(|| "?".into());
                                drop = Some(Reason { rule });
                            }
                        }
                        FileOp::Copy { .. } | FileOp::Rename { .. } => {
                            // Carrier-involving copies/renames: kept (C8).
                        }
                        FileOp::DeleteAll | FileOp::Note { .. } => {}
                    }

                    match drop {
                        Some(reason) => {
                            let path = match op {
                                FileOp::Modify { path, .. } | FileOp::Delete { path } => path,
                                FileOp::Copy { to, .. } | FileOp::Rename { to, .. } => to,
                                _ => unreachable!("DeleteAll/Note never set `drop`"),
                            };
                            self.record(ref_name.as_slice(), c.mark, path.as_slice(), reason);
                        }
                        None => ops.push(op.clone()),
                    }
                }

                // Replay the rewritten view with the survivors.
                self.rewritten.apply_ops(ref_name.as_slice(), &ops);

                if ops.is_empty() && !c.ops.is_empty() {
                    self.report.totals.now_empty_commits += 1;
                }

                out.push(Event::Commit(gfx_core::Commit { ops, ..c }));
            }
            Event::Reset { ref_name, from } => {
                // Tip moves do not clear the index (fast-import semantics).
                self.rewritten.note_committish(ref_name.as_slice(), from.as_ref());
                if self.cfg.stream_rules {
                    if let Some(Committish::Mark(m)) = &from {
                        if let Some(rs) = self.mark_rules.get(m).cloned() {
                            self.ref_rules.insert(ref_name.as_slice().to_vec(), rs);
                        }
                    } else {
                        // A reset without a known mark source restarts the
                        // ref's stream-rule state from empty.
                        self.ref_rules
                            .insert(ref_name.as_slice().to_vec(), Arc::new(Ruleset::new()));
                    }
                }
                out.push(Event::Reset { ref_name, from });
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<Event>) -> Result<(), Error> {
        self.finished = true;
        Ok(())
    }

    fn reset(&mut self) {
        *self = EnforceIgnore::new(self.cfg.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the pass over a hand-built stream and return the output text.
    fn run(cfg: EnforceIgnoreConfig, input: &str) -> (String, IgnoreReport) {
        let mut parser = gfx_core::Parser::new(gfx_core::ParseOptions::default());
        parser.feed(input.as_bytes());
        let mut pass = EnforceIgnore::new(cfg);
        let mut events = Vec::new();
        while let Some(ev) = parser.next_event().unwrap() {
            pass.apply(ev, &mut events).unwrap();
        }
        let mut tail = Vec::new();
        parser.finish(&mut tail).unwrap();
        for ev in tail {
            pass.apply(ev, &mut events).unwrap();
        }
        pass.finish(&mut events).unwrap();
        let mut w = gfx_core::Writer::new();
        for ev in &events {
            w.write(ev).unwrap();
        }
        (String::from_utf8_lossy(&w.take()).into_owned(), pass.report().clone())
    }

    const COMMIT: &str = "commit refs/heads/main\nmark :1\noriginal-oid 1111111111111111111111111111111111111111\nauthor A <a@a> 0 +0000\ncommitter A <a@a> 0 +0000\ndata 2\nm1";

    #[test]
    fn drops_ignored_modifies_and_reports_the_rule() {
        let cfg = EnforceIgnoreConfig {
            external_rules: alloc::vec![BString::from("*.log\nbuild/\n")],
            ..Default::default()
        };
        let input = format!(
            "reset refs/heads/main\n{COMMIT}\nM 100644 inline x.log\ndata 4\nlog\n\nM 100644 inline keep.txt\ndata 5\nkeep\n\nM 100644 inline build/f.o\ndata 3\nbin\n\n"
        );
        let (out, report) = run(cfg, &input);
        assert!(!out.contains("x.log"), "ignored path dropped:\n{out}");
        assert!(out.contains("keep.txt"), "kept path survives");
        assert!(!out.contains("build/f.o"), "path under ignored dir dropped");
        assert_eq!(report.totals.ops_dropped, 2);
        assert_eq!(report.totals.now_empty_commits, 0, "one op survived");
        assert!(report.entries.iter().any(|e| e.reason.rule == "*.log"));
        assert!(report.entries.iter().any(|e| e.reason.rule == "build/"));
    }

    #[test]
    fn gitignore_carrier_survives_even_when_matched() {
        let cfg = EnforceIgnoreConfig {
            external_rules: alloc::vec![BString::from(".*\n")], // dotfiles
            ..Default::default()
        };
        let input = format!(
            "reset refs/heads/main\n{COMMIT}\nM 100644 inline .gitignore\ndata 6\n*.log\n\nM 100644 inline .env\ndata 4\nsec\n\n"
        );
        let (out, report) = run(cfg, &input);
        assert!(out.contains(".gitignore"), "C8: carriers never drop");
        assert!(!out.contains(".env"));
        assert_eq!(report.totals.ops_dropped, 1);
    }

    #[test]
    fn delete_of_dropped_path_is_normalized() {
        let cfg = EnforceIgnoreConfig {
            external_rules: alloc::vec![BString::from("*.log\n")],
            ..Default::default()
        };
        let input = format!(
            "reset refs/heads/main\n{COMMIT}\nM 100644 inline x.log\ndata 4\nlog\n\n\
             commit refs/heads/main\nmark :2\nauthor A <a@a> 0 +0000\ncommitter A <a@a> 0 +0000\ndata 2\nm2\nfrom :1\nD x.log\n"
        );
        let (_out, report) = run(cfg, &input);
        assert_eq!(report.totals.ops_dropped, 1, "the M");
        assert_eq!(report.totals.deletes_normalized, 1, "the D of a path we erased");
    }


    // -- M4: stream-carried .gitignore tracking -------------------------

    /// Join stream lines (each item becomes one line).
    fn lines(parts: &[&str]) -> String {
        let mut s = String::new();
        for p in parts {
            s.push_str(p);
            s.push('\n');
        }
        s
    }

    /// `M 100644 inline <path>` with correctly counted data.
    fn m_inline(path: &str, content: &str) -> String {
        format!("M 100644 inline {}\ndata {}\n{}\n", path, content.len(), content)
    }

    /// A commit header (`commit` … message …) followed by `from`.
    fn commit_hdr(mark: u64, msg: &str, from: Option<u64>) -> String {
        let from = from.map(|m| format!("from :{}\n", m)).unwrap_or_default();
        format!(
            "commit refs/heads/main\nmark :{}\nauthor A <a@a> 0 +0000\ncommitter A <a@a> 0 +0000\ndata {}\n{}\n{}",
            mark,
            msg.len(),
            msg,
            from
        )
    }

    const COMMIT3: &str = "commit refs/heads/main\nmark :3\nauthor A <a@a> 0 +0000\ncommitter A <a@a> 0 +0000\ndata 2\nm3\nfrom :2";

    #[test]
    fn stream_rules_apply_only_after_introduction() {
        let cfg = EnforceIgnoreConfig {
            stream_rules: true,
            ..Default::default()
        };
        // Commit 1 creates x.log before any .gitignore exists; commit 2
        // adds the rule file (blob mark 7); commit 3 touches x.log again.
        let input = format!(
            "{}{}{}{}{}",
            lines(&["reset refs/heads/main", COMMIT]),
            m_inline("x.log", "log"),
            lines(&["blob", "mark :7", "data 6", "*.log\n"]),
            format!("{}M 100644 :7 .gitignore\n", commit_hdr(2, "m2", Some(1))),
            format!("{}{}", commit_hdr(3, "m3", Some(2)), m_inline("x.log", "lg2")),
        );
        let (out, report) = run(cfg, &input);
        assert!(out.contains("log"), "the pre-rule x.log survives");
        assert!(!out.contains("lg2"), "x.log dropped only after the rule exists:\n{out}");
        assert_eq!(report.totals.ops_dropped, 1);
        assert_eq!(report.totals.rule_files_tracked, 1);
        assert!(out.contains(".gitignore"), "carrier kept");
    }

    #[test]
    fn stream_rules_edit_and_delete_take_effect() {
        let cfg = EnforceIgnoreConfig {
            stream_rules: true,
            ..Default::default()
        };
        // c1: .gitignore = *.log (drops a.log in c2); c3: .gitignore =
        // *.tmp (a.log free again in c4, b.tmp dropped); c5: delete the
        // .gitignore (c6's c.tmp survives).
        let input = format!(
            "{}{}{}{}{}{}{}{}{}",
            lines(&["reset refs/heads/main", COMMIT]),
            m_inline(".gitignore", "*.log"),
            format!("{}{}", commit_hdr(2, "m2", Some(1)), m_inline("a.log", "l")),
            format!("{}{}", commit_hdr(3, "m3", Some(2)), m_inline(".gitignore", "*.tmp")),
            format!(
                "{}{}{}",
                commit_hdr(4, "m4", Some(3)),
                m_inline("a.log", "l"),
                m_inline("b.tmp", "t")
            ),
            format!("{}D .gitignore\n", commit_hdr(5, "m5", Some(4))),
            commit_hdr(6, "m6", Some(5)),
            m_inline("c.tmp", "t"),
            ""
        );
        let (out, report) = run(cfg, &input);
        assert_eq!(report.totals.rule_files_tracked, 3, "add + edit + delete");
        let a_log_ops = out.matches("inline a.log").count();
        assert_eq!(a_log_ops, 1, "a.log survives only its post-edit op:\n{out}");
        assert!(!out.contains("b.tmp"), "b.tmp dropped under the edited rules");
        assert!(out.contains("c.tmp"), "c.tmp survives after the delete");
        assert_eq!(report.totals.ops_dropped, 2);
    }

    #[test]
    fn stream_rules_nested_dir_files_scope_to_their_subtree() {
        let cfg = EnforceIgnoreConfig {
            stream_rules: true,
            ..Default::default()
        };
        let input = format!(
            "{}{}{}{}{}",
            lines(&["reset refs/heads/main", COMMIT]),
            m_inline("sub/.gitignore", "*.gen"),
            commit_hdr(2, "m2", Some(1)),
            m_inline("sub/x.gen", "g"),
            m_inline("top.gen", "g"),
        );
        let (out, report) = run(cfg, &input);
        assert!(!out.contains("sub/x.gen"), "nested rule applies below its dir:\n{out}");
        assert!(out.contains("top.gen"), "nested rule does not escape its subtree");
        assert_eq!(report.totals.ops_dropped, 1);
    }

    #[test]
    fn stream_rules_branches_inherit_from_first_parent() {
        let cfg = EnforceIgnoreConfig {
            stream_rules: true,
            ..Default::default()
        };
        // main: c1 adds .gitignore(*.log). A side branch forks from :1 —
        // its commits must see the rule even though they come later in
        // the stream.
        let side = "commit refs/heads/side\nmark :2\nauthor A <a@a> 0 +0000\ncommitter A <a@a> 0 +0000\ndata 2\ns1\nfrom :1\n";
        let input = format!(
            "{}{}{}{}{}",
            lines(&["reset refs/heads/main", COMMIT]),
            m_inline(".gitignore", "*.log"),
            side,
            m_inline("side.log", "l"),
            format!("{}{}", commit_hdr(3, "m2", Some(1)), m_inline("main.log", "l")),
        );
        let (out, report) = run(cfg, &input);
        assert!(!out.contains("side.log"), "branch inherited the rule from :1:\n{out}");
        assert!(!out.contains("main.log"));
        assert_eq!(report.totals.ops_dropped, 2);
    }

    #[test]
    fn external_and_stream_rules_compose() {
        let cfg = EnforceIgnoreConfig {
            external_rules: alloc::vec![BString::from("*.bin\n")],
            stream_rules: true,
            ..Default::default()
        };
        let input = format!(
            "{}{}{}{}{}{}",
            lines(&["reset refs/heads/main", COMMIT]),
            m_inline(".gitignore", "*.log"),
            m_inline("f.bin", "b"),
            commit_hdr(2, "m2", Some(1)),
            m_inline("f.log", "l"),
            m_inline("g.bin", "b"),
        );
        let (out, report) = run(cfg, &input);
        assert!(!out.contains("inline f.bin") && !out.contains("inline g.bin"), "external rules:\n{out}");
        assert!(!out.contains("f.log"), "stream rules");
        assert_eq!(report.totals.ops_dropped, 3);
    }

    #[test]
    fn zero_op_commits_are_kept_and_counted() {
        let cfg = EnforceIgnoreConfig {
            external_rules: alloc::vec![BString::from("*\n")],
            ..Default::default()
        };
        let input = format!(
            "reset refs/heads/main\n{COMMIT}\nM 100644 inline anything\ndata 2\nhi\n\n"
        );
        let (out, report) = run(cfg, &input);
        assert!(out.contains("commit refs/heads/main"), "empty commit kept");
        assert!(!out.contains("anything"));
        assert_eq!(report.totals.now_empty_commits, 1);
    }
}
