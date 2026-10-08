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
use alloc::vec::Vec;

use bstr::{BString, ByteSlice};
use gfx_core::{BString as CoreBString, Error, Event, FileOp, Mark, Mode, Transform};
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
            "commits_observed={} ops_dropped={} deletes_normalized={} now_empty_commits={}",
            self.totals.commits_observed,
            self.totals.ops_dropped,
            self.totals.deletes_normalized,
            self.totals.now_empty_commits,
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
            report: IgnoreReport::default(),
            finished: false,
        }
    }

    pub fn report(&self) -> &IgnoreReport {
        &self.report
    }

    /// The ruleset a commit is judged against: the base (external) rules
    /// in M3. The M4 stream-rules layer will extend this per commit.
    fn ruleset_for(&self, _c: &gfx_core::Commit) -> Ruleset {
        self.base.clone()
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
            Event::Commit(c) => {
                self.report.totals.commits_observed += 1;
                let ref_name = c.ref_name.clone();
                let ruleset = self.ruleset_for(&c);
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
                        FileOp::Copy { from, to } | FileOp::Rename { from, to } => {
                            // A copy/rename *to* an ignored path would
                            // reintroduce ignored content; *from* an
                            // ignored path has no valid source (we dropped
                            // its creation).
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

    fn stream(events: &[&str]) -> Vec<u8> {
        events.join("\n").into_bytes()
    }

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
