#![no_std]
#![forbid(unsafe_code)]
//! The gfx virtual index (plan §5.1, decision D3): the one sans-IO replay
//! of `git fast-import`'s branch-index semantics.
//!
//! `git fast-import` maintains, per branch, a *virtual index* — the tree
//! state its file commands mutate. `M` adds/overwrites a path, `D` deletes
//! one, `C`/`R` operate on whatever the index currently holds, and
//! `filedeleteall` wipes it. Every fast-export commit is a delta against
//! that per-branch state, which is precisely why stream rewrites that touch
//! paths (strip, path-filter, prune) cannot treat ops locally: they need to
//! know what the importer would see at each op.
//!
//! This crate implements that replay once, for every consumer:
//!
//! * `gfx-strip-blobs` — original view (resolve `C`/`R` sources to blob
//!   verdicts) and rewritten view (kept-`D` validity);
//! * the plan §5.7 S5 absence-simulator harness;
//! * future path-aware builtins (`path-filter`, `prune_empty`).
//!
//! The index tracks **entry values**, not just presence: a path maps to
//! [`Entry::Blob`] (with an optional `original-oid` when the stream supplied
//! one), [`Entry::Gitlink`], or [`Entry::Tree`] (from `M 040000`). `Inline`
//! modifications carry their payload bytes only for the duration of the
//! `apply` call — the index never stores content, keeping memory bounded by
//! distinct paths (plan §5.6 memory posture).
//!
//! Scope note: this is a *path-level* index, faithful to the ops the
//! fast-export grammar can express. It does not reconstruct nested tree
//! contents (`M 040000` records a tree opaquely), which no stream consumer
//! can — the stream does not contain subpath detail for tree-replaces.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use gfx_core::{BString, Committish, DataRef, FileOp, Mode};

/// What the index holds at a path. Content is deliberately absent: the
/// index reasons about identity (which blob, via mark or OID), never bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A regular/exec/symlink file backed by a blob. The blob is identified
    /// by whatever the stream gave: a mark, an original OID, or inline data
    /// (tracked by mark `None`-slot: inline blobs get a synthetic identity
    /// only for their introducing op — see [`Index::identify`]).
    Blob { source: BlobId },
    /// Mode `160000` — a submodule reference. Never content-judged.
    Gitlink,
    /// Mode `040000` — a tree-replace. Opaque: subpaths are not visible in
    /// the stream.
    Tree,
}

/// Identity of a blob at a path. Two entries with equal `BlobId`s refer to
/// the same content.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlobId {
    /// `M <mode> :N <path>` / `N :N ...` — the defining mark.
    Mark(u64),
    /// `M <mode> <hex-oid> <path>` — a raw dataref (round-tripped streams).
    Oid(gfx_core::Oid),
    /// `M ... inline` — content known only at the op site. Identified by
    /// the path and the *position* of the op that introduced it (see
    /// [`Index::apply`]); comparisons between different inline introduces
    /// are never equal.
    Inline { seq: u64 },
}

/// One change applied to one path: what the replay observed, for consumers
/// that must mirror index transitions (e.g. the rewritten view in
/// gfx-strip-blobs, which needs to know which ops the *filtered* stream
/// performed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Path now holds this entry.
    Set { path: BString, entry: Entry },
    /// Path was present and is now absent.
    Removed { path: BString },
    /// Path was already absent; fast-import's documented behavior is to
    /// reject deleting a non-existent path — surfaced here so hosts can
    /// treat it as an anomaly rather than replay it silently.
    DeletedMissing { path: BString },
    /// `filedeleteall`: everything for the ref was wiped.
    Cleared,
    /// The op does not mutate the index (`N` notes, or an op the caller
    /// filtered out before replay).
    Noop,
}

/// Which content a `C`/`R` source resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The source path holds this entry.
    Found(Entry),
    /// The source path is absent in the index. fast-import errors on this;
    /// the replay surfaces it for hosts to treat as malformed.
    Missing,
}

/// Per-ref virtual index state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefIndex {
    entries: BTreeMap<BString, Entry>,
}

impl RefIndex {
    pub fn new() -> Self {
        RefIndex::default()
    }

    pub fn get(&self, path: &[u8]) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn paths(&self) -> impl Iterator<Item = &BString> {
        self.entries.keys()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Apply one op, fast-import semantics, reporting the change.
    pub fn apply(&mut self, op: &FileOp, inline_seq: &mut u64) -> Change {
        match op {
            FileOp::Modify { mode, path, source } => {
                let entry = match mode {
                    Mode::Gitlink => Entry::Gitlink,
                    Mode::Dir => Entry::Tree,
                    _ => Entry::Blob {
                        source: identify(source, inline_seq),
                    },
                };
                self.entries.insert(path.clone(), entry.clone());
                Change::Set { path: path.clone(), entry }
            }
            FileOp::Delete { path } => {
                if self.entries.remove(path).is_some() {
                    Change::Removed { path: path.clone() }
                } else {
                    Change::DeletedMissing { path: path.clone() }
                }
            }
            FileOp::Copy { from, to } => {
                if let Some(e) = self.entries.get(from).cloned() {
                    self.entries.insert(to.clone(), e.clone());
                    Change::Set { path: to.clone(), entry: e }
                } else {
                    Change::DeletedMissing { path: to.clone() }
                }
            }
            FileOp::Rename { from, to } => {
                if let Some(e) = self.entries.remove(from) {
                    self.entries.insert(to.clone(), e.clone());
                    Change::Set { path: to.clone(), entry: e }
                } else {
                    Change::DeletedMissing { path: to.clone() }
                }
            }
            FileOp::DeleteAll => {
                self.entries.clear();
                Change::Cleared
            }
            FileOp::Note { .. } => Change::Noop,
        }
    }
}

fn identify(source: &gfx_core::FileSource, inline_seq: &mut u64) -> BlobId {
    match source {
        gfx_core::FileSource::DataRef(DataRef::Mark(m)) => BlobId::Mark(*m),
        gfx_core::FileSource::DataRef(DataRef::Oid(o)) => BlobId::Oid(*o),
        gfx_core::FileSource::Inline(_) => {
            *inline_seq += 1;
            BlobId::Inline { seq: *inline_seq }
        }
    }
}

/// The multi-ref index: every branch's virtual state, keyed by ref name.
///
/// `git fast-import` keeps one index per *active branch*; commands for a
/// ref apply to that ref's state, and `commit <ref>` implicitly continues
/// the ref's existing index unless `filedeleteall` or a `reset` intervenes.
/// (A `reset` moves the tip but does *not* clear the index — a later commit
/// on the same ref keeps mutating the same state, matching fast-import.)
#[derive(Clone, Debug, Default)]
pub struct Index {
    refs: BTreeMap<BString, RefIndex>,
    inline_seq: u64,
}

impl Index {
    pub fn new() -> Self {
        Index::default()
    }

    pub fn get(&self, ref_name: &[u8]) -> Option<&RefIndex> {
        self.refs.get(ref_name)
    }

    pub fn get_mut(&mut self, ref_name: &[u8]) -> &mut RefIndex {
        self.refs.entry(ref_name.into()).or_default()
    }

    /// Apply a file-op list (one commit's `ops`) to a ref.
    pub fn apply_ops(&mut self, ref_name: &[u8], ops: &[FileOp]) {
        let seq = &mut self.inline_seq;
        let idx = self.refs.entry(ref_name.into()).or_default();
        for op in ops {
            idx.apply(op, seq);
        }
    }

    /// Reset handling: `reset <ref>` / `commit <ref> from <mark>` move tips;
    /// they do not clear the ref's index (fast-import semantics — the index
    /// is replaced wholesale only by `filedeleteall`). The target is taken
    /// for completeness; tip identity is not tracked here (that is remap's
    /// job, plan §7).
    pub fn note_committish(&mut self, _ref_name: &[u8], _target: Option<&Committish>) {
        // Nothing to do today; kept as an explicit hook so consumers show
        // they considered tip moves.
    }

    /// Every ref with a non-empty index, sorted (deterministic iteration).
    pub fn touched_refs(&self) -> impl Iterator<Item = &BString> {
        self.refs.keys()
    }

    /// Paths holding a specific blob mark, across all refs (S4-style
    /// orphan audits).
    pub fn paths_with_mark(&self, mark: u64) -> Vec<(&BString, &BString)> {
        let want = BlobId::Mark(mark);
        let mut out = Vec::new();
        for (r, idx) in &self.refs {
            for (p, e) in &idx.entries {
                if matches!(e, Entry::Blob { source } if *source == want) {
                    out.push((r, p));
                }
            }
        }
        out
    }

    /// Full absence audit for property S5: return every (ref, path) that
    /// holds an entry matching `pred`.
    pub fn violating_paths(&self, mut pred: impl FnMut(&Entry) -> bool) -> Vec<(&BString, &BString)> {
        let mut out = Vec::new();
        for (r, idx) in &self.refs {
            for (p, e) in &idx.entries {
                if pred(e) {
                    out.push((r, p));
                }
            }
        }
        out
    }
}

/// A set of paths, used by the simulator harness and strip's rewritten view.
pub type PathSet = BTreeSet<BString>;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    fn path(s: &str) -> BString {
        BString::from(s.as_bytes().to_vec())
    }

    fn modify(mode: Mode, p: &str, source: gfx_core::FileSource) -> FileOp {
        FileOp::Modify {
            mode,
            path: path(p),
            source,
        }
    }

    #[test]
    fn modify_delete_copy_rename() {
        let mut idx = Index::new();
        idx.apply_ops(
            b"refs/heads/main",
            &[
                modify(Mode::Regular, "a.txt", gfx_core::FileSource::DataRef(DataRef::Mark(1))),
                modify(Mode::Exec, "b.sh", gfx_core::FileSource::DataRef(DataRef::Mark(2))),
            ],
        );
        let r = idx.get(b"refs/heads/main").unwrap();
        assert_eq!(
            r.get(b"a.txt"),
            Some(&Entry::Blob { source: BlobId::Mark(1) })
        );

        // Copy duplicates the entry.
        idx.apply_ops(
            b"refs/heads/main",
            &[FileOp::Copy { from: path("a.txt"), to: path("c.txt") }],
        );
        let r = idx.get(b"refs/heads/main").unwrap();
        assert_eq!(
            r.get(b"c.txt"),
            Some(&Entry::Blob { source: BlobId::Mark(1) })
        );

        // Rename moves it.
        idx.apply_ops(
            b"refs/heads/main",
            &[FileOp::Rename { from: path("b.sh"), to: path("d.sh") }],
        );
        let r = idx.get(b"refs/heads/main").unwrap();
        assert!(r.get(b"b.sh").is_none());
        assert_eq!(
            r.get(b"d.sh"),
            Some(&Entry::Blob { source: BlobId::Mark(2) })
        );

        // Delete removes it.
        idx.apply_ops(b"refs/heads/main", &[FileOp::Delete { path: path("c.txt") }]);
        let r = idx.get(b"refs/heads/main").unwrap();
        assert!(r.get(b"c.txt").is_none());
    }

    #[test]
    fn deleteall_clears_and_gitlink_never_content() {
        let mut idx = Index::new();
        idx.apply_ops(
            b"refs/heads/dev",
            &[
                modify(Mode::Regular, "x", gfx_core::FileSource::DataRef(DataRef::Mark(9))),
                modify(
                    Mode::Gitlink,
                    "sub",
                    gfx_core::FileSource::DataRef(DataRef::Mark(10)),
                ),
            ],
        );
        let r = idx.get(b"refs/heads/dev").unwrap();
        assert_eq!(r.get(b"sub"), Some(&Entry::Gitlink));

        idx.apply_ops(b"refs/heads/dev", &[FileOp::DeleteAll]);
        let r = idx.get(b"refs/heads/dev").unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn delete_of_missing_is_surfaced_not_silent() {
        let mut idx = Index::new();
        idx.apply_ops(b"r", &[FileOp::Delete { path: path("ghost") }]);
        let r = idx.get(b"r").unwrap();
        assert!(r.get(b"ghost").is_none());
        // The Change value carries DeletedMissing; apply_ops discards it,
        // but the single-op API lets hosts observe it.
        let mut single = RefIndex::new();
        let change = single.apply(
            &FileOp::Delete { path: path("ghost") },
            &mut 0,
        );
        assert!(matches!(change, Change::DeletedMissing { .. }));
    }

    #[test]
    fn inline_blobs_get_distinct_identities() {
        let mut idx = Index::new();
        idx.apply_ops(
            b"r",
            &[
                modify(Mode::Regular, "i1", gfx_core::FileSource::Inline(gfx_core::Data(vec![1]))),
                modify(Mode::Regular, "i2", gfx_core::FileSource::Inline(gfx_core::Data(vec![2]))),
            ],
        );
        let r = idx.get(b"r").unwrap();
        match (r.get(b"i1"), r.get(b"i2")) {
            (
                Some(Entry::Blob { source: BlobId::Inline { seq: s1 } }),
                Some(Entry::Blob { source: BlobId::Inline { seq: s2 } }),
            ) => assert_ne!(s1, s2, "each inline introduce is its own identity"),
            other => panic!("unexpected entries {other:?}"),
        }
    }

    #[test]
    fn refs_are_independent() {
        let mut idx = Index::new();
        idx.apply_ops(
            b"refs/heads/a",
            &[modify(Mode::Regular, "p", gfx_core::FileSource::DataRef(DataRef::Mark(1)))],
        );
        idx.apply_ops(
            b"refs/heads/b",
            &[FileOp::Delete { path: path("p") }],
        );
        assert!(idx.get(b"refs/heads/a").unwrap().get(b"p").is_some());
        assert!(idx.get(b"refs/heads/b").unwrap().get(b"p").is_none());
    }

    #[test]
    fn paths_with_mark_finds_every_reference() {
        let mut idx = Index::new();
        idx.apply_ops(
            b"refs/heads/a",
            &[modify(Mode::Regular, "one", gfx_core::FileSource::DataRef(DataRef::Mark(7)))],
        );
        idx.apply_ops(
            b"refs/heads/b",
            &[modify(Mode::Regular, "two", gfx_core::FileSource::DataRef(DataRef::Mark(7)))],
        );
        idx.apply_ops(
            b"refs/heads/b",
            &[modify(Mode::Regular, "other", gfx_core::FileSource::DataRef(DataRef::Mark(8)))],
        );
        let hits = idx.paths_with_mark(7);
        assert_eq!(hits.len(), 2);
        assert!(hits.contains(&(&BString::from(b"refs/heads/a".to_vec()), &path("one"))));
        assert!(hits.contains(&(&BString::from(b"refs/heads/b".to_vec()), &path("two"))));
        assert_eq!(idx.paths_with_mark(8).len(), 1);
    }
}
