#![no_std]
#![forbid(unsafe_code)]
//! Builtin #1: commit-hash remapping (plan §7).
//!
//! Watches every commit/tag/reset, records the `original-oid → mark`
//! mapping, and tracks which marks were rewritten upstream. Parentage
//! written as OIDs is preserved verbatim when the target lineage is
//! unchanged (identity preservation, plan §7.1); ref tips whose lineage was
//! rewritten get trailing `reset`-to-mark events at `finish()`.
//!
//! Finalization (mode A, plan §7.2): after a downstream `git fast-import`
//! run exports its marks file, fold it in with [`Remap::finalize_from_marks`]
//! to obtain the complete `old_oid → Option<new_oid>` [`CommitMap`].
//!
//! Rewritten-commit detection uses the **canonical digest** principle
//! (decision 1): remap is decoupled from upstream content builtins — they
//! need only change the stream; remap observes `original-oid` presence and
//! hosts may flag known-rewritten marks via [`Remap::flag_mark_rewritten`].
//! Unchanged subgraphs pass through untouched; with an identity upstream the
//! output is byte-identical to the input (property P4, `identity_is_noop`).

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use gfx_core::{Committish, Error, Event, Mark, MarkFile, ObjectFormat, Oid};

/// Configuration for the remap builtin (plan §7.3).
#[derive(Clone, Debug)]
pub struct RemapConfig {
    pub object_format: ObjectFormat,
    /// If the final map is an identity, emit events unchanged (default true).
    pub identity_is_noop: bool,
    /// Harvest old OIDs referenced in commit messages for a later
    /// message-rewrite pass (plan §7.4).
    pub track_message_oids: bool,
}

impl Default for RemapConfig {
    fn default() -> Self {
        RemapConfig {
            object_format: ObjectFormat::Sha1,
            identity_is_noop: true,
            track_message_oids: false,
        }
    }
}

/// What happened to a commit remap observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemapOutcome {
    /// The commit will get a new hash (content rewritten, or created fresh).
    Rewritten,
    /// Content unchanged; the original hash is preserved.
    Unchanged,
}

/// Ref-tip bookkeeping (plan §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefMap {
    pub ref_name: Vec<u8>,
    pub old_tip: Option<Oid>,
    pub new_tip: Option<Mark>,
}

/// Summary of the final mapping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MapStats {
    pub commits_observed: usize,
    pub commits_rewritten: usize,
    pub refs_rewritten: usize,
    pub message_oids_tracked: usize,
}

/// The `old_oid → Option<new_oid>` commit map. `None` new-side entries mean
/// "rewritten; new OID not yet known" — fill them with
/// [`Remap::finalize_from_marks`].
#[derive(Clone, Debug, Default)]
pub struct CommitMap {
    entries: BTreeMap<Oid, Option<Oid>>,
}

impl CommitMap {
    pub fn get(&self, old: &Oid) -> Option<Option<&Oid>> {
        self.entries.get(old).map(|v| v.as_ref())
    }

    pub fn insert(&mut self, old: Oid, new: Option<Oid>) {
        self.entries.insert(old, new);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Oid, Option<&Oid>)> {
        self.entries.iter().map(|(k, v)| (k, v.as_ref()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The remap transform. Feed it the event stream; collect [`CommitMap`] and
/// [`RefMap`]s around `finish()`.
#[derive(Debug)]
pub struct Remap {
    cfg: RemapConfig,
    /// mark → original oid (from `original-oid` lines).
    mark_to_old: BTreeMap<Mark, Oid>,
    /// original oid → first mark that carried it.
    old_to_mark: BTreeMap<Oid, Mark>,
    /// marks whose content was rewritten (fresh commits or host-flagged).
    rewritten: BTreeSet<Mark>,
    /// refs whose tip was given as an OID, in first-seen order.
    ref_tips: BTreeMap<Vec<u8>, Option<Oid>>,
    ref_order: Vec<Vec<u8>>,
    observed: usize,
    message_oids: BTreeSet<Oid>,
    /// final map, filled by `finalize_from_marks`.
    final_map: CommitMap,
    finished: bool,
}

impl Remap {
    pub fn new(cfg: RemapConfig) -> Self {
        Remap {
            cfg,
            mark_to_old: BTreeMap::new(),
            old_to_mark: BTreeMap::new(),
            rewritten: BTreeSet::new(),
            ref_tips: BTreeMap::new(),
            ref_order: Vec::new(),
            observed: 0,
            message_oids: BTreeSet::new(),
            final_map: CommitMap::default(),
            finished: false,
        }
    }

    pub fn config(&self) -> &RemapConfig {
        &self.cfg
    }

    /// Outcome recorded for a commit mark.
    pub fn outcome(&self, mark: Mark) -> Option<RemapOutcome> {
        if !self.mark_to_old.contains_key(&mark) && !self.rewritten.contains(&mark) {
            return None;
        }
        Some(if self.rewritten.contains(&mark) {
            RemapOutcome::Rewritten
        } else {
            RemapOutcome::Unchanged
        })
    }

    /// Host hook (canonical-digest bookkeeping, decision 1): flag a mark as
    /// rewritten without a second pass.
    pub fn flag_mark_rewritten(&mut self, mark: Mark) {
        self.rewritten.insert(mark);
    }

    /// The mark that carried `old`'s `original-oid`, if any. Multistream
    /// hosts use this with [`Self::outcome`] to resolve recorded source-side
    /// ref tips into expected post-import marks (plan-multistream-pack.md
    /// D8).
    pub fn mark_for(&self, old: &Oid) -> Option<Mark> {
        self.old_to_mark.get(old).copied()
    }

    /// Pre-finalization view: unchanged commits map to themselves, rewritten
    /// commits map to `None`.
    pub fn commit_map(&self) -> CommitMap {
        let mut m = CommitMap::default();
        for (old, mark) in &self.old_to_mark {
            let new = if self.rewritten.contains(mark) {
                None
            } else {
                Some(*old)
            };
            m.insert(*old, new);
        }
        m
    }

    pub fn ref_maps(&self) -> Vec<RefMap> {
        self.ref_order
            .iter()
            .filter_map(|r| {
                self.ref_tips.get(r).map(|old| RefMap {
                    ref_name: r.clone(),
                    old_tip: *old,
                    new_tip: old.and_then(|o| self.old_to_mark.get(&o).copied()),
                })
            })
            .collect()
    }

    pub fn stats(&self) -> MapStats {
        MapStats {
            commits_observed: self.observed,
            commits_rewritten: self.rewritten.len(),
            refs_rewritten: self.ref_order.len(),
            message_oids_tracked: self.message_oids.len(),
        }
    }

    pub fn message_oids(&self) -> impl Iterator<Item = &Oid> {
        self.message_oids.iter()
    }

    /// Mode A finalization (plan §7.2): fold the downstream
    /// `git fast-import` marks file in. Rewritten marks map to their *new*
    /// OIDs; unchanged commits keep their original OID.
    pub fn finalize_from_marks(&mut self, marks: &MarkFile) -> MapStats {
        for (old, mark) in self.old_to_mark.iter() {
            let new = if self.rewritten.contains(mark) {
                marks.get(*mark).copied()
            } else {
                Some(*old)
            };
            self.final_map.insert(*old, new);
        }
        self.stats()
    }

    /// The finalized map (after [`Self::finalize_from_marks`]).
    pub fn final_commit_map(&self) -> &CommitMap {
        &self.final_map
    }
}

impl gfx_core::Transform for Remap {
    fn name(&self) -> &'static str {
        "remap"
    }

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.finished {
            // After finish(), reset() is required before reuse; forward to
            // keep the pipeline contract simple.
            out.push(event);
            return Ok(());
        }
        match event {
            Event::Commit(c) => {
                self.observed += 1;
                if let Some(m) = c.mark {
                    match c.original_oid {
                        Some(old) => {
                            self.mark_to_old.insert(m, old);
                            self.old_to_mark.entry(old).or_insert(m);
                        }
                        // A commit without `original-oid` is being created
                        // fresh — rewritten by definition.
                        None => {
                            self.rewritten.insert(m);
                        }
                    }
                }
                if self.cfg.track_message_oids {
                    harvest_oids(&c.message, self.cfg.object_format, &mut self.message_oids);
                }
                out.push(Event::Commit(c));
            }
            Event::Tag(t) => {
                if let (Some(m), Some(old)) = (t.mark, t.original_oid) {
                    self.mark_to_old.insert(m, old);
                    self.old_to_mark.entry(old).or_insert(m);
                }
                out.push(Event::Tag(t));
            }
            Event::Reset { ref_name, from } => {
                if let Some(Committish::Oid(oid)) = from {
                    if !self.ref_tips.contains_key(&ref_name.to_vec()) {
                        self.ref_order.push(ref_name.to_vec());
                    }
                    self.ref_tips.insert(ref_name.to_vec(), Some(oid));
                }
                out.push(Event::Reset { ref_name, from });
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error> {
        self.finished = true;
        // Emit trailing resets for ref tips whose lineage was rewritten so
        // the downstream importer binds the ref to the new commit (plan §7.5).
        let mut tips = Vec::new();
        for r in &self.ref_order {
            if let Some(Some(old)) = self.ref_tips.get(r) {
                if let Some(mark) = self.old_to_mark.get(old) {
                    if self.rewritten.contains(mark) {
                        tips.push((r.clone(), *mark));
                    }
                }
            }
        }
        for (r, mark) in tips {
            out.push(Event::Reset {
                ref_name: gfx_core::BString::from(r),
                from: Some(Committish::Mark(mark)),
            });
        }
        Ok(())
    }

    fn reset(&mut self) {
        *self = Remap::new(self.cfg.clone());
    }
}

/// Harvest 40/64-hex OIDs out of commit message bytes (plan §7.4: v1 only
/// harvests; the message-rewrite builtin consumes the finished map in a
/// second pass).
fn harvest_oids(data: &gfx_core::Data, fmt: ObjectFormat, out: &mut BTreeSet<Oid>) {
    let bytes = data.as_slice();
    let want = match fmt {
        ObjectFormat::Sha1 => 40usize,
        ObjectFormat::Sha256 => 64usize,
    };
    if bytes.len() < want {
        return;
    }
    for i in 0..=(bytes.len() - want) {
        if let Some(oid) = Oid::from_hex(&bytes[i..i + want], fmt) {
            out.insert(oid);
        }
    }
}
