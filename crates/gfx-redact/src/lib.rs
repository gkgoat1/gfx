#![no_std]
//! `gfx-redact` — builtin pass `redact` (plan: `docs/plan-redact-idents.md`).
//!
//! Rewrites the *people and times* inside a fast-export stream:
//! `author` / `committer` / `tagger` identities under a deterministic policy
//! (exact table, or a host-injected [`IdentPolicy`]), with timestamp modes
//! and timezone handling layered on in M1.
//!
//! Design decision D1 (doc-scoped): **rewrite fields in place, never
//! restructure.** No op is dropped, synthesized, or reordered; marks,
//! `original-oid`, ref names, and topology pass through untouched. A commit
//! whose idents and times the policy leaves unchanged serializes
//! byte-identical to its input.
//!
//! Like `gfx-strip-blobs`, this crate is sans-IO, deterministic, and
//! `no_std`: no clocks, no RNG, no filesystem. The mapping artifact is
//! produced by the host (driver) from [`Redact::report`].

extern crate alloc;

/// Git-style C-quoting primitives. Public because the artifact format is
/// protocol between passes (plan §4.8): the future message-rewrite pass
/// parses `redact-map.txt` with [`quote::c_unquote`].
pub mod quote;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use bstr::BString;
use gfx_core::error::Error;
use gfx_core::event::{Event, Ident};
use gfx_core::transform::Transform;

/// Which ident line is being rewritten. A host [`IdentPolicy`] may treat
/// roles differently; the built-in modes are role-agnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentRole {
    Author,
    Committer,
    Tagger,
}

impl IdentRole {
    fn tag(self) -> u8 {
        match self {
            IdentRole::Author => 0,
            IdentRole::Committer => 1,
            IdentRole::Tagger => 2,
        }
    }
}

/// Host-injected ident policy (library-level knob; the strip pass's
/// injected-matcher pattern applied to idents).
///
/// Contract: a **pure function** of `(role, ident)` — no clocks, no RNG, no
/// shared mutable state. Determinism (plan R2) is a documented requirement;
/// the pass audits *injectivity* rather than trusting it: two distinct
/// originals mapped to one replacement surface as `collision` entries in the
/// report, never silently.
pub trait IdentPolicy {
    fn rewrite(&self, role: IdentRole, ident: &Ident) -> Ident;

    /// Human-readable description for report/artifact headers.
    fn describe(&self) -> String {
        "injected ident policy".into()
    }
}

/// `Clone`able shared handle to a host policy (the `SharedMatcher` pattern).
#[derive(Clone)]
pub struct SharedPolicy(pub Rc<dyn IdentPolicy>);

impl core::fmt::Debug for SharedPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedPolicy({})", self.0.describe())
    }
}

impl IdentPolicy for SharedPolicy {
    fn rewrite(&self, role: IdentRole, ident: &Ident) -> Ident {
        self.0.rewrite(role, ident)
    }

    fn describe(&self) -> String {
        self.0.describe()
    }
}

/// One exact mapping row. `None` fields are wildcards (mailmap-flavored,
/// minus filter-repo's reverse-mapping column). First matching row wins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactRow {
    /// Match on name; `None` = any name.
    pub name: Option<BString>,
    /// Match on email; `None` = any email.
    pub email: Option<BString>,
    pub new_name: BString,
    pub new_email: BString,
}

impl RedactRow {
    fn matches(&self, name: &[u8], email: &[u8]) -> bool {
        let name_ok = match &self.name {
            Some(n) => n.as_slice() == name,
            None => true,
        };
        let email_ok = match &self.email {
            Some(e) => e.as_slice() == email,
            None => true,
        };
        name_ok && email_ok
    }
}

/// How identities are rewritten.
#[derive(Clone, Debug, Default)]
pub enum IdentMode {
    /// No ident change (times may still change in M1).
    #[default]
    Preserve,
    /// Exact rows, first-match-wins; no match ⇒ ident passes through
    /// unchanged. A selective redactor (fast-export `--anonymize-map`
    /// flavored).
    Table(Vec<RedactRow>),
    /// Host-compiled policy (regex rename, org mailmap, role-aware rules).
    Injected(SharedPolicy),
}

impl IdentMode {
    /// Stable label for artifact/report headers.
    pub fn style(&self) -> &'static str {
        match self {
            IdentMode::Preserve => "preserve",
            IdentMode::Table(_) => "table",
            IdentMode::Injected(_) => "injected",
        }
    }
}

/// Pass configuration (plan §4.3). Times are preserved in M0; time modes and
/// tz zeroing arrive with M1 (`time_mode` / `keep_tz` / `seed` fields).
#[derive(Clone, Debug)]
pub struct RedactConfig {
    pub ident_mode: IdentMode,
    /// Cap per-listing entries in the report/artifact; totals stay exact.
    pub map_report_limit: usize,
}

impl Default for RedactConfig {
    fn default() -> Self {
        RedactConfig {
            ident_mode: IdentMode::Preserve,
            map_report_limit: 1000,
        }
    }
}

/// One mapped ident, per (role, original) key.
struct Mapped {
    new_name: BString,
    new_email: BString,
    /// Replacement differs from the original.
    changed: bool,
    suspicious: bool,
    uses: u64,
}

/// Merged per-original report/artifact entry (roles folded together).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactEntry {
    pub old_name: BString,
    pub old_email: BString,
    pub new_name: BString,
    pub new_email: BString,
    /// Roles this ident was seen under, sorted (`author`, `committer`,
    /// `tagger`).
    pub roles: Vec<&'static str>,
    pub uses: u64,
    pub changed: bool,
    pub suspicious: bool,
}

/// Two or more distinct originals mapped to one replacement (plan §4.3
/// injectivity audit). Visible, never an error — merging identities is
/// occasionally the goal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollisionEntry {
    pub new_name: BString,
    pub new_email: BString,
    /// Distinct originals, sorted.
    pub originals: Vec<(BString, BString)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RedactTotals {
    /// Distinct original→replacement rewrites (changed mappings).
    pub idents_redacted: u64,
    /// Total ident lines actually rewritten (uses of changed mappings).
    pub ident_updates: u64,
    /// Injectivity collisions reported.
    pub collisions: usize,
    /// Replacements containing original ident bytes (deterministic substring
    /// check; plan §4.9 "suspicious-replacement").
    pub suspicious: usize,
}

/// Audit surface: exact totals, bounded listings (plan §4.8). The driver
/// writes [`RedactReport::to_text`] as `<gitdir>/gfx/redact-map.txt`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RedactReport {
    pub totals: RedactTotals,
    pub entries: Vec<RedactEntry>,
    pub collisions: Vec<CollisionEntry>,
    /// Truncated because of `map_report_limit`.
    pub truncated: bool,
}

impl RedactReport {
    /// One-line deterministic summary for the driver's run report.
    pub fn summary_text(&self) -> String {
        format!(
            "idents_redacted={} ident_updates={} collisions={} suspicious={}",
            self.totals.idents_redacted,
            self.totals.ident_updates,
            self.totals.collisions,
            self.totals.suspicious,
        )
    }

    /// The `redact-map.txt` artifact. Deterministic: identical run
    /// configuration on identical input yields byte-identical text (A6
    /// analog). The header *is* the sensitivity warning — this file is the
    /// de-anonymization key.
    ///
    /// Line format (pinned by the R9 round-trip test):
    /// `NEW_NAME <NEW_EMAIL> <- OLD_NAME <OLD_EMAIL> [role+role, N uses]`
    /// plus `collision:` lines and a leading comment header. Names and
    /// emails are C-quoted, so non-UTF-8 idents survive verbatim.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("# gfx redact mapping — SENSITIVE: this file re-identifies the anonymized repo.\n");
        s.push_str("# Keep it out of the repository, out of backups you share, and out of git.\n");
        s.push_str(&format!(
            "# idents: {}  collisions: {}\n",
            self.totals.idents_redacted, self.totals.collisions,
        ));
        for e in &self.entries {
            s.push_str(&format!(
                "{} <{}> <- {} <{}> [{}, {} uses]\n",
                quote::c_quote(&e.new_name),
                quote::c_quote(&e.new_email),
                quote::c_quote(&e.old_name),
                quote::c_quote(&e.old_email),
                e.roles.join("+"),
                e.uses,
            ));
        }
        for c in &self.collisions {
            let originals = c
                .originals
                .iter()
                .map(|(n, e)| format!("{} <{}>", quote::c_quote(n), quote::c_quote(e)))
                .collect::<Vec<_>>()
                .join("; ");
            s.push_str(&format!(
                "collision: {} <{}> <- {}\n",
                quote::c_quote(&c.new_name),
                quote::c_quote(&c.new_email),
                originals,
            ));
        }
        if self.truncated {
            s.push_str("# (listing truncated; totals above are exact)\n");
        }
        s
    }
}

/// The `redact` transform (plan §4.2–§4.6).
pub struct Redact {
    cfg: RedactConfig,
    /// Keyed by (role, name, email) — role-keyed so a role-aware host policy
    /// is honored exactly; built-in modes are role-agnostic and produce the
    /// same replacement per key anyway. Report entries merge roles back
    /// together per (original, replacement) pair.
    ledger: BTreeMap<(u8, BString, BString), Mapped>,
    /// Replacement → distinct originals (injectivity audit).
    image: BTreeMap<(BString, BString), BTreeSet<(BString, BString)>>,
    finished: bool,
}

impl Redact {
    pub fn new(cfg: RedactConfig) -> Self {
        Redact {
            cfg,
            ledger: BTreeMap::new(),
            image: BTreeMap::new(),
            finished: false,
        }
    }

    pub fn config(&self) -> &RedactConfig {
        &self.cfg
    }

    /// Audit surface, built on demand from the ledgers (plan §4.3: the
    /// ledger is also the mapping-artifact source).
    pub fn report(&self) -> RedactReport {
        // Merge (role, original) ledger rows into per-(original, replacement)
        // entries, folding roles together.
        let mut merged: BTreeMap<(&BString, &BString, &BString, &BString), RedactEntry> =
            BTreeMap::new();
        for ((role, old_name, old_email), m) in &self.ledger {
            merged
                .entry((old_name, old_email, &m.new_name, &m.new_email))
                .and_modify(|e| {
                    e.uses += m.uses;
                    e.roles.push(label(*role));
                })
                .or_insert_with(|| RedactEntry {
                    old_name: old_name.clone(),
                    old_email: old_email.clone(),
                    new_name: m.new_name.clone(),
                    new_email: m.new_email.clone(),
                    roles: alloc::vec![label(*role)],
                    uses: m.uses,
                    changed: m.changed,
                    suspicious: m.suspicious,
                });
        }
        let mut entries: Vec<RedactEntry> = merged.into_values().collect();
        for e in &mut entries {
            e.roles.sort_unstable();
            e.roles.dedup();
        }

        let collisions = self
            .image
            .iter()
            .filter(|(_, originals)| originals.len() >= 2)
            .map(|((n, e), originals)| CollisionEntry {
                new_name: n.clone(),
                new_email: e.clone(),
                originals: originals.iter().cloned().collect(),
            })
            .collect::<Vec<_>>();

        let changed_entries = entries.iter().filter(|e| e.changed);
        let totals = RedactTotals {
            idents_redacted: changed_entries.clone().count() as u64,
            ident_updates: changed_entries.map(|e| e.uses).sum(),
            collisions: collisions.len(),
            suspicious: entries.iter().filter(|e| e.suspicious).count(),
        };

        let limit = self.cfg.map_report_limit;
        let truncated = entries.len() > limit || collisions.len() > limit;
        entries.truncate(limit);
        let mut collisions = collisions;
        collisions.truncate(limit);

        RedactReport {
            totals,
            entries,
            collisions,
            truncated,
        }
    }

    /// Rewrite one ident per policy, updating the ledgers (plan §4.3:
    /// same input ⇒ same output within a run, enforced by consulting the
    /// ledger before the policy re-runs).
    fn map_ident(&mut self, role: IdentRole, ident: Ident) -> Ident {
        let key = (role.tag(), ident.name.clone(), ident.email.clone());
        if let Some(m) = self.ledger.get_mut(&key) {
            m.uses += 1;
            return Ident {
                name: m.new_name.clone(),
                email: m.new_email.clone(),
                time: ident.time,
            };
        }

        let (new_name, new_email, mapped) = match &self.cfg.ident_mode {
            IdentMode::Preserve => (ident.name.clone(), ident.email.clone(), false),
            IdentMode::Table(rows) => {
                match rows.iter().find(|r| r.matches(&ident.name, &ident.email)) {
                    Some(r) => (r.new_name.clone(), r.new_email.clone(), true),
                    None => (ident.name.clone(), ident.email.clone(), false),
                }
            }
            IdentMode::Injected(p) => {
                let out = p.0.rewrite(role, &ident);
                (out.name, out.email, true)
            }
        };
        let changed = new_name != ident.name || new_email != ident.email;
        let suspicious = changed && is_suspicious(&new_name, &new_email, &ident);
        if mapped {
            self.image
                .entry((new_name.clone(), new_email.clone()))
                .or_default()
                .insert((ident.name.clone(), ident.email.clone()));
        }
        self.ledger.insert(
            key,
            Mapped {
                new_name: new_name.clone(),
                new_email: new_email.clone(),
                changed,
                suspicious,
                uses: 1,
            },
        );

        Ident {
            name: new_name,
            email: new_email,
            time: ident.time,
        }
    }
}

/// Deterministic "operator error" check (plan §4.9): the replacement
/// contains original name/email bytes. Never blocks the run; surfaces as a
/// report flag because the leak-scan property (R4) is what enforces the
/// test side.
fn label(role_tag: u8) -> &'static str {
    match role_tag {
        0 => "author",
        1 => "committer",
        _ => "tagger",
    }
}

fn is_suspicious(new_name: &[u8], new_email: &[u8], orig: &Ident) -> bool {
    let contains = |hay: &[u8], needle: &[u8]| {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    };
    contains(new_name, &orig.name)
        || contains(new_name, &orig.email)
        || contains(new_email, &orig.name)
        || contains(new_email, &orig.email)
}

impl Transform for Redact {
    fn name(&self) -> &'static str {
        "redact"
    }

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.finished {
            out.push(event);
            return Ok(());
        }
        match event {
            Event::Commit(mut c) => {
                // D1: rewrite fields in place; a missing ident line stays
                // missing (fast-import inherits committer; we do not
                // synthesize one).
                if let Some(a) = c.author.take() {
                    c.author = Some(self.map_ident(IdentRole::Author, a));
                }
                if let Some(cm) = c.committer.take() {
                    c.committer = Some(self.map_ident(IdentRole::Committer, cm));
                }
                out.push(Event::Commit(c));
            }
            Event::Tag(mut t) => {
                if let Some(tg) = t.tagger.take() {
                    t.tagger = Some(self.map_ident(IdentRole::Tagger, tg));
                }
                out.push(Event::Tag(t));
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<Event>) -> Result<(), Error> {
        // No residual events: rewriting is purely per-event (plan §4.6).
        self.finished = true;
        Ok(())
    }

    fn reset(&mut self) {
        *self = Redact::new(self.cfg.clone());
    }
}
