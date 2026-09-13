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
mod time;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use bstr::BString;
use gfx_core::error::{BString64, Error};
use gfx_core::event::{Event, Ident, Timestamp};
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
    /// Built-in deterministic pseudonyms for every ident.
    Pseudonymize(PseudonymStyle),
}

impl IdentMode {
    /// Stable label for artifact/report headers.
    pub fn style(&self) -> &'static str {
        match self {
            IdentMode::Preserve => "preserve",
            IdentMode::Table(_) => "table",
            IdentMode::Injected(_) => "injected",
            IdentMode::Pseudonymize(PseudonymStyle::Ordinal) => "ordinal",
            IdentMode::Pseudonymize(PseudonymStyle::Hash) => "hash",
        }
    }
}

/// Calendar bucket boundary for [`TimeMode::Bucket`]. Bucketing happens in
/// **UTC**: doing it in a kept local offset would re-leak the offset it
/// hides (plan §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeBucketUnit {
    /// Floors to the UTC midnight (`86400`-aligned) boundary.
    Day,
    /// Floors to Monday 00:00 UTC.
    Week,
    /// Floors to the first of the UTC calendar month.
    Month,
}

/// Timestamp policy (plan §4.4). Applies to author/committer/tagger times
/// alike; every mode except `preserve` regenerates `raw` canonically as
/// `"<epoch> ±HHMM"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeMode {
    /// Untouched raw bytes (byte-identity possible). Timezone offsets are
    /// still zeroed unless `keep_tz` (decision D3: always-on tz zeroing).
    #[default]
    Preserve,
    /// Every ident time becomes `0 +0000`; order falls back to topology.
    Zero,
    /// Constant offset; order and intervals preserved exactly. `keep_tz` is
    /// honored (the offset rides along when kept).
    Shift(i64),
    /// Floor to a UTC boundary; coarse order kept, ties within a bucket.
    Bucket(TimeBucketUnit),
    /// Seeded bounded jitter: `epoch + (H(seed, role, raw) mod (2J+1)) - J`.
    /// Order is *not* guaranteed monotone; intervals approximately kept.
    /// Not cryptography — obfuscation with a retained seed (plan §4.4).
    Fuzz { jitter_secs: u64 },
}

impl TimeMode {
    /// Stable label for artifact/report headers.
    pub fn label(&self) -> String {
        match self {
            TimeMode::Preserve => "preserve".into(),
            TimeMode::Zero => "zero".into(),
            TimeMode::Shift(s) => alloc::format!("shift({s:+})"),
            TimeMode::Bucket(u) => alloc::format!(
                "bucket({})",
                match u {
                    TimeBucketUnit::Day => "day",
                    TimeBucketUnit::Week => "week",
                    TimeBucketUnit::Month => "month",
                }
            ),
            TimeMode::Fuzz { jitter_secs } => alloc::format!("fuzz({jitter_secs})"),
        }
    }
}

/// Built-in deterministic pseudonyms (plan §4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PseudonymStyle {
    /// First-seen ordinal: `User 1 <user1@example.invalid>`. Derives nothing
    /// from input bytes — no dictionary attack, no cross-repo correlation.
    /// Assignment order is stream order of first occurrence, per distinct
    /// (name, email) regardless of role.
    #[default]
    Ordinal,
    /// Digest-derived: `user-<8 hex> <user-8hex@example.invalid>`. Stable
    /// across repos at the cost of brute-forceability (small candidate sets
    /// can be hashed and compared). Convenience option, not the safe one.
    Hash,
}

/// The ordinal pseudonym for `ordinal` (1-based): `User {n}` /
/// `user{n}@example.invalid`. Public so multistream hosts
/// (plan-multistream-pack.md D3) can pre-assign a *shared* ordinal space
/// across several streams and inject it as an exact [`IdentMode::Table`]
/// without duplicating this format string.
pub fn ordinal_pseudonym(ordinal: u64) -> (BString, BString) {
    (
        BString::from(alloc::format!("User {ordinal}")),
        BString::from(alloc::format!("user{ordinal}@example.invalid")),
    )
}

/// Pass configuration (plan §4.3–§4.4).
#[derive(Clone, Debug)]
pub struct RedactConfig {
    pub ident_mode: IdentMode,
    pub time_mode: TimeMode,
    /// Opt out of timezone-offset zeroing. Honored with
    /// `preserve`/`shift` (the modes where keeping an offset is
    /// meaningful); `zero`/`bucket`/`fuzz` ignore it rather than
    /// half-apply (plan §4.4).
    pub keep_tz: bool,
    /// Seed for `TimeMode::Fuzz`. Never defaulted by higher layers: a
    /// silently-fixed seed would be a shared constant across users' repos.
    pub seed: u64,
    /// Cap per-listing entries in the report/artifact; totals stay exact.
    pub map_report_limit: usize,
}

impl Default for RedactConfig {
    fn default() -> Self {
        RedactConfig {
            ident_mode: IdentMode::Preserve,
            time_mode: TimeMode::Preserve,
            keep_tz: false,
            seed: 0,
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
    /// Ident lines whose `when` field was rewritten (tz zeroing included).
    pub times_altered: u64,
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
            "idents_redacted={} ident_updates={} collisions={} suspicious={} times_altered={}",
            self.totals.idents_redacted,
            self.totals.ident_updates,
            self.totals.collisions,
            self.totals.suspicious,
            self.totals.times_altered,
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
            "# idents: {}  collisions: {}  times_altered: {}\n",
            self.totals.idents_redacted, self.totals.collisions, self.totals.times_altered,
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
    /// First-seen ordinal registry for `PseudonymStyle::Ordinal`, keyed by
    /// (name, email) regardless of role: the same person is the same
    /// pseudonym whether they authored, committed, or tagged.
    pseudonyms: BTreeMap<(BString, BString), u64>,
    next_pseudonym: u64,
    /// Ident lines whose `when` field was rewritten (tz zeroing included).
    times_altered: u64,
    finished: bool,
}

impl Redact {
    pub fn new(cfg: RedactConfig) -> Self {
        Redact {
            cfg,
            ledger: BTreeMap::new(),
            image: BTreeMap::new(),
            pseudonyms: BTreeMap::new(),
            next_pseudonym: 0,
            times_altered: 0,
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
            times_altered: self.times_altered,
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
    /// ledger before the policy re-runs), then apply the time policy
    /// (plan §4.4).
    fn map_ident(&mut self, role: IdentRole, ident: Ident) -> Result<Ident, Error> {
        let key = (role.tag(), ident.name.clone(), ident.email.clone());
        let (new_name, new_email): (BString, BString) = if let Some(m) = self.ledger.get(&key) {
            (m.new_name.clone(), m.new_email.clone())
        } else {
            let (n, e, mapped) = match &self.cfg.ident_mode {
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
                IdentMode::Pseudonymize(style) => {
                    let ordinal = match self.pseudonyms.get(&(
                        ident.name.clone(),
                        ident.email.clone(),
                    )) {
                        Some(&n) => n,
                        None => {
                            self.next_pseudonym += 1;
                            let n = self.next_pseudonym;
                            self.pseudonyms
                                .insert((ident.name.clone(), ident.email.clone()), n);
                            n
                        }
                    };
                    let pseud = match style {
                        PseudonymStyle::Ordinal => ordinal_pseudonym(ordinal),
                        PseudonymStyle::Hash => {
                            let d = time::ident_digest(&ident.name, &ident.email);
                            (
                                BString::from(alloc::format!("user-{}", time::hex8(d))),
                                BString::from(alloc::format!(
                                    "user-{}@example.invalid",
                                    time::hex8(d)
                                )),
                            )
                        }
                    };
                    (pseud.0, pseud.1, true)
                }
            };
            let changed = n != ident.name || e != ident.email;
            let suspicious = changed && is_suspicious(&n, &e, &ident);
            if mapped {
                self.image
                    .entry((n.clone(), e.clone()))
                    .or_default()
                    .insert((ident.name.clone(), ident.email.clone()));
            }
            self.ledger.insert(
                key.clone(),
                Mapped {
                    new_name: n.clone(),
                    new_email: e.clone(),
                    changed,
                    suspicious,
                    uses: 0,
                },
            );
            (n, e)
        };

        // Count this use (the cached-mapping fast path shares the counter).
        if let Some(m) = self.ledger.get_mut(&key) {
            m.uses += 1;
        }

        let new_time = self.apply_time(role, &ident.time)?;
        if new_time.raw != ident.time.raw {
            self.times_altered += 1;
        }

        Ok(Ident {
            name: new_name,
            email: new_email,
            time: new_time,
        })
    }

    /// The §4.4 time policy for one ident's `when` field. Parseable raws are
    /// transformed per mode; the lenient corner (unparseable raw, parser
    /// zero-fills) keeps its bytes under `preserve` and is regenerated as
    /// `0 +0000` under every other mode — it cannot smuggle original bytes
    /// past a redacting mode (plan §4.9).
    fn apply_time(&self, role: IdentRole, t: &Timestamp) -> Result<Timestamp, Error> {
        let zero_tz = |epoch: i64, keep: bool, tz: i16| -> Timestamp {
            let tz = if keep { tz } else { 0 };
            Timestamp {
                raw: time::format_raw(epoch, tz),
                epoch,
                tz_offset_min: tz,
            }
        };
        // Lenient corner: parser zero-fills epoch/tz for unparseable raws.
        let is_lenient = t.epoch == 0 && t.tz_offset_min == 0 && t.raw.as_slice() != b"0 +0000";
        match self.cfg.time_mode {
            TimeMode::Preserve => {
                if self.cfg.keep_tz || is_lenient || t.tz_offset_min == 0 {
                    // Byte-identity path: nothing to change.
                    Ok(t.clone())
                } else {
                    Ok(zero_tz(t.epoch, false, t.tz_offset_min))
                }
            }
            TimeMode::Zero => Ok(Timestamp {
                raw: time::format_raw(0, 0),
                epoch: 0,
                tz_offset_min: 0,
            }),
            TimeMode::Shift(secs) => {
                let epoch = t.epoch.checked_add(secs).ok_or(Error::TimestampOutOfRange {
                    token: BString64::new(t.raw.to_vec()),
                })?;
                Ok(zero_tz(epoch, self.cfg.keep_tz, t.tz_offset_min))
            }
            TimeMode::Bucket(unit) => {
                let epoch = time::bucket_floor(t.epoch, unit).ok_or(Error::TimestampOutOfRange {
                    token: BString64::new(t.raw.to_vec()),
                })?;
                Ok(zero_tz(epoch, false, 0))
            }
            TimeMode::Fuzz { jitter_secs } => {
                let epoch = time::fuzz_shift(
                    t.epoch,
                    self.cfg.seed,
                    role.tag(),
                    t.raw.as_slice(),
                    jitter_secs,
                )
                .ok_or(Error::TimestampOutOfRange {
                    token: BString64::new(t.raw.to_vec()),
                })?;
                Ok(zero_tz(epoch, false, 0))
            }
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
                    c.author = Some(self.map_ident(IdentRole::Author, a)?);
                }
                if let Some(cm) = c.committer.take() {
                    c.committer = Some(self.map_ident(IdentRole::Committer, cm)?);
                }
                out.push(Event::Commit(c));
            }
            Event::Tag(mut t) => {
                if let Some(tg) = t.tagger.take() {
                    t.tagger = Some(self.map_ident(IdentRole::Tagger, tg)?);
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
