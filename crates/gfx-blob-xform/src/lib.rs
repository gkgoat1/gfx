#![no_std]
#![forbid(unsafe_code)]
//! Builtin: generic fallible blob rewriting (plan-blob-xform.md).
//!
//! Fail-open semantics (decision D1): every blob runs a pure, fallible
//! transform chain; `Ok` at the end ⇒ the blob's `data` is replaced, any
//! `Err` ⇒ the **original** bytes flow through untouched and the failure is
//! counted, not raised. This pass exists for best-effort improvement
//! (normalization, re-encoding, fixups) — guaranteed removal belongs to
//! `gfx-strip-blobs`, guaranteed field rewriting to `gfx-redact`.
//!
//! The pass never drops, synthesizes, or reorders an event: marks,
//! `original-oid` lines (preserved verbatim — stale-after-alter is the
//! audit trail, D6), refs, and topology are untouched; the remap builtin
//! owns the resulting commit-hash churn. With a config whose transforms all
//! fail — or whose outputs all equal their inputs — the output is
//! byte-identical input (G3 no-op elision).
//!
//! **Path rules** (plan-blob-xform-paths.md): standalone `blob` events
//! carry no path, so per-extension transforms (`.rs` → rustfmt) cannot run
//! at the blob event — a blob's paths bind late and non-uniquely (the same
//! mark can appear as `a.rs` in one commit and `d.txt` in another). Path
//! rules therefore act at `M` op sites, where path and mode are both
//! known: originals are cached from blob events, the first *matching* use
//! runs the rule's chain on the cached bytes, emits the result as a
//! **synthetic blob event** immediately before that commit under a
//! driver-allocated mark (D3), and rewrites the op to reference it. Later
//! matching uses reuse the cached synthetic mark — the transform runs at
//! most once per (blob, rule). Non-matching uses keep the original bytes;
//! the original blob event always passes through (D2). Mode is known at
//! the op site, so special modes are skipped by default (D6) — the
//! whole-blob mode-blindness hazard does not apply to path rules.
//!
//! Machinery lives here; transforms are injected behind
//! [`SharedBlobTransform`] (`Arc + Send + Sync`, the strip-blobs
//! `SharedMatcher` shape upgraded for the multistream `--jobs` fan-out),
//! or picked from the built-ins in [`builtins`]. Text transforms are an
//! adapter ([`TextTransform`], D3): UTF-8 decode failure is an ordinary
//! retention, so line-oriented cleanups never mangle binary blobs.

extern crate alloc;

pub mod builtins;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use gfx_core::{Error, Event, FileOp, FileSource, Mode};

// ---------------------------------------------------------------------------
// Transforms (D2)

/// A fallible, pure, per-blob byte transform (plan-blob-xform.md §4.1).
///
/// Contract: a pure function of the input bytes — no clocks, no RNG, no
/// cross-blob state. Stateful transforms break determinism (P6) and the
/// multistream fan-out's byte-identical-output guarantee. `Err(())` means
/// "keep the original" and is never surfaced as a stream error.
pub trait BlobTransform: Send + Sync {
    fn name(&self) -> &'static str;

    /// `Ok(new)` alters the blob; `Err(())` retains the original bytes.
    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()>;

    /// Debug output without requiring `Debug` bounds on implementations.
    fn describe(&self) -> String {
        String::from(self.name())
    }
}

/// Clone-cheap, thread-shareable handle (orphan rule: we own the newtype,
/// not the `Arc`).
#[derive(Clone)]
pub struct SharedBlobTransform(pub Arc<dyn BlobTransform>);

impl core::fmt::Debug for SharedBlobTransform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0.describe())
    }
}

impl<F> BlobTransform for F
where
    F: Fn(&[u8]) -> Result<Vec<u8>, ()> + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "<bytes-transform>"
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        self(blob)
    }
}

/// D3: a `Fn(&str) -> Result<String, E>` adapter. UTF-8 decode failure ⇒
/// `Err(())` ⇒ the original bytes are retained, so text transforms are
/// safe to run across mixed text/binary history.
pub struct TextTransform<F> {
    pub name: &'static str,
    pub f: F,
}

impl<F, E> BlobTransform for TextTransform<F>
where
    F: Fn(&str) -> Result<String, E> + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        let text = core::str::from_utf8(blob).map_err(|_| ())?;
        (self.f)(text).map(String::into_bytes).map_err(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Config + report

/// One path rule (plan-blob-xform-paths.md §5.1): extension → transform
/// chain. Path rules act at `M` op sites, not blob events (D2).
#[derive(Clone, Debug)]
pub struct PathRule {
    /// Extension bytes without the dot (`b"rs"`). Matched against the
    /// final path component's bytes after the last `.` — case-sensitive,
    /// byte-exact (D5); a path with no `.`, or ending in `.`, matches
    /// nothing.
    pub extension: Vec<u8>,
    /// Chain, in order; same handles and semantics as the whole-blob stage.
    pub transforms: Vec<SharedBlobTransform>,
    /// Per-rule input selector (same D4 semantics as the base pass).
    pub skip_larger_than: Option<u64>,
    /// Per-rule output guard.
    pub max_output_bytes: Option<u64>,
}

/// Configuration (plan §4.1). `Clone` shares the injected transform
/// handles (immutable shared state); `reset()` clears counters only.
/// `Default` is the documented profile: no transforms, no size guards,
/// inline payloads transformed, special modes skipped.
#[derive(Clone, Debug)]
pub struct BlobXformConfig {
    /// Applied in order; any stage `Err` ⇒ retain the original (D1).
    pub transforms: Vec<SharedBlobTransform>,
    /// D4 input selector: blobs strictly larger than this are left alone
    /// (counted as `retained_guard`). `None` disables.
    pub skip_larger_than: Option<u64>,
    /// D4 output guard: a chain result larger than this is discarded and
    /// the original retained (counted as `retained_guard`). `None`
    /// disables.
    pub max_output_bytes: Option<u64>,
    /// Transform inline `M`/`N` `data` payloads (default true).
    pub include_inline: bool,
    /// Include `Symlink`/`Gitlink` modes when transforming inline payloads
    /// (default false, D5). Standalone `blob` events carry no mode and are
    /// always transformed — see the plan's mode-blindness hazard note.
    pub include_special_modes: bool,
    /// Path rules (plan-blob-xform-paths.md). Empty ⇒ the pass behaves
    /// exactly as the base plan describes.
    pub path_rules: Vec<PathRule>,
    /// Synthetic mark base: stream max mark + 1 (D3). The driver computes
    /// it over the already-parsed stream and injects it here; **required**
    /// when `path_rules` is non-empty — the pass refuses to run without it
    /// (config error surfaced at `finish`), never guesses a base.
    pub mark_base: Option<u64>,
}

impl Default for BlobXformConfig {
    fn default() -> Self {
        BlobXformConfig {
            transforms: Vec::new(),
            skip_larger_than: None,
            max_output_bytes: None,
            include_inline: true,
            include_special_modes: false,
            path_rules: Vec::new(),
            mark_base: None,
        }
    }
}

impl BlobXformConfig {
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty() && self.path_rules.is_empty()
    }
}

/// Per-rule counters (plan-blob-xform-paths.md D9). `ops_examined` is the
/// number of `M`-op payloads a rule judged; it partitions exactly:
/// examined = rewritten + retained_failed + retained_guard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathRuleReport {
    /// Matching `M` ops judged (mark-sourced and inline). Partitions
    /// exactly: examined = rewritten + unchanged + failed + guard.
    pub ops_examined: u64,
    /// Ops rewritten to a synthetic mark (or inline-rewritten).
    pub ops_rewritten: u64,
    /// Chain succeeded with output identical to input: op keeps the
    /// original mark (G3).
    pub unchanged: u64,
    /// Synthetic blob events created (G2: `created <= ops_rewritten`).
    pub blobs_created: u64,
    /// Chain failure on a matching op: original mark/payload kept (D1).
    pub retained_failed: u64,
    /// Guarded out (size guards, special modes): original kept.
    pub retained_guard: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Counters (plan §4.4 report surface). Totals are exact.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobXformReport {
    /// Blob payloads examined (standalone events + transformed inline
    /// payloads).
    pub blobs_examined: u64,
    /// Chain succeeded and output differed from input.
    pub altered: u64,
    /// Chain succeeded with output identical to input (G3: emitted
    /// byte-identically).
    pub unchanged: u64,
    /// Any chain stage failed, or UTF-8 decode failed (D3): original
    /// retained.
    pub retained_failed: u64,
    /// Guarded out (D4 size guards, D5 special modes, inline disabled):
    /// original retained without running the chain.
    pub retained_guard: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Per-rule counters, parallel to `config.path_rules`.
    pub rules: Vec<PathRuleReport>,
}

impl BlobXformReport {
    /// One-line summary for the run report's per-pass detail.
    pub fn detail(&self) -> String {
        alloc::format!(
            "blobs={} altered={} unchanged={} retained={} (failed={} guard={}) bytes={}->{}",
            self.blobs_examined,
            self.altered,
            self.unchanged,
            self.retained_failed + self.retained_guard,
            self.retained_failed,
            self.retained_guard,
            self.bytes_in,
            self.bytes_out
        )
    }

    /// Full detail: whole-blob line plus one segment per path rule (D9).
    pub fn detail_with_rules(&self, rules: &[PathRule]) -> String {
        let mut d = self.detail();
        for (i, r) in self.rules.iter().enumerate() {
            let ext = rules
                .get(i)
                .map(|rule| String::from_utf8_lossy(&rule.extension).into_owned())
                .unwrap_or_default();
            d.push_str(&alloc::format!(
                " | rule[{ext}]: ops={} rewritten={} created={} retained={} (failed={} guard={}) bytes={}->{}",
                r.ops_examined,
                r.ops_rewritten,
                r.blobs_created,
                r.retained_failed + r.retained_guard,
                r.retained_failed,
                r.retained_guard,
                r.bytes_in,
                r.bytes_out,
            ));
        }
        d
    }
}

// ---------------------------------------------------------------------------
// The pass

/// Outcome of judging one payload.
enum Outcome {
    Alter(Vec<u8>),
    Unchanged,
    RetainFailed,
    RetainGuard,
}

/// Cached per-(blob, rule) judgment (G2 create-once; D4).
#[derive(Clone, Copy)]
enum Cached {
    Synthetic(u64),
    Unchanged,
    Failed,
    Guarded,
}

/// The `blob-xform` transform. The whole-blob stage is stateless per blob
/// by design (plan §4.1); path rules add three pieces of cross-event
/// state (plan-blob-xform-paths.md D4): the original-bytes cache (a
/// blob's last matching use is unknowable in streaming, R1), the
/// create-once transformed cache, and the synthetic mark allocator.
pub struct BlobXform {
    cfg: BlobXformConfig,
    report: BlobXformReport,
    finished: bool,
    /// mark → post-whole-blob bytes, every blob seen (D4). Only
    /// populated when path rules exist.
    originals: BTreeMap<u64, Vec<u8>>,
    /// (original mark, rule index) → cached judgment (create-once, G2:
    /// the chain runs at most once per (blob, rule) — retention and
    /// unchanged verdicts are cached too, since chains are pure).
    transformed: BTreeMap<(u64, usize), Cached>,
    /// Next synthetic mark, seeded from `cfg.mark_base` (D3).
    next_mark: u64,
}

impl BlobXform {
    pub fn new(cfg: BlobXformConfig) -> Self {
        let next_mark = cfg.mark_base.unwrap_or(0);
        let mut report = BlobXformReport::default();
        report.rules = alloc::vec::from_elem(PathRuleReport::default(), cfg.path_rules.len());
        BlobXform {
            cfg,
            report,
            finished: false,
            originals: BTreeMap::new(),
            transformed: BTreeMap::new(),
            next_mark,
        }
    }

    pub fn report(&self) -> &BlobXformReport {
        &self.report
    }

    /// Judge one payload against guards + chain. Pure with respect to the
    /// pass (counters are updated by the caller).
    fn judge(&self, blob: &[u8], guarded: bool) -> Outcome {
        if guarded {
            return Outcome::RetainGuard;
        }
        if let Some(cap) = self.cfg.skip_larger_than {
            if blob.len() as u64 > cap {
                return Outcome::RetainGuard;
            }
        }
        let mut current: Vec<u8> = blob.to_vec();
        for t in &self.cfg.transforms {
            match t.0.apply(&current) {
                Ok(next) => current = next,
                Err(()) => return Outcome::RetainFailed,
            }
        }
        if let Some(cap) = self.cfg.max_output_bytes {
            if current.len() as u64 > cap {
                return Outcome::RetainGuard;
            }
        }
        if current == blob {
            Outcome::Unchanged
        } else {
            Outcome::Alter(current)
        }
    }

    /// Apply the outcome to the payload + counters. Returns the (possibly
    /// replaced) payload bytes.
    fn settle(&mut self, original: &[u8], outcome: Outcome) -> Vec<u8> {
        self.report.blobs_examined += 1;
        self.report.bytes_in += original.len() as u64;
        let out = match outcome {
            Outcome::Alter(new) => {
                self.report.altered += 1;
                new
            }
            Outcome::Unchanged => {
                self.report.unchanged += 1;
                original.to_vec()
            }
            Outcome::RetainFailed => {
                self.report.retained_failed += 1;
                original.to_vec()
            }
            Outcome::RetainGuard => {
                self.report.retained_guard += 1;
                original.to_vec()
            }
        };
        self.report.bytes_out += out.len() as u64;
        out
    }

    fn xform_payload(&mut self, blob: &[u8], guarded: bool) -> Vec<u8> {
        let outcome = self.judge(blob, guarded);
        self.settle(blob, outcome)
    }

    /// Judge one payload against a path rule's own guards + chain (D5's
    /// per-rule guards mirror the base D4 semantics).
    fn judge_rule(&self, rule: &PathRule, blob: &[u8], guarded: bool) -> Outcome {
        if guarded {
            return Outcome::RetainGuard;
        }
        if let Some(cap) = rule.skip_larger_than {
            if blob.len() as u64 > cap {
                return Outcome::RetainGuard;
            }
        }
        let mut current: Vec<u8> = blob.to_vec();
        for t in &rule.transforms {
            match t.0.apply(&current) {
                Ok(next) => current = next,
                Err(()) => return Outcome::RetainFailed,
            }
        }
        if let Some(cap) = rule.max_output_bytes {
            if current.len() as u64 > cap {
                return Outcome::RetainGuard;
            }
        }
        if current == blob {
            Outcome::Unchanged
        } else {
            Outcome::Alter(current)
        }
    }


    /// The final path component's extension bytes after the last `.`
    /// (D5). `None` when the component has no `.`, ends with one, or
    /// *starts* with one — `.rs` is a dotfile named `.rs`, not a file
    /// with extension `rs` (shell/gitignore convention).
    fn extension_of(path: &[u8]) -> Option<&[u8]> {
        let component = match path.iter().rposition(|&b| b == b'/') {
            Some(slash) => &path[slash + 1..],
            None => path,
        };
        let dot = component.iter().rposition(|&b| b == b'.')?;
        let ext = &component[dot + 1..];
        if dot == 0 || ext.is_empty() {
            None
        } else {
            Some(ext)
        }
    }

    /// First path rule matching this op's path (D5: one extension ⇒ at
    /// most one match in v1).
    fn matching_rule(&self, path: &[u8]) -> Option<usize> {
        let ext = Self::extension_of(path)?;
        self.cfg
            .path_rules
            .iter()
            .position(|r| r.extension.as_slice() == ext)
    }

    /// Create-once (G2): probe the judgment cache; on miss, run the rule
    /// chain on the cached original bytes, allocate a synthetic mark, and
    /// emit the blob event immediately before the referencing commit.
    /// Returns the mark the op should reference — the original mark on
    /// any retention or unchanged verdict (D1/D2).
    fn materialize(&mut self, out: &mut Vec<Event>, rule_ix: usize, original_mark: u64) -> u64 {
        if let Some(&cached) = self.transformed.get(&(original_mark, rule_ix)) {
            let r = &mut self.report.rules[rule_ix];
            r.ops_examined += 1;
            return match cached {
                Cached::Synthetic(m) => {
                    r.ops_rewritten += 1;
                    m
                }
                Cached::Unchanged => {
                    r.unchanged += 1;
                    original_mark
                }
                Cached::Failed => {
                    r.retained_failed += 1;
                    original_mark
                }
                Cached::Guarded => {
                    r.retained_guard += 1;
                    original_mark
                }
            };
        }
        let Some(original) = self.originals.get(&original_mark).cloned() else {
            // A mark with no cached original cannot occur in a
            // well-formed fast-export stream (blobs precede use); keep
            // the pass total over adversarial input: retain + count.
            let r = &mut self.report.rules[rule_ix];
            r.ops_examined += 1;
            r.retained_failed += 1;
            return original_mark;
        };
        let outcome = self.judge_rule(&self.cfg.path_rules[rule_ix], &original, false);
        let verdict = match &outcome {
            Outcome::Alter(_) => None, // filled in below
            Outcome::Unchanged => Some(Cached::Unchanged),
            Outcome::RetainFailed => Some(Cached::Failed),
            Outcome::RetainGuard => Some(Cached::Guarded),
        };
        let r = &mut self.report.rules[rule_ix];
        r.ops_examined += 1;
        r.bytes_in += original.len() as u64;
        match outcome {
            Outcome::Alter(new) => {
                let new_len = new.len() as u64;
                let synthetic = self.next_mark;
                self.next_mark += 1;
                out.push(Event::Blob {
                    mark: Some(synthetic),
                    original_oid: None,
                    data: gfx_core::Data(new),
                });
                self.transformed.insert((original_mark, rule_ix), Cached::Synthetic(synthetic));
                let r = &mut self.report.rules[rule_ix];
                r.bytes_out += new_len;
                r.ops_rewritten += 1;
                r.blobs_created += 1;
                synthetic
            }
            _ => {
                self.transformed.insert(
                    (original_mark, rule_ix),
                    verdict.expect("non-alter outcomes carry a verdict"),
                );
                let r = &mut self.report.rules[rule_ix];
                r.bytes_out += original.len() as u64;
                match verdict {
                    Some(Cached::Unchanged) => r.unchanged += 1,
                    Some(Cached::Failed) => r.retained_failed += 1,
                    _ => r.retained_guard += 1,
                }
                original_mark
            }
        }
    }
}

impl gfx_core::Transform for BlobXform {
    fn name(&self) -> &'static str {
        "blob-xform"
    }

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        if self.finished {
            out.push(event);
            return Ok(());
        }
        match event {
            Event::Blob { mark, original_oid, data } => {
                // D5: standalone blobs carry no mode — always transformed
                // (documented mode-blindness hazard). D6: original_oid
                // preserved verbatim.
                let bytes = self.xform_payload(data.as_slice(), false);
                if !self.cfg.path_rules.is_empty() {
                    if let Some(m) = mark {
                        // D4/D8: cache the post-whole-blob bytes for
                        // later M-op sites (R1: the last matching use is
                        // unknowable in streaming).
                        self.originals.insert(m, bytes.clone());
                    }
                }
                out.push(Event::Blob {
                    mark,
                    original_oid,
                    data: gfx_core::Data(bytes),
                });
            }
            Event::Commit(mut c) => {
                if self.cfg.include_inline {
                    for op in &mut c.ops {
                        match op {
                            FileOp::Modify { mode, source, .. } => {
                                if let FileSource::Inline(data) = source {
                                    let guarded = !self.cfg.include_special_modes
                                        && matches!(mode, Mode::Symlink | Mode::Gitlink);
                                    let bytes = self.xform_payload(data.as_slice(), guarded);
                                    *data = gfx_core::Data(bytes);
                                }
                            }
                            // Notes carry no mode: treated like standalone
                            // blobs (always transformed).
                            FileOp::Note { data, .. } => {
                                if let FileSource::Inline(data) = data {
                                    let bytes = self.xform_payload(data.as_slice(), false);
                                    *data = gfx_core::Data(bytes);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                // Path rules (plan-blob-xform-paths.md): M ops whose path
                // matches a rule are rewritten to a synthetic blob
                // created once per (blob, rule) and emitted immediately
                // before this commit. Mode-aware by default (D6). Runs
                // AFTER the whole-blob inline stage above (D8): rule
                // chains judge post-whole-blob payloads, matching what
                // mark-sourced ops see (the originals cache holds
                // post-whole-blob blob bytes).
                if !self.cfg.path_rules.is_empty() {
                    let ops = core::mem::take(&mut c.ops);
                    let mut rewritten = Vec::with_capacity(ops.len());
                    for mut op in ops {
                        if let FileOp::Modify { mode, path, source } = &mut op {
                            let mode_guarded = !self.cfg.include_special_modes
                                && matches!(mode, Mode::Symlink | Mode::Gitlink);
                            if let Some(rule_ix) = self.matching_rule(path) {
                                match source {
                                    FileSource::DataRef(gfx_core::DataRef::Mark(m)) => {
                                        if mode_guarded {
                                            let r = &mut self.report.rules[rule_ix];
                                            r.ops_examined += 1;
                                            r.retained_guard += 1;
                                        } else {
                                            let orig = *m;
                                            let new = self.materialize(out, rule_ix, orig);
                                            *m = new;
                                        }
                                    }
                                    FileSource::Inline(data) if self.cfg.include_inline => {
                                        let outcome = self.judge_rule(
                                            &self.cfg.path_rules[rule_ix],
                                            data.as_slice(),
                                            mode_guarded,
                                        );
                                        let r = &mut self.report.rules[rule_ix];
                                        r.ops_examined += 1;
                                        r.bytes_in += data.as_slice().len() as u64;
                                        match outcome {
                                            Outcome::Alter(new) => {
                                                r.bytes_out += new.len() as u64;
                                                r.ops_rewritten += 1;
                                                *data = gfx_core::Data(new);
                                            }
                                            Outcome::Unchanged => {
                                                r.bytes_out += data.as_slice().len() as u64;
                                                r.unchanged += 1;
                                            }
                                            Outcome::RetainFailed => {
                                                r.bytes_out += data.as_slice().len() as u64;
                                                r.retained_failed += 1;
                                            }
                                            Outcome::RetainGuard => {
                                                r.bytes_out += data.as_slice().len() as u64;
                                                r.retained_guard += 1;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        rewritten.push(op);
                    }
                    c.ops = rewritten;
                }
                out.push(Event::Commit(c));
            }
            other => out.push(other),
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<Event>) -> Result<(), Error> {
        // D3: synthetic marks live above the stream max; the base must be
        // injected by the driver — never guessed (R3: a colliding mark
        // fails the import mid-stream).
        if !self.cfg.path_rules.is_empty() && self.cfg.mark_base.is_none() {
            return Err(Error::Internal(
                "blob-xform path rules require an injected mark_base (stream max mark + 1)",
            ));
        }
        self.finished = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.report = BlobXformReport::default();
        self.report.rules =
            alloc::vec::from_elem(PathRuleReport::default(), self.cfg.path_rules.len());
        self.finished = false;
        self.originals.clear();
        self.transformed.clear();
        self.next_mark = self.cfg.mark_base.unwrap_or(0);
    }
}
