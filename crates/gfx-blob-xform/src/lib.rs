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
//! Machinery lives here; transforms are injected behind
//! [`SharedBlobTransform`] (`Arc + Send + Sync`, the strip-blobs
//! `SharedMatcher` shape upgraded for the multistream `--jobs` fan-out),
//! or picked from the built-ins in [`builtins`]. Text transforms are an
//! adapter ([`TextTransform`], D3): UTF-8 decode failure is an ordinary
//! retention, so line-oriented cleanups never mangle binary blobs.

extern crate alloc;

pub mod builtins;

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
}

impl Default for BlobXformConfig {
    fn default() -> Self {
        BlobXformConfig {
            transforms: Vec::new(),
            skip_larger_than: None,
            max_output_bytes: None,
            include_inline: true,
            include_special_modes: false,
        }
    }
}

impl BlobXformConfig {
    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }
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

/// The `blob-xform` transform. Stateless per blob by design (plan §4.1):
/// there is no cross-event state beyond counters, which is what makes
/// per-blob failure isolation trivial.
pub struct BlobXform {
    cfg: BlobXformConfig,
    report: BlobXformReport,
    finished: bool,
}

impl BlobXform {
    pub fn new(cfg: BlobXformConfig) -> Self {
        BlobXform { cfg, report: BlobXformReport::default(), finished: false }
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
                out.push(Event::Commit(c));
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
        self.report = BlobXformReport::default();
        self.finished = false;
    }
}
