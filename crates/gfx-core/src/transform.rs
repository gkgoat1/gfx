//! Builtins compose as [`Transform`]s inside a [`Pipeline`].
//!
//! A pipeline with zero transforms is an identity: `apply` forwards each
//! event unchanged. Builtins are optional feature-gated dependencies
//! (plan §5.5); nothing here knows any specific builtin exists.

use crate::error::Error;
use crate::event::Event;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// A sans-IO stream-to-stream rewrite.
///
/// Contract (enforced by the test kit):
///
/// * 1 event in → 0..N events out, order-preserving;
/// * no silent drops of structural events without explicit policy;
/// * `finish` flushes all residual events and is idempotent afterwards;
/// * deterministic: same input sequence ⇒ same output sequence;
/// * `reset` restores the state of a freshly-constructed transform so hosts
///   can drive deterministic multi-pass rewrites.
pub trait Transform {
    fn name(&self) -> &'static str;

    fn apply(&mut self, event: Event, out: &mut Vec<Event>) -> Result<(), Error>;

    fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error>;

    fn reset(&mut self);
}

/// Compose zero or more [`Transform`]s. Identity when empty.
#[derive(Default)]
pub struct Pipeline {
    transforms: Vec<Box<dyn Transform>>,
    stage: Vec<Event>,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder {
            transforms: Vec::new(),
        }
    }

    /// Number of composed transforms.
    pub fn len(&self) -> usize {
        self.transforms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transforms.is_empty()
    }

    /// Apply one input event through every stage. Output events are appended
    /// to `out` in stream order.
    pub fn apply(&mut self, ev: Event, out: &mut Vec<Event>) -> Result<(), Error> {
        out.push(ev);
        for t in &mut self.transforms {
            let mut next = core::mem::take(&mut self.stage);
            next.clear();
            for e in out.drain(..) {
                t.apply(e, &mut next)?;
            }
            core::mem::swap(&mut self.stage, &mut next);
            out.append(&mut self.stage);
        }
        Ok(())
    }

    /// Flush all stages at end of stream, then reset every transform for a
    /// fresh pass.
    pub fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error> {
        for t in &mut self.transforms {
            let mut next = core::mem::take(&mut self.stage);
            next.clear();
            for e in out.drain(..) {
                t.apply(e, &mut next)?;
            }
            t.finish(&mut next)?;
            core::mem::swap(&mut self.stage, &mut next);
            out.append(&mut self.stage);
        }
        for t in &mut self.transforms {
            t.reset();
        }
        Ok(())
    }
}

impl core::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pipeline")
            .field(
                "transforms",
                &self
                    .transforms
                    .iter()
                    .map(|t| t.name())
                    .collect::<Vec<&'static str>>(),
            )
            .finish()
    }
}

pub struct PipelineBuilder {
    transforms: Vec<Box<dyn Transform>>,
}

impl PipelineBuilder {
    /// Append a transform. Order is the stream order (first pushed runs
    /// first).
    pub fn push(mut self, t: Box<dyn Transform>) -> Self {
        self.transforms.push(t);
        self
    }

    pub fn build(self) -> Pipeline {
        Pipeline {
            transforms: self.transforms,
            stage: Vec::new(),
        }
    }
}
