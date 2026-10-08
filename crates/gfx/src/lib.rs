//! `gfx` — sans-IO, `no_std` implementation of the `git fast-export`
//! protocol, usable with or without builtins (plan §9).
//!
//! Re-exports the core (parser, writer, pipeline) and, behind features, the
//! optional builtins. The `std`/`git` features add host-side adapters; the
//! `no_std` story never requires them.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub use gfx_core as core;

#[cfg(feature = "remap")]
pub use gfx_remap;

#[cfg(feature = "strip-blobs")]
pub use gfx_strip_blobs;

#[cfg(feature = "redact")]
pub use gfx_redact;

#[cfg(feature = "blob-xform")]
pub use gfx_blob_xform;

/// Everything a host typically needs.
pub mod prelude {
    pub use gfx_core::{
        write_event, Commit, Committish, Data, DataRef, Error, Event, FileOp, FileSource, Ident,
        Limits, Mark, MarkFile, Mode, ObjectFormat, Oid, ParseOptions, Parser, Pipeline, Tag,
        Timestamp, Transform, Writer,
    };
}

#[cfg(feature = "std")]
pub mod git;

#[cfg(feature = "git")]
pub mod driver;

#[cfg(feature = "std")]
pub mod streamfile;

#[cfg(feature = "git")]
pub mod remotes;

#[cfg(feature = "std")]
pub use git::rewrite;
