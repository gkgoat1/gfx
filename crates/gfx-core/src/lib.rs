#![no_std]
#![forbid(unsafe_code)]
//! Sans-IO, `no_std` core for the `git fast-export` / `git fast-import` stream
//! protocol.
//!
//! Everything in this crate is a state machine over explicit buffers:
//!
//! * [`Parser`] turns raw stream bytes into [`Event`]s (pull-based; `Ok(None)`
//!   means "need more input").
//! * [`write_event`] serializes an [`Event`] into a caller-owned `Vec<u8>`.
//! * [`Transform`]s (builtins, e.g. `gfx-remap`) rewrite the event stream;
//!   [`Pipeline`] composes zero or more of them. A pipeline with zero
//!   transforms is an identity.
//!
//! The crate never performs I/O, never reads a clock, and never touches the
//! environment: the same input always produces the same output, byte for byte.
//! Hosts own all I/O (files, `git` subprocesses, sockets, async runtimes).

extern crate alloc;

pub mod error;
pub mod event;
pub mod limits;
pub mod markfile;
pub mod parser;
pub mod transform;
pub mod writer;

#[cfg(feature = "test-kit")]
pub mod test_kit;

pub use bstr::BString;

pub use error::Error;
pub use event::{
    Commit, Committish, Data, DataRef, Event, FileOp, FileSource, Ident, Mark, Mode, Oid, Tag,
    Timestamp,
};
pub use limits::{Limits, ObjectFormat, ObjectFormatMode, ParseMode, ParseOptions};
pub use markfile::MarkFile;
pub use parser::Parser;
pub use transform::{Pipeline, PipelineBuilder, Transform};
pub use writer::{write_event, Writer};

/// Convenience re-exports for hosts and builtins.
pub mod prelude {
    pub use crate::{
        write_event, BString, Commit, Committish, Data, DataRef, Error, Event, FileOp, FileSource,
        Ident, Limits, Mark, MarkFile, Mode, ObjectFormat, Oid, ParseOptions, Parser, Pipeline,
        Tag, Timestamp, Transform, Writer,
    };
}
