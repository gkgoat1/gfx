//! Error taxonomy for the protocol core.
//!
//! The core never uses `std::io::Error`; hosts map their own I/O failures at
//! the boundary. Every variant is deterministic and input-derived.

use crate::limits::ObjectFormat;
use alloc::string::String;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A command word outside the grammar.
    UnknownCommand { word: BString64 },
    /// A line was well-formed enough to start a known construct but the rest
    /// did not parse.
    UnexpectedToken {
        context: &'static str,
        found: String,
    },
    /// An `author`/`committer`/`tagger` ident did not match
    /// `name <email> when`.
    MalformedIdent { line: String },
    /// The byte count on a `data` line was not a valid unsigned integer.
    MalformedDataLen { token: String },
    /// A `data` payload exceeded `Limits::max_data`.
    DataTooLarge { size: u64, max: u64 },
    /// A line exceeded `Limits::max_line`.
    LineTooLong { len: usize, max: usize },
    /// Too many `merge` headers on one commit.
    MaxMergesExceeded { max: usize },
    /// Too many file operations on one commit.
    MaxOpsExceeded { max: usize },
    /// A file mode outside `100644|100755|120000|160000|040000`.
    BadMode { token: String },
    /// A mark that is not `:<decimal>` or that overflows `u64`.
    BadMark { token: String },
    /// A ref name that is empty or otherwise unusable.
    BadRefName { token: String },
    /// An OID whose hex form is invalid for the active object format.
    BadOid { token: String },
    /// The stream's `object-format` disagrees with the configured one.
    ObjectFormatMismatch {
        expected: ObjectFormat,
        found: ObjectFormat,
    },
    /// The stream ended in the middle of a construct.
    TruncatedStream { context: &'static str },
    /// Trailing bytes after `done` or after the last construct.
    TrailingBytes { len: usize },
    /// Strict mode rejects this (known-unknown) `feature`.
    UnsupportedFeature { name: String },
    /// A state machine invariant was violated — always a bug in gfx, never
    /// caused by input. Fuzzing proves this variant unreachable on real input.
    Internal(&'static str),
}

/// A short byte string (≤ 64 bytes) used for error context so hostile input
/// cannot balloon error allocations.
#[derive(Clone, PartialEq, Eq)]
pub struct BString64(pub(crate) alloc::vec::Vec<u8>);

impl BString64 {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for BString64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownCommand { word } => {
                write!(
                    f,
                    "unknown command {:?}",
                    String::from_utf8_lossy(word.as_slice())
                )
            }
            Error::UnexpectedToken { context, found } => {
                write!(f, "unexpected token in {context}: {found:?}")
            }
            Error::MalformedIdent { line } => {
                write!(f, "malformed ident line {line:?}")
            }
            Error::MalformedDataLen { token } => {
                write!(f, "malformed data length {token:?}")
            }
            Error::DataTooLarge { size, max } => {
                write!(f, "data payload of {size} bytes exceeds limit of {max}")
            }
            Error::LineTooLong { len, max } => {
                write!(f, "line of {len} bytes exceeds limit of {max}")
            }
            Error::MaxMergesExceeded { max } => {
                write!(f, "more than {max} merge headers on one commit")
            }
            Error::MaxOpsExceeded { max } => {
                write!(f, "more than {max} file operations on one commit")
            }
            Error::BadMode { token } => write!(f, "bad file mode {token:?}"),
            Error::BadMark { token } => write!(f, "bad mark {token:?}"),
            Error::BadRefName { token } => write!(f, "bad ref name {token:?}"),
            Error::BadOid { token } => write!(f, "bad object id {token:?}"),
            Error::ObjectFormatMismatch { expected, found } => {
                write!(
                    f,
                    "stream object-format is {found:?} but {expected:?} was configured"
                )
            }
            Error::TruncatedStream { context } => {
                write!(f, "stream truncated inside {context}")
            }
            Error::TrailingBytes { len } => {
                write!(f, "{len} trailing bytes after end of stream")
            }
            Error::UnsupportedFeature { name } => write!(f, "unsupported feature {name:?}"),
            Error::Internal(ctx) => write!(f, "internal parser error: {ctx}"),
        }
    }
}

impl core::error::Error for Error {}
