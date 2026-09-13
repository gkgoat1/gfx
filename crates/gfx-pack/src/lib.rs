//! `gfx-pack` — multistream archives of rewritten repositories
//! (plan: `docs/plan-multistream-pack.md`).
//!
//! Two driver halves over one format core:
//!
//! * [`pack`] — fan-out: `git fast-export` each repo, run one uniform pass
//!   pipeline per stream (via [`gfx::driver::transform_stream`]), spool the
//!   results, and assemble a deterministic zip (the `.gfxpack`).
//! * [`unpack`] — fan-in: verify manifest + checksums, create fresh repos,
//!   `git fast-import` each stream, finalize each commit map from the
//!   import's marks, and assert the ref tips the manifest recorded.
//!
//! The format core ([`manifest`], [`zip`], [`sha256`]) has no `git`
//! dependency: it turns canned bytes into archives and back, so it is
//! unit-testable without repositories.
//!
//! Decision D1 (fan-out/fan-in, never a merge): every stream in the archive
//! is self-contained — its own marks namespace, its own `original-oid`
//! space — and any single entry can be imported with plain
//! `git fast-import` without this crate.

extern crate std;

use std::fmt;

pub mod manifest;
pub mod pack;
pub mod unpack;
pub mod zip;

pub use manifest::{Manifest, RefTip, RepoEntry};
pub use pack::{pack, PackOptions, PackReport, PackRepo, RepoPackReport};
pub use unpack::{unpack, RepoStatus, RepoUnpackReport, UnpackOptions, UnpackReport};

/// Error surface for the whole crate. Zip/manifest structural problems are
/// plain messages; `git` and driver failures keep their wrapped types.
#[derive(Debug)]
pub enum PackError {
    /// Zip container is malformed, unsupported (multi-disk, zip64,
    /// encrypted entries), or fails integrity checks (CRC, sizes).
    Zip(std::string::String),
    /// Manifest is not valid TOML, fails schema/validation, or records a
    /// format version this build does not read.
    Manifest(std::string::String),
    /// A checksum in the manifest does not match the archived stream.
    Checksum { repo: std::string::String },
    /// Bad CLI/library usage (slug collisions, missing repos, unsafe
    /// destinations).
    Usage(std::string::String),
    Io(std::io::Error),
    Git(gfx::git::process::GitError),
    Driver(gfx::driver::DriverError),
    Core(gfx::core::Error),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::Zip(m) => write!(f, "zip error: {m}"),
            PackError::Manifest(m) => write!(f, "manifest error: {m}"),
            PackError::Checksum { repo } => {
                write!(f, "stream checksum mismatch for repo {repo:?}")
            }
            PackError::Usage(m) => write!(f, "{m}"),
            PackError::Io(e) => write!(f, "i/o error: {e}"),
            PackError::Git(e) => write!(f, "{e}"),
            PackError::Driver(e) => write!(f, "{e}"),
            PackError::Core(e) => write!(f, "stream error: {e}"),
        }
    }
}

impl std::error::Error for PackError {}

impl From<std::io::Error> for PackError {
    fn from(e: std::io::Error) -> Self {
        PackError::Io(e)
    }
}

impl From<gfx::git::process::GitError> for PackError {
    fn from(e: gfx::git::process::GitError) -> Self {
        PackError::Git(e)
    }
}

impl From<gfx::driver::DriverError> for PackError {
    fn from(e: gfx::driver::DriverError) -> Self {
        PackError::Driver(e)
    }
}

impl From<gfx::core::Error> for PackError {
    fn from(e: gfx::core::Error) -> Self {
        PackError::Core(e)
    }
}

/// SHA-256 of `data`, as lowercase hex. Used for per-stream manifest
/// checksums (sha2 is already in the tree via `gfx-hash`).
pub fn sha256_hex(data: &[u8]) -> std::string::String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    let mut out = std::string::String::with_capacity(64);
    for b in digest {
        out.push_str(&std::format!("{b:02x}"));
    }
    out
}

/// Streaming SHA-256 hasher for spooled streams (avoids re-reading large
/// spool files for the manifest checksum).
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    pub fn new() -> Self {
        use sha2::Digest;
        Sha256(sha2::Sha256::new())
    }

    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest;
        self.0.update(data);
    }

    pub fn finish_hex(self) -> std::string::String {
        use sha2::Digest;
        let digest = self.0.finalize();
        let mut out = std::string::String::with_capacity(64);
        for b in digest {
            out.push_str(&std::format!("{b:02x}"));
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}
