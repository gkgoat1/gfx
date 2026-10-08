//! Stream-file framing (plan-stream-files.md D2): optional gzip around
//! fast-export streams.
//!
//! - **Decode** never trusts the file name: the first two bytes are
//!   sniffed for the gzip magic (`1f 8b`); a gzipped file with a `.feat`
//!   name decodes, a raw file with a `.gz` name passes through verbatim.
//! - **Encode** is deterministic (C2): empty original-name field, mtime
//!   0, OS byte 255, and the compression level pinned by the caller.
//!   Byte-stability then holds per flate2/miniz_oxide version — the
//!   workspace pins both in `Cargo.lock`.
//!
//! Buffered, like the rest of the driver (R2): the whole decoded stream
//! lives in memory.

extern crate std;

use alloc::vec::Vec;
use std::io::Read;
use std::path::Path;

use crate::driver::DriverError;

/// gzip member magic (RFC 1952 §2.3.1).
pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// The default gzip level for stream output (zlib's default, pinned).
pub const DEFAULT_GZIP_LEVEL: u32 = 6;

/// Compression selection for stream output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamCompression {
    /// `.gz` suffix ⇒ gzip, otherwise raw (D2).
    #[default]
    Auto,
    /// Always raw bytes.
    None,
    /// Always gzip, whatever the name says.
    Gzip,
}

impl StreamCompression {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(StreamCompression::Auto),
            "none" => Some(StreamCompression::None),
            "gzip" => Some(StreamCompression::Gzip),
            _ => Option::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StreamCompression::Auto => "auto",
            StreamCompression::None => "none",
            StreamCompression::Gzip => "gzip",
        }
    }

    /// Resolve the choice for a concrete output path.
    fn for_path(self, path: &Path) -> bool {
        match self {
            StreamCompression::Auto => {
                path.extension().map_or(false, |e| e == "gz")
            }
            StreamCompression::None => false,
            StreamCompression::Gzip => true,
        }
    }
}

/// Read a stream file, gunzipping when the magic says so.
pub fn read_stream_file(path: &Path) -> Result<Vec<u8>, DriverError> {
    let raw = std::fs::read(path)?;
    if raw.starts_with(&GZIP_MAGIC) {
        let mut out = Vec::with_capacity(raw.len().saturating_mul(4));
        flate2::read::GzDecoder::new(raw.as_slice())
            .read_to_end(&mut out)
            .map_err(|e| {
                DriverError::Endpoint(alloc::format!(
                    "{}: gzip decode failed: {e}",
                    path.display()
                ))
            })?;
        Ok(out)
    } else {
        Ok(raw)
    }
}

/// Write a stream file per the compression selection. Deterministic when
/// gzip is chosen (see module docs).
pub fn write_stream_file(
    path: &Path,
    bytes: &[u8],
    compression: StreamCompression,
    level: u32,
) -> Result<(), DriverError> {
    if compression.for_path(path) {
        let mut enc = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::new(level),
        );
        std::io::Write::write_all(&mut enc, bytes)?;
        let out = enc.finish()?;
        std::fs::write(path, out)?;
    } else {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}
