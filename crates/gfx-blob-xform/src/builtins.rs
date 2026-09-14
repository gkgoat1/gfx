//! Built-in transforms (plan-blob-xform.md §4.2). Deliberately minimal —
//! the built-ins prove the machinery; real workloads arrive via injection.
//! Every built-in is idempotent (`apply ∘ apply == apply`), which the
//! property tests pin, and none ever fails on byte input (the text ones
//! fail only at the UTF-8 decode step, i.e. retain non-UTF-8 blobs).

use alloc::string::String;
use alloc::vec::Vec;

use crate::BlobTransform;

/// CRLF and lone CR line endings → LF. Byte-level (never fails); a blob
/// with no CR bytes is `Unchanged` via no-op elision.
pub struct CrlfToLf;

impl BlobTransform for CrlfToLf {
    fn name(&self) -> &'static str {
        "crlf-to-lf"
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        if !blob.contains(&b'\r') {
            return Ok(blob.to_vec());
        }
        let mut out = Vec::with_capacity(blob.len());
        let mut i = 0;
        while i < blob.len() {
            match blob[i] {
                b'\r' => {
                    out.push(b'\n');
                    if blob.get(i + 1) == Some(&b'\n') {
                        i += 1; // consume the LF of a CRLF pair
                    }
                }
                b => out.push(b),
            }
            i += 1;
        }
        Ok(out)
    }
}

/// Trailing spaces/tabs removed from every line. Line structure and line
/// endings are preserved (a trailing `\r` belongs to the ending —
/// [`CrlfToLf`] owns that, not this transform). Text-only: non-UTF-8 ⇒
/// retain.
pub struct TrimTrailingWhitespace;

impl BlobTransform for TrimTrailingWhitespace {
    fn name(&self) -> &'static str {
        "trim-trailing-whitespace"
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        let text = core::str::from_utf8(blob).map_err(|_| ())?;
        let mut out = String::with_capacity(text.len());
        for (i, line) in text.split('\n').enumerate() {
            if i > 0 {
                out.push('\n');
            }
            // The final empty segment after a trailing '\n' trims to itself.
            out.push_str(line.trim_end_matches([' ', '\t']));
        }
        Ok(out.into_bytes())
    }
}

/// Ensure the blob ends with exactly one `\n` (unless the blob is empty —
/// an empty blob stays empty, plan §4.2). Text-only: non-UTF-8 ⇒ retain.
pub struct EnsureFinalNewline;

impl BlobTransform for EnsureFinalNewline {
    fn name(&self) -> &'static str {
        "ensure-final-newline"
    }

    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        let text = core::str::from_utf8(blob).map_err(|_| ())?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let trimmed = text.trim_end_matches('\n');
        let mut out = String::with_capacity(trimmed.len() + 1);
        out.push_str(trimmed);
        out.push('\n');
        Ok(out.into_bytes())
    }
}

/// All built-ins, in a canonical chain order (line endings → whitespace →
/// final newline). Selection is the host's job; this is convenience.
pub fn all() -> Vec<crate::SharedBlobTransform> {
    Vec::from([
        crate::SharedBlobTransform(alloc::sync::Arc::new(CrlfToLf)),
        crate::SharedBlobTransform(alloc::sync::Arc::new(TrimTrailingWhitespace)),
        crate::SharedBlobTransform(alloc::sync::Arc::new(EnsureFinalNewline)),
    ])
}
