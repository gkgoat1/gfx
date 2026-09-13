//! Git-style C-quoting for the mapping artifact (plan §4.8): idents may be
//! arbitrary bytes, so the artifact quotes non-printables reversibly.

use alloc::string::String;
use alloc::vec::Vec;
use bstr::BString;

/// Quote ident bytes: printable ASCII except `"` and `\` passes through;
/// those two are escaped; everything else becomes `\NNN` (three-digit octal,
/// git's convention). Reversible by [`c_unquote`].
pub fn c_quote(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7E => s.push(b as char),
            _ => {
                s.push('\\');
                s.push((b'0' + (b >> 6)) as char);
                s.push((b'0' + ((b >> 3) & 7)) as char);
                s.push((b'0' + (b & 7)) as char);
            }
        }
    }
    s
}

/// Inverse of [`c_quote`]. Lossless for anything [`c_quote`] produced.
pub fn c_unquote(s: &str) -> BString {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'"' => {
                    out.push(b'"');
                    i += 2;
                    continue;
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                b'0'..=b'3' if i + 3 < bytes.len() => {
                    let o = (bytes[i + 1] - b'0') as u32 * 64
                        + (bytes[i + 2] - b'0') as u32 * 8
                        + (bytes[i + 3] - b'0') as u32;
                    out.push(o as u8);
                    i += 4;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    BString::from(out)
}
