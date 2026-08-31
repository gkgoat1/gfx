//! Canonical serialization: one [`Event`] in, bytes out, into a
//! caller-owned buffer. No state, no I/O.
//!
//! Canonical form (plan §5.4): raw `data <n>` payloads (never `delim`),
//! C-quoted paths only where required, raw timestamps, lowercase hex OIDs,
//! single-`\n` command separators.

use crate::error::Error;
use crate::event::{
    Commit, Committish, Data, DataRef, Event, FileOp, FileSource, Ident, Mark, Tag,
};
use crate::markfile::push_decimal;
use crate::BString;
use alloc::vec::Vec;

/// Serialize one event in canonical form.
pub fn write_event(ev: &Event, out: &mut Vec<u8>) -> Result<(), Error> {
    match ev {
        Event::Blob {
            mark,
            original_oid,
            data,
        } => {
            out.extend_from_slice(b"blob\n");
            if let Some(m) = mark {
                out.extend_from_slice(b"mark ");
                push_mark(out, *m);
                out.push(b'\n');
            }
            if let Some(oid) = original_oid {
                out.extend_from_slice(b"original-oid ");
                out.extend_from_slice(&oid.to_hex());
                out.push(b'\n');
            }
            write_data(out, data.as_slice());
            out.push(b'\n'); // block separator (fast-export layout)
        }
        Event::Commit(c) => {
            write_commit(out, c)?;
        }
        Event::Tag(t) => {
            write_tag(out, t)?;
        }
        Event::Reset { ref_name, from } => {
            out.extend_from_slice(b"reset ");
            out.extend_from_slice(ref_name);
            out.push(b'\n');
            if let Some(c) = from {
                out.extend_from_slice(b"from ");
                write_committish(out, c)?;
                out.push(b'\n');
                out.push(b'\n'); // block separator (fast-export layout)
            }
        }
        Event::Checkpoint => out.extend_from_slice(b"checkpoint\n"),
        Event::Progress { bytestring } => {
            out.extend_from_slice(b"progress ");
            out.extend_from_slice(bytestring);
            out.push(b'\n');
        }
        Event::Feature { name, arg } => {
            out.extend_from_slice(b"feature ");
            out.extend_from_slice(name);
            if let Some(a) = arg {
                out.push(b'=');
                out.extend_from_slice(a);
            }
            out.push(b'\n');
        }
        Event::Option { arg } => {
            out.extend_from_slice(b"option ");
            out.extend_from_slice(arg);
            out.push(b'\n');
        }
        Event::Done => out.extend_from_slice(b"done\n"),
        Event::Alias { mark, target } => {
            out.extend_from_slice(b"alias\n");
            out.extend_from_slice(b"mark ");
            push_mark(out, *mark);
            out.push(b'\n');
            let mut body = Vec::new();
            write_committish(&mut body, target)?;
            write_data(out, &body);
        }
        Event::GetMark { mark } => {
            out.extend_from_slice(b"get-mark ");
            push_mark(out, *mark);
            out.push(b'\n');
        }
        Event::CatBlob { dataref } => {
            out.extend_from_slice(b"cat-blob ");
            write_dataref(out, dataref)?;
            out.push(b'\n');
        }
        Event::Ls { dataref, path } => {
            out.extend_from_slice(b"ls");
            if let Some(d) = dataref {
                out.push(b' ');
                write_dataref(out, d)?;
                if let Some(p) = path {
                    out.push(b' ');
                    write_path(out, p, false);
                }
            } else if let Some(p) = path {
                out.push(b' ');
                write_path(out, p, false);
            }
            out.push(b'\n');
        }
        Event::Comment { text } => {
            out.push(b'#');
            out.extend_from_slice(text);
            out.push(b'\n');
        }
    }
    Ok(())
}

/// Buffered sugar over [`write_event`].
#[derive(Debug, Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn write(&mut self, ev: &Event) -> Result<(), Error> {
        write_event(ev, &mut self.out)
    }

    /// Drain the accumulated bytes.
    pub fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.out
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }
}

fn write_commit(out: &mut Vec<u8>, c: &Commit) -> Result<(), Error> {
    out.extend_from_slice(b"commit ");
    out.extend_from_slice(&c.ref_name);
    out.push(b'\n');
    if let Some(m) = c.mark {
        out.extend_from_slice(b"mark ");
        push_mark(out, m);
        out.push(b'\n');
    }
    if let Some(oid) = &c.original_oid {
        out.extend_from_slice(b"original-oid ");
        out.extend_from_slice(&oid.to_hex());
        out.push(b'\n');
    }
    if let Some(a) = &c.author {
        out.extend_from_slice(b"author ");
        write_ident(out, a);
    }
    if let Some(cm) = &c.committer {
        out.extend_from_slice(b"committer ");
        write_ident(out, cm);
    }
    if let Some(enc) = &c.encoding {
        out.extend_from_slice(b"encoding ");
        out.extend_from_slice(enc);
        out.push(b'\n');
    }
    write_data(out, c.message.as_slice());
    if let Some(f) = &c.from {
        out.extend_from_slice(b"from ");
        write_committish(out, f)?;
        out.push(b'\n');
    }
    for m in &c.merges {
        out.extend_from_slice(b"merge ");
        write_committish(out, m)?;
        out.push(b'\n');
    }
    for op in &c.ops {
        write_op(out, op)?;
    }
    out.push(b'\n'); // block separator (fast-export layout)
    Ok(())
}

fn write_op(out: &mut Vec<u8>, op: &FileOp) -> Result<(), Error> {
    match op {
        FileOp::Modify { mode, path, source } => {
            out.push(b'M');
            out.push(b' ');
            out.extend_from_slice(mode.as_octal());
            out.push(b' ');
            let mut inline: Option<&Data> = None;
            match source {
                FileSource::DataRef(d) => write_dataref(out, d)?,
                FileSource::Inline(d) => {
                    out.extend_from_slice(b"inline");
                    inline = Some(d);
                }
            }
            out.push(b' ');
            write_path(out, path, false);
            out.push(b'\n');
            if let Some(d) = inline {
                write_data(out, d.as_slice());
            }
        }
        FileOp::Delete { path } => {
            out.extend_from_slice(b"D ");
            write_path(out, path, false);
            out.push(b'\n');
        }
        FileOp::Copy { from, to } | FileOp::Rename { from, to } => {
            out.push(if matches!(op, FileOp::Copy { .. }) {
                b'C'
            } else {
                b'R'
            });
            out.push(b' ');
            // Two-path lines: quote if the path contains SP so the pair stays
            // unambiguous.
            write_path(out, from, true);
            out.push(b' ');
            write_path(out, to, true);
            out.push(b'\n');
        }
        FileOp::DeleteAll => out.extend_from_slice(b"filedeleteall\n"),
        FileOp::Note { data, commit } => {
            out.extend_from_slice(b"N ");
            let mut inline: Option<&Data> = None;
            match data {
                FileSource::DataRef(d) => write_dataref(out, d)?,
                FileSource::Inline(d) => {
                    out.extend_from_slice(b"inline");
                    inline = Some(d);
                }
            }
            out.push(b' ');
            write_committish(out, commit)?;
            out.push(b'\n');
            if let Some(d) = inline {
                write_data(out, d.as_slice());
            }
        }
    }
    Ok(())
}

fn write_tag(out: &mut Vec<u8>, t: &Tag) -> Result<(), Error> {
    out.extend_from_slice(b"tag ");
    out.extend_from_slice(&t.name);
    out.push(b'\n');
    if let Some(m) = t.mark {
        out.extend_from_slice(b"mark ");
        push_mark(out, m);
        out.push(b'\n');
    }
    if let Some(oid) = &t.original_oid {
        out.extend_from_slice(b"original-oid ");
        out.extend_from_slice(&oid.to_hex());
        out.push(b'\n');
    }
    if let Some(f) = &t.from {
        out.extend_from_slice(b"from ");
        write_committish(out, f)?;
        out.push(b'\n');
    }
    if let Some(g) = &t.tagger {
        out.extend_from_slice(b"tagger ");
        write_ident(out, g);
    }
    write_data(out, t.message.as_slice());
    out.push(b'\n'); // block separator (fast-export layout)
    Ok(())
}

fn write_ident(out: &mut Vec<u8>, id: &Ident) {
    out.extend_from_slice(&id.name);
    out.extend_from_slice(b" <");
    out.extend_from_slice(&id.email);
    out.extend_from_slice(b"> ");
    out.extend_from_slice(&id.time.raw);
    out.push(b'\n');
}

fn write_data(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(b"data ");
    push_decimal(out, data.len() as u64);
    out.push(b'\n');
    out.extend_from_slice(data);
}

fn push_mark(out: &mut Vec<u8>, m: Mark) {
    out.push(b':');
    push_decimal(out, m);
}

fn write_committish(out: &mut Vec<u8>, c: &Committish) -> Result<(), Error> {
    match c {
        Committish::Mark(m) => push_mark(out, *m),
        Committish::Oid(o) => out.extend_from_slice(&o.to_hex()),
    }
    Ok(())
}

fn write_dataref(out: &mut Vec<u8>, d: &DataRef) -> Result<(), Error> {
    match d {
        DataRef::Mark(m) => push_mark(out, *m),
        DataRef::Oid(o) => out.extend_from_slice(&o.to_hex()),
    }
    Ok(())
}

/// Write a path, C-quoting when required. `two_path_line` additionally forces
/// quoting when the path contains a space (C/R disambiguation).
pub fn write_path(out: &mut Vec<u8>, path: &[u8], two_path_line: bool) {
    if needs_quoting(path, two_path_line) {
        write_quoted(out, path);
    } else {
        out.extend_from_slice(path);
    }
}

fn needs_quoting(path: &[u8], two_path_line: bool) -> bool {
    path.iter()
        .any(|&b| b == b'"' || b == b'\\' || b < 0x20 || b == 0x7f)
        || (two_path_line && path.contains(&b' '))
}

fn write_quoted(out: &mut Vec<u8>, path: &[u8]) {
    out.push(b'"');
    for &b in path {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x07 => out.extend_from_slice(b"\\a"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x0b => out.extend_from_slice(b"\\v"),
            _ if b < 0x20 || b == 0x7f => {
                out.push(b'\\');
                out.push(b'0' + (b >> 6));
                out.push(b'0' + ((b >> 3) & 7));
                out.push(b'0' + (b & 7));
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}

/// C-unquote a path token. `None` if the token is malformed (unterminated
/// quote, bad escape).
pub fn unquote_path(tok: &[u8]) -> Option<BString> {
    if tok.first() != Some(&b'"') {
        return None;
    }
    let mut out = Vec::with_capacity(tok.len());
    let mut i = 1;
    while i < tok.len() {
        let b = tok[i];
        match b {
            b'"' => return Some(BString::from(out)),
            b'\\' => {
                i += 1;
                let e = *tok.get(i)?;
                out.push(match e {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'a' => 0x07,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    b'0'..=b'7' => {
                        let mut v: u16 = (e - b'0') as u16;
                        for _ in 0..2 {
                            i += 1;
                            let d = *tok.get(i)?;
                            if !(b'0'..=b'7').contains(&d) {
                                return None;
                            }
                            v = v * 8 + (d - b'0') as u16;
                        }
                        u8::try_from(v).ok()?
                    }
                    _ => return None,
                });
            }
            _ => out.push(b),
        }
        i += 1;
    }
    // Unterminated quote.
    None
}
