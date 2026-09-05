//! Incremental, pull-based parser for the fast-export/fast-import stream.
//!
//! `feed` appends bytes; [`Parser::next_event`] pulls the next complete
//! [`Event`] (`Ok(None)` = feed more). Hosts call `next_event` until it
//! returns `Ok(None)`, then [`Parser::finish`] to flush the trailing
//! construct (the last commit/tag/reset of a stream is only known complete
//! at EOF) and validate end-of-stream.
//!
//! The parser stages at most one construct at a time; `feed` chunk sizes
//! never affect output. No I/O, no clocks, no panics on any input.

use crate::error::Error;
use crate::event::{
    Commit, Committish, Data, DataRef, Event, FileOp, FileSource, Ident, Mark, Mode, Oid, Tag,
    Timestamp,
};
use crate::limits::{ObjectFormat, ObjectFormatMode, ParseMode, ParseOptions};
use crate::markfile::parse_decimal;
use crate::writer::unquote_path;
use crate::BString;
use alloc::vec::Vec;

/// Incremental stream parser.
#[derive(Debug)]
pub struct Parser {
    opts: ParseOptions,
    object_format: ObjectFormat,
    reader: LineReader,
    /// Commit under construction (parked across `data` payloads).
    pending_commit: Option<CommitAcc>,
    /// Tag under construction (parked across its `data` payload).
    pending_tag: Option<TagAcc>,
    /// `M <mode> inline <path>` awaiting its `data` line.
    inline_op: Option<(Mode, BString)>,
    blob_mark: Option<Mark>,
    blob_original_oid: Option<Oid>,
    alias_mark: Option<Mark>,
    reset_ref: Option<BString>,
    data_mode: Option<DataMode>,
    data_req: Option<DataReq>,
    data_acc: Vec<u8>,
    /// Event produced by `complete_data` that `next_event` should return.
    emitted: Option<Event>,
    seen_done: bool,
    state: State,
}

/// Result of draining a pending `data` payload.
enum PumpOutcome {
    /// Blocked on input (`Ok(None)` from `next_event`).
    Blocked,
    /// Payload completed (event may be in `emitted`, or the construct
    /// continues in another state).
    Completed,
}

#[derive(Debug, Default)]
struct LineReader {
    buf: Vec<u8>,
    pos: usize,
    line_start: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Blob,
    Commit,
    Tag,
    Reset,
    Alias,
    /// `M ... inline <path>` seen; the next line must be `data <n>`.
    Inline,
    Data,
    Done,
    Finished,
}

#[derive(Debug)]
struct CommitAcc {
    c: Commit,
    /// headers (`mark`/`original-oid`/idents/`encoding`) vs body
    /// (`data` message + `from`/`merge`/file-ops).
    in_headers: bool,
    seen_from: bool,
    seen_merge_or_op: bool,
}

#[derive(Debug)]
struct TagAcc {
    t: Tag,
}

#[derive(Debug)]
enum DataReq {
    Blob {
        mark: Option<Mark>,
        original_oid: Option<Oid>,
    },
    CommitMessage,
    TagMessage,
    AliasTarget {
        mark: Mark,
    },
    /// `M <mode> inline <path>` — payload completes the op on the parked
    /// commit in `pending_commit`.
    InlineOp {
        mode: Mode,
        path: BString,
    },
}

#[derive(Debug)]
enum DataMode {
    Counted { remaining: u64 },
    Delim { delim: BString },
}

impl Parser {
    pub fn new(opts: ParseOptions) -> Self {
        let object_format = match opts.object_format {
            ObjectFormatMode::Sha1 => ObjectFormat::Sha1,
            ObjectFormatMode::Sha256 => ObjectFormat::Sha256,
            ObjectFormatMode::Auto => ObjectFormat::Sha1, // until a feature line says otherwise
        };
        Parser {
            opts,
            object_format,
            reader: LineReader::default(),
            pending_commit: None,
            pending_tag: None,
            inline_op: None,
            blob_mark: None,
            blob_original_oid: None,
            alias_mark: None,
            reset_ref: None,
            data_mode: None,
            data_req: None,
            data_acc: Vec::new(),
            emitted: None,
            seen_done: false,
            state: State::Start,
        }
    }

    /// Object format currently in effect (changes on `feature object-format`).
    pub fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    /// Debug aid (used by examples/tests): current state name and reader position.
    pub fn debug_state(&self) -> (&'static str, usize, usize) {
        let name = match self.state {
            State::Start => "Start",
            State::Blob => "Blob",
            State::Commit => "Commit",
            State::Tag => "Tag",
            State::Reset => "Reset",
            State::Alias => "Alias",
            State::Inline => "Inline",
            State::Data => "Data",
            State::Done => "Done",
            State::Finished => "Finished",
        };
        (name, self.reader.pos, self.reader.buf.len())
    }

    /// Append raw bytes. Never parses; never fails.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.reader.buf.extend_from_slice(bytes);
    }

    /// Pull the next complete event; `Ok(None)` = more input needed.
    pub fn next_event(&mut self) -> Result<Option<Event>, Error> {
        loop {
            match self.state {
                State::Start | State::Finished => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    match self.dispatch_command(&line)? {
                        Some(ev) => return Ok(Some(ev)),
                        None => continue,
                    }
                }
                State::Blob => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    if let Some(tok) = line.strip_prefix(b"mark ") {
                        self.blob_mark = Some(parse_mark_token(tok)?);
                        continue;
                    }
                    if let Some(tok) = line.strip_prefix(b"original-oid ") {
                        self.blob_original_oid =
                            Some(parse_oid(self.object_format, self.opts.object_format, tok)?);
                        continue;
                    }
                    if let Some(rest) = line.strip_prefix(b"data ") {
                        let mark = self.blob_mark.take();
                        let original_oid = self.blob_original_oid.take();
                        let mode = parse_data_header(rest, self.opts.mode)?;
                        self.begin_data(mode, DataReq::Blob { mark, original_oid })?;
                        continue;
                    }
                    return Err(Error::UnexpectedToken {
                        context: "blob",
                        found: preview(&line),
                    });
                }
                State::Commit => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    if let Some(rest) = line.strip_prefix(b"data ") {
                        let Some(acc) = self.pending_commit.as_mut() else {
                            return Err(Error::Internal("commit state without accumulator"));
                        };
                        acc.in_headers = false;
                        let mode = parse_data_header(rest, self.opts.mode)?;
                        self.begin_data(mode, DataReq::CommitMessage)?;
                        continue;
                    }
                    let (fmt, ofmode, pm) =
                        (self.object_format, self.opts.object_format, self.opts.mode);
                    let mut acc = self
                        .pending_commit
                        .take()
                        .ok_or(Error::Internal("commit state without accumulator"))?;
                    if acc.in_headers {
                        commit_header_line(&mut acc, fmt, ofmode, pm, &line)?;
                        self.pending_commit = Some(acc);
                        continue;
                    }
                    match self.commit_body_line(&mut acc, fmt, ofmode, pm, &line) {
                        Ok(ev) => {
                            if self.pending_commit.is_none() {
                                self.pending_commit = Some(acc);
                            }
                            if let Some(ev) = ev {
                                return Ok(Some(ev));
                            }
                            continue;
                        }
                        Err(e) => {
                            if self.pending_commit.is_none() {
                                self.pending_commit = Some(acc);
                            }
                            return Err(e);
                        }
                    }
                }
                State::Tag => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    if let Some(rest) = line.strip_prefix(b"data ") {
                        let mode = parse_data_header(rest, self.opts.mode)?;
                        self.begin_data(mode, DataReq::TagMessage)?;
                        continue;
                    }
                    let (fmt, ofmode, pm) =
                        (self.object_format, self.opts.object_format, self.opts.mode);
                    let Some(acc) = self.pending_tag.as_mut() else {
                        return Err(Error::Internal("tag state without accumulator"));
                    };
                    if let Some(tok) = line.strip_prefix(b"mark ") {
                        acc.t.mark = Some(parse_mark_token(tok)?);
                        continue;
                    }
                    if let Some(tok) = line.strip_prefix(b"original-oid ") {
                        acc.t.original_oid = Some(parse_oid(fmt, ofmode, tok)?);
                        continue;
                    }
                    if let Some(tok) = line.strip_prefix(b"from ") {
                        acc.t.from = Some(parse_committish(fmt, ofmode, tok)?);
                        continue;
                    }
                    if let Some(tok) = line.strip_prefix(b"tagger ") {
                        acc.t.tagger = Some(parse_ident(pm, tok)?);
                        continue;
                    }
                    return Err(Error::UnexpectedToken {
                        context: "tag",
                        found: preview(&line),
                    });
                }
                State::Reset => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    if let Some(tok) = line.strip_prefix(b"from ") {
                        let from = self.parse_committish(tok)?;
                        let ref_name = self
                            .reset_ref
                            .take()
                            .ok_or(Error::Internal("reset state without ref"))?;
                        self.state = State::Start;
                        return Ok(Some(Event::Reset {
                            ref_name,
                            from: Some(from),
                        }));
                    }
                    // Anything else is the next command; `reset` completes
                    // without a `from` (ref deletion). Rewind and re-dispatch.
                    let ref_name = self
                        .reset_ref
                        .take()
                        .ok_or(Error::Internal("reset state without ref"))?;
                    self.reader.rewind();
                    self.state = State::Start;
                    return Ok(Some(Event::Reset {
                        ref_name,
                        from: None,
                    }));
                }
                State::Alias => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    if let Some(tok) = line.strip_prefix(b"mark ") {
                        self.alias_mark = Some(parse_mark_token(tok)?);
                        continue;
                    }
                    if let Some(rest) = line.strip_prefix(b"data ") {
                        let mark = self.alias_mark.take().ok_or(Error::UnexpectedToken {
                            context: "alias",
                            found: alloc::string::String::from("data before mark"),
                        })?;
                        let mode = parse_data_header(rest, self.opts.mode)?;
                        self.begin_data(mode, DataReq::AliasTarget { mark })?;
                        continue;
                    }
                    return Err(Error::UnexpectedToken {
                        context: "alias",
                        found: preview(&line),
                    });
                }
                State::Inline => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    let Some(rest) = line.strip_prefix(b"data ") else {
                        return Err(Error::UnexpectedToken {
                            context: "M inline data",
                            found: preview(&line),
                        });
                    };
                    let (mode, path) = self
                        .inline_op
                        .take()
                        .ok_or(Error::Internal("inline state without op"))?;
                    let dm = parse_data_header(rest, self.opts.mode)?;
                    self.begin_data(dm, DataReq::InlineOp { mode, path })?;
                    continue;
                }
                State::Data => match self.pump_data()? {
                    PumpOutcome::Blocked => return Ok(None),
                    PumpOutcome::Completed => {
                        if let Some(ev) = self.emitted.take() {
                            return Ok(Some(ev));
                        }
                        continue;
                    }
                },
                State::Done => {
                    let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                        return Ok(None);
                    };
                    if let Some(ev) = self.comment_event(&line) {
                        return Ok(Some(ev));
                    }
                    return Err(Error::UnexpectedToken {
                        context: "after done",
                        found: preview(&line),
                    });
                }
            }
        }
    }

    /// Flush the trailing construct and validate end-of-stream. Pushes any
    /// final events into `out`.
    ///
    /// Call only after `next_event` has returned `Ok(None)`.
    pub fn finish(&mut self, out: &mut Vec<Event>) -> Result<(), Error> {
        match self.state {
            State::Start | State::Finished | State::Done => {}
            State::Blob => return Err(Error::TruncatedStream { context: "blob" }),
            State::Commit => {
                let acc = self
                    .pending_commit
                    .take()
                    .ok_or(Error::TruncatedStream { context: "commit" })?;
                out.push(Event::Commit(acc.c));
            }
            State::Tag => return Err(Error::TruncatedStream { context: "tag" }),
            State::Reset => {
                let ref_name = self
                    .reset_ref
                    .take()
                    .ok_or(Error::Internal("reset state without ref"))?;
                out.push(Event::Reset {
                    ref_name,
                    from: None,
                });
            }
            State::Alias | State::Inline => {
                return Err(Error::TruncatedStream {
                    context: "inline/alias",
                });
            }
            State::Data => return Err(Error::TruncatedStream { context: "data" }),
        }
        self.state = State::Finished;
        let leftover = trim_blank(&self.reader.buf[self.reader.pos..]);
        if !leftover.is_empty() {
            return Err(Error::TrailingBytes {
                len: leftover.len(),
            });
        }
        Ok(())
    }

    // ----- internals ------------------------------------------------------

    fn comment_event(&self, line: &[u8]) -> Option<Event> {
        if line.first() == Some(&b'#') && self.opts.keep_comments {
            // Decision 2: line-level granularity, one event per `#` line,
            // text = the bytes after `#`.
            return Some(Event::Comment {
                text: BString::from(line[1..].to_vec()),
            });
        }
        None
    }

    fn dispatch_command(&mut self, line: &[u8]) -> Result<Option<Event>, Error> {
        let line = strip_trailing_cr(line);
        if line.is_empty() {
            return match self.opts.mode {
                ParseMode::Lenient => Ok(None),
                ParseMode::Strict => Err(Error::UnexpectedToken {
                    context: "command start",
                    found: alloc::string::String::from("\"\""),
                }),
            };
        }
        if line.first() == Some(&b'#') {
            return Ok(self.comment_event(line));
        }
        if self.seen_done {
            return Err(Error::UnexpectedToken {
                context: "after done",
                found: preview(line),
            });
        }
        if line == b"blob" {
            self.blob_mark = None;
            self.blob_original_oid = None;
            self.state = State::Blob;
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"commit ") {
            let ref_name = parse_ref_name(rest)?;
            self.pending_commit = Some(CommitAcc {
                c: Commit {
                    ref_name,
                    mark: None,
                    original_oid: None,
                    author: None,
                    committer: None,
                    encoding: None,
                    message: Data::default(),
                    from: None,
                    merges: Vec::new(),
                    ops: Vec::new(),
                },
                in_headers: true,
                seen_from: false,
                seen_merge_or_op: false,
            });
            self.state = State::Commit;
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"tag ") {
            let name = parse_ref_name(rest)?;
            self.pending_tag = Some(TagAcc {
                t: Tag {
                    name,
                    mark: None,
                    original_oid: None,
                    from: None,
                    tagger: None,
                    message: Data::default(),
                },
            });
            self.state = State::Tag;
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"reset ") {
            let ref_name = parse_ref_name(rest)?;
            self.reset_ref = Some(ref_name);
            self.state = State::Reset;
            return Ok(None);
        }
        if line == b"checkpoint" {
            return Ok(Some(Event::Checkpoint));
        }
        if let Some(rest) = line.strip_prefix(b"progress ") {
            return Ok(Some(Event::Progress {
                bytestring: BString::from(rest.to_vec()),
            }));
        }
        if let Some(rest) = line.strip_prefix(b"feature ") {
            return self.parse_feature(rest);
        }
        if let Some(rest) = line.strip_prefix(b"option ") {
            return Ok(Some(Event::Option {
                arg: BString::from(rest.to_vec()),
            }));
        }
        if line == b"done" {
            self.seen_done = true;
            self.state = State::Done;
            return Ok(Some(Event::Done));
        }
        if line == b"alias" {
            self.alias_mark = None;
            self.state = State::Alias;
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"get-mark ") {
            let mark = parse_mark_token(rest)?;
            return Ok(Some(Event::GetMark { mark }));
        }
        if let Some(rest) = line.strip_prefix(b"cat-blob ") {
            let dataref = self.parse_dataref(rest)?;
            return Ok(Some(Event::CatBlob { dataref }));
        }
        if line == b"ls" || line.starts_with(b"ls ") {
            let ev = self.parse_ls(&line[2..])?;
            return Ok(Some(ev));
        }
        Err(Error::UnknownCommand {
            word: first_word(line),
        })
    }

    fn parse_feature(&mut self, rest: &[u8]) -> Result<Option<Event>, Error> {
        let (name, arg) = match rest.iter().position(|&b| b == b'=') {
            Some(i) => (&rest[..i], Some(BString::from(rest[i + 1..].to_vec()))),
            None => (rest, None),
        };
        if name == b"object-format" {
            let fmt = match arg.as_deref().map(|a| &a[..]) {
                Some(b"sha1") => ObjectFormat::Sha1,
                Some(b"sha256") => ObjectFormat::Sha256,
                _ => {
                    return Err(Error::UnsupportedFeature {
                        name: crate::markfile::str_lossy(rest),
                    });
                }
            };
            match self.opts.object_format {
                ObjectFormatMode::Auto => self.object_format = fmt,
                ObjectFormatMode::Sha1 if fmt == ObjectFormat::Sha1 => {}
                ObjectFormatMode::Sha256 if fmt == ObjectFormat::Sha256 => {}
                _ => {
                    let expected = match self.opts.object_format {
                        ObjectFormatMode::Sha1 | ObjectFormatMode::Auto => ObjectFormat::Sha1,
                        ObjectFormatMode::Sha256 => ObjectFormat::Sha256,
                    };

                    return Err(Error::ObjectFormatMismatch {
                        expected,
                        found: fmt,
                    });
                }
            }
        } else if self.opts.mode == ParseMode::Strict && !is_known_feature(name) {
            return Err(Error::UnsupportedFeature {
                name: crate::markfile::str_lossy(name),
            });
        }
        Ok(Some(Event::Feature {
            name: BString::from(name.to_vec()),
            arg,
        }))
    }

    fn parse_ls(&mut self, rest: &[u8]) -> Result<Event, Error> {
        let rest = strip_leading_sp(rest);
        if rest.is_empty() {
            return Ok(Event::Ls {
                dataref: None,
                path: None,
            });
        }
        if rest.first() == Some(&b':') {
            let sp =
                rest.iter()
                    .position(|&b| b == b' ')
                    .ok_or_else(|| Error::UnexpectedToken {
                        context: "ls",
                        found: preview(rest),
                    })?;
            let dataref = self.parse_dataref(&rest[..sp])?;
            let path = parse_path_token(&rest[sp + 1..])?;
            return Ok(Event::Ls {
                dataref: Some(dataref),
                path: Some(path),
            });
        }
        let path = parse_path_token(rest)?;
        Ok(Event::Ls {
            dataref: None,
            path: Some(path),
        })
    }

    fn commit_body_line(
        &mut self,
        acc: &mut CommitAcc,
        fmt: ObjectFormat,
        ofmode: ObjectFormatMode,
        pm: ParseMode,
        line: &[u8],
    ) -> Result<Option<Event>, Error> {
        // Next command? Then this commit is complete — rewind and emit.
        if starts_command(line) {
            self.reader.rewind();
            self.state = State::Start;
            let c = core::mem::take(&mut acc.c);
            return Ok(Some(Event::Commit(c)));
        }
        // Lenient: tolerate blank lines between commands (fast-import does).
        if line.is_empty() {
            return Ok(None);
        }
        if let Some(tok) = line.strip_prefix(b"from ") {
            if acc.seen_from {
                return Err(Error::UnexpectedToken {
                    context: "commit body",
                    found: alloc::string::String::from("duplicate from"),
                });
            }
            if pm == ParseMode::Strict && acc.seen_merge_or_op {
                return Err(Error::UnexpectedToken {
                    context: "commit body",
                    found: alloc::string::String::from("from after merge/file-op"),
                });
            }
            acc.c.from = Some(parse_committish(fmt, ofmode, tok)?);
            acc.seen_from = true;
            return Ok(None);
        }
        if let Some(tok) = line.strip_prefix(b"merge ") {
            if pm == ParseMode::Strict && !acc.seen_from {
                return Err(Error::UnexpectedToken {
                    context: "commit body",
                    found: alloc::string::String::from("merge before from"),
                });
            }
            if acc.c.merges.len() >= self.opts.limits.max_merges {
                return Err(Error::MaxMergesExceeded {
                    max: self.opts.limits.max_merges,
                });
            }
            acc.c.merges.push(parse_committish(fmt, ofmode, tok)?);
            acc.seen_merge_or_op = true;
            return Ok(None);
        }
        if acc.c.ops.len() >= self.opts.limits.max_ops {
            return Err(Error::MaxOpsExceeded {
                max: self.opts.limits.max_ops,
            });
        }
        if let Some(rest) = line.strip_prefix(b"M ") {
            acc.seen_merge_or_op = true;
            let sp1 =
                rest.iter()
                    .position(|&b| b == b' ')
                    .ok_or_else(|| Error::UnexpectedToken {
                        context: "M (filemodify)",
                        found: preview(rest),
                    })?;
            let mode = Mode::from_octal(&rest[..sp1]).ok_or_else(|| Error::BadMode {
                token: crate::markfile::str_lossy(&rest[..sp1]),
            })?;
            let rest = &rest[sp1 + 1..];
            let sp2 =
                rest.iter()
                    .position(|&b| b == b' ')
                    .ok_or_else(|| Error::UnexpectedToken {
                        context: "M (filemodify)",
                        found: preview(rest),
                    })?;
            let src = &rest[..sp2];
            let path = parse_path_token(&rest[sp2 + 1..])?;
            if src == b"inline" {
                // Payload arrives on the next `data` line; commit stays parked.
                self.inline_op = Some((mode, path));
                self.state = State::Inline;
                return Ok(None);
            }
            let dataref = parse_dataref(fmt, ofmode, src)?;
            acc.c.ops.push(FileOp::Modify {
                mode,
                path,
                source: FileSource::DataRef(dataref),
            });
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"D ") {
            acc.seen_merge_or_op = true;
            let path = parse_path_token(rest)?;
            acc.c.ops.push(FileOp::Delete { path });
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"C ") {
            acc.seen_merge_or_op = true;
            let (from, to) = parse_two_paths(rest)?;
            acc.c.ops.push(FileOp::Copy { from, to });
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"R ") {
            acc.seen_merge_or_op = true;
            let (from, to) = parse_two_paths(rest)?;
            acc.c.ops.push(FileOp::Rename { from, to });
            return Ok(None);
        }
        if line == b"filedeleteall" {
            acc.seen_merge_or_op = true;
            acc.c.ops.push(FileOp::DeleteAll);
            return Ok(None);
        }
        if let Some(rest) = line.strip_prefix(b"N ") {
            acc.seen_merge_or_op = true;
            let sp =
                rest.iter()
                    .position(|&b| b == b' ')
                    .ok_or_else(|| Error::UnexpectedToken {
                        context: "N (notemodify)",
                        found: preview(rest),
                    })?;
            let data = parse_dataref(fmt, ofmode, &rest[..sp])?;
            let commit = parse_committish(fmt, ofmode, &rest[sp + 1..])?;
            acc.c.ops.push(FileOp::Note {
                data: FileSource::DataRef(data),
                commit,
            });
            return Ok(None);
        }
        Err(Error::UnexpectedToken {
            context: "commit body",
            found: preview(line),
        })
    }

    /// Set up the `data` accumulator; the caller has already parsed `mode`.
    fn begin_data(&mut self, mode: DataMode, req: DataReq) -> Result<(), Error> {
        if let DataMode::Counted { remaining } = mode {
            if remaining > self.opts.limits.max_data {
                return Err(Error::DataTooLarge {
                    size: remaining,
                    max: self.opts.limits.max_data,
                });
            }
        }
        self.data_mode = Some(mode);
        self.data_req = Some(req);
        self.data_acc.clear();
        self.state = State::Data;
        Ok(())
    }

    fn pump_data(&mut self) -> Result<PumpOutcome, Error> {
        let mode = self
            .data_mode
            .take()
            .ok_or(Error::Internal("data state without mode"))?;
        match mode {
            DataMode::Counted { remaining } => {
                if remaining == 0 {
                    return self.complete_data();
                }
                let avail = self.reader.buf.len() - self.reader.pos;
                if avail == 0 {
                    self.data_mode = Some(DataMode::Counted { remaining });
                    return Ok(PumpOutcome::Blocked); // need more input
                }
                let want = (remaining as usize).min(avail);
                self.data_acc
                    .extend_from_slice(&self.reader.buf[self.reader.pos..self.reader.pos + want]);
                self.reader.pos += want;
                self.reader.compact();
                let remaining = remaining - want as u64;
                if remaining > 0 {
                    self.data_mode = Some(DataMode::Counted { remaining });
                    return Ok(PumpOutcome::Blocked); // need more input
                }
                self.complete_data()
            }
            DataMode::Delim { delim } => loop {
                let Some(line) = self.reader.take_line(self.opts.limits.max_line)? else {
                    self.data_mode = Some(DataMode::Delim { delim });
                    return Ok(PumpOutcome::Blocked); // need more input
                };
                let matches = line == delim[..]
                    || (self.opts.mode == ParseMode::Lenient
                        && strip_trailing_cr(&line) == &delim[..]);
                if matches {
                    return self.complete_data();
                }
                self.data_acc.extend_from_slice(&line);
                self.data_acc.push(b'\n');
                if self.data_acc.len() as u64 > self.opts.limits.max_data {
                    return Err(Error::DataTooLarge {
                        size: self.data_acc.len() as u64,
                        max: self.opts.limits.max_data,
                    });
                }
            },
        }
    }

    fn complete_data(&mut self) -> Result<PumpOutcome, Error> {
        let req = self
            .data_req
            .take()
            .ok_or(Error::Internal("data completion without request"))?;
        let data = Data(core::mem::take(&mut self.data_acc));
        self.state = State::Start;
        match req {
            DataReq::Blob { mark, original_oid } => {
                self.emitted = Some(Event::Blob {
                    mark,
                    original_oid,
                    data,
                });
            }
            DataReq::CommitMessage => {
                let mut acc = self
                    .pending_commit
                    .take()
                    .ok_or(Error::TruncatedStream { context: "commit" })?;
                acc.c.message = data;
                self.pending_commit = Some(acc);
                self.state = State::Commit;
            }
            DataReq::TagMessage => {
                // `data` is the tag's last construct: the tag completes here.
                let mut acc = self
                    .pending_tag
                    .take()
                    .ok_or(Error::TruncatedStream { context: "tag" })?;
                acc.t.message = data;
                self.emitted = Some(Event::Tag(acc.t));
            }
            DataReq::AliasTarget { mark } => {
                let target = parse_committish_bytes(data.as_slice())?;
                self.emitted = Some(Event::Alias { mark, target });
            }
            DataReq::InlineOp { mode, path } => {
                let mut acc = self
                    .pending_commit
                    .take()
                    .ok_or(Error::TruncatedStream { context: "commit" })?;
                acc.c.ops.push(FileOp::Modify {
                    mode,
                    path,
                    source: FileSource::Inline(data),
                });
                self.pending_commit = Some(acc);
                self.state = State::Commit;
            }
        }
        Ok(PumpOutcome::Completed)
    }

    // ----- token parsers (borrow only &self) ------------------------------

    fn parse_committish(&self, tok: &[u8]) -> Result<Committish, Error> {
        let tok = strip_trailing_cr(tok);
        if tok.first() == Some(&b':') {
            return Ok(Committish::Mark(parse_mark_token(tok)?));
        }
        Ok(Committish::Oid(parse_oid(
            self.object_format,
            self.opts.object_format,
            tok,
        )?))
    }

    fn parse_dataref(&self, tok: &[u8]) -> Result<DataRef, Error> {
        let tok = strip_trailing_cr(tok);
        if tok.first() == Some(&b':') {
            return Ok(DataRef::Mark(parse_mark_token(tok)?));
        }
        Ok(DataRef::Oid(parse_oid(
            self.object_format,
            self.opts.object_format,
            tok,
        )?))
    }
}

impl LineReader {
    fn take_line(&mut self, max_line: usize) -> Result<Option<Vec<u8>>, Error> {
        let start = self.pos;
        let Some(rel) = self.buf[start..].iter().position(|&b| b == b'\n') else {
            if self.buf.len() - start > max_line {
                return Err(Error::LineTooLong {
                    len: self.buf.len() - start,
                    max: max_line,
                });
            }
            return Ok(None);
        };
        let end = start + rel;
        let line = self.buf[start..end].to_vec();
        self.line_start = start;
        self.pos = end + 1;
        self.compact();
        Ok(Some(line))
    }

    /// Rewind to the start of the last line taken (used when a line turns
    /// out to begin the next command instead of continuing the current one).
    fn rewind(&mut self) {
        self.pos = self.line_start;
    }

    fn compact(&mut self) {
        if self.pos > 32 * 1024 && self.pos * 2 > self.buf.len() {
            self.buf.drain(..self.pos);
            // `line_start` may legitimately point before `pos` (it records
            // the start of the last *taken line* for rewind, while data
            // pumping can advance `pos` far past it). Clamp instead of
            // underflowing; after the drain the stale rewind target is
            // meaningless anyway, and the next take_line re-anchors it.
            self.line_start = self.line_start.saturating_sub(self.pos);
            self.pos = 0;
        }
    }
}

/// One header line of a `commit` command (before its message `data`).
fn commit_header_line(
    acc: &mut CommitAcc,
    fmt: ObjectFormat,
    ofmode: ObjectFormatMode,
    pm: ParseMode,
    line: &[u8],
) -> Result<(), Error> {
    let line = strip_trailing_cr(line);
    if let Some(tok) = line.strip_prefix(b"mark ") {
        acc.c.mark = Some(parse_mark_token(tok)?);
        return Ok(());
    }
    if let Some(tok) = line.strip_prefix(b"original-oid ") {
        acc.c.original_oid = Some(parse_oid(fmt, ofmode, tok)?);
        return Ok(());
    }
    if let Some(tok) = line.strip_prefix(b"author ") {
        if pm == ParseMode::Strict && acc.c.committer.is_some() {
            return Err(Error::UnexpectedToken {
                context: "commit headers",
                found: alloc::string::String::from("author after committer"),
            });
        }
        acc.c.author = Some(parse_ident(pm, tok)?);
        return Ok(());
    }
    if let Some(tok) = line.strip_prefix(b"committer ") {
        acc.c.committer = Some(parse_ident(pm, tok)?);
        return Ok(());
    }
    if let Some(tok) = line.strip_prefix(b"encoding ") {
        acc.c.encoding = Some(BString::from(tok.to_vec()));
        return Ok(());
    }
    Err(Error::UnexpectedToken {
        context: "commit headers",
        found: preview(line),
    })
}

// ----- free helpers ---------------------------------------------------------

fn is_known_feature(name: &[u8]) -> bool {
    matches!(
        name,
        b"date-format"
            | b"import-marks"
            | b"import-marks-if-exists"
            | b"export-marks"
            | b"relative-marks"
            | b"no-relative-marks"
            | b"force"
            | b"dump-pack-file"
            | b"object-format"
            | b"quiet"
            | b"stats"
            | b"done"
    )
}

/// Parse the tail of a `data ...` line into a fill mode.
fn parse_data_header(rest: &[u8], pm: ParseMode) -> Result<DataMode, Error> {
    if let Some(r) = rest.strip_prefix(b"literal ") {
        let n = parse_decimal(strip_trailing_cr(r)).ok_or_else(|| Error::MalformedDataLen {
            token: crate::markfile::str_lossy(r),
        })?;
        return Ok(DataMode::Counted { remaining: n });
    }
    if let Some(r) = rest.strip_prefix(b"delim ") {
        let delim = if r.first() == Some(&b'"') {
            unquote_path(r).ok_or_else(|| Error::UnexpectedToken {
                context: "data delim",
                found: preview(r),
            })?
        } else if pm == ParseMode::Strict {
            return Err(Error::UnexpectedToken {
                context: "data delim",
                found: preview(r),
            });
        } else {
            BString::from(r.to_vec())
        };
        return Ok(DataMode::Delim { delim });
    }
    let n = parse_decimal(strip_trailing_cr(rest)).ok_or_else(|| Error::MalformedDataLen {
        token: crate::markfile::str_lossy(rest),
    })?;
    Ok(DataMode::Counted { remaining: n })
}

/// Does this line start a new top-level command?
fn starts_command(line: &[u8]) -> bool {
    line == b"blob"
        || line.starts_with(b"commit ")
        || line.starts_with(b"tag ")
        || line.starts_with(b"reset ")
        || line == b"checkpoint"
        || line.starts_with(b"progress ")
        || line.starts_with(b"feature ")
        || line.starts_with(b"option ")
        || line == b"done"
        || line == b"alias"
        || line.starts_with(b"get-mark ")
        || line.starts_with(b"cat-blob ")
        || line == b"ls"
        || line.starts_with(b"ls ")
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(s) => s,
        None => line,
    }
}

fn trim_blank(b: &[u8]) -> &[u8] {
    let mut s = b;
    while let Some((f, r)) = s.split_first() {
        if *f == b'\n' || *f == b'\r' {
            s = r;
        } else {
            break;
        }
    }
    s
}

fn trim_end(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b' ' || b[end - 1] == b'\t') {
        end -= 1;
    }
    &b[..end]
}

fn trim_start(b: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < b.len() && (b[start] == b' ' || b[start] == b'\t') {
        start += 1;
    }
    &b[start..]
}

fn strip_leading_sp(b: &[u8]) -> &[u8] {
    if b.first() == Some(&b' ') {
        &b[1..]
    } else {
        b
    }
}

fn preview(line: &[u8]) -> alloc::string::String {
    const MAX: usize = 64;
    let cut = line.len().min(MAX);
    let mut s = alloc::string::String::from_utf8_lossy(&line[..cut]).into_owned();
    if line.len() > MAX {
        s.push_str("...");
    }
    s
}

fn first_word(line: &[u8]) -> crate::error::BString64 {
    let end = line.iter().position(|&b| b == b' ').unwrap_or(line.len());
    crate::error::BString64(line[..end.min(64)].to_vec())
}

fn parse_mark_token(tok: &[u8]) -> Result<Mark, Error> {
    let tok = strip_trailing_cr(tok);
    let Some(rest) = tok.strip_prefix(b":") else {
        return Err(Error::BadMark {
            token: crate::markfile::str_lossy(tok),
        });
    };
    parse_decimal(rest).ok_or_else(|| Error::BadMark {
        token: crate::markfile::str_lossy(tok),
    })
}

fn parse_ref_name(tok: &[u8]) -> Result<BString, Error> {
    let tok = strip_trailing_cr(tok);
    if tok.is_empty() || tok.contains(&0) {
        return Err(Error::BadRefName {
            token: crate::markfile::str_lossy(tok),
        });
    }
    Ok(BString::from(tok.to_vec()))
}

/// Parse a path token: C-quoted when it starts with `"`, otherwise raw
/// rest-of-line.
fn parse_path_token(tok: &[u8]) -> Result<BString, Error> {
    if tok.first() == Some(&b'"') {
        unquote_path(tok).ok_or_else(|| Error::UnexpectedToken {
            context: "path",
            found: preview(tok),
        })
    } else {
        Ok(BString::from(tok.to_vec()))
    }
}

/// `C <from> <to>` / `R <from> <to>`: two path tokens. Quoted paths are
/// self-delimiting; unquoted paths split on the first SP.
fn parse_two_paths(rest: &[u8]) -> Result<(BString, BString), Error> {
    if rest.first() == Some(&b'"') {
        let mut i = 1;
        while i < rest.len() {
            if rest[i] == b'\\' {
                i += 2;
                continue;
            }
            if rest[i] == b'"' {
                let from = unquote_path(&rest[..=i]).ok_or_else(|| Error::UnexpectedToken {
                    context: "C/R paths",
                    found: preview(rest),
                })?;
                let to = parse_path_token(strip_leading_sp(&rest[i + 1..]))?;
                return Ok((from, to));
            }
            i += 1;
        }
        return Err(Error::UnexpectedToken {
            context: "C/R paths",
            found: preview(rest),
        });
    }
    let sp = rest
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| Error::UnexpectedToken {
            context: "C/R paths",
            found: preview(rest),
        })?;
    let from = BString::from(rest[..sp].to_vec());
    let to = parse_path_token(&rest[sp + 1..])?;
    Ok((from, to))
}

fn parse_oid(fmt: ObjectFormat, ofmode: ObjectFormatMode, tok: &[u8]) -> Result<Oid, Error> {
    let hex = strip_trailing_cr(tok);
    let mut ok = Oid::from_hex(hex, fmt);
    if ok.is_none() && ofmode == ObjectFormatMode::Auto {
        ok = Oid::from_hex(hex, ObjectFormat::Sha256);
    }
    ok.ok_or_else(|| Error::BadOid {
        token: crate::markfile::str_lossy(hex),
    })
}

fn parse_committish(
    fmt: ObjectFormat,
    ofmode: ObjectFormatMode,
    tok: &[u8],
) -> Result<Committish, Error> {
    let tok = strip_trailing_cr(tok);
    if tok.first() == Some(&b':') {
        return Ok(Committish::Mark(parse_mark_token(tok)?));
    }
    Ok(Committish::Oid(parse_oid(fmt, ofmode, tok)?))
}

fn parse_dataref(
    fmt: ObjectFormat,
    ofmode: ObjectFormatMode,
    tok: &[u8],
) -> Result<DataRef, Error> {
    let tok = strip_trailing_cr(tok);
    if tok.first() == Some(&b':') {
        return Ok(DataRef::Mark(parse_mark_token(tok)?));
    }
    Ok(DataRef::Oid(parse_oid(fmt, ofmode, tok)?))
}

fn parse_ident(pm: ParseMode, tok: &[u8]) -> Result<Ident, Error> {
    let tok = strip_trailing_cr(tok);
    let Some(lt) = tok.iter().position(|&b| b == b'<') else {
        return Err(Error::MalformedIdent { line: preview(tok) });
    };
    let name = trim_end(&tok[..lt]);
    let Some(gt_rel) = tok[lt..].iter().position(|&b| b == b'>') else {
        return Err(Error::MalformedIdent { line: preview(tok) });
    };
    let gt = lt + gt_rel;
    let email = &tok[lt + 1..gt];
    if email.contains(&b'<') {
        return Err(Error::MalformedIdent { line: preview(tok) });
    }
    let when_raw = trim_start(&tok[gt + 1..]);
    let parsed = parse_when(when_raw);
    if pm == ParseMode::Strict && parsed.is_none() {
        return Err(Error::MalformedIdent { line: preview(tok) });
    }
    let (epoch, tz) = parsed.unwrap_or((0, 0));
    Ok(Ident {
        name: BString::from(name.to_vec()),
        email: BString::from(email.to_vec()),
        time: Timestamp {
            raw: BString::from(when_raw.to_vec()),
            epoch,
            tz_offset_min: tz,
        },
    })
}

fn parse_committish_bytes(bytes: &[u8]) -> Result<Committish, Error> {
    let bytes = strip_trailing_cr(bytes);
    if bytes.first() == Some(&b':') {
        return Ok(Committish::Mark(parse_mark_token(bytes)?));
    }
    // Accept either hash length (alias targets are length-ambiguous in
    // practice; be permissive here).
    let oid = Oid::from_hex(bytes, ObjectFormat::Sha1)
        .or_else(|| Oid::from_hex(bytes, ObjectFormat::Sha256));
    oid.map(Committish::Oid).ok_or_else(|| Error::BadOid {
        token: crate::markfile::str_lossy(bytes),
    })
}

/// Raw-format `<epoch> <±HHMM>` parse; `None` when the text is not raw format
/// (e.g. rfc2822).
fn parse_when(when: &[u8]) -> Option<(i64, i16)> {
    let sp = when.iter().position(|&b| b == b' ')?;
    let epoch = parse_i64(&when[..sp])?;
    let tz = &when[sp + 1..];
    if tz.len() != 5 || (tz[0] != b'+' && tz[0] != b'-') {
        return None;
    }
    let h = parse_decimal(&tz[1..3])?;
    let m = parse_decimal(&tz[3..5])?;
    let mag = (h * 60 + m) as i16;
    let tz = if tz[0] == b'-' { -mag } else { mag };
    Some((epoch, tz))
}

fn parse_i64(b: &[u8]) -> Option<i64> {
    let (neg, digits) = match b.first() {
        Some(b'-') => (true, &b[1..]),
        Some(b'+') => (false, &b[1..]),
        _ => (false, b),
    };
    let mut n: i64 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((d - b'0') as i64)?;
    }
    Some(if neg { -n } else { n })
}
