//! Typed event model for the fast-export/fast-import stream.
//!
//! Events own their payloads (v1, see plan §5.6); parsing APIs are
//! lifetime-free. Paths, ref names, ident parts and raw timestamps are byte
//! strings — protocol data is *not* guaranteed UTF-8.

use crate::BString;
use alloc::vec::Vec;

/// A fast-import mark (`:N`). fast-export assigns marks from a single counter
/// shared by blobs and commits, in walk order.
pub type Mark = u64;

/// Object id: 20-byte SHA-1 or 32-byte SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Oid {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl Oid {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Oid::Sha1(b) => b,
            Oid::Sha256(b) => b,
        }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn object_format(&self) -> crate::limits::ObjectFormat {
        match self {
            Oid::Sha1(_) => crate::limits::ObjectFormat::Sha1,
            Oid::Sha256(_) => crate::limits::ObjectFormat::Sha256,
        }
    }

    /// Lowercase hex encoding.
    pub fn to_hex(&self) -> BString {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = self.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        }
        BString::from(out)
    }

    /// Parse lowercase or uppercase hex of the exact expected length.
    pub fn from_hex(hex: &[u8], format: crate::limits::ObjectFormat) -> Option<Oid> {
        let want = match format {
            crate::limits::ObjectFormat::Sha1 => 40usize,
            crate::limits::ObjectFormat::Sha256 => 64usize,
        };
        if hex.len() != want {
            return None;
        }
        let mut buf = [0u8; 32];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            buf[i] = (hi as u8) << 4 | lo as u8;
        }
        Some(match format {
            crate::limits::ObjectFormat::Sha1 => Oid::Sha1(buf[..20].try_into().ok()?),
            crate::limits::ObjectFormat::Sha256 => Oid::Sha256(buf),
        })
    }
}

/// A commit-ish reference target: a mark or an object id.
///
/// Deliberately distinct from [`DataRef`] (decision 4): `from`/`merge` /
/// `reset.from` / `tag.from` use this type; blob/content references use
/// [`DataRef`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Committish {
    Mark(Mark),
    Oid(Oid),
}

/// A blob/content reference: a mark or an object id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataRef {
    Mark(Mark),
    Oid(Oid),
}

/// File mode on an `M` (filemodify) operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Regular, // 100644
    Exec,    // 100755
    Symlink, // 120000
    Gitlink, // 160000
    Dir,     // 040000 (tree replace; version-dependent, plan §3.1)
}

impl Mode {
    pub fn from_octal(token: &[u8]) -> Option<Mode> {
        match token {
            b"100644" => Some(Mode::Regular),
            b"100755" => Some(Mode::Exec),
            b"120000" => Some(Mode::Symlink),
            b"160000" => Some(Mode::Gitlink),
            b"040000" => Some(Mode::Dir),
            _ => None,
        }
    }

    pub fn as_octal(&self) -> &'static [u8] {
        match self {
            Mode::Regular => b"100644",
            Mode::Exec => b"100755",
            Mode::Symlink => b"120000",
            Mode::Gitlink => b"160000",
            Mode::Dir => b"040000",
        }
    }
}

/// Byte payload. The `data delim` / `data literal` forms are normalized to
/// raw `data <n>` at parse time (plan §5.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Data(pub Vec<u8>);

impl Data {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Where an `M`/`N` operation gets its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileSource {
    DataRef(DataRef),
    Inline(Data),
}

/// One path-mutating operation inside a commit. Order is significant: the
/// downstream importer applies these in order against the branch's virtual
/// index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileOp {
    Modify {
        mode: Mode,
        path: BString,
        source: FileSource,
    },
    Delete {
        path: BString,
    },
    Copy {
        from: BString,
        to: BString,
    },
    Rename {
        from: BString,
        to: BString,
    },
    DeleteAll,
    /// `N <dataref> <committish>` (notemodify).
    Note {
        data: FileSource,
        commit: Committish,
    },
}

/// `name <email> when` — raw text is preserved; the epoch/offset fields are a
/// best-effort raw-format parse (zeros when the raw text is not in `raw`
/// format, e.g. rfc2822 streams).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ident {
    pub name: BString,
    pub email: BString,
    pub time: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// The exact bytes between `>` and end of line.
    pub raw: BString,
    /// Seconds since epoch (0 when `raw` is not parseable as raw format).
    pub epoch: i64,
    /// Offset east of UTC in minutes (0 when not parseable).
    pub tz_offset_min: i16,
}

/// A `commit` command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Commit {
    pub ref_name: BString,
    pub mark: Option<Mark>,
    pub original_oid: Option<Oid>,
    /// `None` means the importer defaults the author to the committer.
    pub author: Option<Ident>,
    pub committer: Option<Ident>,
    pub encoding: Option<BString>,
    pub message: Data,
    pub from: Option<Committish>,
    pub merges: Vec<Committish>,
    pub ops: Vec<FileOp>,
}

/// A `tag` command (annotated tag object).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub name: BString,
    pub mark: Option<Mark>,
    pub original_oid: Option<Oid>,
    pub from: Option<Committish>,
    pub tagger: Option<Ident>,
    pub message: Data,
}

/// One parsed stream command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Blob {
        mark: Option<Mark>,
        original_oid: Option<Oid>,
        data: Data,
    },
    Commit(Commit),
    Tag(Tag),
    Reset {
        ref_name: BString,
        from: Option<Committish>,
    },
    Checkpoint,
    Progress {
        bytestring: BString,
    },
    Feature {
        name: BString,
        arg: Option<BString>,
    },
    Option {
        arg: BString,
    },
    Done,
    /// Mark aliasing (newer git).
    Alias {
        mark: Mark,
        target: Committish,
    },
    /// Import-side request: dump the oid bound to a mark.
    GetMark {
        mark: Mark,
    },
    /// Import-side request: emit a blob on the cat-blob channel.
    CatBlob {
        dataref: DataRef,
    },
    /// Import-side request: dump directory entries.
    Ls {
        dataref: Option<DataRef>,
        path: Option<BString>,
    },
    /// One `#` line (only captured when `ParseOptions::keep_comments` is set;
    /// decision 2: line-level granularity, text = bytes after `#`).
    Comment {
        text: BString,
    },
}
