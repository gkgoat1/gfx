//! fast-import marks files (`:1 <hex>` per line), used by
//! `feature import-marks` / `feature export-marks` and by `gfx-remap` to
//! finalize the old→new commit map (plan §7.2, decision 3: this lives in the
//! core because marks files are protocol surface, not remap-specific).

use crate::error::Error;
use crate::event::{Mark, Oid};
use crate::limits::ObjectFormat;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarkFile {
    entries: BTreeMap<Mark, Oid>,
}

impl MarkFile {
    pub fn new() -> Self {
        MarkFile::default()
    }

    pub fn get(&self, mark: Mark) -> Option<&Oid> {
        self.entries.get(&mark)
    }

    pub fn insert(&mut self, mark: Mark, oid: Oid) {
        self.entries.insert(mark, oid);
    }

    pub fn iter(&self) -> impl Iterator<Item = (Mark, &Oid)> {
        self.entries.iter().map(|(k, v)| (*k, v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Parse the textual marks format. Blank lines are skipped; `#` comment
    /// lines are skipped; everything else must be `:<decimal> SP <hex>`.
    pub fn parse(bytes: &[u8]) -> Result<MarkFile, Error> {
        let mut mf = MarkFile::new();
        for line in bytes.split(|&b| b == b'\n') {
            let line = strip_cr(line);
            if line.is_empty() || line.first() == Some(&b'#') {
                continue;
            }
            let rest = line.strip_prefix(b":").ok_or_else(|| bad_mark(line))?;
            let sp = rest
                .iter()
                .position(|&b| b == b' ')
                .ok_or_else(|| bad_mark(line))?;
            let mark = parse_decimal(&rest[..sp]).ok_or_else(|| bad_mark(line))?;
            let hex = &rest[sp + 1..];
            let oid = Oid::from_hex(hex, guess_format(hex)).ok_or_else(|| Error::BadOid {
                token: str_lossy(hex),
            })?;
            mf.entries.insert(mark, oid);
        }
        Ok(mf)
    }

    /// Serialize in canonical marks format (`:N <lowercase hex>` lines).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (mark, oid) in self.iter() {
            out.push(b':');
            push_decimal(&mut out, mark);
            out.push(b' ');
            out.extend_from_slice(&oid.to_hex());
            out.push(b'\n');
        }
        out
    }
}

fn bad_mark(line: &[u8]) -> Error {
    Error::BadMark {
        token: str_lossy(line),
    }
}

fn guess_format(hex: &[u8]) -> ObjectFormat {
    if hex.len() >= 64 {
        ObjectFormat::Sha256
    } else {
        ObjectFormat::Sha1
    }
}

fn strip_cr(line: &[u8]) -> &[u8] {
    match line.strip_suffix(b"\r") {
        Some(s) => s,
        None => line,
    }
}

pub(crate) fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

pub(crate) fn push_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&tmp[i..]);
}

pub(crate) fn str_lossy(bytes: &[u8]) -> alloc::string::String {
    alloc::string::String::from_utf8_lossy(bytes).into_owned()
}
