//! Minimal, deterministic ZIP container (plan-multistream-pack.md D4).
//!
//! Scope, deliberately narrow: the writer produces archives of *stored* or
//! *deflated* entries with fixed DOS-epoch timestamps, no extra fields, no
//! comments, and sizes deferred to data descriptors (so entries stream
//! straight from spool files without a pre-pass). The reader is equally
//! strict — single disk, no zip64, no encrypted entries, CRC and sizes
//! verified on extract — because the only archives this crate reads are its
//! own. The container stays standard: any `unzip` extracts the streams for
//! plain `git fast-import` (decision D1).
//!
//! zip64 is out of scope for v1: an entry, the archive, or the entry count
//! crossing a 32-bit / 65535 limit is a hard error, never silent truncation.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::PackError;

const LOCAL_SIG: u32 = 0x0403_4b50;
const DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// General-purpose flags: bit 3 = sizes in a data descriptor after the
/// data, bit 11 = entry name is UTF-8.
const FLAGS: u16 = 0x0008 | 0x0800;

/// Fixed timestamp: 1980-01-01 00:00:00, the DOS epoch — reproducible
/// archives embed no wall-clock (D4).
const DOS_TIME: u16 = 0;
const DOS_DATE: u16 = 1 << 5 | 1;

const COPY_BUF: usize = 64 * 1024;

/// Compression for one entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Method {
    Store,
    #[default]
    Deflate,
}

impl Method {
    fn code(self) -> u16 {
        match self {
            Method::Store => METHOD_STORE,
            Method::Deflate => METHOD_DEFLATE,
        }
    }
}

fn zip_err(msg: impl Into<String>) -> PackError {
    PackError::Zip(msg.into())
}

/// Entry-name validation, applied on write and on read: relative `/`-joined
/// paths only — no absolute paths, no `.`/`..` components, no backslashes,
/// colons, or NULs. This is the zip-slip guard for attacker-controlled
/// archives as much as a writer discipline.
pub fn validate_entry_name(name: &str) -> Result<(), PackError> {
    if name.is_empty() || name.len() > u16::MAX as usize {
        return Err(zip_err(format!("bad entry name length ({} bytes)", name.len())));
    }
    if name.starts_with('/') || name.contains(['\\', ':', '\0']) {
        return Err(zip_err(format!("unsafe entry name {name:?}")));
    }
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(zip_err(format!("unsafe entry name {name:?}")));
        }
    }
    Ok(())
}

fn u32_bound(what: &str, v: u64) -> Result<u32, PackError> {
    u32::try_from(v).map_err(|_| zip_err(format!("{what} exceeds zip32 limit; zip64 unsupported")))
}

struct Central {
    name: String,
    method: u16,
    crc32: u32,
    csize: u64,
    usize_: u64,
    local_offset: u64,
}

/// Streaming archive writer over any `Write`. Entries are appended in call
/// order; `finish` writes the central directory.
pub struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    entries: Vec<Central>,
    finished: bool,
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        ZipWriter {
            out,
            offset: 0,
            entries: Vec::new(),
            finished: false,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        self.out.write_all(bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    /// Append one entry, streaming `data` through the compressor. CRC-32
    /// and sizes are computed here and deferred to a data descriptor, so
    /// `data` is consumed exactly once.
    pub fn write_entry(&mut self, name: &str, method: Method, mut data: impl Read) -> Result<(), PackError> {
        if self.finished {
            return Err(zip_err("entry written after finish"));
        }
        validate_entry_name(name)?;
        if self.entries.len() >= u16::MAX as usize {
            return Err(zip_err("entry count exceeds zip32 limit; zip64 unsupported"));
        }
        let local_offset = u32_bound("archive size", self.offset)?;

        let mut header = Vec::with_capacity(30 + name.len());
        header.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        header.extend_from_slice(&20u16.to_le_bytes()); // version needed
        header.extend_from_slice(&FLAGS.to_le_bytes());
        header.extend_from_slice(&method.code().to_le_bytes());
        header.extend_from_slice(&DOS_TIME.to_le_bytes());
        header.extend_from_slice(&DOS_DATE.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // crc: deferred
        header.extend_from_slice(&0u32.to_le_bytes()); // csize: deferred
        header.extend_from_slice(&0u32.to_le_bytes()); // usize: deferred
        header.extend_from_slice(&(name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes()); // extra len
        header.extend_from_slice(name.as_bytes());
        self.put(&header)?;

        let mut crc = crc32fast::Hasher::new();
        let mut usize_: u64 = 0;
        let mut buf = [0u8; COPY_BUF];
        let csize = {
            let mut counting = CountingWriter { w: &mut self.out, n: 0 };
            match method {
                Method::Store => loop {
                    let n = data.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    crc.update(&buf[..n]);
                    counting.write_all(&buf[..n])?;
                    usize_ += n as u64;
                },
                Method::Deflate => {
                    let mut enc = flate2::write::DeflateEncoder::new(
                        &mut counting,
                        flate2::Compression::new(6),
                    );
                    loop {
                        let n = data.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        crc.update(&buf[..n]);
                        enc.write_all(&buf[..n])?;
                        usize_ += n as u64;
                    }
                    enc.finish()?;
                }
            }
            counting.n
        };
        self.offset += csize;

        let crc32 = crc.finalize();
        let mut desc = Vec::with_capacity(16);
        desc.extend_from_slice(&DESCRIPTOR_SIG.to_le_bytes());
        desc.extend_from_slice(&crc32.to_le_bytes());
        desc.extend_from_slice(&u32_bound("entry size", csize)?.to_le_bytes());
        desc.extend_from_slice(&u32_bound("entry size", usize_)?.to_le_bytes());
        self.put(&desc)?;

        self.entries.push(Central {
            name: name.to_string(),
            method: method.code(),
            crc32,
            csize,
            usize_,
            local_offset: local_offset as u64,
        });
        Ok(())
    }

    /// Convenience buffered form of [`Self::write_entry`].
    pub fn write_entry_bytes(&mut self, name: &str, method: Method, data: &[u8]) -> Result<(), PackError> {
        self.write_entry(name, method, data)
    }

    /// Write the central directory and end-of-central-directory record.
    pub fn finish(mut self) -> Result<W, PackError> {
        let cd_offset = u32_bound("archive size", self.offset)?;
        let mut cd = Vec::new();
        for e in &self.entries {
            cd.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
            cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
            cd.extend_from_slice(&FLAGS.to_le_bytes());
            cd.extend_from_slice(&e.method.to_le_bytes());
            cd.extend_from_slice(&DOS_TIME.to_le_bytes());
            cd.extend_from_slice(&DOS_DATE.to_le_bytes());
            cd.extend_from_slice(&e.crc32.to_le_bytes());
            cd.extend_from_slice(&u32_bound("entry size", e.csize)?.to_le_bytes());
            cd.extend_from_slice(&u32_bound("entry size", e.usize_)?.to_le_bytes());
            cd.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // extra
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cd.extend_from_slice(&0x81A4_0000u32.to_le_bytes()); // regular file, 0644
            cd.extend_from_slice(&u32_bound("entry offset", e.local_offset)?.to_le_bytes());
            cd.extend_from_slice(e.name.as_bytes());
        }
        let cd_size = cd.len() as u64;
        self.put(&cd)?;
        let count = u16::try_from(self.entries.len())
            .map_err(|_| zip_err("entry count exceeds zip32 limit; zip64 unsupported"))?;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&u32_bound("central directory size", cd_size)?.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment
        self.put(&eocd)?;
        self.finished = true;
        self.out.flush()?;
        Ok(self.out)
    }
}

struct CountingWriter<'a, W: Write> {
    w: &'a mut W,
    n: u64,
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.w.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

/// One central-directory record, as parsed on open.
#[derive(Clone, Debug)]
pub struct EntryInfo {
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    local_offset: u64,
}

/// Strict reader over `Read + Seek`. Parses the central directory on open;
/// [`Self::extract_to`] verifies CRC-32 and the uncompressed size.
pub struct ZipReader<R: Read + Seek> {
    inner: R,
    entries: Vec<EntryInfo>,
}

impl<R: Read + Seek> ZipReader<R> {
    pub fn open(mut inner: R) -> Result<Self, PackError> {
        let len = inner.seek(SeekFrom::End(0))?;
        if len < 22 {
            return Err(zip_err("file too small for a zip archive"));
        }
        let tail_len = len.min(22 + u16::MAX as u64) as usize;
        inner.seek(SeekFrom::End(-(tail_len as i64)))?;
        let mut tail = vec![0u8; tail_len];
        inner.read_exact(&mut tail)?;

        // Find the EOCD: last occurrence of its signature, validated by the
        // comment length reaching exactly the end of file.
        let mut eocd = None;
        for i in (0..=tail.len() - 22).rev() {
            if u32::from_le_bytes(tail[i..i + 4].try_into().unwrap()) != EOCD_SIG {
                continue;
            }
            let comment = u16::from_le_bytes(tail[i + 20..i + 22].try_into().unwrap()) as usize;
            if i + 22 + comment == tail.len() {
                eocd = Some(i);
                break;
            }
        }
        let eocd = eocd.ok_or_else(|| zip_err("no end-of-central-directory record"))?;
        let rec = &tail[eocd..eocd + 22];
        let disk = u16::from_le_bytes(rec[4..6].try_into().unwrap());
        let cd_disk = u16::from_le_bytes(rec[6..8].try_into().unwrap());
        let disk_entries = u16::from_le_bytes(rec[8..10].try_into().unwrap());
        let total_entries = u16::from_le_bytes(rec[10..12].try_into().unwrap());
        let cd_size = u32::from_le_bytes(rec[12..16].try_into().unwrap()) as u64;
        let cd_offset = u32::from_le_bytes(rec[16..20].try_into().unwrap()) as u64;
        if disk != 0 || cd_disk != 0 || disk_entries != total_entries {
            return Err(zip_err("multi-disk archives unsupported"));
        }
        if cd_offset + cd_size > len {
            return Err(zip_err("central directory out of bounds"));
        }

        inner.seek(SeekFrom::Start(cd_offset))?;
        let mut cd = vec![0u8; cd_size as usize];
        inner.read_exact(&mut cd)?;

        let mut entries = Vec::with_capacity(total_entries as usize);
        let mut p = 0usize;
        for _ in 0..total_entries {
            if p + 46 > cd.len() || u32::from_le_bytes(cd[p..p + 4].try_into().unwrap()) != CENTRAL_SIG {
                return Err(zip_err("truncated central directory"));
            }
            let flags = u16::from_le_bytes(cd[p + 8..p + 10].try_into().unwrap());
            let method = u16::from_le_bytes(cd[p + 10..p + 12].try_into().unwrap());
            let crc32 = u32::from_le_bytes(cd[p + 16..p + 20].try_into().unwrap());
            let csize = u32::from_le_bytes(cd[p + 20..p + 24].try_into().unwrap()) as u64;
            let usize_ = u32::from_le_bytes(cd[p + 24..p + 28].try_into().unwrap()) as u64;
            let name_len = u16::from_le_bytes(cd[p + 28..p + 30].try_into().unwrap()) as usize;
            let extra_len = u16::from_le_bytes(cd[p + 30..p + 32].try_into().unwrap()) as usize;
            let comment_len = u16::from_le_bytes(cd[p + 32..p + 34].try_into().unwrap()) as usize;
            let disk_start = u16::from_le_bytes(cd[p + 34..p + 36].try_into().unwrap());
            let local_offset = u32::from_le_bytes(cd[p + 42..p + 46].try_into().unwrap()) as u64;
            let name_end = p + 46 + name_len;
            if name_end > cd.len() {
                return Err(zip_err("truncated central directory entry name"));
            }
            let name = String::from_utf8(cd[p + 46..name_end].to_vec())
                .map_err(|_| zip_err("entry name is not UTF-8"))?;
            validate_entry_name(&name)?;
            if flags & 1 != 0 {
                return Err(zip_err(format!(
                    "entry {name:?} is encrypted; zip-level encryption unsupported (use whole-archive age)"
                )));
            }
            if method != METHOD_STORE && method != METHOD_DEFLATE {
                return Err(zip_err(format!("entry {name:?} uses unsupported method {method}")));
            }
            if disk_start != 0 {
                return Err(zip_err("multi-disk archives unsupported"));
            }
            if entries.iter().any(|e: &EntryInfo| e.name == name) {
                return Err(zip_err(format!("duplicate entry {name:?}")));
            }
            entries.push(EntryInfo {
                name,
                method,
                crc32,
                compressed_size: csize,
                uncompressed_size: usize_,
                local_offset,
            });
            p = name_end + extra_len + comment_len;
        }
        Ok(ZipReader { inner, entries })
    }

    /// Central-directory entries, in archive order.
    pub fn entries(&self) -> &[EntryInfo] {
        &self.entries
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    /// Extract `name` into `out`, verifying CRC-32 and uncompressed size.
    /// Returns the number of bytes written.
    pub fn extract_to(&mut self, name: &str, mut out: impl Write) -> Result<u64, PackError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| zip_err(format!("no such entry {name:?}")))?
            .clone();

        // Re-read the local header: name must match the central record
        // (guards against offset confusion in a hostile file).
        self.inner.seek(SeekFrom::Start(entry.local_offset))?;
        let mut lh = [0u8; 30];
        self.inner.read_exact(&mut lh)?;
        if u32::from_le_bytes(lh[0..4].try_into().unwrap()) != LOCAL_SIG {
            return Err(zip_err(format!("entry {name:?}: bad local header")));
        }
        let name_len = u16::from_le_bytes(lh[26..28].try_into().unwrap()) as u64;
        let extra_len = u16::from_le_bytes(lh[28..30].try_into().unwrap()) as u64;
        let mut lname = vec![0u8; name_len as usize];
        self.inner.read_exact(&mut lname)?;
        if lname != entry.name.as_bytes() {
            return Err(zip_err(format!(
                "entry {name:?}: local header name does not match central directory"
            )));
        }
        let data_start = entry.local_offset + 30 + name_len + extra_len;
        if data_start + entry.compressed_size > self.inner.seek(SeekFrom::End(0))? {
            return Err(zip_err(format!("entry {name:?}: data out of bounds")));
        }
        self.inner.seek(SeekFrom::Start(data_start))?;
        let mut raw = (&mut self.inner).take(entry.compressed_size);
        let mut decoded: Box<dyn Read> = match entry.method {
            METHOD_STORE => Box::new(&mut raw),
            METHOD_DEFLATE => Box::new(flate2::read::DeflateDecoder::new(&mut raw)),
            other => return Err(zip_err(format!("entry {name:?}: unsupported method {other}"))),
        };
        // Cap decompression at the recorded size + 1: a stream yielding
        // more than the central directory claims is corrupt or hostile.
        let mut capped = (&mut *decoded).take(entry.uncompressed_size + 1);
        let mut crc = crc32fast::Hasher::new();
        let mut written = 0u64;
        let mut buf = [0u8; COPY_BUF];
        loop {
            let n = capped.read(&mut buf)?;
            if n == 0 {
                break;
            }
            crc.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            written += n as u64;
            if written > entry.uncompressed_size {
                return Err(zip_err(format!("entry {name:?}: decompressed beyond recorded size")));
            }
        }
        if written != entry.uncompressed_size || crc.finalize() != entry.crc32 {
            return Err(zip_err(format!("entry {name:?}: integrity check failed")));
        }
        Ok(written)
    }

    /// Buffered form of [`Self::extract_to`].
    pub fn extract(&mut self, name: &str) -> Result<Vec<u8>, PackError> {
        let mut out = Vec::new();
        self.extract_to(name, &mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Deterministic pseudo-random bytes (incompressible-ish) without a
    /// rand dependency: xorshift64*.
    fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
            })
            .collect()
    }

    fn build(entries: &[(&str, Method, &[u8])]) -> Vec<u8> {
        let mut w = ZipWriter::new(Vec::new());
        for (name, method, data) in entries {
            w.write_entry_bytes(name, *method, data).unwrap();
        }
        w.finish().unwrap()
    }

    #[test]
    fn round_trip_byte_equal() {
        let big = prng_bytes(0x1234, 300_000); // forces deflate + descriptor
        let zip = build(&[
            ("manifest.toml", Method::Deflate, b"format = 1\n"),
            ("streams/alpha.fi", Method::Deflate, &big),
            ("streams/empty.fi", Method::Store, b""),
        ]);
        let mut r = ZipReader::open(Cursor::new(zip)).unwrap();
        assert_eq!(r.entries().len(), 3);
        assert_eq!(r.extract("manifest.toml").unwrap(), b"format = 1\n");
        assert_eq!(r.extract("streams/alpha.fi").unwrap(), big);
        assert_eq!(r.extract("streams/empty.fi").unwrap(), b"");
        assert!(r.extract("nope").is_err());
    }

    #[test]
    fn writes_are_deterministic() {
        let data = prng_bytes(7, 50_000);
        let a = build(&[("s/a.fi", Method::Deflate, &data), ("s/b.fi", Method::Store, &data)]);
        let b = build(&[("s/a.fi", Method::Deflate, &data), ("s/b.fi", Method::Store, &data)]);
        assert_eq!(a, b, "same inputs ⇒ identical archive bytes (D4)");
        // DOS-epoch timestamp bytes (time = 0, date = 0x21) in the first header.
        assert_eq!(&a[10..14], &[0, 0, 0x21, 0]);
    }

    #[test]
    fn deflate_actually_deflates() {
        let repetitive = vec![b'x'; 200_000];
        let zip = build(&[("s/x.fi", Method::Deflate, &repetitive)]);
        assert!(zip.len() < repetitive.len() / 10);
        let mut r = ZipReader::open(Cursor::new(zip)).unwrap();
        assert_eq!(r.extract("s/x.fi").unwrap(), repetitive);
    }

    #[test]
    fn rejects_corrupt_data() {
        let data = prng_bytes(9, 10_000);
        let mut zip = build(&[("s/a.fi", Method::Deflate, &data)]);
        // Flip a byte inside the entry data (after the 30-byte local header).
        zip[60] ^= 0xFF;
        let mut r = ZipReader::open(Cursor::new(zip)).unwrap();
        assert!(r.extract("s/a.fi").is_err(), "CRC/size must catch corruption");
    }

    #[test]
    fn rejects_bad_names_on_write_and_read() {
        for bad in ["", "/abs", "a/../b", "a//b", "./x", "a\\b", "c:/x"] {
            let mut w = ZipWriter::new(Vec::new());
            assert!(w.write_entry_bytes(bad, Method::Store, b"x").is_err(), "{bad:?}");
        }
        // Hand-craft a stored entry with a `..` name: writer refuses, so
        // patch the bytes of a valid archive instead.
        let zip = build(&[("aa.fi", Method::Store, b"payload")]);
        let mut patched = zip.clone();
        // "aa.fi" → "../f" keeps length: replace name bytes at local header.
        patched[30..35].copy_from_slice(b"../fi");
        // Also patch the central record (at the end of the archive).
        let pos = patched.windows(5).rposition(|w| w == b"aa.fi").unwrap();
        patched[pos..pos + 5].copy_from_slice(b"../fi");
        assert!(ZipReader::open(Cursor::new(patched)).is_err(), "zip-slip names rejected on read");
    }

    #[test]
    fn rejects_truncated_and_multi_disk() {
        let zip = build(&[("a", Method::Store, b"xy")]);
        assert!(ZipReader::open(Cursor::new(&zip)).is_ok());
        let short = &zip[..zip.len() - 10];
        assert!(ZipReader::open(Cursor::new(short)).is_err());
        // Multi-disk: set disk numbers in the EOCD (last 22 bytes).
        let mut md = zip.clone();
        let n = md.len();
        md[n - 18] = 1;
        assert!(ZipReader::open(Cursor::new(md)).is_err());
    }

    #[test]
    fn streaming_large_entry() {
        let big = prng_bytes(0xBEEF, 3_000_000);
        let mut w = ZipWriter::new(Vec::new());
        w.write_entry("s/big.fi", Method::Deflate, Cursor::new(&big)).unwrap();
        let zip = w.finish().unwrap();
        let mut r = ZipReader::open(Cursor::new(zip)).unwrap();
        let mut out = Vec::new();
        let n = r.extract_to("s/big.fi", &mut out).unwrap();
        assert_eq!(n as usize, big.len());
        assert_eq!(out, big);
    }
}
