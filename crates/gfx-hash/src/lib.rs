#![no_std]
#![forbid(unsafe_code)]
//! Hasher abstraction over git object ids. The core stays hash-agnostic
//! (plan §4.2): hosts inject an implementation, and bundled SHA-1/SHA-256
//! (RustCrypto) arrive via the `sha1`/`sha256` features.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Incremental object hasher. Implementations must produce git object ids
/// (`hash = H("<type> <len>\\0" + body)` is applied by the caller in
/// `digest_object`).
pub trait Hasher {
    /// Feed a chunk of bytes.
    fn update(&mut self, data: &[u8]);

    /// Finish and reset; returns the raw digest (20 or 32 bytes).
    fn finalize_reset(&mut self) -> Vec<u8>;

    /// Expected digest size.
    fn digest_len(&self) -> usize;

    /// Object format this hasher belongs to.
    fn object_format(&self) -> gfx_core::ObjectFormat;
}

/// Hash a git object: wraps the header around `body` and returns the [`Oid`].
pub fn digest_object<H: Hasher>(
    h: &mut H,
    kind: ObjectKind,
    body: &[u8],
) -> Result<gfx_core::Oid, gfx_core::Error> {
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(&itoa(body.len() as u64));
    h.update(b"\0");
    h.update(body);
    let raw = h.finalize_reset();
    let oid = match h.object_format() {
        gfx_core::ObjectFormat::Sha1 => {
            let arr: [u8; 20] = raw
                .as_slice()
                .try_into()
                .map_err(|_| gfx_core::Error::Internal("sha1 digest length mismatch"))?;
            gfx_core::Oid::Sha1(arr)
        }
        gfx_core::ObjectFormat::Sha256 => {
            let arr: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| gfx_core::Error::Internal("sha256 digest length mismatch"))?;
            gfx_core::Oid::Sha256(arr)
        }
    };
    Ok(oid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

impl ObjectKind {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            ObjectKind::Blob => b"blob",
            ObjectKind::Tree => b"tree",
            ObjectKind::Commit => b"commit",
            ObjectKind::Tag => b"tag",
        }
    }
}

fn itoa(mut n: u64) -> Vec<u8> {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf[i..].to_vec()
}

#[cfg(feature = "sha1")]
pub mod sha1_impl {
    use super::{Hasher, ObjectKind};
    use alloc::vec::Vec;

    #[derive(Default)]
    pub struct Sha1Hasher(sha1::Sha1);

    impl Hasher for Sha1Hasher {
        fn update(&mut self, data: &[u8]) {
            use sha1::Digest;
            self.0.update(data);
        }

        fn finalize_reset(&mut self) -> Vec<u8> {
            use sha1::Digest;
            self.0.finalize_reset().to_vec()
        }

        fn digest_len(&self) -> usize {
            20
        }

        fn object_format(&self) -> gfx_core::ObjectFormat {
            gfx_core::ObjectFormat::Sha1
        }
    }

    /// Convenience: hash a whole object at once.
    pub fn digest_object_sha1(kind: ObjectKind, body: &[u8]) -> gfx_core::Oid {
        let mut h = Sha1Hasher::default();
        super::digest_object(&mut h, kind, body).expect("sha1 digest")
    }
}

#[cfg(feature = "sha1")]
pub use sha1_impl::{digest_object_sha1, Sha1Hasher};

#[cfg(feature = "sha256")]
pub mod sha256_impl {
    use super::{Hasher, ObjectKind};
    use alloc::vec::Vec;

    #[derive(Default)]
    pub struct Sha256Hasher(sha2::Sha256);

    impl Hasher for Sha256Hasher {
        fn update(&mut self, data: &[u8]) {
            use sha2::Digest;
            self.0.update(data);
        }

        fn finalize_reset(&mut self) -> Vec<u8> {
            use sha2::Digest;
            self.0.finalize_reset().to_vec()
        }

        fn digest_len(&self) -> usize {
            32
        }

        fn object_format(&self) -> gfx_core::ObjectFormat {
            gfx_core::ObjectFormat::Sha256
        }
    }

    /// Convenience: hash a whole object at once.
    pub fn digest_object_sha256(kind: ObjectKind, body: &[u8]) -> gfx_core::Oid {
        let mut h = Sha256Hasher::default();
        super::digest_object(&mut h, kind, body).expect("sha256 digest")
    }
}

#[cfg(feature = "sha256")]
pub use sha256_impl::{digest_object_sha256, Sha256Hasher};

#[derive(Debug)]
pub enum HashError {
    DigestLength,
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::DigestLength => write!(f, "digest length mismatch"),
        }
    }
}

impl core::error::Error for HashError {}
