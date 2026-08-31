//! SHA-1/SHA-256 object hashing against git's canonical test vectors
//! (SHA-256 vectors verified against local `git hash-object`).

#[cfg(feature = "sha1")]
mod sha1_tests {
    use gfx_hash::{digest_object, digest_object_sha1, ObjectKind};

    #[test]
    fn git_sha1_blob_vectors() {
        // "test content\n" (blob)
        let oid = digest_object_sha1(ObjectKind::Blob, b"test content\n");
        assert_eq!(
            &oid.to_hex()[..],
            &b"d670460b4b4aece5915caf5c68d12f560a9fe3e4"[..]
        );
        // "hello world\n" blob
        let oid = digest_object_sha1(ObjectKind::Blob, b"hello world\n");
        assert_eq!(
            &oid.to_hex()[..],
            &b"3b18e512dba79e4c8300dd08aeb37f8e728b8dad"[..]
        );
        // empty blob
        let oid = digest_object_sha1(ObjectKind::Blob, b"");
        assert_eq!(
            &oid.to_hex()[..],
            &b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"[..]
        );
    }

    #[test]
    fn incremental_matches_oneshot() {
        use gfx_hash::Hasher;
        let mut h = gfx_hash::Sha1Hasher::default();
        h.update(b"ignored-then-reset");
        let _ = h.finalize_reset();
        let oid = digest_object(&mut h, ObjectKind::Blob, b"test content\n").unwrap();
        assert_eq!(
            &oid.to_hex()[..],
            &b"d670460b4b4aece5915caf5c68d12f560a9fe3e4"[..]
        );
    }
}

#[cfg(feature = "sha256")]
mod sha256_tests {
    use gfx_hash::{digest_object_sha256, ObjectKind};

    #[test]
    fn git_sha256_blob_vectors() {
        // From `git init --object-format=sha256` + `git hash-object --stdin`:
        let oid = digest_object_sha256(ObjectKind::Blob, b"test content\n");
        assert_eq!(
            &oid.to_hex()[..],
            &b"13b7e821533d3fe3728a3c4560606a65aab99f4390b9df0714f9075c0ef4c2d6"[..]
        );
        let oid = digest_object_sha256(ObjectKind::Blob, b"hello world\n");
        assert_eq!(
            &oid.to_hex()[..],
            &b"0bd69098bd9b9cc5934a610ab65da429b525361147faa7b5b922919e9a23143d"[..]
        );
        let oid = digest_object_sha256(ObjectKind::Blob, b"");
        assert_eq!(
            &oid.to_hex()[..],
            &b"473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"[..]
        );
    }
}
