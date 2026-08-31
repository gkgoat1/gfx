//! Handcrafted raw streams (fast-export shaped) parsed into expected events,
//! plus strict-mode, limits, comments, delim data, sha256 and marks-file
//! behavior.

use gfx_core::prelude::*;

fn parse_all(bytes: &[u8]) -> Result<Vec<Event>, Error> {
    parse_with(bytes, ParseOptions::default())
}

fn parse_with(bytes: &[u8], opts: ParseOptions) -> Result<Vec<Event>, Error> {
    let mut p = Parser::new(opts);
    p.feed(bytes);
    let mut out = Vec::new();
    while let Some(ev) = p.next_event()? {
        out.push(ev);
    }
    p.finish(&mut out)?;
    Ok(out)
}

fn fast_export_fixture() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(b"blob\nmark :1\ndata 6\nhello \n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :2\n");
    s.extend_from_slice(b"original-oid 0123456789abcdef0123456789abcdef01234567\n");
    s.extend_from_slice(b"author A U Thor <author@example.com> 1112911993 -0700\n");
    s.extend_from_slice(b"committer C O Mitter <committer@example.com> 1112912053 +0000\n");
    s.extend_from_slice(b"data 8\ninitial\n");
    s.extend_from_slice(b"M 100644 :1 file.txt\n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :3\n");
    s.extend_from_slice(b"committer C O Mitter <committer@example.com> 1112912053 +0000\n");
    s.extend_from_slice(b"data 7\nsecond\n");
    s.extend_from_slice(b"from :2\n");
    s.extend_from_slice(b"M 100644 inline data.bin\n");
    s.extend_from_slice(b"data 4\n\x00\x01\x02\x03");
    s.extend_from_slice(b"reset refs/tags/v1\nfrom :3\n");
    s
}

#[test]
fn parses_fast_export_fixture() {
    let events = parse_all(&fast_export_fixture()).expect("parse");
    assert_eq!(
        events.len(),
        4,
        "blob, commit, commit(with inline op), reset"
    );
    match &events[0] {
        Event::Blob {
            mark: Some(1),
            original_oid: _,
            data,
        } => assert_eq!(data.as_slice(), b"hello "),
        other => panic!("expected blob, got {other:?}"),
    }
    match &events[3] {
        Event::Reset { ref_name, from } => {
            assert_eq!(&ref_name[..], b"refs/tags/v1");
            assert_eq!(*from, Some(Committish::Mark(3)));
        }
        other => panic!("expected reset, got {other:?}"),
    }
}

#[test]
fn blob_data_exact() {
    let events = parse_all(b"blob\nmark :1\ndata 6\nhello \n").unwrap();
    match &events[0] {
        Event::Blob {
            mark: Some(1),
            original_oid: _,
            data,
        } => assert_eq!(data.as_slice(), b"hello "),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn commit_headers_and_inline_op() {
    let mut s = Vec::new();
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :2\n");
    s.extend_from_slice(b"original-oid 0123456789abcdef0123456789abcdef01234567\n");
    s.extend_from_slice(b"author A U Thor <author@example.com> 1112911993 -0700\n");
    s.extend_from_slice(b"data 8\ninitial\n");
    s.extend_from_slice(b"from 0123456789abcdef0123456789abcdef01234567\n");
    s.extend_from_slice(b"merge ffffffffffffffffffffffffffffffffffffffff\n");
    s.extend_from_slice(b"M 100644 inline data.bin\n");
    s.extend_from_slice(b"data 4\n\x00\x01\x02\x03");
    s.extend_from_slice(b"D gone.txt\n");

    let events = parse_all(&s).unwrap();
    // The inline op's data payload arrives after the M line, so the commit
    // completes at EOF (finish flushes it).
    assert_eq!(events.len(), 1);
    let Event::Commit(c) = &events[0] else {
        panic!("expected commit")
    };
    assert_eq!(c.mark, Some(2));
    assert_eq!(
        c.original_oid.unwrap().to_hex(),
        &b"0123456789abcdef0123456789abcdef01234567"[..]
    );
    let author = c.author.as_ref().unwrap();
    assert_eq!(&author.name[..], b"A U Thor");
    assert_eq!(&author.email[..], b"author@example.com");
    assert_eq!(author.time.epoch, 1_112_911_993);
    assert_eq!(author.time.tz_offset_min, -7 * 60);
    assert_eq!(c.message.as_slice(), b"initial\n");
    assert_eq!(
        c.from,
        Some(Committish::Oid(
            Oid::from_hex(
                b"0123456789abcdef0123456789abcdef01234567",
                ObjectFormat::Sha1
            )
            .unwrap()
        ))
    );
    assert_eq!(c.merges.len(), 1);
    assert_eq!(c.ops.len(), 2);
    match &c.ops[0] {
        FileOp::Modify {
            mode: Mode::Regular,
            path,
            source: FileSource::Inline(d),
        } => {
            assert_eq!(&path[..], b"data.bin");
            assert_eq!(d.as_slice(), b"\x00\x01\x02\x03");
        }
        other => panic!("unexpected op {other:?}"),
    }
}

#[test]
fn reset_without_from_deletes_ref() {
    let events = parse_all(b"reset refs/heads/gone\ncommit refs/heads/x\ndata 0\n").unwrap();
    assert_eq!(
        events[0],
        Event::Reset {
            ref_name: BString::from(b"refs/heads/gone".to_vec()),
            from: None,
        }
    );
    assert!(matches!(events[1], Event::Commit(_)));
}

#[test]
fn reset_at_eof_flushes() {
    let events = parse_all(b"reset refs/heads/x\n").unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::Reset { from: None, .. }));
}

#[test]
fn data_delim_form() {
    let mut s = Vec::new();
    s.extend_from_slice(b"blob\nmark :1\ndata delim \"EOF\"\nline1\nlin\"2\nEOF\n");
    let events = parse_all(&s).unwrap();
    match &events[0] {
        Event::Blob { data, .. } => assert_eq!(data.as_slice(), b"line1\nlin\"2\n"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn data_literal_form() {
    let events = parse_all(b"blob\ndata literal 3\nabc").unwrap();
    match &events[0] {
        Event::Blob { data, .. } => assert_eq!(data.as_slice(), b"abc"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn comments_are_lines_and_skipped_by_default() {
    // `data 0` payload is empty; the trailing `#` line is a command-level
    // comment, not payload.
    let s = b"# a comment\nblob\ndata 0\n# not a comment (this line is after the blob)\n";
    let events = parse_all(s).unwrap();
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::Blob { data, .. } => assert!(data.as_slice().is_empty()),
        other => panic!("unexpected {other:?}"),
    }
    let opts = ParseOptions {
        keep_comments: true,
        ..ParseOptions::default()
    };
    let events = parse_with(s, opts).unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0],
        Event::Comment {
            text: BString::from(b" a comment".to_vec())
        }
    );
    assert!(matches!(events[1], Event::Blob { .. }));
    assert_eq!(
        events[2],
        Event::Comment {
            text: BString::from(b" not a comment (this line is after the blob)".to_vec())
        }
    );
}

#[test]
fn quoted_paths_roundtrip_through_parse() {
    let events =
        parse_all(b"commit refs/heads/x\ndata 0\nD \"we\\\\ird\\tname\"\nM 100755 :1 \"sp ace\"\n")
            .unwrap();
    let Event::Commit(c) = &events[0] else {
        panic!()
    };
    match &c.ops[0] {
        FileOp::Delete { path } => assert_eq!(&path[..], b"we\\ird\tname"),
        other => panic!("unexpected {other:?}"),
    }
    match &c.ops[1] {
        FileOp::Modify { path, .. } => assert_eq!(&path[..], b"sp ace"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn cr_lf_lines_are_tolerated_in_lenient_mode() {
    let events = parse_all(b"blob\r\ndata 3\r\nabc").unwrap();
    match &events[0] {
        Event::Blob { data, .. } => assert_eq!(data.as_slice(), b"abc"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn sha256_stream() {
    let mut s = Vec::new();
    s.extend_from_slice(b"feature object-format=sha256\n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :1\n");
    s.extend_from_slice(
        b"original-oid 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n",
    );
    s.extend_from_slice(b"data 0\n");
    let events = parse_all(&s).unwrap();
    assert!(matches!(events[0], Event::Feature { .. }));
    let Event::Commit(c) = &events[1] else {
        panic!()
    };
    assert_eq!(c.original_oid.as_ref().unwrap().len(), 32);
}

#[test]
fn object_format_mismatch_is_rejected() {
    let opts = ParseOptions {
        object_format: gfx_core::ObjectFormatMode::Sha1,
        ..ParseOptions::default()
    };
    let mut s = Vec::new();
    s.extend_from_slice(b"feature object-format=sha256\n");
    let err = parse_with(&s, opts).unwrap_err();
    assert!(matches!(err, Error::ObjectFormatMismatch { .. }));
}

#[test]
fn strict_mode_rejects_unknown_feature() {
    let err = parse_with(b"feature not-a-real-feature\n", ParseOptions::strict()).unwrap_err();
    assert!(matches!(err, Error::UnsupportedFeature { .. }));
    // lenient passes it through
    let events = parse_all(b"feature not-a-real-feature\n").unwrap();
    assert!(matches!(events[0], Event::Feature { .. }));
}

#[test]
fn strict_mode_rejects_empty_line_and_bad_order() {
    let err = parse_with(b"\n", ParseOptions::strict()).unwrap_err();
    assert!(matches!(err, Error::UnexpectedToken { .. }));

    let mut s = Vec::new();
    s.extend_from_slice(b"commit refs/heads/x\n");
    s.extend_from_slice(b"committer C <c@e> 1 +0000\n");
    s.extend_from_slice(b"author A <a@e> 1 +0000\n");
    s.extend_from_slice(b"data 0\n");
    let err = parse_with(&s, ParseOptions::strict()).unwrap_err();
    assert!(matches!(
        err,
        Error::UnexpectedToken {
            context: "commit headers",
            ..
        }
    ));
}

#[test]
fn limits_reject_oversized_data() {
    let opts = ParseOptions {
        limits: Limits {
            max_data: 4,
            ..Limits::default()
        },
        ..ParseOptions::default()
    };
    let mut p = Parser::new(opts);
    p.feed(b"blob\ndata 100\n");
    let err = p.next_event().unwrap_err();
    assert!(matches!(err, Error::DataTooLarge { size: 100, max: 4 }));
}

#[test]
fn truncated_stream_errors() {
    let mut p = Parser::new(ParseOptions::default());
    p.feed(b"blob\nmark :1\n");
    while p.next_event().unwrap().is_some() {}
    let mut out = Vec::new();
    let err = p.finish(&mut out).unwrap_err();
    assert!(matches!(err, Error::TruncatedStream { context: "blob" }));
}

#[test]
fn unknown_command_errors() {
    let err = parse_all(b"frobnicate\n").unwrap_err();
    assert!(matches!(err, Error::UnknownCommand { .. }));
}

#[test]
fn import_side_requests_parse() {
    let events = parse_all(
        b"get-mark :3\ncat-blob :1\ncat-blob 0123456789abcdef0123456789abcdef01234567\nls\nls :3 file.txt\nls \"a b\"\n",
    )
    .unwrap();
    assert_eq!(events[0], Event::GetMark { mark: 3 });
    assert_eq!(
        events[1],
        Event::CatBlob {
            dataref: DataRef::Mark(1)
        }
    );
    assert_eq!(
        events[2],
        Event::CatBlob {
            dataref: DataRef::Oid(
                Oid::from_hex(
                    b"0123456789abcdef0123456789abcdef01234567",
                    ObjectFormat::Sha1
                )
                .unwrap()
            )
        }
    );
    assert_eq!(
        events[3],
        Event::Ls {
            dataref: None,
            path: None
        }
    );
    assert_eq!(
        events[4],
        Event::Ls {
            dataref: Some(DataRef::Mark(3)),
            path: Some(BString::from(b"file.txt".to_vec())),
        }
    );
    assert_eq!(
        events[5],
        Event::Ls {
            dataref: None,
            path: Some(BString::from(b"a b".to_vec()))
        }
    );
}

#[test]
fn alias_command() {
    let events =
        parse_all(b"alias\nmark :5\ndata 40\n0123456789abcdef0123456789abcdef01234567").unwrap();
    assert_eq!(
        events[0],
        Event::Alias {
            mark: 5,
            target: Committish::Oid(
                Oid::from_hex(
                    b"0123456789abcdef0123456789abcdef01234567",
                    ObjectFormat::Sha1
                )
                .unwrap()
            )
        }
    );
}

#[test]
fn two_path_ops_with_quoting() {
    let events =
        parse_all(b"commit refs/heads/x\ndata 0\nC \"a b.txt\" c.txt\nR d.txt \"e f.txt\"\n")
            .unwrap();
    let Event::Commit(c) = &events[0] else {
        panic!()
    };
    match (&c.ops[0], &c.ops[1]) {
        (FileOp::Copy { from, to }, FileOp::Rename { from: rf, to: rt }) => {
            assert_eq!(&from[..], b"a b.txt");
            assert_eq!(&to[..], b"c.txt");
            assert_eq!(&rf[..], b"d.txt");
            assert_eq!(&rt[..], b"e f.txt");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn markfile_roundtrip() {
    let mut mf = MarkFile::new();
    mf.insert(
        1,
        Oid::from_hex(
            b"0123456789abcdef0123456789abcdef01234567",
            ObjectFormat::Sha1,
        )
        .unwrap(),
    );
    let bytes = mf.to_bytes();
    assert_eq!(&bytes[..], b":1 0123456789abcdef0123456789abcdef01234567\n");
    let back = MarkFile::parse(&bytes).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(
        back.get(1).unwrap().to_hex(),
        &b"0123456789abcdef0123456789abcdef01234567"[..]
    );
    // comments and blank lines tolerated
    let with_noise = b"# comment\n\n:2 ffffffffffffffffffffffffffffffffffffffff\n";
    let back = MarkFile::parse(with_noise).unwrap();
    assert_eq!(back.len(), 1);
    let bad = MarkFile::parse(b"1 nope\n");
    assert!(bad.is_err());
}
