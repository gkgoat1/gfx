//! Property P1: `parse(write(e)) == e` for a rich, representative event set
//! (plan §10.1).

use gfx_core::prelude::*;

/// Build the canonical event set: everything the protocol core models.
fn sample_events() -> Vec<Event> {
    let oid1 = Oid::from_hex(
        b"0123456789abcdef0123456789abcdef01234567",
        ObjectFormat::Sha1,
    )
    .unwrap();
    let oid2 = Oid::from_hex(
        b"ffffffffffffffffffffffffffffffffffffffff",
        ObjectFormat::Sha1,
    )
    .unwrap();
    vec![
        Event::Feature {
            name: BString::from(b"object-format".to_vec()),
            arg: Some(BString::from(b"sha1".to_vec())),
        },
        Event::Feature {
            name: BString::from(b"export-marks".to_vec()),
            arg: Some(BString::from(b"marks.txt".to_vec())),
        },
        Event::Option {
            arg: BString::from(b"quiet".to_vec()),
        },
        Event::Blob {
            mark: Some(1),
            original_oid: None,
            data: Data(b"hello\n".to_vec()),
        },
        Event::Blob {
            mark: None,
            original_oid: None,
            data: Data(vec![0u8, 159, 146, 150, b'\n', b'\0']),
        },
        Event::Commit(Commit {
            ref_name: BString::from(b"refs/heads/main".to_vec()),
            mark: Some(2),
            original_oid: Some(oid1),
            author: Some(Ident {
                name: BString::from(b"A U Thor".to_vec()),
                email: BString::from(b"author@example.com".to_vec()),
                time: Timestamp {
                    raw: BString::from(b"1112911993 -0700".to_vec()),
                    epoch: 1_112_911_993,
                    tz_offset_min: -7 * 60,
                },
            }),
            committer: Some(Ident {
                name: BString::from(b"C O Mitter".to_vec()),
                email: BString::from(b"committer@example.com".to_vec()),
                time: Timestamp {
                    raw: BString::from(b"1112912053 +0000".to_vec()),
                    epoch: 1_112_912_053,
                    tz_offset_min: 0,
                },
            }),
            encoding: Some(BString::from(b"ISO-8859-1".to_vec())),
            message: Data(b"initial\n".to_vec()),
            from: None,
            merges: Vec::new(),
            ops: vec![
                FileOp::Modify {
                    mode: Mode::Regular,
                    path: BString::from(b"file.txt".to_vec()),
                    source: FileSource::DataRef(DataRef::Mark(1)),
                },
                FileOp::Modify {
                    mode: Mode::Exec,
                    path: BString::from(vec![0x63, 0x72, 0x0a, 0x6c, 0x66]), // "cr\nlf"
                    source: FileSource::Inline(Data(b"#!/bin/sh\n".to_vec())),
                },
                FileOp::Delete {
                    path: BString::from(b"gone.txt".to_vec()),
                },
                FileOp::Copy {
                    from: BString::from(b"a.txt".to_vec()),
                    to: BString::from(b"b.txt".to_vec()),
                },
                FileOp::Rename {
                    from: BString::from(b"x.txt".to_vec()),
                    to: BString::from(b"y z.txt".to_vec()),
                },
                FileOp::DeleteAll,
                FileOp::Note {
                    data: FileSource::DataRef(DataRef::Mark(1)),
                    commit: Committish::Mark(2),
                },
            ],
        }),
        Event::Commit(Commit {
            ref_name: BString::from(b"refs/heads/main".to_vec()),
            mark: Some(3),
            original_oid: None,
            author: None, // defaults to committer downstream
            committer: Some(Ident {
                name: BString::from(Vec::new()),
                email: BString::from(b"committer@example.com".to_vec()),
                time: Timestamp {
                    raw: BString::from(b"1112912053 -0430".to_vec()),
                    epoch: 1_112_912_053,
                    tz_offset_min: -4 * 60 - 30,
                },
            }),
            encoding: None,
            message: Data(b"second\n\nbody with # hash and :marks\n".to_vec()),
            from: Some(Committish::Mark(2)),
            merges: vec![Committish::Oid(oid2)],
            ops: vec![
                FileOp::Modify {
                    mode: Mode::Symlink,
                    path: BString::from(b"link".to_vec()),
                    source: FileSource::DataRef(DataRef::Oid(oid1)),
                },
                FileOp::Modify {
                    mode: Mode::Gitlink,
                    path: BString::from(b"sub".to_vec()),
                    source: FileSource::DataRef(DataRef::Oid(oid2)),
                },
                FileOp::Modify {
                    mode: Mode::Dir,
                    path: BString::from(b"dir".to_vec()),
                    source: FileSource::DataRef(DataRef::Oid(oid1)),
                },
            ],
        }),
        Event::Tag(Tag {
            name: BString::from(b"v1".to_vec()),
            mark: Some(4),
            original_oid: Some(oid2),
            from: Some(Committish::Mark(3)),
            tagger: Some(Ident {
                name: BString::from(b"T A Gger".to_vec()),
                email: BString::from(b"tagger@example.com".to_vec()),
                time: Timestamp {
                    raw: BString::from(b"1112912053 +0530".to_vec()),
                    epoch: 1_112_912_053,
                    tz_offset_min: 5 * 60 + 30,
                },
            }),
            message: Data(b"release v1\n".to_vec()),
        }),
        Event::Reset {
            ref_name: BString::from(b"refs/heads/other".to_vec()),
            from: Some(Committish::Mark(3)),
        },
        Event::Reset {
            ref_name: BString::from(b"refs/heads/gone".to_vec()),
            from: None,
        },
        Event::Progress {
            bytestring: BString::from(b"counting objects".to_vec()),
        },
        Event::Checkpoint,
        Event::Alias {
            mark: 9,
            target: Committish::Mark(3),
        },
        Event::GetMark { mark: 3 },
        Event::CatBlob {
            dataref: DataRef::Mark(1),
        },
        Event::Ls {
            dataref: Some(DataRef::Mark(3)),
            path: Some(BString::from(b"file.txt".to_vec())),
        },
        Event::Ls {
            dataref: None,
            path: Some(BString::from(b"dir".to_vec())),
        },
        Event::Ls {
            dataref: None,
            path: None,
        },
        Event::Done,
    ]
}

fn decode(bytes: &[u8]) -> Result<Vec<Event>, Error> {
    let mut p = Parser::new(ParseOptions::default());
    p.feed(bytes);
    let mut out = Vec::new();
    while let Some(ev) = p.next_event()? {
        out.push(ev);
    }
    p.finish(&mut out)?;
    Ok(out)
}

fn encode(events: &[Event]) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    for ev in events {
        w.write(ev)?;
    }
    Ok(w.take())
}

#[test]
fn p1_parse_write_roundtrip() {
    let events = sample_events();
    let bytes = encode(&events).expect("encode");
    let back = decode(&bytes).expect("decode");
    assert_eq!(events, back, "round-trip mismatch");
}

#[test]
fn p1_roundtrip_is_stable() {
    // write(parse(write(e))) == write(e)
    let events = sample_events();
    let bytes1 = encode(&events).expect("encode 1");
    let back = decode(&bytes1).expect("decode");
    let bytes2 = encode(&back).expect("encode 2");
    assert_eq!(bytes1, bytes2, "canonical form is not stable");
}

#[test]
fn p3_identity_pipeline() {
    // P3: bytes == rewrite(bytes, []) — empty pipeline is an identity.
    let events = sample_events();
    let bytes = encode(&events).expect("encode");
    let mut pipeline = Pipeline::builder().build();
    assert!(pipeline.is_empty());

    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(&bytes);
    let mut out = Vec::new();
    while let Some(ev) = parser.next_event().expect("parse") {
        pipeline.apply(ev, &mut out).expect("apply");
    }
    let mut fin = Vec::new();
    parser.finish(&mut fin).expect("finish");
    for ev in fin {
        pipeline.apply(ev, &mut out).expect("apply");
    }
    pipeline.finish(&mut out).expect("pipeline finish");
    let mut w = Writer::new();
    for ev in &out {
        w.write(ev).expect("write");
    }
    assert_eq!(w.take(), bytes);
}

#[test]
fn chunked_feed_is_invariant() {
    // Feed one byte at a time; parser output must not change.
    let events = sample_events();
    let bytes = encode(&events).expect("encode");

    let mut p = Parser::new(ParseOptions::default());
    let mut out = Vec::new();
    for chunk in bytes.chunks(3) {
        p.feed(chunk);
        while let Some(ev) = p.next_event().expect("parse") {
            out.push(ev);
        }
    }
    p.finish(&mut out).expect("finish");
    assert_eq!(out, events);
}
