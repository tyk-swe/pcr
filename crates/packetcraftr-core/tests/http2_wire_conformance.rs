// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::protocol::application::http2::{
    CLIENT_PREFACE, Error, Frame, Limit, Payload, Priority, Setting, parse_frame,
};

const MAX: usize = 1 << 20;

fn wire(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

fn parse(bytes: &Bytes) -> Result<(Frame, usize), Error> {
    parse_frame(bytes, MAX)?.ok_or(Error::Invalid("test requires a complete frame"))
}

#[test]
fn client_preface_matches_rfc9113() {
    assert_eq!(CLIENT_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    assert_eq!(CLIENT_PREFACE.len(), 24);
}

#[test]
fn data_frame_splits_padding_from_content() {
    let payload = [&[5u8][..], b"hello", &[0; 5]].concat();
    let (frame, consumed) = parse(&wire(0x0, 0x9, 1, &payload)).unwrap();
    assert_eq!(consumed, 9 + 11);
    assert_eq!(frame.header.length, 11);
    assert_eq!(frame.header.frame_type, 0x0);
    assert_eq!(frame.header.flags, 0x9);
    assert_eq!(frame.header.stream_id, 1);
    assert!(!frame.header.reserved);
    let Payload::Data { data, padding } = &frame.payload else {
        panic!("expected DATA")
    };
    assert_eq!(data.as_ref(), b"hello");
    assert_eq!(padding.len(), 5);
    assert_eq!(frame.wire().len(), consumed);
}

#[test]
fn headers_frame_parses_priority_and_padding() {
    let payload = [&[3u8][..], &[0x80, 0, 0, 7, 0x0f], b"block", &[0; 3]].concat();
    let (frame, consumed) = parse(&wire(0x1, 0x4 | 0x8 | 0x20, 3, &payload)).unwrap();
    assert_eq!(consumed, 9 + 14);
    let Payload::Headers {
        fragment,
        priority,
        padding,
    } = &frame.payload
    else {
        panic!("expected HEADERS")
    };
    assert_eq!(fragment.as_ref(), b"block");
    assert_eq!(padding.len(), 3);
    assert_eq!(
        *priority,
        Some(Priority {
            exclusive: true,
            dependency: 7,
            weight: 16,
        })
    );
}

#[test]
fn remaining_frame_types_decode_their_fields() {
    let (frame, n) = parse(&wire(0x2, 0, 9, &[0, 0, 0, 3, 200])).unwrap();
    assert_eq!(n, 14);
    assert_eq!(
        frame.payload,
        Payload::Priority(Priority {
            exclusive: false,
            dependency: 3,
            weight: 201,
        })
    );

    let (frame, n) = parse(&wire(0x3, 0, 9, &8u32.to_be_bytes())).unwrap();
    assert_eq!(n, 13);
    assert_eq!(frame.payload, Payload::Reset { error_code: 8 });

    let mut settings = Vec::new();
    settings.extend_from_slice(&1u16.to_be_bytes());
    settings.extend_from_slice(&4096u32.to_be_bytes());
    settings.extend_from_slice(&3u16.to_be_bytes());
    settings.extend_from_slice(&100u32.to_be_bytes());
    let (frame, n) = parse(&wire(0x4, 0, 0, &settings)).unwrap();
    assert_eq!(n, 21);
    assert_eq!(
        frame.payload,
        Payload::Settings(vec![
            Setting { id: 1, value: 4096 },
            Setting { id: 3, value: 100 },
        ])
    );
    let (frame, _) = parse(&wire(0x4, 0x1, 0, &[])).unwrap();
    assert_eq!(frame.payload, Payload::Settings(vec![]));

    let mut promised = [0x80, 0, 0, 2].to_vec();
    promised.extend_from_slice(b"frag");
    let (frame, _) = parse(&wire(0x5, 0x4, 1, &promised)).unwrap();
    assert_eq!(
        frame.payload,
        Payload::PushPromise {
            promised_stream_id: 2,
            fragment: Bytes::from_static(b"frag"),
            padding: Bytes::new(),
        }
    );

    let (frame, _) = parse(&wire(0x6, 0x1, 0, b"12345678")).unwrap();
    assert_eq!(frame.payload, Payload::Ping(*b"12345678"));

    let mut goaway = Vec::new();
    goaway.extend_from_slice(&0x8000_0007u32.to_be_bytes());
    goaway.extend_from_slice(&11u32.to_be_bytes());
    goaway.extend_from_slice(b"bye");
    let (frame, _) = parse(&wire(0x7, 0, 0, &goaway)).unwrap();
    assert_eq!(
        frame.payload,
        Payload::Goaway {
            last_stream_id: 7,
            error_code: 11,
            debug: Bytes::from_static(b"bye"),
        }
    );

    let (frame, _) = parse(&wire(0x8, 0, 1, &0x8000_0400u32.to_be_bytes())).unwrap();
    assert_eq!(frame.payload, Payload::WindowUpdate { increment: 1024 });
    let (frame, _) = parse(&wire(0x8, 0, 0, &65_535u32.to_be_bytes())).unwrap();
    assert_eq!(frame.payload, Payload::WindowUpdate { increment: 65_535 });

    let (frame, _) = parse(&wire(0x9, 0x4, 1, b"more")).unwrap();
    assert_eq!(
        frame.payload,
        Payload::Continuation(Bytes::from_static(b"more"))
    );
}

#[test]
fn incomplete_input_returns_none_at_every_prefix() {
    for frame in [
        wire(0x0, 0x9, 1, &[7, b'a', b'b', 0, 0, 0, 0, 0, 0, 0]),
        wire(0x1, 0x25, 1, &[0x80, 0, 0, 7, 9, b'x']),
        wire(0x2, 0, 1, &[0, 0, 0, 0, 1]),
        wire(0x3, 0, 1, &[0, 0, 0, 8]),
        wire(0x4, 0, 0, &[0, 6, 0, 0, 0, 0]),
        wire(0x4, 0x1, 0, &[]),
        wire(0x5, 0x8, 1, &[4, 0, 0, 0, 2, b'x', 0, 0, 0, 0]),
        wire(0x6, 0, 0, b"12345678"),
        wire(0x7, 0, 0, &[0, 0, 0, 5, 0, 0, 0, 0, b'x']),
        wire(0x8, 0, 0, &[0, 0, 0, 1]),
        wire(0x9, 0x4, 1, b"tail"),
        wire(0x1f, 0xaa, 5, b"extension"),
    ] {
        for prefix in 0..frame.len() {
            assert!(
                parse_frame(&frame.slice(..prefix), MAX).unwrap().is_none(),
                "prefix {prefix} of {frame:?}"
            );
        }
        assert_eq!(
            parse_frame(&frame, MAX).unwrap().map(|(_, n)| n),
            Some(frame.len())
        );
    }
}

#[test]
fn concatenated_frames_report_consumed_bytes() {
    let first = wire(0x6, 0, 0, b"12345678");
    let second = wire(0x9, 0x4, 3, b"tail");
    let mut joined = first.to_vec();
    joined.extend_from_slice(&second);
    let input = Bytes::from(joined);
    let (frame, consumed) = parse_frame(&input, MAX).unwrap().unwrap();
    assert_eq!(consumed, first.len());
    assert_eq!(frame.wire().as_ref(), first.as_ref());
    let (frame, consumed) = parse_frame(&input.slice(consumed..), MAX).unwrap().unwrap();
    assert_eq!(consumed, second.len());
    assert_eq!(
        frame.payload,
        Payload::Continuation(Bytes::from_static(b"tail"))
    );
}

#[test]
fn reserved_and_unknown_bits_are_preserved() {
    let (frame, _) = parse(&wire(0x0, 0x42, 0x8000_0001, b"abc")).unwrap();
    assert!(frame.header.reserved);
    assert_eq!(frame.header.stream_id, 1);
    assert_eq!(frame.header.flags, 0x42);

    let (frame, _) = parse(&wire(0x1, 0x12, 1, b"frag")).unwrap();
    let Payload::Headers { fragment, .. } = &frame.payload else {
        panic!("expected HEADERS")
    };
    assert_eq!(fragment.as_ref(), b"frag");
    assert_eq!(frame.header.flags, 0x12);

    let (frame, _) = parse(&wire(0x1f, 0xa5, 0xffff_fffe, b"opaque")).unwrap();
    assert_eq!(frame.header.frame_type, 0x1f);
    assert_eq!(frame.header.flags, 0xa5);
    assert_eq!(frame.header.stream_id, 0x7fff_fffe);
    assert!(frame.header.reserved);
    assert_eq!(
        frame.payload,
        Payload::Unknown(Bytes::from_static(b"opaque"))
    );
}

#[test]
fn fixed_length_and_stream_rules_are_enforced() {
    for (frame_type, stream, payload) in [
        (0x2, 1, &[0u8; 4][..]),
        (0x2, 1, &[0u8; 6][..]),
        (0x3, 1, &[0u8; 3][..]),
        (0x3, 1, &[0u8; 5][..]),
        (0x6, 0, &[0u8; 7][..]),
        (0x6, 0, &[0u8; 9][..]),
        (0x8, 1, &[0u8; 5][..]),
        (0x4, 0, &[0u8; 5][..]),
        (0x7, 0, &[0u8; 7][..]),
    ] {
        let complete = wire(frame_type, 0, stream, payload);
        for input in [complete.slice(..9), complete] {
            assert!(
                matches!(parse_frame(&input, MAX), Err(Error::Invalid(_))),
                "type {frame_type} length {}",
                payload.len()
            );
        }
    }
    let complete = wire(0x4, 0x1, 0, &[0; 6]);
    for input in [complete.slice(..9), complete] {
        assert!(matches!(parse_frame(&input, MAX), Err(Error::Invalid(_))));
    }
}

#[test]
fn minimum_lengths_are_rejected_from_the_header() {
    for (frame_type, flags, stream, length) in [
        (0x0, 0x8, 1, 0u32),
        (0x1, 0x8, 1, 0),
        (0x1, 0x20, 1, 4),
        (0x1, 0x28, 1, 5),
        (0x5, 0, 1, 3),
        (0x5, 0x8, 1, 4),
    ] {
        let header = wire(frame_type, flags, stream, &vec![0; length as usize]).slice(..9);
        assert!(
            matches!(parse_frame(&header, MAX), Err(Error::Invalid(_))),
            "type {frame_type} length {length}"
        );
    }
    assert!(matches!(
        parse_frame(&wire(0x5, 0, 1, &[0x80, 0, 0, 0]), MAX),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn stream_zero_rules_match_rfc9113() {
    for frame_type in [0x0u8, 0x1, 0x2, 0x3, 0x5, 0x9] {
        let len = match frame_type {
            0x2 => 5,
            0x3 => 4,
            _ => 0,
        };
        assert!(
            matches!(
                parse_frame(&wire(frame_type, 0, 0, &vec![0; len]), MAX),
                Err(Error::Invalid(_))
            ),
            "type {frame_type}"
        );
    }
    for frame_type in [0x4u8, 0x6, 0x7] {
        let len = match frame_type {
            0x6 | 0x7 => 8,
            _ => 0,
        };
        assert!(
            matches!(
                parse_frame(&wire(frame_type, 0, 7, &vec![0; len]), MAX),
                Err(Error::Invalid(_))
            ),
            "type {frame_type}"
        );
    }
    assert!(parse(&wire(0x8, 0, 0, &1u32.to_be_bytes())).is_ok());
}

#[test]
fn padding_and_dependency_malformations_are_rejected() {
    assert!(matches!(
        parse_frame(&wire(0x0, 0x8, 1, &[4, 0, 0, 0]), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x0, 0x8, 1, &[]), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x2, 0, 5, &[0, 0, 0, 5, 16]), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x1, 0x20, 3, &[0, 0, 0, 3, 16, b'x']), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x1, 0x20 | 0x8, 3, &[4, 0, 0, 0, 2, 0, 0, 0, 0]), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x5, 0x8, 1, &[2, 0, 0, 0]), MAX),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        parse_frame(&wire(0x8, 0, 1, &0u32.to_be_bytes()), MAX),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn advertised_length_is_capped_before_buffering() {
    let oversized = Bytes::from_static(&[0xff, 0xff, 0xff, 0x0, 0, 0, 0, 0, 1]);
    assert!(matches!(
        parse_frame(&oversized, MAX),
        Err(Error::Limit(Limit::FrameBytes))
    ));
    let header = wire(0x0, 0, 1, &[]);
    let mut advertised = header.to_vec();
    advertised[..3].copy_from_slice(&(MAX as u32).to_be_bytes()[1..]);
    assert!(
        parse_frame(&Bytes::from(advertised), MAX)
            .unwrap()
            .is_none()
    );
}

#[test]
fn zero_length_and_acknowledgment_frames_decode() {
    let (frame, consumed) = parse(&wire(0x0, 0x1, 1, &[])).unwrap();
    assert_eq!(consumed, 9);
    let Payload::Data { data, padding } = &frame.payload else {
        panic!("expected DATA")
    };
    assert!(data.is_empty() && padding.is_empty());

    let (frame, _) = parse(&wire(0x1, 0x5, 1, &[])).unwrap();
    assert_eq!(
        frame.payload,
        Payload::Headers {
            fragment: Bytes::new(),
            priority: None,
            padding: Bytes::new(),
        }
    );

    let (frame, _) = parse(&wire(0x9, 0, 1, &[])).unwrap();
    assert_eq!(frame.payload, Payload::Continuation(Bytes::new()));
}
