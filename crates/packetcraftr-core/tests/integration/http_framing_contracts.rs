// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::protocol::application::http::{self, Body, BodyDecoder};

#[test]
fn terminated_invalid_lines_are_rejected_before_the_head_terminator() {
    for wire in [
        b"HTTP/1.1 XYZ Bad\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nBadHeader\r\n",
        b"HTTP/1.1 200 OK\r\nBad Name: value\r\n",
        b"HTTP/1.1 200 OK\r\nX-Fixture: bad\0value\r\n",
    ] {
        assert!(matches!(
            http::parse_head(&Bytes::copy_from_slice(wire)),
            Err(http::Error::Invalid(_))
        ));
    }
    let wire = format!("HTTP/1.1 200 OK\r\n{}", "X-Fixture: ok\r\n".repeat(257));
    assert!(matches!(
        http::parse_head(&Bytes::from(wire)),
        Err(http::Error::Limit(http::Limit::HeaderCount))
    ));
    for wire in [
        b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n",
    ] {
        for end in 0..wire.len() {
            assert!(
                http::parse_head(&Bytes::copy_from_slice(&wire[..end]))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            http::parse_head(&Bytes::copy_from_slice(wire))
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn invalid_delimiters_fail_explicit() {
    for wire in [
        b"GET / HTTP/1.1\n\n".as_slice(),
        b"GET / HTTP/1.1\r\n Folded: bad\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\n",
    ] {
        assert!(http::parse_head(&Bytes::copy_from_slice(wire)).is_err());
    }
    assert!(http::parse_head(&Bytes::from(vec![b'a'; http::MAX_HEADER_BYTES])).is_err());
    assert!(
        http::parse_head(&Bytes::from_static(b"GET / HTTP/1.1\r\nHost: x\r\n"))
            .unwrap()
            .is_none()
    );
    for wire in [
        b"1\na\r\n0\r\n\r\n".as_slice(),
        b"1\r\naX\n0\r\n\r\n",
        b"0\r\nContent-Length: 1\r\n\r\n",
        b"ff\r\n",
    ] {
        assert!(BodyDecoder::new(Body::Chunked, 5).consume(wire).is_err());
    }
    assert!(
        BodyDecoder::new(Body::Length(6), 5)
            .consume(b"abcdef")
            .is_err()
    );
}
