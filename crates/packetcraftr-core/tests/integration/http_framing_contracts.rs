// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::protocol::application::http::{self, Body, BodyDecoder};
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
