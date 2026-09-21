// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::protocol::application::http::{self, Body, BodyDecoder, StartLine};

#[test]
fn borrowed_headers_preserve_limit_and_trailing_byte_errors() {
    let oversized = vec![b'a'; http::MAX_HEADER_BYTES * 2];
    let error = http::Http::try_from(oversized.as_slice()).unwrap_err();
    assert!(error.to_string().contains("header bytes"));

    let mut trailing = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    trailing.resize(http::MAX_HEADER_BYTES * 2, b'a');
    let error = http::Http::try_from(trailing.as_slice()).unwrap_err();
    assert!(error.to_string().contains("body or trailing bytes"));
}

#[test]
fn headers_preserve_octets_and_duplicates_and_choose_unambiguous_boundaries() {
    let wire =
        b"GET /a%20b HTTP/1.1\r\nHost: example.test\r\nX-Test: one\r\nX-Test: \xff\r\n\r\ntrailing";
    let (head, n) = http::parse_head(&Bytes::from_static(wire))
        .unwrap()
        .unwrap();
    assert_eq!(&wire[n..], b"trailing");
    assert_eq!(head.wire().as_ref(), &wire[..n]);
    assert_eq!(
        head.values("x-test").collect::<Vec<_>>(),
        [b"one".as_slice(), b"\xff"]
    );
    assert_eq!(head.body(None).unwrap(), Body::None);
    assert!(
        matches!(&head.start,StartLine::Request {method,target,..} if method=="GET"&&target.as_ref()==b"/a%20b")
    );
    let (head, _) = http::parse_head(&Bytes::from_static(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\n\r\n",
    ))
    .unwrap()
    .unwrap();
    assert_eq!(head.body(None).unwrap(), Body::Length(3));
    assert_eq!(head.body(Some("HEAD")).unwrap(), Body::None);
    assert_eq!(head.body(Some("CONNECT")).unwrap(), Body::Tunnel);
    for fields in [
        "Content-Length: 2\r\nContent-Length: 3\r\n",
        "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
        "Transfer-Encoding: chunked, gzip\r\n",
        "Transfer-Encoding: chunked, chunked\r\n",
    ] {
        let wire = format!("POST / HTTP/1.1\r\n{fields}\r\n");
        let (head, _) = http::parse_head(&Bytes::from(wire.clone()))
            .unwrap()
            .unwrap();
        assert!(head.body(None).is_err());
    }
}
#[test]
fn transfer_codings_parse_parameters_without_splitting_quoted_strings() {
    fn body_of(wire: &[u8]) -> Result<Body, http::Error> {
        http::parse_head(&Bytes::copy_from_slice(wire))
            .unwrap()
            .unwrap()
            .0
            .body(None)
    }
    // Commas and semicolons inside a quoted parameter separate nothing, so
    // "chunked" there cannot select chunked framing.
    for wire in [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a,chunked;b\"\r\nConnection: close\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a;b\"\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a\",b;q=\"c,d\"\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a\\\",b\"\r\n\r\n".as_slice(),
    ] {
        assert_eq!(body_of(wire), Ok(Body::Close), "{wire:?}");
    }
    // Whitespace before a parameter is part of the grammar; the actual final
    // coding still decides framing.
    for wire in [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom ;p=token, chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a\\\\\", chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;p=\"a,b\"\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
    ] {
        assert_eq!(body_of(wire), Ok(Body::Chunked), "{wire:?}");
    }
    // Malformed lists and unterminated quoted strings fail deterministically.
    for wire in [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"unterminated\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;p=\"a\"x\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom;,chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: custom ;\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ,chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n".as_slice(),
    ] {
        assert!(body_of(wire).is_err(), "{wire:?}");
    }
    // A non-chunked final coding on a request remains an error.
    assert!(
        body_of(b"POST / HTTP/1.1\r\nTransfer-Encoding: custom;p=\"a,chunked\"\r\n\r\n").is_err()
    );
}
#[test]
fn bytewise_chunks_include_trailers_and_stop_before_the_next_message() {
    let wire = b"3;ext=\"ok\"\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: done\r\n\r\nnext";
    let mut decoder = BodyDecoder::new(Body::Chunked, 10);
    let mut consumed = 0;
    while !decoder.complete() {
        let progress = decoder.consume(&wire[consumed..consumed + 1]).unwrap();
        consumed += progress.consumed;
    }
    assert_eq!(&wire[consumed..], b"next");
    assert_eq!(decoder.body_bytes(), 5);
    assert_eq!(decoder.trailers()[0].name, "X-Checksum");
    assert_eq!(decoder.trailers()[0].value.as_ref(), b"done");
    let mut decoder = BodyDecoder::new(Body::Length(3), 3);
    assert_eq!(decoder.consume(b"abcNEXT").unwrap().consumed, 3);
    assert!(decoder.complete());
    let mut decoder = BodyDecoder::new(Body::Close, 5);
    decoder.consume(b"abc").unwrap();
    assert!(!decoder.complete());
    assert!(decoder.close());
}
#[test]
fn chunk_size_tolerates_whitespace_only_before_extensions() {
    for wire in [
        b"3 ;x=y\r\nabc\r\n0\r\n\r\n".as_slice(),
        b"3\t;x=y\r\nabc\r\n0\r\n\r\n".as_slice(),
        b"3;x=y\r\nabc\r\n0\r\n\r\n".as_slice(),
        b"3\r\nabc\r\n0\r\n\r\n".as_slice(),
    ] {
        let mut decoder = BodyDecoder::new(Body::Chunked, 16);
        let progress = decoder.consume(wire).unwrap();
        assert!(
            progress.complete && progress.consumed == wire.len(),
            "{wire:?}"
        );
        assert_eq!(decoder.body_bytes(), 3);
    }
    // Whitespace inside the digits, before them, or ahead of a bare CRLF
    // remains invalid.
    for wire in [
        b"3 4;x=y\r\nabcd\r\n0\r\n\r\n".as_slice(),
        b" 3;x=y\r\nabc\r\n0\r\n\r\n".as_slice(),
        b"3 \r\nabc\r\n0\r\n\r\n".as_slice(),
        b"3 g;x=y\r\nabc\r\n0\r\n\r\n".as_slice(),
    ] {
        assert!(
            BodyDecoder::new(Body::Chunked, 16).consume(wire).is_err(),
            "{wire:?}"
        );
    }
}
#[test]
fn invalid_delimiters_oversized_input_and_body_limits_fail_explicitly() {
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
