// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::protocol::application::http::{self, Body, BodyDecoder, StartLine};

#[test]
fn headers_preserve_octets_and_duplicates_and_choose_unambiguous_boundaries() {
    let wire =
        b"GET /a%20b HTTP/1.1\r\nHost: example.test\r\nX-Test: one\r\nX-Test: \xff\r\n\r\ntrailing";
    let (head, n) = http::parse_head(wire).unwrap().unwrap();
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
    let (head, _) =
        http::parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\n\r\n")
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
        let (head, _) = http::parse_head(wire.as_bytes()).unwrap().unwrap();
        assert!(head.body(None).is_err());
    }
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
fn invalid_delimiters_oversized_input_and_body_limits_fail_explicitly() {
    for wire in [
        b"GET / HTTP/1.1\n\n".as_slice(),
        b"GET / HTTP/1.1\r\n Folded: bad\r\n\r\n",
        b"PRI * HTTP/2.0\r\n\r\n",
    ] {
        assert!(http::parse_head(wire).is_err());
    }
    assert!(http::parse_head(&vec![b'a'; http::MAX_HEADER_BYTES]).is_err());
    assert!(
        http::parse_head(b"GET / HTTP/1.1\r\nHost: x\r\n")
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
