// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::protocol::application::http::{
    self, Body, BodyDecoder, ConsumeError, StartLine,
};
use std::convert::Infallible;

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

/// Feeds `decoder` every slice of `pieces`, extending `emitted` from each
/// callback span.
fn consume_in(
    decoder: &mut BodyDecoder,
    pieces: &[&[u8]],
    emitted: &mut Vec<u8>,
) -> Result<usize, ConsumeError<Infallible>> {
    let mut consumed = 0;
    for piece in pieces {
        let progress = decoder.consume_with(piece, &mut |span| {
            emitted.extend_from_slice(span);
            Ok(())
        })?;
        consumed += progress.consumed;
    }
    Ok(consumed)
}

#[test]
fn consume_with_delivers_binary_body_bytes_exactly_in_any_segmentation() {
    // NUL and non-UTF8 octets plus content-coded-looking bytes (a gzip
    // magic prefix): entity spans pass through unchanged, whatever the
    // delivery boundaries.
    let mut body = vec![0x1f, 0x8b, 0x00, 0x08];
    body.extend_from_slice(b"\x00\xff\xfeBINARY");
    body.extend(0u8..=255);
    body.extend_from_slice(b"\xff\x00tail");
    for size in [1, 2, 3, 7, 64, body.len()] {
        let mut decoder = BodyDecoder::new(Body::Length(body.len() as u64), 1 << 20);
        let mut emitted = Vec::new();
        let mut consumed = 0;
        while consumed < body.len() {
            let end = (consumed + size).min(body.len());
            let progress = decoder
                .consume_with(&body[consumed..end], &mut |span| {
                    emitted.extend_from_slice(span);
                    Ok::<(), Infallible>(())
                })
                .unwrap();
            assert_eq!(progress.consumed, end - consumed, "piece size {size}");
            consumed += progress.consumed;
        }
        assert!(decoder.complete(), "piece size {size}");
        assert_eq!(emitted, body, "piece size {size}");
        assert_eq!(decoder.body_bytes() as usize, body.len());
        assert_eq!(decoder.buffered_bytes(), 0);
    }
    // Bytes past the declared length stay with the next message.
    let mut decoder = BodyDecoder::new(Body::Length(3), 3);
    let mut emitted = Vec::new();
    let progress = decoder
        .consume_with(b"abcNEXT", &mut |span| {
            emitted.extend_from_slice(span);
            Ok::<(), Infallible>(())
        })
        .unwrap();
    assert_eq!(progress.consumed, 3);
    assert_eq!(emitted, b"abc");
}

#[test]
fn consume_with_emits_only_chunk_data_once_in_any_segmentation() {
    // Sizes, extensions, CRLF separators, trailers, and the pipelined
    // message stay framing-side; only chunk data reaches the callback.
    let wire = b"3;ext=\"ok\"\r\nabc\r\n2;x\r\nde\r\n0\r\nX-Checksum: done\r\n\r\nnext";
    let entity_end = wire.len() - 4;
    for size in 1..wire.len() {
        let mut decoder = BodyDecoder::new(Body::Chunked, 64);
        let mut emitted = Vec::new();
        let mut consumed = 0;
        while consumed < entity_end {
            let end = (consumed + size).min(entity_end);
            let progress = decoder
                .consume_with(&wire[consumed..end], &mut |span| {
                    emitted.extend_from_slice(span);
                    Ok::<(), Infallible>(())
                })
                .unwrap();
            assert_eq!(progress.consumed, end - consumed, "piece size {size}");
            consumed += progress.consumed;
        }
        assert!(decoder.complete(), "piece size {size}");
        assert_eq!(emitted, b"abcde", "piece size {size}");
        assert_eq!(decoder.body_bytes(), 5);
        assert_eq!(decoder.trailers()[0].name, "X-Checksum");
        assert_eq!(decoder.trailers()[0].value.as_ref(), b"done");
    }
    // One shot stops before the pipelined message's bytes.
    let mut decoder = BodyDecoder::new(Body::Chunked, 64);
    let mut emitted = Vec::new();
    let progress = decoder
        .consume_with(wire, &mut |span| {
            emitted.extend_from_slice(span);
            Ok::<(), Infallible>(())
        })
        .unwrap();
    assert_eq!(progress.consumed, entity_end);
    assert!(progress.complete);
    assert_eq!(&wire[progress.consumed..], b"next");
    assert_eq!(emitted, b"abcde");
}

#[test]
fn consume_with_close_delimited_streams_until_a_clean_fin() {
    let mut decoder = BodyDecoder::new(Body::Close, 64);
    let mut emitted = Vec::new();
    for piece in [b"ab".as_slice(), b"cd".as_slice()] {
        let progress = decoder
            .consume_with(piece, &mut |span| {
                emitted.extend_from_slice(span);
                Ok::<(), Infallible>(())
            })
            .unwrap();
        assert_eq!(progress.consumed, piece.len());
        assert!(!progress.complete);
    }
    assert_eq!(emitted, b"abcd");
    // The decoder reports no completion on its own: only a clean FIN does.
    assert!(!decoder.complete());
    assert!(decoder.close());
}

#[test]
fn consume_with_never_invokes_the_callback_without_entity_bytes() {
    for body in [Body::None, Body::Tunnel, Body::Length(0)] {
        let mut decoder = BodyDecoder::new(body, 8);
        let mut calls = 0;
        let progress = decoder
            .consume_with(b"opaque", &mut |_| {
                calls += 1;
                Ok::<(), Infallible>(())
            })
            .unwrap();
        assert_eq!(calls, 0, "{body:?}");
        assert_eq!(progress.consumed, 0);
        assert!(progress.complete);
    }
}

#[test]
fn consume_with_sink_failure_is_terminal_and_leaves_the_span_uncommitted() {
    let mut decoder = BodyDecoder::new(Body::Length(6), 16);
    let mut calls = 0;
    decoder
        .consume_with(b"abc", &mut |_| {
            calls += 1;
            Ok::<(), &'static str>(())
        })
        .unwrap();
    let error = decoder
        .consume_with(b"defXXX", &mut |_| -> Result<(), &'static str> {
            calls += 1;
            Err("full")
        })
        .unwrap_err();
    assert!(matches!(error, ConsumeError::Sink("full")));
    assert_eq!(calls, 2);
    // The refused span committed nothing: only the first span's three
    // bytes count, and the body stays open.
    assert_eq!(decoder.body_bytes(), 3);
    assert!(!decoder.complete());

    // A chunked body that fails mid-stream never delivers later chunks.
    let mut decoder = BodyDecoder::new(Body::Chunked, 16);
    let mut calls = 0;
    let error = decoder
        .consume_with(b"2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n", &mut |_| -> Result<
            (),
            &'static str,
        > {
            calls += 1;
            if calls == 1 { Ok(()) } else { Err("stop") }
        })
        .unwrap_err();
    assert!(matches!(error, ConsumeError::Sink("stop")));
    assert_eq!(calls, 2);
    assert_eq!(decoder.body_bytes(), 2);
}

#[test]
fn consume_with_never_delivers_bytes_beyond_the_ceiling() {
    let mut delivered = Vec::new();
    // A Content-Length span that crosses the ceiling fails before the
    // callback sees any of it, even in one large input slice.
    let mut decoder = BodyDecoder::new(Body::Length(6), 5);
    let error = decoder
        .consume_with(b"abcdef", &mut |span| {
            delivered.extend_from_slice(span);
            Ok::<(), Infallible>(())
        })
        .unwrap_err();
    assert!(matches!(
        error,
        ConsumeError::Framing(http::Error::Limit(http::Limit::BodyBytes))
    ));
    assert!(delivered.is_empty());
    assert_eq!(decoder.body_bytes(), 0);

    // A close-delimited body delivers only through the ceiling.
    let mut decoder = BodyDecoder::new(Body::Close, 4);
    consume_in(&mut decoder, &[b"abc".as_slice()], &mut delivered).unwrap();
    let error = consume_in(&mut decoder, &[b"def".as_slice()], &mut delivered).unwrap_err();
    assert!(matches!(
        error,
        ConsumeError::Framing(http::Error::Limit(http::Limit::BodyBytes))
    ));
    assert_eq!(delivered, b"abc");

    // A chunk size beyond the remaining ceiling fails at its line, before
    // any chunk data is parsed or delivered.
    let mut decoder = BodyDecoder::new(Body::Chunked, 5);
    let error = consume_in(
        &mut decoder,
        &[b"6\r\nabcdef\r\n0\r\n\r\n".as_slice()],
        &mut delivered,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ConsumeError::Framing(http::Error::Limit(http::Limit::BodyBytes))
    ));
    assert_eq!(delivered, b"abc");
}

#[test]
fn consume_with_borrows_bounded_spans_and_buffers_nothing_proportional() {
    // A body far larger than the decoder's framing buffers produces only
    // spans that borrow the input; retained buffer stays independent of
    // body length.
    let body_len: usize = 512 * 1024;
    let body: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();
    let piece = 8 * 1024;
    let mut decoder = BodyDecoder::new(Body::Length(body_len as u64), 1 << 20);
    let mut spans = Vec::new();
    let mut offset = 0;
    while offset < body.len() {
        let input = &body[offset..(offset + piece).min(body.len())];
        let base = input.as_ptr() as usize;
        let end = base + input.len();
        let progress = decoder
            .consume_with(input, &mut |span| {
                let start = span.as_ptr() as usize;
                assert!(
                    start >= base && start + span.len() <= end,
                    "an entity span borrows the delivery, never a copied buffer"
                );
                spans.push((start - base, span.len()));
                Ok::<(), Infallible>(())
            })
            .unwrap();
        offset += progress.consumed;
        // A length body buffers nothing no matter how much was delivered.
        assert_eq!(decoder.buffered_bytes(), 0);
    }
    assert_eq!(decoder.body_bytes(), body_len as u64);
    assert_eq!(spans.len(), body_len.div_ceil(piece));
    assert_eq!(spans.iter().map(|(_, n)| *n).sum::<usize>(), body_len);
    assert!(spans.iter().all(|(start, n)| *start + n <= piece));

    // A chunked body buffers only its partial chunk/trailer lines.
    let body_len = 64 * 1024;
    let mut wire = Vec::new();
    let mut remaining = body_len;
    while remaining > 0 {
        let size = remaining.min(4096);
        wire.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        wire.extend(std::iter::repeat_n(b'x', size));
        wire.extend_from_slice(b"\r\n");
        remaining -= size;
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    let mut decoder = BodyDecoder::new(Body::Chunked, 1 << 20);
    let mut emitted = 0;
    for piece in wire.chunks(777) {
        decoder
            .consume_with(piece, &mut |span| {
                emitted += span.len();
                Ok::<(), Infallible>(())
            })
            .unwrap();
        assert!(
            decoder.buffered_bytes() <= http::MAX_START_LINE + 16,
            "only partial chunk/trailer lines buffer: {}",
            decoder.buffered_bytes()
        );
    }
    assert!(decoder.complete());
    assert_eq!(emitted, body_len);
}

#[test]
fn consume_and_consume_with_share_one_state_machine() {
    // The discard path reports identical progress, completion, and errors
    // as an infallible-callback run over the same wires.
    for wire in [
        b"abcNEXT".as_slice(),
        b"3;ext=\"ok\"\r\nabc\r\n2\r\nde\r\n0\r\nX-T: y\r\n\r\nnext",
        b"1\na\r\n0\r\n\r\n",
    ] {
        for (body, maximum) in [(Body::Length(3), 8), (Body::Chunked, 8), (Body::Close, 8)] {
            let mut counted = BodyDecoder::new(body, maximum);
            let mut streamed = BodyDecoder::new(body, maximum);
            let discard = counted.consume(wire);
            let emitted = streamed.consume_with(wire, &mut |_| Ok::<(), Infallible>(()));
            match (discard, emitted) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "{wire:?} {body:?}"),
                (Err(a), Err(ConsumeError::Framing(b))) => assert_eq!(a, b, "{wire:?} {body:?}"),
                (a, b) => panic!("mismatched outcome {a:?} vs {b:?}"),
            }
        }
    }
}
