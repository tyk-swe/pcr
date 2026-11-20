use std::time::Duration;

use bytes::Bytes;

use super::{Code, Event, Exchange, Limits, SectionKind, inspect};
use crate::analysis::{Endpoint, quic, scope};
use crate::budget::Deadline;

fn stream(id: u64, direction: quic::Direction, data: &[u8]) -> quic::Stream {
    quic::Stream {
        id,
        direction,
        ranges: vec![quic::Range {
            offset: 0,
            data: Bytes::copy_from_slice(data),
        }],
        final_size: Some(data.len() as u64),
        reset_error: None,
        complete: true,
        conflicting_overlap: false,
        final_size_error: false,
        omitted_bytes: 0,
        early_data: false,
    }
}

fn connection(streams: Vec<quic::Stream>) -> quic::Connection {
    let mut scopes = scope::Interner::default();
    let id = scopes.intern(Some(0), Vec::new()).unwrap();
    quic::Connection {
        connection: 0,
        scope: scopes.definition(id).unwrap().clone(),
        version: 1,
        client_endpoint: Endpoint {
            address: "192.0.2.1".parse().unwrap(),
            port: 49152,
        },
        server_endpoint: Endpoint {
            address: "192.0.2.2".parse().unwrap(),
            port: 443,
        },
        first_frame: 1,
        last_frame: 1,
        source_frames: vec![1],
        source_frames_omitted: 0,
        connection_ids: Vec::new(),
        paths: Vec::new(),
        sni: None,
        sni_is_outer: false,
        offered_alpn: vec!["h3".to_owned()],
        negotiated_alpn: Some("h3".to_owned()),
        cipher_suite: None,
        ja3: None,
        ja4: None,
        client_hello_frame: None,
        server_hello_frame: None,
        hello_elapsed_ms: None,
        client_finished_frame: None,
        server_finished_frame: None,
        handshake_done_frame: None,
        early_data: quic::EarlyData::Rejected,
        client_transport_parameters: Vec::new(),
        server_transport_parameters: Vec::new(),
        streams,
        metrics: quic::Metrics::default(),
        diagnostics: Vec::new(),
        diagnostics_omitted: 0,
        pending_packets: 0,
        closed: false,
        close_error: None,
        close_reason: None,
        stateless_reset: false,
        incomplete: true,
        end_reason: String::new(),
    }
}

fn exchanges(streams: Vec<quic::Stream>, limits: Limits) -> Vec<Exchange> {
    selected_exchanges(streams, None, limits)
}

fn selected_exchanges(
    streams: Vec<quic::Stream>,
    selected: Option<u64>,
    limits: Limits,
) -> Vec<Exchange> {
    let mut results = Vec::new();
    inspect(
        &connection(streams),
        selected,
        limits,
        &Deadline::new(Duration::MAX),
        &mut |event| {
            if let Event::Exchange(exchange) = event {
                results.push(exchange);
            }
            Ok(())
        },
    )
    .unwrap();
    results
}

#[test]
fn retains_complete_prefix_before_gap_and_excludes_unaccepted_early_data() {
    use quic::Direction::{Client, Server};
    let mut rejected = stream(0, Client, b"\x01\x08\0\0\xd4\xd7\xc1\x50\x01a");
    rejected.early_data = true;
    let mut request = stream(0, Client, b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a\0\x04ab");
    request.complete = false;
    request.final_size = Some(16);
    request.ranges.push(quic::Range {
        offset: 15,
        data: Bytes::from_static(b"d"),
    });
    let response = stream(0, Server, b"\x01\x03\0\0\xd9");
    let result = exchanges(vec![request, rejected, response], Limits::default());
    let [exchange] = result.as_slice() else {
        panic!("expected one exchange")
    };
    let request = exchange.request.as_ref().unwrap();
    assert_eq!(request.header_sections[0].method.as_deref(), Some("GET"));
    assert_eq!(request.data_bytes, 0);
    assert!(!request.complete);
    assert!(
        request
            .issues
            .iter()
            .any(|issue| issue.code == Code::StreamGap && issue.offset == Some(14))
    );
    assert!(
        request
            .issues
            .iter()
            .any(|issue| issue.code == Code::TruncatedFrame && issue.offset == Some(10))
    );
    let response = exchange.response.as_ref().unwrap();
    assert!(response.complete);
    assert_eq!(response.header_sections[0].status, Some(200));
}

#[test]
fn distinguishes_missing_and_wrapped_qpack_history_while_decoding_static_sections() {
    use quic::Direction::{Client, Server};
    let settings = b"\0\x04\x05\x01\x40\x40\x07\x01";
    let run = |encoder: &[u8], limit| {
        exchanges(
            vec![
                stream(3, Server, settings),
                stream(6, Client, encoder),
                stream(0, Client, b"\x01\x09\x02\x80\xd1\xd7\xc1\x50\x01a\x10"),
                stream(4, Client, b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a"),
            ],
            limit,
        )
    };

    let one = run(b"\x02\x3f\x21\x41x\x01a", Limits::default());
    let request = one[0].request.as_ref().unwrap();
    let section = &request.header_sections[0];
    assert!(request.complete);
    assert_eq!(section.required_insert_count, Some(1));
    let field = section.fields.last().unwrap();
    assert_eq!(field.name.as_ref(), b"x");
    assert_eq!(field.value.as_ref(), b"a");

    let wrapped = b"\x02\x3f\x21\x41x\x01a\x41x\x01b\x41x\x01c\x41x\x01d\x41x\x01e";
    let uneven = b"\x02\x3f\x21\x41x\x02aa\x41x\x01b\x41x\x01c\x41x\x01d\x41x\x01e";
    let limit = Limits {
        max_header_section_bytes: 201,
        ..Limits::default()
    };
    for (encoder, limits, expected) in [
        (
            b"\x02\x3f\x21".as_slice(),
            Limits::default(),
            Code::QpackUnavailable,
        ),
        (wrapped.as_slice(), Limits::default(), Code::QpackAmbiguous),
        (b"\x02\x3f\x21\x41x\x02aa".as_slice(), limit, Code::Limit),
        (uneven.as_slice(), limit, Code::QpackAmbiguous),
        (
            wrapped.as_slice(),
            Limits {
                max_qpack_history_bytes: 1,
                ..Limits::default()
            },
            Code::QpackUnavailable,
        ),
    ] {
        let result = run(encoder, limits);
        let request = result[0].request.as_ref().unwrap();
        assert!(request.issues.iter().any(|issue| issue.code == expected));
        assert!(request.header_sections[0].fields.is_empty());
        let static_request = result[1].request.as_ref().unwrap();
        assert!(static_request.complete);
        assert_eq!(static_request.header_sections[0].kind, SectionKind::Request);
    }
}

#[test]
fn rejects_references_at_or_above_the_required_insert_count_without_history() {
    use quic::Direction::Client;
    for headers in [
        b"\x01\x03\x02\0\x10".as_slice(),
        b"\x01\x05\x02\x01\0\x01x",
        b"\x01\x03\x02\x80\x11",
        b"\x01\x03\x02\x01\x80",
    ] {
        let result = exchanges(vec![stream(0, Client, headers)], Limits::default());
        let issues = &result[0].request.as_ref().unwrap().issues;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, Code::QpackInvalid);
    }
}

#[test]
fn decodes_huffman_literals_and_enforces_decoded_header_limit() {
    use quic::Direction::Client;
    // RFC 7541 Appendix C.4.1 (May 2015) provides the Huffman bytes.
    let data = b"\x01\x13\0\0\xd1\xd7\xc1\x50\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    let result = exchanges(vec![stream(0, Client, data)], Limits::default());
    let request = result[0].request.as_ref().unwrap();
    assert!(request.complete);
    assert_eq!(
        request.header_sections[0]
            .fields
            .last()
            .unwrap()
            .value
            .as_ref(),
        b"www.example.com"
    );

    let limit = Limits {
        max_header_section_bytes: 64,
        ..Limits::default()
    };
    let result = exchanges(vec![stream(0, Client, data)], limit);
    let request = result[0].request.as_ref().unwrap();
    assert!(!request.complete);
    assert!(request.issues.iter().any(|issue| issue.code == Code::Limit));
}

#[test]
fn distinguishes_an_uninspected_stream_from_invalid_or_misplaced_headers() {
    use quic::Direction::{Client, Server};
    let request = b"\x01\x03\0\0\xd1";
    let response = b"\x01\x03\0\0\xd8\0\x01a\x01\x03\0\0\xd9";
    let result = exchanges(
        vec![stream(0, Client, request), stream(0, Server, response)],
        Limits::default(),
    );
    let request = result[0].request.as_ref().unwrap();
    assert!(
        request
            .issues
            .iter()
            .any(|issue| issue.code == Code::InvalidHeaders)
    );
    let response = result[0].response.as_ref().unwrap();
    assert_eq!(response.header_sections[0].status, Some(103));
    assert_eq!(response.header_sections[1].status, Some(200));
    assert!(
        response
            .issues
            .iter()
            .any(|issue| issue.code == Code::InvalidFramePlacement && issue.offset == Some(5))
    );
    assert!(!response.complete);

    let limits = Limits {
        max_steps: 0,
        ..Limits::default()
    };
    let result = exchanges(
        vec![stream(0, Client, b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a")],
        limits,
    );
    let request = result[0].request.as_ref().unwrap();
    assert!(request.issues.iter().any(|issue| issue.code == Code::Limit));
    assert!(
        !request
            .issues
            .iter()
            .any(|issue| issue.code == Code::MissingInitialHeaders)
    );
}

#[test]
fn reports_headers_after_trailers_when_the_evidence_budget_is_exhausted() {
    use quic::Direction::Client;
    let head = b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a";
    let trailers = b"\x01\x06\0\0\x21x\x01y";
    let request = [head.as_slice(), trailers, trailers].concat();
    let result = exchanges(
        vec![stream(0, Client, &request)],
        Limits {
            max_exchange_bytes: 360,
            ..Limits::default()
        },
    );
    let side = result[0].request.as_ref().unwrap();
    assert_eq!(side.header_sections.len(), 2);
    assert_eq!(side.header_sections[1].kind, SectionKind::Trailers);
    let issues: Vec<_> = side
        .issues
        .iter()
        .map(|issue| (issue.code, issue.offset))
        .collect();
    let offset = Some((head.len() + trailers.len()) as u64);
    assert_eq!(
        issues,
        [(Code::InvalidFramePlacement, offset), (Code::Limit, offset)]
    );
}

#[test]
fn recovers_qpack_sections_across_duplicate_insertion_and_eviction() {
    use quic::Direction::{Client, Server};
    // Encoder bytes and references from RFC 9204 Appendix B.2–B.5 (June 2022).
    // See the IETF Trust Revised BSD terms in THIRD_PARTY_NOTICES.md.
    let settings = b"\0\x04\x05\x01\x40\xdc\x07\x02";
    let encoder = b"\x02\x3f\xbd\x01\xc0\x0fwww.example.com\xc1\x0c/sample/path\x4acustom-key\x0ccustom-value\x02\x81\x0dcustom-value2";
    let exchanges = exchanges(
        vec![
            stream(3, Server, settings),
            stream(6, Client, encoder),
            stream(4, Client, b"\x01\x06\x03\x81\xd1\xd7\x10\x11"),
            stream(8, Client, b"\x01\x07\x05\0\xd1\xd7\x80\xc1\x81"),
            stream(12, Client, b"\x01\x09\x06\0\xd1\xd7\xc1\x50\x01a\x80"),
        ],
        Limits::default(),
    );
    let expected: &[(u64, &[u8], &[u8])] = &[
        (2, b":path", b"/sample/path"),
        (4, b"custom-key", b"custom-value"),
        (5, b"custom-key", b"custom-value2"),
    ];
    assert_eq!(exchanges.len(), expected.len());
    for (exchange, &(count, name, value)) in exchanges.iter().zip(expected) {
        let request = exchange.request.as_ref().unwrap();
        assert!(request.complete, "{:?}", request.issues);
        let header = &request.header_sections[0];
        assert_eq!(header.required_insert_count, Some(count));
        let field = header.fields.last().unwrap();
        assert_eq!(field.name.as_ref(), name);
        assert_eq!(field.value.as_ref(), value);
    }
}

#[test]
fn selecting_a_stream_keeps_other_exchanges_from_spending_its_budget() {
    use quic::Direction::Client;
    let busy = [0x21, 0].repeat(1024);
    let request = b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a";
    let result = selected_exchanges(
        vec![stream(0, Client, &busy), stream(4, Client, request)],
        Some(4),
        Limits {
            max_steps: 512,
            ..Limits::default()
        },
    );
    let [exchange] = result.as_slice() else {
        panic!("expected only the selected exchange");
    };
    assert_eq!(exchange.stream, 4);
    let request = exchange.request.as_ref().unwrap();
    assert!(request.complete);
    assert_eq!(request.header_sections[0].method.as_deref(), Some("GET"));
}

#[test]
fn checks_content_length_when_the_body_is_complete_and_allowed() {
    use quic::Direction::{Client, Server};
    let get = b"\x01\x08\0\0\xd1\xd7\xc1\x50\x01a";
    let head = b"\x01\x08\0\0\xd2\xd7\xc1\x50\x01a";
    let response = b"\x01\x06\0\0\xd9\x54\x015";
    let short = [response.as_slice(), b"\0\x03abc"].concat();
    let exact = [response.as_slice(), b"\0\x02ab\0\x03cde"].concat();
    let mut partial = stream(12, Server, &short);
    partial.complete = false;
    partial.final_size = None;
    let result = exchanges(
        vec![
            stream(0, Client, get),
            stream(0, Server, &short),
            stream(4, Client, get),
            stream(4, Server, &exact),
            stream(8, Client, head),
            stream(8, Server, response),
            stream(12, Client, get),
            partial,
            stream(16, Server, &short),
        ],
        Limits::default(),
    );
    assert_eq!(result.len(), 5);
    for (exchange, complete) in result.iter().zip([false, true, true, false, false]) {
        assert_eq!(exchange.response.as_ref().unwrap().complete, complete);
    }
    for index in [0, 4] {
        let issues = &result[index].response.as_ref().unwrap().issues;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, Code::ContentLengthMismatch);
    }
    assert!(result[3].response.as_ref().unwrap().issues.is_empty());
}

#[test]
fn retains_a_decoded_status_after_an_unavailable_header_section() {
    use quic::Direction::Server;
    let response = b"\x01\x03\x02\0\x80\x01\x03\0\0\xd9";
    let result = exchanges(vec![stream(0, Server, response)], Limits::default());
    let side = result[0].response.as_ref().unwrap();
    assert!(!side.complete);
    assert_eq!(side.header_sections[0].status, None);
    assert_eq!(side.header_sections[1].status, Some(200));
    assert_eq!(side.header_sections[1].kind, SectionKind::Unclassified);
}

#[test]
fn retains_decoded_methods_and_statuses_after_unrelated_field_errors() {
    use quic::Direction::{Client, Server};
    let head = b"\x01\x0c\0\0\xd2\xd7\xc1\x50\x01a\x21X\x01y";
    let result = exchanges(
        vec![
            stream(0, Client, head),
            stream(0, Server, b"\x01\x03\0\0\xd9\0\x01x"),
            stream(4, Server, b"\x01\x07\0\0\xd8\x21X\x01y"),
        ],
        Limits::default(),
    );
    let request = result[0].request.as_ref().unwrap();
    assert_eq!(request.header_sections[0].method.as_deref(), Some("HEAD"));
    assert_eq!(request.issues[0].code, Code::InvalidHeaders);
    let response = result[0].response.as_ref().unwrap();
    assert_eq!(response.issues[0].code, Code::UnexpectedResponseContent);

    let response = result[1].response.as_ref().unwrap();
    let section = &response.header_sections[0];
    assert_eq!(section.status, Some(103));
    assert_eq!(section.kind, SectionKind::Informational);
    assert_eq!(response.issues[0].code, Code::InvalidHeaders);
    assert_eq!(response.issues[1].code, Code::MissingFinalResponse);
}

#[test]
fn rejects_invalid_request_targets_and_accepts_equivalent_authorities() {
    use quic::Direction::Client;
    let run = |fields: &[u8]| {
        let length = u8::try_from(fields.len()).unwrap();
        let request = [&[1, length][..], fields].concat();
        exchanges(vec![stream(0, Client, &request)], Limits::default())
    };
    for (fields, complete) in [
        (b"\0\0\xd1\xd7\x51\x03/%Q\x50\x01a".as_slice(), false),
        (b"\0\0\xd1\xd7\xc1\x50\x01a\x24host\x01b", false),
        (b"\0\0\xd1\xd7\xc1\x50\x01a\x24host\x05A:443", true),
        (b"\0\0\xcf\x50\x07a:65535", true),
        (b"\0\0\xcf\x50\x07a:65536", false),
    ] {
        let result = run(fields);
        let side = result[0].request.as_ref().unwrap();
        assert_eq!(side.complete, complete, "{fields:?}");
        if !complete {
            assert!(
                side.issues
                    .iter()
                    .any(|issue| issue.code == Code::InvalidHeaders)
            );
        }
    }
}

#[test]
fn retains_settings_for_qpack_after_a_duplicate_settings_frame() {
    use quic::Direction::{Client, Server};
    let mut control = stream(3, Server, b"\0\x04\x05\x01\x40\x40\x07\x01\x04\0");
    control.complete = false;
    control.final_size = None;
    let input = connection(vec![
        control,
        stream(6, Client, b"\x02\x3f\x21\x41x\x01a"),
        stream(0, Client, b"\x01\x09\x02\x80\xd1\xd7\xc1\x50\x01a\x10"),
    ]);
    let mut server = None;
    let mut request = None;
    inspect(
        &input,
        None,
        Limits::default(),
        &Deadline::new(Duration::MAX),
        &mut |event| {
            match event {
                Event::Connection(connection) => server = Some(connection.server),
                Event::Exchange(exchange) => request = exchange.request,
            }
            Ok(())
        },
    )
    .unwrap();
    let server = server.unwrap();
    assert_eq!(server.max_table_capacity, Some(64));
    assert_eq!(server.qpack_blocked_streams, Some(1));
    assert_eq!(server.issues.len(), 1);
    assert_eq!(server.issues[0].code, Code::InvalidSettings);
    let request = request.unwrap();
    assert!(request.complete, "{:?}", request.issues);
    assert_eq!(request.header_sections[0].required_insert_count, Some(1));
    assert_eq!(
        request.header_sections[0].fields.last().unwrap().value,
        b"a"[..]
    );
}

#[test]
fn diagnoses_a_control_stream_closed_after_settings() {
    use quic::Direction::Client;
    let control = stream(2, Client, b"\0\x04\0");
    let mut reset = stream(2, Client, b"\0\x04\0");
    reset.complete = false;
    reset.reset_error = Some(0x104);
    for ended in [control, reset] {
        let mut observed_settings = None;
        let mut issues = Vec::new();
        inspect(
            &connection(vec![ended]),
            None,
            Limits::default(),
            &Deadline::new(Duration::MAX),
            &mut |event| {
                if let Event::Connection(connection) = event {
                    observed_settings = connection.client.max_table_capacity;
                    issues = connection.client.issues;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(observed_settings, Some(0));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, Code::ClosedControlStream);
    }
}

#[test]
fn open_critical_streams_do_not_mask_a_transport_gap() {
    use quic::Direction::Client;
    let critical = || {
        let mut control = stream(2, Client, b"\0\x04\0");
        control.final_size = None;
        control.complete = false;
        control
    };
    let mut gapped = critical();
    gapped.ranges.push(quic::Range {
        offset: 4,
        data: Bytes::from_static(b"\0"),
    });
    for (closed, control, expected) in [
        (true, critical(), false),
        (false, critical(), true),
        (true, gapped, true),
    ] {
        let mut transport = connection(vec![control]);
        transport.closed = closed;
        let mut observed = None;
        inspect(
            &transport,
            None,
            Limits::default(),
            &Deadline::new(Duration::MAX),
            &mut |event| {
                if let Event::Connection(connection) = event {
                    observed = Some(connection.transport_incomplete);
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(observed, Some(expected));
    }
}

#[test]
fn rejects_nonempty_data_on_bodyless_responses() {
    use quic::Direction::{Client, Server};
    let head = b"\x01\x08\0\0\xd2\xd7\xc1\x50\x01a";
    let cases = [
        (None, b"\x01\x04\0\0\xff\x01".as_slice()),
        (None, b"\x01\x03\0\0\xda".as_slice()),
        (None, b"\x01\x08\0\0\x5f\x09\x03205".as_slice()),
        (Some(head.as_slice()), b"\x01\x03\0\0\xd9".as_slice()),
    ];
    for (request, headers) in cases {
        for (data, complete) in [(b"\0\0".as_slice(), true), (b"\0\x01x", false)] {
            let response = [headers, data].concat();
            let streams = request
                .map(|bytes| stream(0, Client, bytes))
                .into_iter()
                .chain([stream(0, Server, &response)])
                .collect();
            let result = exchanges(streams, Limits::default());
            let side = result[0].response.as_ref().unwrap();
            assert_eq!(side.complete, complete, "{:?}", side.issues);
            assert_eq!(side.data_bytes, u64::from(!complete));
            if !complete {
                assert_eq!(side.issues.len(), 1);
                assert_eq!(side.issues[0].code, Code::UnexpectedResponseContent);
                assert_eq!(side.issues[0].offset, Some(headers.len() as u64));
            }
        }
    }
}

#[test]
fn recognizes_request_trailers_after_unavailable_initial_headers() {
    use quic::Direction::Client;
    let request = b"\x01\x03\x02\0\x80\0\x01x\x01\x06\0\0\x21x\x01y";
    let result = exchanges(vec![stream(0, Client, request)], Limits::default());
    let side = result[0].request.as_ref().unwrap();
    assert!(!side.complete);
    assert_eq!(side.header_sections[1].kind, SectionKind::Trailers);
    assert_eq!(side.header_sections[1].fields[0].value.as_ref(), b"y");
    assert_eq!(side.data_bytes, 1);
    assert_eq!(side.issues.len(), 1);
    assert_eq!(side.issues[0].code, Code::QpackUnavailable);
}

#[test]
fn rejects_headers_on_successful_connect_responses_and_keeps_tunnel_data() {
    use quic::Direction::{Client, Server};
    let connect = b"\x01\x0a\0\0\xcf\x50\x05a:443";
    let tail = b"\x01\x06\0\0\x21x\x01y";
    for (status, trailers, complete) in
        [(0xd9, false, true), (0xd9, true, false), (0xdb, true, true)]
    {
        let mut response = vec![1, 3, 0, 0, status, 0, 1, b'x'];
        if trailers {
            response.extend_from_slice(tail);
        }
        let result = exchanges(
            vec![stream(0, Client, connect), stream(0, Server, &response)],
            Limits::default(),
        );
        assert!(result[0].request.as_ref().unwrap().complete);
        let side = result[0].response.as_ref().unwrap();
        assert_eq!(side.complete, complete, "{:?}", side.issues);
        assert_eq!(side.data_bytes, 1);
        if trailers && complete {
            assert_eq!(side.header_sections[1].kind, SectionKind::Trailers);
        } else if !complete {
            assert!(
                side.issues
                    .iter()
                    .any(|issue| issue.code == Code::InvalidFramePlacement
                        && issue.offset == Some(8))
            );
            assert!(
                side.header_sections
                    .iter()
                    .all(|section| section.kind != SectionKind::Trailers)
            );
        }
    }
}

#[test]
fn reports_forbidden_connect_content_length_before_a_truncated_tunnel_frame() {
    use quic::Direction::{Client, Server};
    let request = b"\x01\x0a\0\0\xcf\x50\x05a:443";
    let mut response = stream(0, Server, b"\x01\x06\0\0\xd9\x54\x011\0\x02x");
    response.complete = false;
    response.final_size = None;
    let result = exchanges(
        vec![stream(0, Client, request), response],
        Limits::default(),
    );
    let response = result[0].response.as_ref().unwrap();
    assert_eq!(response.header_sections[0].status, Some(200));
    let issues: Vec<_> = response
        .issues
        .iter()
        .map(|issue| (issue.code, issue.offset))
        .collect();
    assert_eq!(
        issues,
        [
            (Code::InvalidHeaders, Some(0)),
            (Code::TruncatedFrame, Some(8))
        ]
    );
}

#[test]
fn checks_extended_connect_against_observed_server_settings() {
    use quic::Direction::{Client, Server};
    let request = b"\x01\x15\0\0\xcf\xd7\xc1\x50\x01a\x27\x02:protocol\x01x";
    for (settings, expected) in [
        (Some(b"\0\x04\x02\x08\x01".as_slice()), None),
        (
            Some(b"\0\x04\x02\x08\0".as_slice()),
            Some(Code::ExtendedConnectDisabled),
        ),
        (
            Some(b"\0\x04\0".as_slice()),
            Some(Code::ExtendedConnectDisabled),
        ),
        (
            Some(b"\0\x04\x02\x08\x02".as_slice()),
            Some(Code::ExtendedConnectSettingsUnavailable),
        ),
        (None, Some(Code::ExtendedConnectSettingsUnavailable)),
    ] {
        let mut streams = vec![stream(0, Client, request)];
        if let Some(settings) = settings {
            streams.push(stream(3, Server, settings));
        }
        let result = exchanges(streams, Limits::default());
        let side = result[0].request.as_ref().unwrap();
        assert_eq!(side.complete, expected.is_none(), "{:?}", side.issues);
        assert_eq!(side.issues.len(), usize::from(expected.is_some()));
        assert_eq!(side.issues.first().map(|issue| issue.code), expected);
        assert_eq!(side.header_sections[0].method.as_deref(), Some("CONNECT"));
    }
}

fn client_critical_issues(streams: Vec<quic::Stream>, limits: Limits) -> Vec<Code> {
    let mut issues = Vec::new();
    inspect(
        &connection(streams),
        None,
        limits,
        &Deadline::new(Duration::MAX),
        &mut |event| {
            if let Event::Connection(connection) = event {
                issues.extend(connection.client.issues.into_iter().map(|issue| issue.code));
            }
            Ok(())
        },
    )
    .unwrap();
    issues
}

#[test]
fn reports_qpack_stream_closure_even_at_instruction_boundaries() {
    use quic::Direction::Client;
    for (kind, reset) in [(2, false), (3, false), (2, true), (3, true)] {
        let mut qpack = stream(6, Client, &[kind]);
        if reset {
            qpack.complete = false;
            qpack.reset_error = Some(0x104);
        }
        let mut control = stream(2, Client, b"\0\x04\0");
        control.complete = false;
        control.final_size = None;
        let issues = client_critical_issues(vec![control, qpack], Limits::default());
        let expected = if kind == 2 {
            Code::ClosedQpackEncoderStream
        } else {
            Code::ClosedQpackDecoderStream
        };
        assert_eq!(issues, vec![expected]);
    }
}

#[test]
fn reports_duplicate_qpack_decoder_streams_from_one_peer() {
    use quic::Direction::{Client, Server};
    let open = |id, direction| quic::Stream {
        complete: false,
        final_size: None,
        ..stream(id, direction, b"\x03")
    };
    let mut control = stream(2, Client, b"\0\x04\0");
    control.complete = false;
    control.final_size = None;
    let streams = vec![control, open(6, Client), open(7, Server)];
    assert!(client_critical_issues(streams.clone(), Limits::default()).is_empty());
    let issues = client_critical_issues(
        [streams, vec![open(10, Client)]].concat(),
        Limits::default(),
    );
    assert_eq!(issues, vec![Code::DuplicateCriticalStream]);
}

#[test]
fn distinguishes_missing_final_response_from_missing_initial_headers() {
    use quic::Direction::Server;
    let mut open = stream(8, Server, b"\x01\x03\0\0\xd8");
    open.complete = false;
    open.final_size = None;
    let result = exchanges(
        vec![
            stream(0, Server, b""),
            stream(4, Server, b"\x01\x03\0\0\xd8"),
            open,
        ],
        Limits::default(),
    );
    let empty = result[0].response.as_ref().unwrap();
    assert_eq!(empty.issues[0].code, Code::MissingInitialHeaders);
    let closed = result[1].response.as_ref().unwrap();
    assert!(!closed.complete);
    assert_eq!(closed.header_sections[0].status, Some(103));
    assert_eq!(closed.issues.len(), 1);
    assert_eq!(closed.issues[0].code, Code::MissingFinalResponse);
    assert!(result[2].response.as_ref().unwrap().issues.is_empty());
}

#[test]
fn rejects_trailers_on_bodyless_statuses() {
    use quic::Direction::Server;
    let trailers = b"\x01\x06\0\0\x21x\x01y";
    for headers in [b"\x01\x04\0\0\xff\x01".as_slice(), b"\x01\x03\0\0\xda"] {
        let response = [headers, trailers].concat();
        let result = exchanges(vec![stream(0, Server, &response)], Limits::default());
        let side = result[0].response.as_ref().unwrap();
        assert!(!side.complete);
        assert_eq!(side.header_sections.len(), 1);
        assert_eq!(side.issues.len(), 1);
        assert_eq!(side.issues[0].code, Code::InvalidFramePlacement);
        assert_eq!(side.issues[0].offset, Some(headers.len() as u64));
    }
}

#[test]
fn only_successful_connect_disallows_later_request_headers() {
    use quic::Direction::{Client, Server};
    let headers = b"\x01\x0b\0\0\xcf\x50\x05a:443\xc4";
    let data = b"\0\x01x";
    let trailers = b"\x01\x06\0\0\x21x\x01y";
    for (status, before_data, data, after_data, complete) in [
        (0xd9, b"".as_slice(), data.as_slice(), b"".as_slice(), true),
        (
            0xd9,
            trailers.as_slice(),
            data.as_slice(),
            b"".as_slice(),
            false,
        ),
        (
            0xdb,
            b"".as_slice(),
            b"".as_slice(),
            trailers.as_slice(),
            true,
        ),
    ] {
        let request = [headers.as_slice(), before_data, data, after_data].concat();
        let response = [1, 3, 0, 0, status];
        let result = exchanges(
            vec![stream(0, Client, &request), stream(0, Server, &response)],
            Limits::default(),
        );
        let side = result[0].request.as_ref().unwrap();
        assert_eq!(side.complete, complete);
        assert_eq!(side.data_bytes, u64::from(!data.is_empty()));
        if !complete {
            assert_eq!(side.issues.len(), 1);
            assert_eq!(side.issues[0].code, Code::InvalidFramePlacement);
            assert_eq!(side.issues[0].offset, Some(headers.len() as u64));
            assert_eq!(side.header_sections.len(), 1);
        } else if status == 0xdb {
            assert_eq!(side.header_sections[1].kind, SectionKind::Trailers);
        }
    }
}

#[test]
fn illegal_tunnel_headers_do_not_spend_the_response_header_budget() {
    use quic::Direction::{Client, Server};
    let headers = b"\x01\x0a\0\0\xcf\x50\x05a:443";
    let trailer = b"\x01\x06\0\0\x21x\x01y";
    let request = [headers.as_slice(), &trailer.repeat(4), b"\0\x01x"].concat();
    let response = b"\x01\x03\0\0\xd9";
    let result = exchanges(
        vec![stream(0, Client, &request), stream(0, Server, response)],
        Limits {
            max_exchange_bytes: 300,
            ..Limits::default()
        },
    );
    let request = result[0].request.as_ref().unwrap();
    let response = result[0].response.as_ref().unwrap();
    assert!(response.complete);
    assert_eq!(response.header_sections[0].status, Some(200));
    assert_eq!(request.data_bytes, 1);
    assert!(!request.complete);
    assert_eq!(request.issues.len(), 4);
    assert!(
        request
            .issues
            .iter()
            .all(|issue| issue.code == Code::InvalidFramePlacement)
    );
}

#[test]
fn connect_request_retains_frame_diagnostics_under_shared_work_limit() {
    use quic::Direction::{Client, Server};
    let request = b"\x01\x0a\0\0\xcf\x50\x05a:443\x01\x02\0\0\0\x01x";
    let response = [b"\x01\x03\0\0\xd9".as_slice(), &b"\0\0".repeat(256)].concat();
    let result = exchanges(
        vec![stream(0, Client, request), stream(0, Server, &response)],
        Limits {
            max_steps: 256,
            ..Limits::default()
        },
    );
    let request = result[0].request.as_ref().unwrap();
    let response = result[0].response.as_ref().unwrap();
    assert_eq!(request.issues[0].code, Code::InvalidFramePlacement);
    assert_eq!(request.data_bytes, 1);
    assert_eq!(response.header_sections[0].status, Some(200));
    assert_eq!(response.issues[0].code, Code::Limit);
}

#[test]
fn classifies_encoder_capacity_violations_separately_from_history_limits() {
    use quic::Direction::{Client, Server};
    let with_instructions = |capacity: u8, encoder: &[u8], limits| {
        let streams = vec![
            stream(2, Client, b"\0\x04\0"),
            stream(3, Server, &[0, 4, 3, 1, 0x40, capacity]),
            stream(6, Client, encoder),
        ]
        .into_iter()
        .map(|stream| quic::Stream {
            complete: false,
            final_size: None,
            ..stream
        })
        .collect();
        client_critical_issues(streams, limits)
    };
    let limits = Limits::default();
    assert!(with_instructions(0, b"\x02", limits).is_empty());
    // Capacity 34 leaves two bytes for the name and value of an entry.
    for instructions in [
        b"\x02\x3f\x03\x43abc\0".as_slice(),
        b"\x02\x3f\x03\x41x\x02yz",
        b"\x02\x3f\x03\xc0\0",
        b"\x02\x3f\x03\x41x\x82\x00\x3f",
    ] {
        assert_eq!(
            with_instructions(34, instructions, limits),
            [Code::QpackEncoderError]
        );
    }
    let valid = b"\x02\x3f\x03\x41x\x01y";
    assert!(with_instructions(34, valid, limits).is_empty());
    assert_eq!(
        with_instructions(
            34,
            valid,
            Limits {
                max_qpack_history_bytes: 32,
                ..limits
            }
        ),
        [Code::Limit]
    );
    let limits = Limits {
        max_steps: 24,
        ..limits
    };
    let small_table = [b"\x02\x3f\x03\x41x\x1e".as_slice(), &[b'y'; 30]].concat();
    let large_table = [b"\x02\x3f\x20\x41x\x1e".as_slice(), &[b'y'; 30]].concat();
    let compressed = [b"\x02\x3f\x03\x41x\x9e".as_slice(), &[0; 30]].concat();
    for instructions in [&small_table, &compressed] {
        assert_eq!(
            with_instructions(34, instructions, limits),
            [Code::QpackEncoderError]
        );
    }
    assert_eq!(with_instructions(63, &large_table, limits), [Code::Limit]);
}

#[test]
fn rejects_encoder_instructions_when_peer_capacity_is_zero() {
    use quic::Direction::{Client, Server};
    let open = |id, direction, bytes: &[u8]| quic::Stream {
        final_size: None,
        complete: false,
        ..stream(id, direction, bytes)
    };
    let streams = vec![
        open(2, Client, b"\0\x04\0"),
        open(3, Server, b"\0\x04\0"),
        open(6, Client, b"\x02\x20"),
    ];
    assert_eq!(
        client_critical_issues(streams, Limits::default()),
        [Code::QpackEncoderError]
    );
}
