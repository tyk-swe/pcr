// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::tls_capture::{Capture, Stream};
use common::{reader, registry};
use packetcraftr_core::{
    analysis::{self, Options, StreamRef, StreamTransport, http, stats, tls, websocket},
    error::BoundaryError,
};
use std::time::Duration;

#[test]
fn websocket_upgrade_segmented_masked_continuations_and_control_frames() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 80;
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    );
    capture.server(
        &mut stream,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    );
    capture.client(&mut stream, &[0x01, 0x82, 1, 2]);
    capture.client(&mut stream, &[3, 4, b'h' ^ 1, b'i' ^ 2]);
    capture.client(&mut stream, &[0x89, 0x81, 1, 2, 3, 4, b'?' ^ 1]);
    capture.client(&mut stream, &[0x80, 0x81, 1, 2, 3, 4, b'!' ^ 1]);
    let mut collector = websocket::Collector::new(
        StreamRef {
            transport: StreamTransport::Tcp,
            index: 0,
        },
        websocket::Limits::default(),
        false,
    )
    .unwrap();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            events.extend(collector.observe(&record)?);
            Ok(())
        },
    )
    .unwrap();
    let (last, summary) = collector.finish(&run).unwrap();
    events.extend(last);
    assert_eq!(summary.messages, 1);
    assert_eq!(summary.control_frames, 1);
    assert!(events.iter().any(|event| matches!(event,websocket::Event::Message {bytes,opcode:1,..} if bytes.as_ref()==b"hi!")));
    assert!(events.iter().any(|event| matches!(event,websocket::Event::Control {bytes,opcode:9,..} if bytes.as_ref()==b"?")));
}

#[test]
fn websocket_data_frames_after_close_are_rejected_per_direction() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    capture.client(&mut stream, &[0x81, 0x01, b'a']);
    capture.client(&mut stream, &[0x88, 0x00]);
    capture.client(&mut stream, &[0x81, 0x01, b'b']);
    capture.server(&mut stream, &[0x89, 0x00]);
    capture.server(&mut stream, &[0x81, 0x01, b'c']);
    let mut collector = websocket::Collector::new(
        StreamRef {
            transport: StreamTransport::Tcp,
            index: 0,
        },
        websocket::Limits::default(),
        true,
    )
    .unwrap();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            events.extend(collector.observe(&record)?);
            Ok(())
        },
    )
    .unwrap();
    let (last, summary) = collector.finish(&run).unwrap();
    events.extend(last);
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.control_frames, 2);
    assert_eq!(summary.malformed_frames, 1);
    assert!(
        events.iter().any(
            |event| matches!(event,websocket::Event::Message {bytes,..} if bytes.as_ref()==b"a")
        )
    );
    assert!(
        events.iter().any(
            |event| matches!(event,websocket::Event::Message {bytes,..} if bytes.as_ref()==b"c")
        )
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, websocket::Event::Control { opcode: 8, .. }))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, websocket::Event::Control { opcode: 9, .. }))
    );
    assert!(events.iter().any(|event| matches!(event,
        websocket::Event::Issue { direction: analysis::follow::PeerDirection::ClientToServer, reason, .. }
        if reason.contains("close"))));
    assert!(
        !events.iter().any(
            |event| matches!(event,websocket::Event::Message {bytes,..} if bytes.as_ref()==b"b")
        )
    );
}

#[test]
fn websocket_conflicting_retransmissions_stop_ambiguous_framing_until_stream_reuse() {
    use packetcraftr_core::protocol::transport::Tcp;

    for (prefix, retransmission, tail, conflicting) in [
        (
            b"\x82\x03a".as_slice(),
            b"\x82\x03X".as_slice(),
            b"bc".as_slice(),
            true,
        ),
        (
            b"\x82\x03a".as_slice(),
            b"\x82\x03Xbc".as_slice(),
            b"".as_slice(),
            true,
        ),
        (
            b"\x02\x01a".as_slice(),
            b"\x02\x01X".as_slice(),
            b"\x80\x02bc".as_slice(),
            true,
        ),
        (
            b"\x82\x03a".as_slice(),
            b"\x82\x03a".as_slice(),
            b"bc".as_slice(),
            false,
        ),
    ] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.open(&mut stream);
        let spec = capture.client_spec(&stream, Tcp::ACK);
        capture.client(&mut stream, prefix);
        capture.push(spec, retransmission);
        capture.client(&mut stream, tail);
        capture.server(&mut stream, b"\x82\x02ok");
        capture.reopen(&mut stream, 10000);
        capture.client(&mut stream, b"\x82\x03new");

        let collector = websocket::Collector::new(
            StreamRef {
                transport: StreamTransport::Tcp,
                index: 0,
            },
            websocket::Limits::default(),
            true,
        )
        .unwrap();
        let mut events = Vec::new();
        let outcome = analysis::Session::new(registry(), Options::default(), collector, None)
            .run(
                &mut reader(&capture.frames),
                |_| Ok(()),
                |event| {
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(outcome.summary.malformed_frames, u64::from(conflicting));
        assert_eq!(outcome.summary.messages, if conflicting { 2 } else { 3 });
        assert_eq!(outcome.summary.incomplete_messages, 0);
        let messages: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                websocket::Event::Message { bytes, .. } => Some(bytes.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(messages.contains(&b"abc".as_slice()), !conflicting);
        assert!(messages.contains(&b"ok".as_slice()));
        assert!(messages.contains(&b"new".as_slice()));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event,
                    websocket::Event::Issue { number: 5, reason, .. }
                        if reason.contains("conflicting TCP retransmission")
                ))
                .count(),
            usize::from(conflicting)
        );
    }
}

#[test]
fn websocket_conflicts_in_pending_bytes_are_reported_and_charge_evidence_limits() {
    use packetcraftr_core::protocol::transport::Tcp;

    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    let mut pending = capture.client_spec(&stream, Tcp::ACK);
    pending.sequence += 2;
    capture.push(pending.clone(), b"abc");
    capture.push(pending, b"Xbc");
    capture.client(&mut stream, b"\x82\x03");
    for maximum in [1, websocket::Limits::default().max_retained_bytes] {
        let collector = websocket::Collector::new(
            StreamRef {
                transport: StreamTransport::Tcp,
                index: 0,
            },
            websocket::Limits {
                max_retained_bytes: maximum,
                ..Default::default()
            },
            true,
        )
        .unwrap();
        let mut events = Vec::new();
        let outcome = analysis::Session::new(registry(), Options::default(), collector, None).run(
            &mut reader(&capture.frames),
            |_| Ok(()),
            |event| {
                events.push(event);
                Ok(())
            },
        );
        if maximum == 1 {
            let analysis::Error::Sink { source, .. } = outcome.err().unwrap() else {
                panic!("expected a collector evidence-limit error");
            };
            assert!(source.to_string().contains("retained evidence limit"));
        } else {
            let outcome = outcome.unwrap();
            assert_eq!(outcome.summary.messages, 0);
            assert_eq!(outcome.summary.malformed_frames, 1);
            assert!(matches!(
                events.as_slice(),
                [websocket::Event::Issue { .. }]
            ));
        }
    }
}

#[test]
fn websocket_limits_count_each_message_in_one_delivery_and_final_issues() {
    let selector = StreamRef {
        transport: StreamTransport::Tcp,
        index: 0,
    };
    for payload in [
        b"\x82\x01a\x82\x01b".as_slice(),
        b"\x82\x01a\x89\x01b".as_slice(),
    ] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.open(&mut stream);
        capture.client(&mut stream, payload);
        let mut collector = websocket::Collector::new(
            selector,
            websocket::Limits {
                max_messages: 1,
                ..Default::default()
            },
            true,
        )
        .unwrap();
        let error = analysis::run(
            &mut reader(&capture.frames),
            registry(),
            &Options {
                tcp_events: true,
                ..Default::default()
            },
            |record| {
                collector.observe(&record)?;
                Ok(())
            },
        )
        .unwrap_err();
        let analysis::Error::Sink { source, .. } = error else {
            panic!("{error}");
        };
        assert!(
            source.to_string().contains("message count limit"),
            "{source}"
        );
    }
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    capture.client(&mut stream, b"\x82\x01");
    let mut collector = websocket::Collector::new(
        selector,
        websocket::Limits {
            max_retained_bytes: 1,
            ..Default::default()
        },
        true,
    )
    .unwrap();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            collector.observe(&record)?;
            Ok(())
        },
    )
    .unwrap();
    assert!(
        collector
            .finish(&run)
            .unwrap_err()
            .to_string()
            .contains("retained evidence limit")
    );
}

#[test]
fn http_entities_are_streamed_after_transfer_decoding_and_before_completion() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 80;
    capture.open(&mut stream);
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na",
    );
    capture.server(&mut stream, b"bc\r\n2\r\nde\r\n0\r\n\r\n");
    let collector = http::Collector::new(
        analysis::application::Limits::default(),
        [80],
        16 * 1024 * 1024,
    )
    .unwrap()
    .with_body_chunks();
    let (events, summary) = common::http::collect_events(&capture.frames, collector);
    let body: Vec<u8> = events
        .iter()
        .filter_map(|event| {
            if let http::Event::BodyChunk { bytes, .. } = event {
                Some(bytes.as_ref())
            } else {
                None
            }
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(body, b"abcde");
    assert_eq!(summary.complete_messages, 2);
    assert!(
        matches!(events.last(),Some(http::Event::Message(message)) if message.status==http::Status::Complete && message.body_bytes==5)
    );
}

#[test]
fn tls12_certificates_cross_records_and_tls13_reports_encryption() {
    use common::tls_frames::{
        ClientHelloSpec, ServerHelloSpec, TLS_1_2, client_hello, handshake_record,
        handshake_records, server_hello,
    };
    for encrypted in [false, true] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.open(&mut stream);
        capture.client(
            &mut stream,
            &handshake_record(&client_hello(&ClientHelloSpec::default())),
        );
        let mut server = ServerHelloSpec::default();
        if !encrypted {
            server.selected_version = Some(TLS_1_2);
        }
        capture.server(&mut stream, &handshake_record(&server_hello(&server)));
        if !encrypted {
            let certificate = [11, 0, 0, 9, 0, 0, 6, 0, 0, 3, 1, 2, 3];
            for segment in handshake_records(&certificate, 5).chunks(3) {
                capture.server(&mut stream, segment);
            }
        }
        let mut collector = tls::Collector::new(tls::Limits::default())
            .unwrap()
            .with_certificates();
        let mut events = Vec::new();
        let run = analysis::run(
            &mut reader(&capture.frames),
            registry(),
            &Options {
                tcp_events: true,
                ..Default::default()
            },
            |record| {
                events.extend(collector.observe(&record));
                Ok(())
            },
        )
        .unwrap();
        let (last, _) = collector.finish(&run);
        events.extend(last);
        assert_eq!(events.len(), 1);
        let chain = events[0].session.certificates.as_ref().unwrap();
        assert_eq!(
            chain.status,
            if encrypted {
                tls::CertificateStatus::Encrypted
            } else {
                tls::CertificateStatus::Complete
            }
        );
        if !encrypted {
            assert_eq!(chain.entries[0].der.as_ref(), [1, 2, 3]);
        }
    }
}

#[test]
fn certificates_without_client_hello_retain_the_chain_and_missing_hello_gap() {
    use common::tls_frames::{ServerHelloSpec, TLS_1_2, handshake_record, server_hello};

    for (version, segmented) in [(TLS_1_2, false), (TLS_1_2, true), (0x0304, false)] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        let mut payload = handshake_record(&server_hello(&ServerHelloSpec {
            selected_version: Some(version),
            ..Default::default()
        }));
        if version == TLS_1_2 {
            payload.extend(handshake_record(&[11, 0, 0, 9, 0, 0, 6, 0, 0, 3, 1, 2, 3]));
        }
        if segmented {
            for bytes in payload.chunks(3) {
                capture.server(&mut stream, bytes);
            }
        } else {
            capture.server(&mut stream, &payload);
        }
        let collector = tls::Collector::new(tls::Limits::default())
            .unwrap()
            .with_certificates();
        let mut events = Vec::new();
        let outcome = analysis::Session::new(registry(), Options::default(), collector, None)
            .run(
                &mut reader(&capture.frames),
                |_| Ok(()),
                |event| {
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(outcome.summary.by_status.get(&tls::Status::Gap), Some(&1));
        let session = &events[0].session;
        assert_eq!(session.status, tls::Status::Gap);
        assert_eq!(session.reason.as_deref(), Some("no ClientHello observed"));
        assert!(session.client.is_none());
        assert!(session.server.is_some());
        let chain = session.certificates.as_ref().unwrap();
        if version == TLS_1_2 {
            assert_eq!(chain.status, tls::CertificateStatus::Complete);
            assert_eq!(chain.entries.len(), 1);
            assert_eq!(chain.entries[0].der.as_ref(), [1, 2, 3]);
        } else {
            assert_eq!(chain.status, tls::CertificateStatus::Encrypted);
            assert!(chain.entries.is_empty());
        }
    }
}

#[test]
fn certificates_without_client_hello_keep_gap_evidence_when_no_chain_arrives() {
    use common::tls_frames::{
        ServerHelloSpec, TLS_1_2, change_cipher_spec, handshake_record, server_hello,
    };
    use packetcraftr_core::protocol::transport::Tcp;

    for ending in ["capture", "fin", "cipher"] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.server(
            &mut stream,
            &handshake_record(&server_hello(&ServerHelloSpec {
                selected_version: Some(TLS_1_2),
                ..Default::default()
            })),
        );
        match ending {
            "fin" => capture.push(capture.server_spec(&stream, Tcp::FIN | Tcp::ACK), &[]),
            "cipher" => capture.server(&mut stream, &change_cipher_spec()),
            _ => {}
        }
        let collector = tls::Collector::new(tls::Limits::default())
            .unwrap()
            .with_certificates();
        let mut events = Vec::new();
        let outcome = analysis::Session::new(registry(), Options::default(), collector, None)
            .run(
                &mut reader(&capture.frames),
                |_| Ok(()),
                |event| {
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(events.len(), 1, "{ending}");
        assert_eq!(outcome.summary.by_status.get(&tls::Status::Gap), Some(&1));
        let session = &events[0].session;
        assert_eq!(session.status, tls::Status::Gap);
        assert_eq!(session.reason.as_deref(), Some("no ClientHello observed"));
        let chain = session.certificates.as_ref().unwrap();
        assert!(chain.entries.is_empty());
        assert_eq!(
            chain.status,
            if ending == "cipher" {
                tls::CertificateStatus::NotObserved
            } else {
                tls::CertificateStatus::Incomplete
            }
        );
    }
}

#[test]
fn timing_and_sizes_are_public_stats_tables() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    capture.client(&mut stream, b"abc");
    capture.server(&mut stream, b"def");
    let mut collector = stats::Collector::new(Duration::from_secs(1)).unwrap();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options::default(),
        |record| {
            collector.observe(&record);
            Ok::<_, BoundaryError>(())
        },
    )
    .unwrap();
    let report = collector.finish(&run);
    assert_eq!(report.sizes.iter().map(|bin| bin.frames).sum::<u64>(), 5);
    assert_eq!(report.tcp_timing.len(), 1);
    let timing = &report.tcp_timing[0];
    assert_eq!(
        timing.handshake_syn_to_syn_ack,
        Some(Duration::from_secs(1))
    );
    assert_eq!(timing.handshake_syn_to_ack, Some(Duration::from_secs(2)));
    assert!(timing.ack_rtt_a_to_b.count > 0 || timing.ack_rtt_b_to_a.count > 0);
}

#[test]
fn websocket_upgrade_roles_and_partial_messages_are_diagnostic() {
    for (response, frame, expected_malformed) in [
        (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".as_slice(), b"\x81\x01a".as_slice(), true),
        (b"GET /other HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".as_slice(), b"\x81\x81\x01\x02\x03\x04\x60".as_slice(), true),
        (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".as_slice(), b"\x81\x82\x01\x02\x03\x04\x60".as_slice(), false),
    ] {
        let mut capture = Capture::new(); let mut stream = Stream::new(40000); stream.server_port = 80; capture.open(&mut stream);
        capture.client(&mut stream,b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");capture.server(&mut stream,response);capture.client(&mut stream,frame);
        let mut collector = websocket::Collector::new(StreamRef { transport:StreamTransport::Tcp,index:0 },websocket::Limits::default(),false).unwrap();let mut events=Vec::new();let run=analysis::run(&mut reader(&capture.frames),registry(),&Options {tcp_events:true,..Default::default()},|record|{events.extend(collector.observe(&record)?);Ok(())}).unwrap();let (last,summary)=collector.finish(&run).unwrap();events.extend(last);
        assert_eq!(summary.messages,0);assert!(events.iter().any(|event|matches!(event,websocket::Event::Issue {..})));if expected_malformed {assert!(summary.malformed_frames>0);}else {assert_eq!(summary.incomplete_messages,1);}
    }
}

#[test]
fn tls_certificate_count_and_incomplete_collection_remain_explicit() {
    use common::tls_frames::{
        ClientHelloSpec, ServerHelloSpec, TLS_1_2, client_hello, handshake_record, server_hello,
    };
    for (chain, expected) in [
        (
            {
                let mut body = vec![0, 0, 132];
                for _ in 0..33 {
                    body.extend([0, 0, 1, 0x30]);
                }
                let mut handshake = vec![11, 0, 0, 135];
                handshake.extend(body);
                handshake
            },
            tls::CertificateStatus::Limit,
        ),
        (
            vec![11, 0, 0, 9, 0, 0, 7, 0, 0, 3, 1, 2, 3],
            tls::CertificateStatus::Malformed,
        ),
        (vec![11, 0, 0, 9, 0, 0], tls::CertificateStatus::Incomplete),
    ] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40000);
        capture.open(&mut stream);
        capture.client(
            &mut stream,
            &handshake_record(&client_hello(&ClientHelloSpec::default())),
        );
        capture.server(
            &mut stream,
            &handshake_record(&server_hello(&ServerHelloSpec {
                selected_version: Some(TLS_1_2),
                ..Default::default()
            })),
        );
        capture.server(&mut stream, &handshake_record(&chain));
        let mut collector = tls::Collector::new(tls::Limits::default())
            .unwrap()
            .with_certificates();
        let mut events = Vec::new();
        let run = analysis::run(
            &mut reader(&capture.frames),
            registry(),
            &Options {
                tcp_events: true,
                ..Default::default()
            },
            |record| {
                events.extend(collector.observe(&record));
                Ok(())
            },
        )
        .unwrap();
        let (last, _) = collector.finish(&run);
        events.extend(last);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].session.certificates.as_ref().unwrap().status,
            expected
        );
        if expected == tls::CertificateStatus::Limit {
            assert_eq!(events[0].session.status, tls::Status::Complete);
        } else if expected == tls::CertificateStatus::Malformed {
            assert_eq!(events[0].session.status, tls::Status::Malformed);
        }
    }
}

#[test]
fn websocket_disabled_directions_discard_deliveries_without_charging_buffer() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    capture.open(&mut stream);
    capture.client(&mut stream, &[0x83, 0]);
    capture.client(&mut stream, &[0; 64]);
    capture.server(&mut stream, &[0x82, 1, b'a']);
    let mut collector = websocket::Collector::new(
        StreamRef {
            transport: StreamTransport::Tcp,
            index: 0,
        },
        websocket::Limits {
            max_buffered_bytes: 8,
            ..Default::default()
        },
        true,
    )
    .unwrap();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            events.extend(collector.observe(&record)?);
            Ok(())
        },
    )
    .unwrap();
    let (_, summary) = collector.finish(&run).unwrap();
    assert_eq!(summary.malformed_frames, 1);
    assert_eq!(summary.messages, 1);
    assert!(events.iter().any(|event| matches!(event,
        websocket::Event::Message { bytes, .. } if bytes.as_ref() == b"a")));
}

#[test]
fn websocket_stream_reuse_requires_fresh_upgrade_in_both_directions() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 80;
    capture.open(&mut stream);
    for generation in 0..2 {
        if generation != 0 {
            capture.reopen(&mut stream, 10000);
        }
        capture.client(
            &mut stream,
            b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        capture.server(&mut stream,b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        capture.client(&mut stream, b"\x81\x81\x01\x02\x03\x04\x60");
    }
    let mut collector = websocket::Collector::new(
        StreamRef {
            transport: StreamTransport::Tcp,
            index: 0,
        },
        websocket::Limits::default(),
        false,
    )
    .unwrap();
    let run = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            collector.observe(&record)?;
            Ok(())
        },
    )
    .unwrap();
    let (_, summary) = collector.finish(&run).unwrap();
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.malformed_frames, 0);
}
