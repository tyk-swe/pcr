// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::tls_capture::{Capture, Stream};
use packetcraftr_core::analysis::{self, Options, Session, application, dns, http};
use packetcraftr_core::build::{Builder, Options as BuildOptions};
use packetcraftr_core::codec::Addresses;
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use std::time::{Duration, UNIX_EPOCH};

fn tcp_capture(port: u16, wire: &[u8], segment: usize) -> Capture {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = port;
    capture.open(&mut stream);
    for bytes in wire.chunks(segment) {
        capture.client(&mut stream, bytes);
    }
    capture
}

fn http_message(capture: &Capture) -> http::Message {
    let mut messages = Vec::new();
    Session::new(
        capture.registry.clone(),
        Options::default(),
        http::Collector::new(application::Limits::default(), [80], 8192).unwrap(),
    )
    .run(
        &mut common::reader(&capture.frames),
        |_| Ok(()),
        |event| {
            if let http::Event::Message(message) = event {
                messages.push(*message);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(messages.len(), 1);
    messages.pop().unwrap()
}

#[test]
fn segmented_http_preserves_wire_meaning_and_each_physical_contributor() {
    let head = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1024\r\n\r\n";
    let mut wire = head.to_vec();
    wire.extend(std::iter::repeat_n(b'x', 1024));
    for size in [1, 7, 64, wire.len()] {
        let capture = tcp_capture(80, &wire, size);
        let message = http_message(&capture);
        assert_eq!(message.status, http::Status::Complete);
        assert_eq!(message.header_wire.as_ref(), head);
        assert_eq!(message.body_bytes, 1024);
        assert_eq!(
            message
                .sources
                .frames()
                .iter()
                .map(|source| source.number)
                .collect::<Vec<_>>(),
            (4..=capture.frames.len() as u64).collect::<Vec<_>>()
        );
        let snapshot = message.sources.clone();
        drop(message);
        assert_eq!(snapshot.len(), wire.len().div_ceil(size));
        assert!(matches!(
            snapshot.union(&http_message(&capture).sources),
            Err(analysis::provenance::Error::DifferentCapture)
        ));
    }
}

#[test]
fn reordered_and_duplicate_tcp_contributions_preserve_exact_http_sources() {
    let wire = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let mut capture = tcp_capture(80, wire, 4);
    // Physical arrival order differs from transport byte order. A retransmission
    // after assembly is captured but contributes no newly delivered bytes.
    capture.frames.swap(3, 4);
    let duplicate = capture.frames[3].clone();
    let contributing = capture.frames.len() as u64;
    capture.frames.push(duplicate);
    for (index, frame) in capture.frames.iter_mut().enumerate() {
        frame.timestamp = Some(UNIX_EPOCH + Duration::from_secs(index as u64 + 1));
    }
    let message = http_message(&capture);
    assert_eq!(message.status, http::Status::Complete);
    assert_eq!(message.header_wire.as_ref(), wire);
    assert_eq!(
        message
            .sources
            .iter()
            .map(|source| source.number)
            .collect::<Vec<_>>(),
        (4..=contributing).collect::<Vec<_>>()
    );
}

#[test]
fn segmented_tcp_dns_freezes_message_and_transaction_sources() {
    let dns_wire = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01a\x00\x00\x01\x00\x01";
    let mut wire = (dns_wire.len() as u16).to_be_bytes().to_vec();
    wire.extend_from_slice(dns_wire);
    for size in [1, 3, wire.len()] {
        let capture = tcp_capture(53, &wire, size);
        let mut messages = Vec::new();
        let mut transactions = Vec::new();
        Session::new(
            capture.registry.clone(),
            Options::default(),
            dns::Collector::new(application::Limits::default(), [53]).unwrap(),
        )
        .run(
            &mut common::reader(&capture.frames),
            |_| Ok(()),
            |event| {
                match event {
                    dns::Event::Message(message) => messages.push(*message),
                    dns::Event::Transaction(transaction) => transactions.push(transaction),
                    dns::Event::Issue(_) => {}
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].status, dns::Status::Complete);
        assert_eq!(messages[0].wire.as_ref(), dns_wire);
        assert_eq!(
            messages[0]
                .sources
                .iter()
                .map(|source| source.number)
                .collect::<Vec<_>>(),
            (4..=capture.frames.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(transactions.len(), 1);
        assert_eq!(transactions[0].status, dns::TransactionStatus::Unanswered);
        assert_eq!(
            transactions[0].sources.frames(),
            messages[0].sources.frames()
        );
    }
}

fn fragments(chunk: usize) -> Vec<Frame> {
    let payload = [7u8; 96];
    let registry = common::registry();
    let mut frames = Vec::new();
    for (index, bytes) in payload.chunks(chunk).enumerate() {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: common::CLIENT,
            destination: common::SERVER,
            protocol: WireValue::Exact(253),
            identification: 0x321,
            more_fragments: (index + 1) * chunk < payload.len(),
            fragment_offset: (index * chunk / 8) as u16,
            ..Ipv4::default()
        });
        packet.push(Raw::new(bytes.to_vec()));
        let built = Builder::new(registry.clone())
            .build(packet, Addresses::default(), BuildOptions::default())
            .unwrap();
        frames.push(
            Frame::new(
                UNIX_EPOCH + Duration::from_secs(index as u64 + 1),
                LinkType::IPV4,
                built.bytes,
            )
            .unwrap(),
        );
    }
    frames
}

#[test]
fn reordered_duplicate_fragments_freeze_all_capture_order_contributors() {
    for chunk in [8, 16, 32] {
        let mut frames = fragments(chunk);
        frames.swap(0, 1);
        frames.insert(1, frames[0].clone());
        let mut sources = Vec::new();
        analysis::run(
            &mut common::reader(&frames),
            common::registry(),
            &Options {
                track_sources: true,
                ..Options::default()
            },
            |record| {
                for derived in record.derived_datagrams() {
                    assert_eq!(&derived.decoded.frame.bytes()[20..], &[7u8; 96]);
                    sources.push(derived.sources.clone().unwrap());
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(
            sources[0]
                .iter()
                .map(|source| source.number)
                .collect::<Vec<_>>(),
            (1..=frames.len() as u64).collect::<Vec<_>>()
        );
    }
}

#[test]
fn provenance_limit_refuses_assembly_without_success() {
    let mut wire = b"POST / HTTP/1.1\r\nContent-Length: 512\r\n\r\n".to_vec();
    wire.extend(std::iter::repeat_n(b'x', 512));
    let capture = tcp_capture(80, &wire, 1);
    let mut options = Options::default();
    options.limits.max_provenance_bytes = 8192;
    let result = Session::new(
        capture.registry.clone(),
        options,
        http::Collector::new(application::Limits::default(), [80], 8192).unwrap(),
    )
    .run(&mut common::reader(&capture.frames), |_| Ok(()), |_| Ok(()));
    assert_eq!(
        result
            .err()
            .expect("finite provenance budget must refuse")
            .classification()
            .code,
        "policy.provenance_limit"
    );
}
