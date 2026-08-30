// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use proptest::prelude::*;

use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::analysis::reassembly::Limits as ReassemblyLimits;
use packetcraftr_core::analysis::reassembly::tcp::{
    Event as TcpEvent, FlowKey, Reassembler, ScopedFlowKey, Segment,
};
use packetcraftr_core::analysis::scope::Interner;
use packetcraftr_core::build::{Builder, Context, Options};
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::{
    DocumentLimits, Format, Layer as DocLayer, PACKET_DOCUMENT_SCHEMA_V1, Packet as DocPacket,
};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

fn test_registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in protocols must register"))
}

// Strategy for FieldValue
fn arb_field_value() -> impl Strategy<Value = FieldValue> {
    prop_oneof![
        any::<bool>().prop_map(FieldValue::Bool),
        (0..=i64::MAX as u64).prop_map(FieldValue::Unsigned),
        any::<i64>().prop_map(FieldValue::Signed),
        // A lone "-" is excluded: noyalib 0.0.28 serializes it unquoted, which
        // its own parser then reads as a block-sequence entry. The CLI never
        // emits YAML, so this is a fixture constraint, not a parser gap.
        "[a-zA-Z0-9_-]{1,30}"
            .prop_filter("bare dash is mis-serialized upstream", |text| text != "-")
            .prop_map(FieldValue::Text),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(FieldValue::from),
        any::<[u8; 4]>().prop_map(|octets| FieldValue::Ipv4(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| FieldValue::Ipv6(Ipv6Addr::from(octets))),
        any::<[u8; 6]>().prop_map(FieldValue::Mac),
    ]
}

// Strategy for DocLayer
fn arb_doc_layer() -> impl Strategy<Value = DocLayer> {
    let protocols = prop_oneof![
        Just("ethernet"),
        Just("ipv4"),
        Just("ipv6"),
        Just("tcp"),
        Just("udp"),
        Just("raw"),
    ];
    let fields = prop::collection::btree_map("[a-z][a-z0-9_]{0,15}", arb_field_value(), 0..6);
    (protocols, fields).prop_map(|(protocol, fields)| DocLayer {
        protocol: protocol.into(),
        fields: fields.into_iter().collect(),
    })
}

// Strategy for DocPacket
fn arb_doc_packet() -> impl Strategy<Value = DocPacket> {
    prop::collection::vec(arb_doc_layer(), 1..6).prop_map(|layers| DocPacket {
        schema: PACKET_DOCUMENT_SCHEMA_V1.to_string(),
        layers,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn property_document_json_roundtrip(packet in arb_doc_packet()) {
        let serialized = serde_json::to_string(&packet).expect("serialization to JSON must succeed");
        let parsed = DocPacket::parse_with_limits(&serialized, Format::Json, &DocumentLimits { max_input_bytes: 1024 * 1024, max_layers: 64, ..DocumentLimits::DEFAULT }).expect("JSON re-parse must succeed");

        prop_assert_eq!(parsed.layers.len(), packet.layers.len());
        for (actual, expected) in parsed.layers.iter().zip(packet.layers.iter()) {
            prop_assert_eq!(&actual.protocol, &expected.protocol);
            prop_assert_eq!(&actual.fields, &expected.fields);
        }
    }

    #[test]
    fn property_document_yaml_roundtrip(packet in arb_doc_packet()) {
        let yaml = noyalib::to_string(&packet).expect("serialization to YAML must succeed");
        let parsed = DocPacket::parse_with_limits(&yaml, Format::Yaml, &DocumentLimits::DEFAULT)
            .expect("YAML re-parse must succeed");
        prop_assert_eq!(&parsed, &packet);
        let json = serde_json::to_string(&packet).expect("serialization to JSON must succeed");
        let from_json = DocPacket::parse_with_limits(&json, Format::Json, &DocumentLimits::DEFAULT)
            .expect("JSON re-parse must succeed");
        prop_assert_eq!(from_json, parsed);
    }

    #[test]
    fn property_length_and_offset_arithmetic(
        src_port in 1024_u16..65535,
        dst_port in 1_u16..1024,
        seq in any::<u32>(),
        ack in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let registry = test_registry();
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Tcp {
            source_port: src_port,
            destination_port: dst_port,
            sequence: seq,
            acknowledgment: ack,
            flags: 0x0018, // PSH | ACK
            ..Tcp::default()
        });
        if !payload.is_empty() {
            packet.push(Raw::new(payload.clone()));
        }

        let built = Builder::new(Arc::clone(&registry))
            .build(packet, Context::default(), Options::default())
            .expect("build must succeed");

        let frame = Frame::new(SystemTime::now(), LinkType::IPV4, built.bytes.clone())
            .expect("frame must be valid");

        let dissector = Dissector::new(Arc::clone(&registry));
        let decoded = dissector
            .decode(frame, DecodeOptions::default())
            .expect("decode must succeed");

        // Layout offsets must be monotonically non-decreasing and within total frame bytes
        let mut last_end = 0;
        for layer in &decoded.layout.layers {
            prop_assert!(layer.range.start >= last_end);
            prop_assert!(layer.range.end <= built.bytes.len());
            last_end = layer.range.end;
        }

        // Layout total coverage must equal built length
        prop_assert_eq!(last_end, built.bytes.len());
    }

    #[test]
    fn property_capture_pcap_and_pcapng_consistency(
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 10..200), 1..8),
    ) {
        let timestamp = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Classic PCAP
        let mut pcap_writer = Writer::pcap(Vec::new(), LinkType::IPV4).expect("pcap writer init");
        for (i, p) in payloads.iter().enumerate() {
            let ts = timestamp + Duration::from_millis(i as u64 * 10);
            let frame = Frame::new(ts, LinkType::IPV4, Bytes::from(p.clone())).expect("valid frame");
            pcap_writer.write_frame(&frame).expect("frame write");
        }
        let pcap_bytes = pcap_writer.into_inner();

        let mut pcap_reader = Reader::new(Cursor::new(pcap_bytes)).expect("pcap reader init");
        let mut read_frames = Vec::new();
        while let Some(frame) = pcap_reader.next_frame().expect("next frame") {
            read_frames.push(frame);
        }
        prop_assert_eq!(read_frames.len(), payloads.len());
        for (actual, expected) in read_frames.iter().zip(payloads.iter()) {
            prop_assert_eq!(actual.bytes().as_ref(), expected.as_slice());
            prop_assert_eq!(actual.link_type, LinkType::IPV4);
        }

        // PCAPNG
        let mut pcapng_writer = Writer::pcapng(Vec::new()).expect("pcapng writer init");
        let _iface_idx = pcapng_writer.add_interface(LinkType::IPV4).expect("add iface");
        for (i, p) in payloads.iter().enumerate() {
            let ts = timestamp + Duration::from_millis(i as u64 * 10);
            let frame = Frame::new(ts, LinkType::IPV4, Bytes::from(p.clone())).expect("valid frame");
            pcapng_writer.write_frame(&frame).expect("pcapng frame write");
        }
        let pcapng_bytes = pcapng_writer.into_inner();

        let mut pcapng_reader = Reader::new(Cursor::new(pcapng_bytes)).expect("pcapng reader init");
        let mut read_ng_frames = Vec::new();
        while let Some(frame) = pcapng_reader.next_frame().expect("next frame") {
            read_ng_frames.push(frame);
        }
        prop_assert_eq!(read_ng_frames.len(), payloads.len());
        for (actual, expected) in read_ng_frames.iter().zip(payloads.iter()) {
            prop_assert_eq!(actual.bytes().as_ref(), expected.as_slice());
            prop_assert_eq!(actual.link_type, LinkType::IPV4);
        }
    }

    #[test]
    fn property_tcp_reassembly_in_order_and_overlaps(
        base_seq in any::<u32>(),
        chunk_sizes in prop::collection::vec(1_usize..128, 1..8),
    ) {
        let mut interner = Interner::new();
        let root_scope = interner.intern(None, Vec::new()).expect("root scope");
        let flow = ScopedFlowKey {
            scope: root_scope,
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                source_port: 12345,
                destination_port: 80,
            },
        };

        let limits = ReassemblyLimits {
            max_flows: 10,
            max_aggregate_bytes: 1024 * 1024,
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(limits);
        let start_time = Instant::now();

        // 1. Send SYN
        let syn_seg = Segment {
            flow: flow.clone(),
            sequence: base_seq,
            syn: true,
            fin: false,
            rst: false,
            payload: Bytes::new(),
        };
        let events = reassembler.push(syn_seg, start_time).expect("push syn");
        prop_assert!(events.is_empty());

        // 2. Prepare payload slices
        let mut current_seq = base_seq.wrapping_add(1);
        let mut full_payload = Vec::new();
        let mut segments = Vec::new();

        for (i, &size) in chunk_sizes.iter().enumerate() {
            let chunk: Vec<u8> = (0..size)
                .map(|b| u8::try_from((i * 31 + b) % 256).unwrap())
                .collect();
            full_payload.extend_from_slice(&chunk);
            segments.push(Segment {
                flow: flow.clone(),
                sequence: current_seq,
                syn: false,
                fin: false,
                rst: false,
                payload: Bytes::from(chunk),
            });
            current_seq = current_seq.wrapping_add(u32::try_from(size).unwrap());
        }

        // 3. Push segments with possible duplicate retransmissions
        let mut reassembled_stream = Vec::new();
        for seg in &segments {
            let events = reassembler.push(seg.clone(), start_time).expect("push segment");
            for event in events {
                if let TcpEvent::Data { bytes, .. } = event {
                    reassembled_stream.extend_from_slice(&bytes);
                }
            }
            // Retransmit same segment to test duplicate tolerance
            let dup_events = reassembler.push(seg.clone(), start_time).expect("push dup segment");
            for event in dup_events {
                if let TcpEvent::Data { bytes, .. } = event {
                    reassembled_stream.extend_from_slice(&bytes);
                }
            }
        }

        // 4. Send FIN
        let fin_seg = Segment {
            flow,
            sequence: current_seq,
            syn: false,
            fin: true,
            rst: false,
            payload: Bytes::new(),
        };
        let fin_events = reassembler.push(fin_seg, start_time).expect("push fin");
        for event in fin_events {
            if let TcpEvent::Data { bytes, .. } = event {
                reassembled_stream.extend_from_slice(&bytes);
            }
        }

        // The reassembled stream must match original payload exactly
        prop_assert_eq!(reassembled_stream, full_payload);
    }

    #[test]
    fn property_filter_expression_evaluation_safety(
        port in 1_u16..65535,
        octets in any::<[u8; 4]>(),
    ) {
        let registry = test_registry();
        let ip = Ipv4Addr::from(octets);

        // Build a sample frame
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: ip,
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Tcp {
            source_port: port,
            destination_port: 80,
            ..Tcp::default()
        });
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, Context::default(), Options::default())
            .expect("build");
        let frame = Frame::new(SystemTime::now(), LinkType::IPV4, built.bytes).expect("frame");
        let dissector = Dissector::new(Arc::clone(&registry));
        let decoded = dissector.decode(frame, DecodeOptions::default()).expect("decode");

        let filter_str = format!("ipv4.source == {ip} && tcp.srcport == {port}");
        let compiled = Filter::compile(&filter_str, &registry, FilterOptions::default())
            .expect("filter compile");

        let context = FilterContext {
            decoded: &decoded,
            derived: &[],
            number: 1,
            tcp_stream: None,
            udp_stream: None,
        };

        let result = compiled.matches(&context).expect("filter match");
        prop_assert!(result, "filter should match the constructed packet");

        // Negation test
        let neg_filter_str = format!("!(ipv4.source == {ip} && tcp.srcport == {port})");
        let neg_compiled = Filter::compile(&neg_filter_str, &registry, FilterOptions::default())
            .expect("neg filter compile");
        let neg_result = neg_compiled.matches(&context).expect("neg filter match");
        prop_assert!(!neg_result, "negated filter should not match");
    }
}
