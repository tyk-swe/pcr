// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::hint::black_box;
use std::io::{self, Cursor, Seek};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions, Writer};
use packetcraftr_core::analysis::reassembly::Limits as ReassemblyLimits;
use packetcraftr_core::analysis::reassembly::tcp::{FlowKey, Reassembler, ScopedFlowKey, Segment};
use packetcraftr_core::analysis::scope::Interner;
use packetcraftr_core::build::{Builder, Context, Options as BuildOptions};
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::application::tls::{
    Handshake, Outcome, Transport, ja3, ja4, parse_handshake, parse_record,
};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

fn bench_registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in registry"))
}

fn bench_packet_decode_and_rebuild(c: &mut Criterion) {
    let registry = bench_registry();
    let dissector = Dissector::new(Arc::clone(&registry));
    let builder = Builder::new(Arc::clone(&registry));

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 44321,
        destination_port: 80,
        sequence: 1000,
        acknowledgment: 2000,
        flags: 0x0018,
        ..Tcp::default()
    });
    packet.push(Raw::new(vec![0x41; 256]));

    let built = builder
        .build(packet.clone(), Context::default(), BuildOptions::default())
        .expect("build");
    let frame = Frame::new(SystemTime::now(), LinkType::IPV4, built.bytes.clone()).expect("frame");

    c.bench_function("packet_decode", |b| {
        b.iter(|| {
            let decoded = dissector
                .decode(
                    black_box(frame.clone()),
                    black_box(DecodeOptions::default()),
                )
                .expect("decode");
            black_box(decoded);
        });
    });

    c.bench_function("packet_rebuild", |b| {
        b.iter(|| {
            let res = builder
                .build(
                    black_box(packet.clone()),
                    black_box(Context::default()),
                    black_box(BuildOptions::default()),
                )
                .expect("rebuild");
            black_box(res);
        });
    });
}

fn bench_document_parsing(c: &mut Criterion) {
    let json_doc = r#"{
      "schema": "packetcraftr.packet/v1",
      "layers": [
        {
          "protocol": "ipv4",
          "fields": {
            "source": {"type": "ipv4", "value": "192.0.2.1"},
            "destination": {"type": "ipv4", "value": "198.51.100.2"}
          }
        },
        {
          "protocol": "tcp",
          "fields": {
            "source_port": {"type": "unsigned", "value": 12345},
            "destination_port": {"type": "unsigned", "value": 80}
          }
        },
        {
          "protocol": "raw",
          "fields": {
            "bytes": {"type": "bytes", "value": [1, 2, 3, 4, 5, 6, 7, 8]}
          }
        }
      ]
    }"#;

    let yaml_doc = r#"schema: "packetcraftr.packet/v1"
layers:
  - protocol: ipv4
    fields:
      source: {type: ipv4, value: 192.0.2.1}
      destination: {type: ipv4, value: 198.51.100.2}
  - protocol: tcp
    fields:
      source_port: {type: unsigned, value: 12345}
      destination_port: {type: unsigned, value: 80}
  - protocol: raw
    fields:
      bytes: {type: bytes, value: [1, 2, 3, 4, 5, 6, 7, 8]}
"#;

    c.bench_function("document_parse_json", |b| {
        b.iter(|| {
            let doc = DocPacket::parse_with_limits(
                black_box(json_doc),
                Format::Json,
                &DocumentLimits {
                    max_input_bytes: 64 * 1024,
                    max_layers: 32,
                    ..DocumentLimits::DEFAULT
                },
            )
            .expect("parse json");
            black_box(doc);
        });
    });

    c.bench_function("document_parse_yaml", |b| {
        b.iter(|| {
            let doc = DocPacket::parse_with_limits(
                black_box(yaml_doc),
                Format::Yaml,
                &DocumentLimits {
                    max_input_bytes: 64 * 1024,
                    max_layers: 32,
                    ..DocumentLimits::DEFAULT
                },
            )
            .expect("parse yaml");
            black_box(doc);
        });
    });
}

fn bench_capture_processing_and_encoding(c: &mut Criterion) {
    let frame_payload = Bytes::from_static(b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02\x04\xd2\x00\x50\x00\x00\x03\xe8\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00");
    let frame = Frame::new(SystemTime::now(), LinkType::IPV4, frame_payload).expect("frame");

    // Pre-generate PCAP and PCAPNG buffers with 100 frames
    let mut pcap_writer = Writer::pcap(Vec::new(), LinkType::IPV4).expect("pcap writer");
    let mut pcapng_writer = Writer::pcapng(Vec::new()).expect("pcapng writer");
    let _iface = pcapng_writer
        .add_interface(LinkType::IPV4)
        .expect("add iface");

    for _ in 0..100 {
        pcap_writer.write_frame(&frame).expect("write frame");
        pcapng_writer.write_frame(&frame).expect("write ng frame");
    }
    let pcap_data = pcap_writer.into_inner();
    let pcapng_data = pcapng_writer.into_inner();

    c.bench_function("capture_read_pcap_frames", |b| {
        b.iter(|| {
            let mut reader =
                Reader::with_options(Cursor::new(black_box(&pcap_data)), ReaderOptions::default())
                    .expect("reader");
            let mut count = 0_usize;
            while let Ok(Some(f)) = reader.next_frame() {
                black_box(f);
                count = count
                    .checked_add(1)
                    .expect("benchmark frame count fits usize");
            }
            black_box(count);
        });
    });

    c.bench_function("capture_read_pcapng_records", |b| {
        b.iter(|| {
            let mut reader = Reader::with_options(
                Cursor::new(black_box(&pcapng_data)),
                ReaderOptions::default(),
            )
            .expect("reader");
            let mut count = 0_usize;
            while let Ok(Some(r)) = reader.next_record() {
                black_box(r);
                count = count
                    .checked_add(1)
                    .expect("benchmark record count fits usize");
            }
            black_box(count);
        });
    });

    c.bench_function("capture_encode_pcap", |b| {
        b.iter(|| {
            let mut writer =
                Writer::pcap(Vec::with_capacity(4096), LinkType::IPV4).expect("writer");
            for _ in 0..10 {
                writer.write_frame(black_box(&frame)).expect("write");
            }
            black_box(writer.into_inner());
        });
    });

    c.bench_function("capture_encode_pcapng", |b| {
        b.iter(|| {
            let mut writer = Writer::pcapng(Vec::with_capacity(4096)).expect("writer");
            let _ = writer.add_interface(LinkType::IPV4).expect("iface");
            for _ in 0..10 {
                writer.write_frame(black_box(&frame)).expect("write");
            }
            black_box(writer.into_inner());
        });
    });

    // Model the CLI's transactional spooled capture path with enough payload
    // to expose capture-sized memory growth in peak-RSS measurements. The
    // payload is shared by every frame, so measured growth belongs to encoded
    // output rather than benchmark setup. This stays practical for local runs
    // while producing a capture a little over 16 MiB.
    const LARGE_FRAME_COUNT: u64 = 4_096;
    const LARGE_PAYLOAD_BYTES: usize = 4_096;
    let large_payload = Bytes::from(vec![0x5a; LARGE_PAYLOAD_BYTES]);
    let large_frame =
        Frame::new(SystemTime::now(), LinkType::IPV4, large_payload).expect("large frame");
    let encoded_bytes = LARGE_FRAME_COUNT
        .checked_mul(u64::try_from(LARGE_PAYLOAD_BYTES + 16).expect("payload size fits u64"))
        .and_then(|bytes| bytes.checked_add(24))
        .expect("benchmark capture size fits u64");
    let mut group = c.benchmark_group("capture_output");
    group.throughput(Throughput::Bytes(encoded_bytes));
    group.bench_function("large_transactional_spool", |b| {
        b.iter(|| {
            let spool = tempfile::tempfile().expect("anonymous temporary file");
            let mut writer = Writer::pcap(spool, LinkType::IPV4).expect("writer");
            for _ in 0..LARGE_FRAME_COUNT {
                writer
                    .write_frame(black_box(&large_frame))
                    .expect("write frame");
            }
            writer.flush().expect("flush encoded capture");
            let mut encoded = writer.into_inner();
            encoded.rewind().expect("rewind encoded capture");
            let copied = io::copy(black_box(&mut encoded), &mut io::sink()).expect("copy output");
            black_box(copied);
        });
    });
    group.finish();
}

fn bench_tcp_reassembly(c: &mut Criterion) {
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

    let payload = Bytes::from_static(&[0x42; 256]);
    let segments: Vec<_> = (0_u32..10)
        .map(|i| Segment {
            flow: flow.clone(),
            sequence: i
                .checked_mul(256)
                .and_then(|offset| 1_000_u32.checked_add(offset))
                .expect("ten fixed-size benchmark segments fit a TCP sequence"),
            syn: i == 0,
            fin: false,
            rst: false,
            payload: payload.clone(),
        })
        .collect();

    c.bench_function("tcp_reassembly_10_segments", |b| {
        b.iter(|| {
            let limits = ReassemblyLimits {
                max_flows: 10,
                max_aggregate_bytes: 64 * 1024,
                ..Default::default()
            };
            let mut reassembler = Reassembler::new(limits);
            let now = Instant::now();
            for seg in &segments {
                let events = reassembler.push(black_box(seg.clone()), now).expect("push");
                black_box(events);
            }
        });
    });
}

fn client_hello_record_from_capture() -> Bytes {
    let capture = include_bytes!("../../../examples/captures/tls-handshake.pcapng");
    let reader = Reader::new(Cursor::new(capture.as_slice())).expect("TLS benchmark capture");
    for frame in reader {
        let frame = frame.expect("TLS benchmark frame");
        for offset in 0..frame.bytes().len() {
            let candidate = frame
                .bytes()
                .get(offset..)
                .expect("offset is within the frame");
            let Outcome::Complete {
                consumed,
                value: record,
            } = parse_record(candidate)
            else {
                continue;
            };
            if !matches!(
                parse_handshake(record.body.as_ref()),
                Outcome::Complete {
                    value: Handshake::ClientHello(_),
                    ..
                }
            ) {
                continue;
            }
            let end = offset
                .checked_add(consumed)
                .expect("TLS record end fits the frame");
            let record = frame
                .bytes()
                .get(offset..end)
                .expect("parsed TLS record is within the frame");
            return Bytes::copy_from_slice(record);
        }
    }
    panic!("TLS benchmark capture contains no complete ClientHello record");
}

fn bench_tls_assembly(c: &mut Criterion) {
    let raw_client_hello = client_hello_record_from_capture();

    c.bench_function("tls_record_and_handshake_parse", |b| {
        b.iter(|| {
            let Outcome::Complete { value: record, .. } =
                parse_record(black_box(raw_client_hello.as_ref()))
            else {
                panic!("validated TLS record became unparsable");
            };
            let Outcome::Complete {
                value: Handshake::ClientHello(hello),
                ..
            } = parse_handshake(black_box(record.body.as_ref()))
            else {
                panic!("validated ClientHello became unparsable");
            };
            let hello = black_box(hello.as_ref());
            black_box(ja3(hello));
            black_box(ja4(hello, black_box(Transport::Tcp)));
        });
    });
}

fn bench_filter_evaluation(c: &mut Criterion) {
    let registry = bench_registry();
    let filter_str = "ipv4.source in 192.0.2.0/24 && tcp.dstport == 80";
    let compiled =
        Filter::compile(filter_str, &registry, FilterOptions::default()).expect("compile");

    let dissector = Dissector::new(Arc::clone(&registry));
    let frame_payload = Bytes::from_static(b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00\xc0\x00\x02\x01\xc6\x33\x64\x02\x04\xd2\x00\x50\x00\x00\x03\xe8\x00\x00\x00\x00\x50\x02\x20\x00\x00\x00\x00\x00");
    let frame = Frame::new(SystemTime::now(), LinkType::IPV4, frame_payload).expect("frame");
    let decoded = dissector
        .decode(frame, DecodeOptions::default())
        .expect("decode");

    let context = FilterContext {
        decoded: &decoded,
        number: 1,
        tcp_stream: None,
        udp_stream: None,
    };

    c.bench_function("filter_evaluation", |b| {
        b.iter(|| {
            let matched = compiled.matches(black_box(&context)).expect("match");
            black_box(matched);
        });
    });
}

criterion_group!(
    benches,
    bench_packet_decode_and_rebuild,
    bench_document_parsing,
    bench_capture_processing_and_encoding,
    bench_tcp_reassembly,
    bench_tls_assembly,
    bench_filter_evaluation,
);
criterion_main!(benches);
