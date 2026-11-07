#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::{self, quic},
    capture_file,
    protocol::application::quic::{parse_frames, parse_packet, parse_varint},
};
use std::{hint::black_box, io::Cursor, time::Duration};

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(65536)];
    black_box(parse_varint(input)).ok();
    black_box(parse_packet(input, Some(8))).ok();
    black_box(parse_frames(input, 128)).ok();
    let mut keylog = quic::KeyLog::new();
    for chunk in input.chunks(31) {
        black_box(keylog.append(chunk, false));
    }
    black_box(keylog.append(&[], true));
    let Ok(mut reader) = capture_file::Reader::with_limits(
        Cursor::new(input),
        capture_file::ReaderLimits {
            max_size: 65536,
            ..capture_file::ReaderLimits::default()
        },
    ) else {
        return;
    };
    let mut collector = quic::Collector::new(quic::Limits {
        max_connections: 8,
        max_buffered_bytes: 256 * 1024,
        max_pending_packets: 4,
        max_stream_bytes: 16384,
        max_streams_per_connection: 32,
        max_ranges: 64,
        ..quic::Limits::default()
    })
    .expect("valid bounded limits");
    collector.append_keylog(
        include_bytes!("../../examples/captures/quic-demo.keys"),
        true,
    );
    let session = analysis::Session::new(
        packetcraftr_fuzz::registry(),
        analysis::SessionOptions {
            limits: analysis::Limits {
                max_frames: 64,
                max_bytes: 256 * 1024,
                max_frame_bytes: 65536,
                max_duration: Duration::from_millis(100),
                ..analysis::Limits::default()
            },
            ..analysis::SessionOptions::default()
        },
        collector,
    );
    black_box(session.run(
        &mut reader,
        |_| Ok(()),
        |event| {
            black_box(event);
            Ok(())
        },
    ))
    .ok();
});
