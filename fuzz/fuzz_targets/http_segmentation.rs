// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::{self, application, http},
    error::BoundaryError,
    frame::Frame,
    protocol::{builtin, transport::Tcp},
};

fn messages(frames: &[Frame]) -> Option<Vec<(http::Status, Vec<u8>, u64)>> {
    let mut reader = composed_support::reader(frames);
    let mut options = composed_support::options();
    options.tcp_events = true;
    options.track_sources = true;
    let mut collector = http::Collector::new(
        application::Limits {
            max_messages: 16,
            max_streams: 4,
            max_buffer_bytes: 65536,
            max_retained_bytes: 1024 * 1024,
            max_source_spans: 1024,
        },
        [80],
        65536,
    )
    .unwrap();
    let mut output = Vec::new();
    let mut retain = |events: Vec<http::Event>| {
        for event in events {
            if let http::Event::Message(message) = event {
                output.push((
                    message.status,
                    message.header_wire.to_vec(),
                    message.body_bytes,
                ));
            }
        }
    };
    let summary = analysis::run(&mut reader, builtin::registry(), &options, |record| {
        retain(
            collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?,
        );
        Ok(())
    })
    .ok()?;
    let (tail, _) = collector.finish(&summary).ok()?;
    retain(tail);
    Some(output)
}

fuzz_target!(|data: &[u8]| {
    let body = &data[..data.len().min(256)];
    let mut wire = format!(
        "POST /fixture HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    wire.extend_from_slice(body);
    let chunk = usize::from(data.first().copied().unwrap_or(0) % 64) + 1;
    let whole = [
        composed_support::tcp(0, Tcp::SYN, &[]),
        composed_support::tcp(1, Tcp::ACK, &wire),
        composed_support::tcp(1 + wire.len() as u32, Tcp::FIN | Tcp::ACK, &[]),
    ];
    let mut split = vec![composed_support::tcp(0, Tcp::SYN, &[])];
    let mut sequence = 1;
    for bytes in wire.chunks(chunk) {
        split.push(composed_support::tcp(sequence, Tcp::ACK, bytes));
        sequence += bytes.len() as u32;
    }
    split.push(composed_support::tcp(sequence, Tcp::FIN | Tcp::ACK, &[]));
    if let (Some(whole), Some(split)) = (messages(&whole), messages(&split)) {
        // Physical source-frame sets may differ; the complete message must not.
        assert_eq!(whole, split);
        assert_eq!(whole.len(), 1);
        assert_eq!(whole[0].0, http::Status::Complete);
        assert_eq!(whole[0].2, body.len() as u64);
    }
});
