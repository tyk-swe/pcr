// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;
mod http2_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::http2;

fn messages(
    frames: &[packetcraftr_core::frame::Frame],
) -> Vec<(http2::Status, u64, Vec<(Vec<u8>, Vec<u8>)>)> {
    let events = http2_support::collect(frames).expect("generated valid bounded exchange");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, http2::Event::Connection(_)))
            .count(),
        1,
        "one final connection event"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, http2::Event::Issue(issue)
            if matches!(issue.status, http2::Status::Malformed | http2::Status::Limit))),
        "a generated valid exchange must not produce malformed or limit issues"
    );
    events
        .into_iter()
        .filter_map(|event| match event {
            http2::Event::Message(message) => Some((
                message.status,
                message.body_bytes,
                message
                    .headers
                    .iter()
                    .map(|field| (field.name.to_vec(), field.value.to_vec()))
                    .collect(),
            )),
            _ => None,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let body = &data[..data.len().min(256)];
    let wire = http2_support::request_exchange(body);
    let chunk = usize::from(data.first().copied().unwrap_or(0) % 64) + 1;
    let whole = messages(&http2_support::tcp_frames(&wire, wire.len()));
    let split = messages(&http2_support::tcp_frames(&wire, chunk));
    assert_eq!(
        whole, split,
        "TCP segmentation must not change decoded evidence"
    );
    assert_eq!(whole.len(), 1);
    assert_eq!(whole[0].0, http2::Status::Complete);
    assert_eq!(whole[0].1, body.len() as u64);
    let fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"http".to_vec()),
        (b":path".to_vec(), b"/".to_vec()),
        (b":authority".to_vec(), b"x".to_vec()),
    ];
    assert_eq!(whole[0].2, fields);
});
