// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The first byte modulo four selects request frames, a QPACK field section,
//! encoder instructions after an insertion, or server control frames.

#![no_main]

use std::{hint::black_box, time::Duration};

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    analysis::{Endpoint, http3, quic, scope},
    budget::Deadline,
};
use quic::Direction::{Client, Server};

const MAX_INPUT: usize = 4096;
const SETTINGS: &[u8] = b"\0\x04\x05\x01\x40\x40\x07\x01";
const ENCODER: &[u8] = b"\x02\x3f\x21\x41x\x01a";
const REQUEST: &[u8] = b"\x01\x09\x02\x80\xd1\xd7\xc1\x50\x01a\x10";

fn stream(id: u64, direction: quic::Direction, data: Vec<u8>) -> quic::Stream {
    let complete = id % 4 < 2;
    quic::Stream {
        id,
        direction,
        final_size: complete.then_some(data.len() as u64),
        ranges: vec![quic::Range {
            offset: 0,
            data: data.into(),
        }],
        reset_error: None,
        complete,
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
            address: [192, 0, 2, 1].into(),
            port: 49152,
        },
        server_endpoint: Endpoint {
            address: [192, 0, 2, 2].into(),
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
        offered_alpn: vec!["h3".into()],
        negotiated_alpn: Some("h3".into()),
        cipher_suite: None,
        ja3: None,
        ja4: None,
        client_hello_frame: None,
        server_hello_frame: None,
        hello_elapsed_ms: None,
        client_finished_frame: None,
        server_finished_frame: None,
        handshake_done_frame: None,
        early_data: quic::EarlyData::NotObserved,
        client_transport_parameters: Vec::new(),
        server_transport_parameters: Vec::new(),
        streams,
        metrics: quic::Metrics::default(),
        diagnostics: Vec::new(),
        diagnostics_omitted: 0,
        pending_packets: 0,
        closed: true,
        close_error: None,
        close_reason: None,
        stateless_reset: false,
        incomplete: false,
        end_reason: String::new(),
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&mode, data)) = input.split_first() else {
        return;
    };
    let data = &data[..data.len().min(MAX_INPUT)];
    let [mut request, mut encoder, mut settings] =
        [REQUEST.to_vec(), ENCODER.to_vec(), SETTINGS.to_vec()];
    match mode % 4 {
        0 => request = data.to_vec(),
        1 => {
            let length = u16::try_from(data.len()).expect("bounded input length");
            request = [&[1][..], &(0x4000 | length).to_be_bytes(), data].concat();
        }
        2 => encoder.extend_from_slice(data),
        _ => settings = [&[0][..], data].concat(),
    }
    let connection = connection(vec![
        stream(0, Client, request),
        stream(2, Client, b"\0\x04\0".to_vec()),
        stream(3, Server, settings),
        stream(6, Client, encoder),
    ]);
    black_box(http3::inspect(
        &connection,
        None,
        http3::Limits {
            max_qpack_history_bytes: 8192,
            max_header_section_bytes: 8192,
            max_exchange_bytes: 16384,
            max_steps: 32768,
        },
        &Deadline::new(Duration::MAX),
        &mut |event| {
            black_box(event);
            Ok(())
        },
    ))
    .ok();
});
