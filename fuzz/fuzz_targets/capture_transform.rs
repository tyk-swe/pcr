// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    capture_file::{self, compression},
    transform,
};
use std::io::{Cursor, Read, Write};

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(64 * 1024)];
    let limits = capture_file::Limits {
        max_frames: 64,
        max_bytes: 64 * 1024,
    };
    if let Ok(mut source) = capture_file::Reader::new(Cursor::new(data))
        && let Ok((output, _)) = capture_file::rewrite(&mut source, Vec::new(), limits)
    {
        // Fidelity rewrite is intentionally not a decode/re-encode oracle.
        assert_eq!(output, data);
        for format in [compression::Format::Gzip, compression::Format::Zstd] {
            let mut compressed = compression::Output::new(Vec::new(), format).unwrap();
            compressed.write_all(&output).unwrap();
            let encoded = compressed.finish().unwrap();
            let mut decoded = compression::Input::new(
                Cursor::new(encoded),
                compression::Limits {
                    max_encoded_bytes: 128 * 1024,
                    max_decoded_bytes: 128 * 1024,
                    ..compression::Limits::default()
                },
            )
            .unwrap();
            let mut roundtrip = Vec::new();
            decoded.read_to_end(&mut roundtrip).unwrap();
            assert_eq!(roundtrip, output);
        }
    }

    // A generated valid packet ensures arbitrary bytes still exercise editing.
    let payload = &data[..data.len().min(512)];
    let frame = composed_support::udp(40000, payload);
    let no_op = transform::rewrite(
        &frame,
        &transform::HeaderRewrite::default(),
        transform::RewriteLimits {
            max_output_bytes: 4096,
        },
    )
    .unwrap();
    assert_eq!(no_op.bytes(), frame.bytes());
    let edited = transform::rewrite(
        &frame,
        &transform::HeaderRewrite {
            source_port: Some(40001),
            ..transform::HeaderRewrite::default()
        },
        transform::RewriteLimits {
            max_output_bytes: 4096,
        },
    )
    .unwrap();
    assert_eq!(&edited.bytes()[..20], &frame.bytes()[..20]);
    assert_eq!(&edited.bytes()[22..26], &frame.bytes()[22..26]);
    assert_eq!(&edited.bytes()[28..], &frame.bytes()[28..]);
    assert_eq!(&edited.bytes()[20..22], &40001u16.to_be_bytes());

    let frames = [frame.clone(), frame];
    let mut source = composed_support::reader(&frames);
    let (selected, report) = capture_file::select(&mut source, Vec::new(), limits, |number, _| {
        Ok(number % 2 == 0)
    })
    .unwrap();
    let mut output = capture_file::Reader::new(Cursor::new(selected)).unwrap();
    assert_eq!(
        output.next_frame().unwrap().unwrap().bytes(),
        frames[1].bytes()
    );
    assert!(output.next_frame().unwrap().is_none());
    let _ = report;
});
