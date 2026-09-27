// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    capture_file::{self, compression, split},
    error::BoundaryError,
    transform,
};
use std::io::{Cursor, Read, Write};

/// Collects every emitted part's decoded bytes.
#[derive(Default)]
struct PartBytes(Vec<Vec<u8>>);

impl split::Sink for PartBytes {
    fn begin(
        &mut self,
        _index: u64,
        _format: capture_file::Format,
    ) -> Result<(), BoundaryError> {
        self.0.push(Vec::new());
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        self.0
            .last_mut()
            .expect("begin precedes write")
            .extend_from_slice(bytes);
        Ok(())
    }

    fn finish(&mut self, _part: &split::Part) -> Result<(), BoundaryError> {
        Ok(())
    }
}

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

    // Splitting reproduces `select` byte-for-byte on every part's range.
    for boundary in 1..=3_u64 {
        let mut source = composed_support::reader(&frames);
        let plan = split::plan(
            &mut source,
            split::Options {
                frames_per_file: boundary,
                limits: split::Limits {
                    input: limits,
                    max_files: 4,
                    max_metadata_records: 4,
                    max_metadata_bytes: 64 * 1024,
                    max_output_bytes: 128 * 1024,
                },
            },
        )
        .unwrap();
        let mut sink = PartBytes::default();
        let report = split::write(&mut source, plan, &mut sink).unwrap();
        for (bytes, part) in sink.0.iter().zip(&report.parts) {
            let mut oracle = composed_support::reader(&frames);
            let (expected, _) = capture_file::select(&mut oracle, Vec::new(), limits, |number, _| {
                Ok(
                    (part.first_frame.unwrap_or(1)..=part.last_frame.unwrap_or(0))
                        .contains(&number),
                )
            })
            .unwrap();
            assert_eq!(bytes, &expected);
        }
    }
});
