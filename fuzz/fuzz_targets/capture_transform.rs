// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::{
    capture_file::{self, compression},
    frame::{Frame, LinkType},
    protocol, transform,
};
use std::{
    io::{Cursor, Read, Write},
    time::UNIX_EPOCH,
};

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

    // The mapping comes from the input: a prefix of the frame's source address
    // moves to an arbitrary prefix of the same length.
    let byte = |index: usize| data.get(index).copied().unwrap_or(0);
    let length = byte(0) % 33;
    let network = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
    let source = u32::from_be_bytes([192, 0, 2, 1]);
    let replacement = u32::from_be_bytes([byte(1), byte(2), byte(3), byte(4)]) & network;
    let mapping = format!(
        "{}/{length}={}/{length}",
        std::net::Ipv4Addr::from(source & network),
        std::net::Ipv4Addr::from(replacement),
    );
    let map = transform::AddressMap::new(&[mapping.parse().unwrap()], &[]).unwrap();
    let limits_bytes = transform::RewriteLimits {
        max_output_bytes: 4096,
    };
    let mapped = map.apply(&frame, limits_bytes).unwrap();
    assert_eq!(mapped.bytes().len(), frame.bytes().len());
    // Source and destination are looked up independently; both may fall inside the prefix.
    let expected = |address: u32| {
        if address & network == source & network {
            replacement | (address & !network)
        } else {
            address
        }
    };
    assert_eq!(mapped.bytes()[12..16], expected(source).to_be_bytes());
    assert_eq!(
        mapped.bytes()[16..20],
        expected(u32::from_be_bytes([198, 51, 100, 2])).to_be_bytes()
    );
    assert_eq!(&mapped.bytes()[28..], &frame.bytes()[28..]);
    let ip_header = &mapped.bytes()[..20];
    assert_eq!(protocol::checksum(ip_header), 0);
    let udp_length = u16::try_from(mapped.bytes().len() - 20)
        .unwrap()
        .to_be_bytes();
    assert_eq!(
        protocol::checksum_parts(&[
            &mapped.bytes()[12..20],
            &[0, 17],
            &udp_length,
            &mapped.bytes()[20..],
        ]),
        0
    );
    // Arbitrary bytes under every link type the map reads are refused with a
    // typed error or keep their length.
    for link_type in [LinkType::ETHERNET, LinkType::IPV4, LinkType::IPV6] {
        if let Ok(raw) = Frame::new(UNIX_EPOCH, link_type, data.to_vec())
            && let Ok(output) = map.apply(&raw, limits_bytes)
        {
            assert_eq!(output.bytes().len(), raw.bytes().len());
        }
    }

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
