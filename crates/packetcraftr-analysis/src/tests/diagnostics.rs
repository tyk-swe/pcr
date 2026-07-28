// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn expert_surfaces_decode_diagnostics_as_findings() {
    // A frame whose transport claims UDP but carries a truncated header
    // dissects with diagnostics; expert folds them in as findings.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    let mut bytes = build_bytes(udp_packet([10, 0, 0, 3], 53, 53)).to_vec();
    bytes.truncate(24);
    // Repair the IPv4 total length so only the UDP header is short.
    bytes[2..4].copy_from_slice(&24_u16.to_be_bytes());
    bytes[10..12].copy_from_slice(&[0, 0]);
    let checksum = {
        let mut sum = 0_u32;
        for pair in bytes[..20].chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).unwrap()
    };
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    writer
        .write_frame(&Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap())
        .unwrap();
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();

    let mut collector = expert::ExpertCollector::new();
    let mut findings = Vec::new();
    run(
        &mut reader,
        registry(),
        &AnalysisOptions::default(),
        |record| {
            findings.extend(collector.observe(&record));
            Ok(())
        },
    )
    .unwrap();
    assert!(!findings.is_empty(), "truncated UDP must produce findings");
    assert!(findings.iter().all(|finding| finding.number == 1));
}

#[test]
fn sink_failures_carry_their_frame_number_and_classification() {
    let error = run(
        &mut two_conversation_capture(),
        registry(),
        &AnalysisOptions::default(),
        |record| {
            if record.number == 2 {
                Err(crate::BoundaryError::new(
                    "sink failed by test design",
                    Classification::new("io.test_sink", Kind::Io, None),
                    Vec::new(),
                ))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert!(matches!(error, Error::Sink { number: 2, .. }));
    assert_eq!(error.classification().code, "io.test_sink");
}
