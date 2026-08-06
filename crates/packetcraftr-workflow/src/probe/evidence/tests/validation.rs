// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use bytes::Bytes;
use packetcraftr_client::Stats;
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, layout};

use super::super::exact_validation::validate_decoded_frame;
use super::super::{ExchangeEvidence, ExchangeEvidenceError, validate_exchange_evidence};
use super::support::{NoMatchedResponses, frame};

#[test]
fn exact_frame_validation_preserves_failure_context() {
    let exact = frame(&[1]);
    let decoded = DecodedPacket {
        packet: Packet::new(),
        original: Bytes::from_static(&[2]),
        frame: exact,
        layout: layout::Packet::default(),
        diagnostics: Vec::new(),
    };
    assert_eq!(
        validate_decoded_frame(&decoded, "matched response"),
        Err("matched response original bytes differ from its exact frame".to_owned())
    );
}

#[test]
fn exchange_validation_reports_shared_accounting_failures_semantically() {
    let sent_frame = frame(&[1, 2]);
    let sent_packets = [Packet::new()];
    let sent_frames = [sent_frame];
    let matched = Vec::<NoMatchedResponses>::new();
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 2,
        ..Stats::default()
    };
    assert_eq!(
        validate_exchange_evidence(
            ExchangeEvidence {
                request_count: 1,
                sent_packets: &sent_packets,
                sent_frames: &sent_frames,
                matched_responses: &matched,
                unsolicited: &[],
                undecoded: &[],
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            1,
            2,
            |_, _| false,
        ),
        Err(ExchangeEvidenceError::SentPacketMismatch { request_index: 0 })
    );

    assert_eq!(
        validate_exchange_evidence(
            ExchangeEvidence {
                request_count: 1,
                sent_packets: &sent_packets,
                sent_frames: &sent_frames,
                matched_responses: &matched,
                unsolicited: &[],
                undecoded: &[],
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            1,
            2,
            |_, _| true,
        ),
        Ok(())
    );

    let stats = Stats { bytes: 1, ..stats };
    assert_eq!(
        validate_exchange_evidence(
            ExchangeEvidence {
                request_count: 1,
                sent_packets: &sent_packets,
                sent_frames: &sent_frames,
                matched_responses: &matched,
                unsolicited: &[],
                undecoded: &[],
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            1,
            2,
            |_, _| true,
        ),
        Err(ExchangeEvidenceError::SentByteCountMismatch {
            reported: 1,
            actual: 2,
        })
    );
}
