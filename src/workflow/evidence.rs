// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

use std::time::{Duration, SystemTime};

use crate::capture::Frame;
use crate::net::capture::Statistics as CaptureStatistics;
use crate::packet::Packet;
use crate::packet::decode::Result as DecodedPacket;

use super::Stats;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceBudgetError {
    FrameCountOverflow,
    ByteCountOverflow,
    LimitExceeded,
}

#[derive(Default)]
pub(super) struct EvidenceBudget {
    retained_frame_count: usize,
    retained_byte_count: usize,
}

impl EvidenceBudget {
    pub(super) fn retain(
        &mut self,
        frame: &Frame,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), EvidenceBudgetError> {
        let next_frame_count = self
            .retained_frame_count
            .checked_add(1)
            .ok_or(EvidenceBudgetError::FrameCountOverflow)?;
        let next_byte_count = self
            .retained_byte_count
            .checked_add(frame.bytes().len())
            .ok_or(EvidenceBudgetError::ByteCountOverflow)?;
        if next_frame_count > max_frames || next_byte_count > max_bytes {
            return Err(EvidenceBudgetError::LimitExceeded);
        }
        self.retained_frame_count = next_frame_count;
        self.retained_byte_count = next_byte_count;
        Ok(())
    }
}

pub(super) fn checked_frame_count(counts: &[usize]) -> Option<usize> {
    counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
}

pub(super) fn checked_frame_bytes<'a>(
    frames: impl IntoIterator<Item = &'a Frame>,
) -> Option<usize> {
    frames.into_iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.bytes().len())
    })
}

pub(super) fn checked_sent_frame_bytes(frames: &[Frame]) -> Option<u64> {
    frames.iter().try_fold(0_u64, |total, frame| {
        total.checked_add(frame.bytes().len() as u64)
    })
}

pub(super) fn validate_frame(frame: &Frame, kind: &str) -> Result<(), String> {
    frame
        .validate()
        .map_err(|error| format!("{kind} frame is invalid: {error}"))
}

pub(super) fn validate_decoded_frame(decoded: &DecodedPacket, kind: &str) -> Result<(), String> {
    validate_frame(&decoded.frame, kind)?;
    if decoded.original != decoded.frame.bytes() {
        return Err(format!("{kind} original bytes differ from its exact frame"));
    }
    Ok(())
}

pub(super) fn validate_capture_statistics(statistics: CaptureStatistics) -> Result<(), String> {
    statistics
        .validate()
        .map(|_| ())
        .map_err(|error| format!("capture statistics are invalid: {error}"))
}

pub(super) trait MatchedResponseEvidence {
    fn request_index(&self) -> usize;
    fn response(&self) -> &DecodedPacket;
    fn latency(&self) -> Duration;
}

pub(super) struct ExchangeEvidence<'a, M> {
    pub(super) request_count: usize,
    pub(super) sent_packets: &'a [Packet],
    pub(super) sent_frames: &'a [Frame],
    pub(super) matched_responses: &'a [M],
    pub(super) unsolicited: &'a [DecodedPacket],
    pub(super) undecoded: &'a [Frame],
    pub(super) timeout: Duration,
    pub(super) stats: &'a Stats,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ExchangeEvidenceError {
    SentCardinality {
        expected: usize,
        packets: usize,
        frames: usize,
    },
    MatchedResponseOutsideBatch,
    CapturedFrameCountOverflow,
    CapturedFrameLimitExceeded {
        actual: usize,
        limit: usize,
    },
    CapturedByteCountOverflow,
    CapturedByteLimitExceeded {
        actual: usize,
        limit: usize,
    },
    SentPacketMismatch {
        request_index: usize,
    },
    InvalidSentFrame {
        request_index: usize,
        message: String,
    },
    SentByteCountOverflow,
    SentByteCountMismatch {
        reported: u64,
        actual: u64,
    },
    InvalidMatchedResponse {
        message: String,
    },
    MatchedResponseAfterTimeout {
        latency: Duration,
        timeout: Duration,
    },
    InvalidUnsolicitedResponse {
        message: String,
    },
    InvalidUndecodedFrame {
        message: String,
    },
    InvalidCaptureStatistics {
        message: String,
    },
    IncompleteStatistics,
}

pub(super) fn validate_exchange_evidence<M, F>(
    evidence: ExchangeEvidence<'_, M>,
    max_captured_frames: usize,
    max_captured_bytes: usize,
    mut sent_packet_matches: F,
) -> Result<(), ExchangeEvidenceError>
where
    M: MatchedResponseEvidence,
    F: FnMut(usize, &Packet) -> bool,
{
    if evidence.sent_packets.len() != evidence.request_count
        || evidence.sent_frames.len() != evidence.request_count
    {
        return Err(ExchangeEvidenceError::SentCardinality {
            expected: evidence.request_count,
            packets: evidence.sent_packets.len(),
            frames: evidence.sent_frames.len(),
        });
    }
    if evidence
        .matched_responses
        .iter()
        .any(|response| response.request_index() >= evidence.request_count)
    {
        return Err(ExchangeEvidenceError::MatchedResponseOutsideBatch);
    }

    let captured_frames = checked_frame_count(&[
        evidence.matched_responses.len(),
        evidence.unsolicited.len(),
        evidence.undecoded.len(),
    ])
    .ok_or(ExchangeEvidenceError::CapturedFrameCountOverflow)?;
    if captured_frames > max_captured_frames {
        return Err(ExchangeEvidenceError::CapturedFrameLimitExceeded {
            actual: captured_frames,
            limit: max_captured_frames,
        });
    }
    let captured_bytes = checked_frame_bytes(
        evidence
            .matched_responses
            .iter()
            .map(|response| &response.response().frame)
            .chain(evidence.unsolicited.iter().map(|response| &response.frame))
            .chain(evidence.undecoded),
    )
    .ok_or(ExchangeEvidenceError::CapturedByteCountOverflow)?;
    if captured_bytes > max_captured_bytes {
        return Err(ExchangeEvidenceError::CapturedByteLimitExceeded {
            actual: captured_bytes,
            limit: max_captured_bytes,
        });
    }

    for (request_index, (sent, frame)) in evidence
        .sent_packets
        .iter()
        .zip(evidence.sent_frames)
        .enumerate()
    {
        if !sent_packet_matches(request_index, sent) {
            return Err(ExchangeEvidenceError::SentPacketMismatch { request_index });
        }
        validate_frame(frame, "sent").map_err(|message| {
            ExchangeEvidenceError::InvalidSentFrame {
                request_index,
                message,
            }
        })?;
    }

    let sent_bytes = checked_sent_frame_bytes(evidence.sent_frames)
        .ok_or(ExchangeEvidenceError::SentByteCountOverflow)?;
    if evidence.stats.bytes != sent_bytes {
        return Err(ExchangeEvidenceError::SentByteCountMismatch {
            reported: evidence.stats.bytes,
            actual: sent_bytes,
        });
    }
    for response in evidence.matched_responses {
        validate_decoded_frame(response.response(), "matched response")
            .map_err(|message| ExchangeEvidenceError::InvalidMatchedResponse { message })?;
        if response.latency() > evidence.timeout {
            return Err(ExchangeEvidenceError::MatchedResponseAfterTimeout {
                latency: response.latency(),
                timeout: evidence.timeout,
            });
        }
    }
    for response in evidence.unsolicited {
        validate_decoded_frame(response, "unsolicited response")
            .map_err(|message| ExchangeEvidenceError::InvalidUnsolicitedResponse { message })?;
    }
    for frame in evidence.undecoded {
        validate_frame(frame, "undecoded")
            .map_err(|message| ExchangeEvidenceError::InvalidUndecodedFrame { message })?;
    }
    validate_capture_statistics(evidence.stats.capture)
        .map_err(|message| ExchangeEvidenceError::InvalidCaptureStatistics { message })?;
    if evidence.stats.packets_attempted != evidence.request_count as u64
        || evidence.stats.packets_completed != evidence.request_count as u64
    {
        return Err(ExchangeEvidenceError::IncompleteStatistics);
    }
    Ok(())
}

pub(super) fn response_within_deadline(
    latency: Option<Duration>,
    captured_at: SystemTime,
    sent_at: SystemTime,
    timeout: Duration,
) -> bool {
    match latency {
        Some(latency) => latency <= timeout,
        None => captured_at
            .duration_since(sent_at)
            .is_ok_and(|captured_latency| captured_latency <= timeout),
    }
}

pub(super) fn preferred_latency(candidate: Option<Duration>, current: Option<Duration>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate < current,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::capture::LinkType;
    use crate::packet::{Packet, layout};

    struct NoMatchedResponses;

    impl MatchedResponseEvidence for NoMatchedResponses {
        fn request_index(&self) -> usize {
            unreachable!()
        }

        fn response(&self) -> &DecodedPacket {
            unreachable!()
        }

        fn latency(&self) -> Duration {
            unreachable!()
        }
    }

    fn frame(bytes: &'static [u8]) -> Frame {
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap()
    }

    #[test]
    fn checked_evidence_totals_fail_closed_on_overflow() {
        assert_eq!(checked_frame_count(&[2, 3, 5]), Some(10));
        assert_eq!(checked_frame_count(&[usize::MAX, 1]), None);

        let first = frame(&[1, 2]);
        let second = frame(&[3]);
        assert_eq!(checked_frame_bytes([&first, &second]), Some(3));
        assert_eq!(
            checked_sent_frame_bytes(&[first.clone(), second.clone()]),
            Some(3)
        );
    }

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
}
