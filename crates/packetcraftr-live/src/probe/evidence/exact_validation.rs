// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact-frame, deadline, statistics, and exchange-contract validation.

use std::time::Duration;

use crate::SentPacket;
use crate::Stats;
use packetcraftr_network::capture::Statistics;
use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket};

use super::budget::{checked_frame_bytes, checked_frame_count};

pub(crate) fn validate_decoded_frame(decoded: &DecodedPacket, kind: &str) -> Result<(), String> {
    if decoded.original != decoded.frame.bytes() {
        return Err(format!("{kind} original bytes differ from its exact frame"));
    }
    Ok(())
}

pub(crate) fn validate_capture_statistics(statistics: Statistics) -> Result<(), String> {
    statistics
        .validate()
        .map(|_| ())
        .map_err(|error| format!("capture statistics are invalid: {error}"))
}

pub(crate) trait ResponseEvidence {
    fn response(&self) -> &DecodedPacket;
    fn latency(&self) -> Duration;
}

pub(crate) trait MatchedResponseEvidence: ResponseEvidence {
    fn request_index(&self) -> usize;
}

pub(crate) struct ExchangeEvidence<'a, M> {
    pub(crate) request_count: usize,
    pub(crate) sent: &'a [SentPacket],
    pub(crate) matched_responses: &'a [M],
    pub(crate) unsolicited: &'a [DecodedPacket],
    pub(crate) undecoded: &'a [Frame],
    pub(crate) timeout: Duration,
    pub(crate) stats: &'a Stats,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExchangeEvidenceError {
    SentCardinality {
        expected: usize,
        receipts: usize,
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
    SentByteCountOverflow,
    SentByteCountMismatch {
        reported: u64,
        actual: u64,
    },
    TimestampUnavailable {
        evidence: &'static str,
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
    InvalidCaptureStatistics {
        message: String,
    },
    IncompleteStatistics,
}

pub(crate) fn validate_aggregate_evidence_limits<M: ResponseEvidence>(
    matched_responses: &[M],
    unsolicited: &[DecodedPacket],
    undecoded: &[Frame],
    max_captured_frames: usize,
    max_captured_bytes: usize,
) -> Result<(), ExchangeEvidenceError> {
    let captured_frames =
        checked_frame_count(&[matched_responses.len(), unsolicited.len(), undecoded.len()])
            .ok_or(ExchangeEvidenceError::CapturedFrameCountOverflow)?;
    if captured_frames > max_captured_frames {
        return Err(ExchangeEvidenceError::CapturedFrameLimitExceeded {
            actual: captured_frames,
            limit: max_captured_frames,
        });
    }
    let captured_bytes = checked_frame_bytes(
        matched_responses
            .iter()
            .map(|response| &response.response().frame)
            .chain(unsolicited.iter().map(|response| &response.frame))
            .chain(undecoded),
    )
    .ok_or(ExchangeEvidenceError::CapturedByteCountOverflow)?;
    if captured_bytes > max_captured_bytes {
        return Err(ExchangeEvidenceError::CapturedByteLimitExceeded {
            actual: captured_bytes,
            limit: max_captured_bytes,
        });
    }
    Ok(())
}

pub(crate) fn validate_sent_byte_accounting(
    sent: &[SentPacket],
    reported: u64,
) -> Result<(), ExchangeEvidenceError> {
    let actual = sent
        .iter()
        .try_fold(0_u64, |total, sent| {
            total.checked_add(sent.bytes_sent() as u64)
        })
        .ok_or(ExchangeEvidenceError::SentByteCountOverflow)?;
    if reported != actual {
        return Err(ExchangeEvidenceError::SentByteCountMismatch { reported, actual });
    }
    Ok(())
}

pub(crate) fn validate_response_frames_and_deadlines<M: ResponseEvidence>(
    matched_responses: &[M],
    unsolicited: &[DecodedPacket],
    timeout: Duration,
) -> Result<(), ExchangeEvidenceError> {
    for response in matched_responses {
        validate_decoded_frame(response.response(), "matched response")
            .map_err(|message| ExchangeEvidenceError::InvalidMatchedResponse { message })?;
        validate_frame_timestamp(&response.response().frame, "matched response")?;
        let latency = response.latency();
        if latency > timeout {
            return Err(ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout });
        }
    }
    for response in unsolicited {
        validate_decoded_frame(response, "unsolicited response")
            .map_err(|message| ExchangeEvidenceError::InvalidUnsolicitedResponse { message })?;
        validate_frame_timestamp(&response.frame, "unsolicited response")?;
    }
    Ok(())
}

fn validate_frame_timestamp(
    frame: &Frame,
    evidence: &'static str,
) -> Result<(), ExchangeEvidenceError> {
    if frame.timestamp.is_none() {
        return Err(ExchangeEvidenceError::TimestampUnavailable { evidence });
    }
    Ok(())
}

pub(crate) fn validate_capture_statistics_evidence(
    statistics: Statistics,
) -> Result<(), ExchangeEvidenceError> {
    validate_capture_statistics(statistics)
        .map_err(|message| ExchangeEvidenceError::InvalidCaptureStatistics { message })
}

pub(crate) fn format_exchange_evidence_error(
    error: ExchangeEvidenceError,
    batch_kind: &str,
    workflow: &str,
) -> String {
    match error {
        ExchangeEvidenceError::SentCardinality { expected, receipts } => {
            format!("expected {expected} sent receipts, received {receipts}")
        }
        ExchangeEvidenceError::MatchedResponseOutsideBatch => {
            format!("matched response references a request outside the {batch_kind}")
        }
        ExchangeEvidenceError::CapturedFrameCountOverflow => {
            "executor capture frame-count accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured frames beyond max_evidence_frames={limit}")
        }
        ExchangeEvidenceError::CapturedByteCountOverflow => {
            "executor capture byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedByteLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured bytes beyond max_evidence_bytes={limit}")
        }
        ExchangeEvidenceError::SentPacketMismatch { .. } => {
            format!("sent packet does not preserve the {workflow} destination and probe identity")
        }
        ExchangeEvidenceError::InvalidMatchedResponse { message }
        | ExchangeEvidenceError::InvalidUnsolicitedResponse { message }
        | ExchangeEvidenceError::InvalidCaptureStatistics { message } => message,
        ExchangeEvidenceError::SentByteCountOverflow => {
            "sent frame byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::SentByteCountMismatch { reported, actual } => format!(
            "successful exchange reported {reported} sent bytes for {actual} exact frame bytes"
        ),
        ExchangeEvidenceError::TimestampUnavailable { evidence } => {
            format!("executor returned {evidence} without a timestamp")
        }
        ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::IncompleteStatistics => {
            format!("successful exchange statistics do not account for every {workflow} probe")
        }
    }
}

pub(crate) fn validate_exchange_evidence<M, F>(
    evidence: ExchangeEvidence<'_, M>,
    max_captured_frames: usize,
    max_captured_bytes: usize,
    mut sent_packet_matches: F,
) -> Result<(), ExchangeEvidenceError>
where
    M: MatchedResponseEvidence,
    F: FnMut(usize, &Packet) -> bool,
{
    if evidence.sent.len() != evidence.request_count {
        return Err(ExchangeEvidenceError::SentCardinality {
            expected: evidence.request_count,
            receipts: evidence.sent.len(),
        });
    }
    if evidence
        .matched_responses
        .iter()
        .any(|response| response.request_index() >= evidence.request_count)
    {
        return Err(ExchangeEvidenceError::MatchedResponseOutsideBatch);
    }

    validate_aggregate_evidence_limits(
        evidence.matched_responses,
        evidence.unsolicited,
        evidence.undecoded,
        max_captured_frames,
        max_captured_bytes,
    )?;

    for (request_index, sent) in evidence.sent.iter().enumerate() {
        if !sent_packet_matches(request_index, &sent.built().packet) {
            return Err(ExchangeEvidenceError::SentPacketMismatch { request_index });
        }
    }

    validate_sent_byte_accounting(evidence.sent, evidence.stats.bytes)?;
    validate_response_frames_and_deadlines(
        evidence.matched_responses,
        evidence.unsolicited,
        evidence.timeout,
    )?;
    validate_capture_statistics_evidence(evidence.stats.capture)?;
    if evidence.stats.packets_attempted != evidence.request_count as u64
        || evidence.stats.packets_completed != evidence.request_count as u64
    {
        return Err(ExchangeEvidenceError::IncompleteStatistics);
    }
    Ok(())
}
