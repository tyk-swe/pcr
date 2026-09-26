// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact validation of what executors return: sent bytes and packets, matched
//! and unsolicited responses, capture statistics, and aggregate evidence
//! limits, checked before any evidence is charged or published.

use std::time::Duration;

use crate::SentPacket;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::Stats;

fn validate_decoded_frame(decoded: &DecodedPacket, kind: &str) -> Result<(), String> {
    if decoded.original != decoded.frame.bytes() {
        return Err(format!("{kind} original bytes differ from its exact frame"));
    }
    Ok(())
}

fn validate_capture_statistics(statistics: Stats) -> Result<(), String> {
    statistics
        .validate()
        .map(|_| ())
        .map_err(|error| format!("capture statistics are invalid: {error}"))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExchangeEvidenceError {
    SentCardinality {
        expected: usize,
        receipts: usize,
    },
    ResponseOutsideBatch,
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
    ResponseAfterTimeout {
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

impl ExchangeEvidenceError {
    pub(crate) const fn request_index(&self) -> Option<usize> {
        match self {
            Self::SentPacketMismatch { request_index } => Some(*request_index),
            _ => None,
        }
    }
}

pub(crate) fn validate_aggregate_evidence_limits(
    matched_responses: &[crate::exchange::Response],
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
            .map(|response| &response.response.frame)
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
    let actual = crate::evidence::total_bytes_sent(sent)
        .ok_or(ExchangeEvidenceError::SentByteCountOverflow)?;
    if reported != actual {
        return Err(ExchangeEvidenceError::SentByteCountMismatch { reported, actual });
    }
    Ok(())
}

pub(crate) fn validate_response_frames_and_deadlines(
    matched_responses: &[crate::exchange::Response],
    unsolicited: &[DecodedPacket],
    timeout: Duration,
) -> Result<(), ExchangeEvidenceError> {
    for response in matched_responses {
        validate_decoded_frame(&response.response, "matched response")
            .map_err(|message| ExchangeEvidenceError::InvalidMatchedResponse { message })?;
        validate_frame_timestamp(&response.response.frame, "matched response")?;
        if response.latency > timeout {
            return Err(ExchangeEvidenceError::ResponseAfterTimeout {
                latency: response.latency,
                timeout,
            });
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
    statistics: Stats,
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
        ExchangeEvidenceError::ResponseOutsideBatch => {
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
        ExchangeEvidenceError::ResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::IncompleteStatistics => {
            format!("successful exchange statistics do not account for every {workflow} probe")
        }
    }
}

fn checked_frame_count(counts: &[usize]) -> Option<usize> {
    counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
}

fn checked_frame_bytes<'a>(frames: impl IntoIterator<Item = &'a Frame>) -> Option<usize> {
    frames.into_iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.bytes().len())
    })
}
