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

/// Why the evidence an executor returned for one step is inconsistent with
/// the step it was granted: the exact sent packets and bytes, the captured
/// responses and their timing, capture statistics, or evidence limits.
///
/// Workflows report it at the step it concerns, in their own error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ExchangeEvidenceError {
    /// The evidence is bound to a different execution permit than the one
    /// the step was granted.
    #[error("executor returned evidence for a different execution permit")]
    PermitMismatch,
    #[error("expected {expected} sent receipts, received {receipts}")]
    SentCardinality { expected: usize, receipts: usize },
    #[error("matched response references a request outside the executed step")]
    ResponseOutsideBatch,
    #[error("executor capture frame-count accounting overflowed")]
    CapturedFrameCountOverflow,
    #[error("executor returned {actual} captured frames beyond max_evidence_frames={limit}")]
    CapturedFrameLimitExceeded { actual: usize, limit: usize },
    #[error("executor capture byte accounting overflowed")]
    CapturedByteCountOverflow,
    #[error("executor returned {actual} captured bytes beyond max_evidence_bytes={limit}")]
    CapturedByteLimitExceeded { actual: usize, limit: usize },
    /// The packet at `request_index` does not carry the destination and
    /// probe identity the step requested.
    #[error("sent packet does not preserve the requested destination and probe identity")]
    SentPacketMismatch { request_index: usize },
    #[error("sent frame byte accounting overflowed")]
    SentByteCountOverflow,
    #[error("successful exchange reported {reported} sent bytes for {actual} exact frame bytes")]
    SentByteCountMismatch { reported: u64, actual: u64 },
    #[error("executor returned {evidence} without a timestamp")]
    TimestampUnavailable { evidence: &'static str },
    #[error("{message}")]
    InvalidMatchedResponse { message: String },
    #[error("matched response latency {latency:?} exceeds timeout {timeout:?}")]
    ResponseAfterTimeout {
        latency: Duration,
        timeout: Duration,
    },
    #[error("{message}")]
    InvalidUnsolicitedResponse { message: String },
    #[error("{message}")]
    InvalidCaptureStatistics { message: String },
    #[error("successful exchange statistics do not account for every request")]
    IncompleteStatistics,
}

impl ExchangeEvidenceError {
    pub(crate) const fn request_index(&self) -> Option<usize> {
        match self {
            Self::SentPacketMismatch { request_index } => Some(*request_index),
            _ => None,
        }
    }

    /// The message a workflow reports, naming what one executed step is
    /// (`step`, such as "hop batch") and the workflow (`workflow`) where the
    /// neutral [`Display`](std::fmt::Display) text leaves them generic.
    pub(crate) fn describe(&self, step: &str, workflow: &str) -> String {
        match self {
            Self::ResponseOutsideBatch => {
                format!("matched response references a request outside the {step}")
            }
            Self::SentPacketMismatch { .. } => {
                format!(
                    "sent packet does not preserve the {workflow} destination and probe identity"
                )
            }
            Self::IncompleteStatistics => {
                format!("successful exchange statistics do not account for every {workflow} probe")
            }
            error => error.to_string(),
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
