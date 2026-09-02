// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact-frame, deadline, statistics, and exchange-contract validation.

use std::time::Duration;

use crate::SentPacket;
use crate::probe::runner::{Batch, Execution, Sequenced};
use crate::probe::{Error, ErrorKind, Workflow};

use super::EvidenceLimits;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{Packet, decode::DecodedPacket};
use packetcraftr_netio::capture::Statistics;

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

pub(crate) fn validate_batch_exchange_evidence<P, F>(
    batch: &Batch<P>,
    execution: &Execution,
    max_captured_frames: usize,
    max_captured_bytes: usize,
    mut sent_packet_matches: F,
) -> Result<(), ExchangeEvidenceError>
where
    F: FnMut(&P, &Packet) -> bool,
{
    if execution.sent.len() != batch.probes.len() {
        return Err(ExchangeEvidenceError::SentCardinality {
            expected: batch.probes.len(),
            receipts: execution.sent.len(),
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index >= batch.probes.len())
    {
        return Err(ExchangeEvidenceError::ResponseOutsideBatch);
    }

    validate_aggregate_evidence_limits(
        &execution.responses,
        &execution.unsolicited,
        &execution.undecoded,
        max_captured_frames,
        max_captured_bytes,
    )?;

    for (request_index, (sent, probe)) in execution.sent.iter().zip(&batch.probes).enumerate() {
        if !sent_packet_matches(probe, &sent.built().packet) {
            return Err(ExchangeEvidenceError::SentPacketMismatch { request_index });
        }
    }

    validate_sent_byte_accounting(&execution.sent, execution.stats.bytes)?;
    validate_response_frames_and_deadlines(
        &execution.responses,
        &execution.unsolicited,
        batch.timeout,
    )?;
    validate_capture_statistics_evidence(execution.stats.capture)?;
    if execution.stats.packets_attempted != u64::try_from(batch.probes.len()).unwrap_or(u64::MAX)
        || execution.stats.packets_completed
            != u64::try_from(batch.probes.len()).unwrap_or(u64::MAX)
    {
        return Err(ExchangeEvidenceError::IncompleteStatistics);
    }
    Ok(())
}

/// Validates one batch's executor evidence under the workflow's limits and
/// reports any inconsistency at the sequence of the probe it concerns.
pub(crate) fn validate_batch_evidence<P: Sequenced>(
    workflow: Workflow,
    batch: &Batch<P>,
    execution: &Execution,
    limits: EvidenceLimits,
    sent_packet_matches: impl FnMut(&P, &Packet) -> bool,
) -> Result<(), Error> {
    validate_batch_exchange_evidence(
        batch,
        execution,
        limits.max_frames,
        limits.max_bytes,
        sent_packet_matches,
    )
    .map_err(|error| {
        let sequence = error
            .request_index()
            .and_then(|index| batch.probes.get(index))
            .or_else(|| batch.probes.first())
            .map_or(0, Sequenced::sequence);
        Error::new(
            workflow,
            ErrorKind::InvalidEvidence {
                sequence,
                message: format_exchange_evidence_error(
                    error,
                    workflow.batch_noun(),
                    workflow.as_str(),
                ),
            },
        )
    })
}
