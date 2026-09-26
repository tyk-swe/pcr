// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact validation of what executors return: sent bytes and packets, matched
//! and unsolicited responses, capture statistics, and aggregate evidence
//! limits, checked before any evidence is charged or published.

use std::time::Duration;

use crate::evidence::{self, SentPacket};
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

pub(crate) fn validate_aggregate_evidence_limits(
    matched_responses: &[crate::exchange::Response],
    unsolicited: &[DecodedPacket],
    undecoded: &[Frame],
    max_captured_frames: usize,
    max_captured_bytes: usize,
) -> Result<(), evidence::Error> {
    let captured_frames =
        checked_frame_count(&[matched_responses.len(), unsolicited.len(), undecoded.len()])
            .ok_or(evidence::Error::CapturedFrameCountOverflow)?;
    if captured_frames > max_captured_frames {
        return Err(evidence::Error::CapturedFrameLimitExceeded {
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
    .ok_or(evidence::Error::CapturedByteCountOverflow)?;
    if captured_bytes > max_captured_bytes {
        return Err(evidence::Error::CapturedByteLimitExceeded {
            actual: captured_bytes,
            limit: max_captured_bytes,
        });
    }
    Ok(())
}

pub(crate) fn validate_sent_byte_accounting(
    sent: &[SentPacket],
    reported: u64,
) -> Result<(), evidence::Error> {
    let actual =
        crate::evidence::total_bytes_sent(sent).ok_or(evidence::Error::SentByteCountOverflow)?;
    if reported != actual {
        return Err(evidence::Error::SentByteCountMismatch { reported, actual });
    }
    Ok(())
}

pub(crate) fn validate_response_frames_and_deadlines(
    matched_responses: &[crate::exchange::Response],
    unsolicited: &[DecodedPacket],
    timeout: Duration,
) -> Result<(), evidence::Error> {
    for response in matched_responses {
        validate_decoded_frame(&response.response, "matched response")
            .map_err(|message| evidence::Error::InvalidMatchedResponse { message })?;
        validate_frame_timestamp(&response.response.frame, "matched response")?;
        if response.latency > timeout {
            return Err(evidence::Error::ResponseAfterTimeout {
                latency: response.latency,
                timeout,
            });
        }
    }
    for response in unsolicited {
        validate_decoded_frame(response, "unsolicited response")
            .map_err(|message| evidence::Error::InvalidUnsolicitedResponse { message })?;
        validate_frame_timestamp(&response.frame, "unsolicited response")?;
    }
    Ok(())
}

fn validate_frame_timestamp(frame: &Frame, evidence: &'static str) -> Result<(), evidence::Error> {
    if frame.timestamp.is_none() {
        return Err(evidence::Error::TimestampUnavailable { evidence });
    }
    Ok(())
}

pub(crate) fn validate_capture_statistics_evidence(
    statistics: Stats,
) -> Result<(), evidence::Error> {
    validate_capture_statistics(statistics)
        .map_err(|message| evidence::Error::InvalidCaptureStatistics { message })
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
