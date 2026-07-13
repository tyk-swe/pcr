// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

use std::time::{Duration, SystemTime};

use crate::capture::Frame;
use crate::net::capture::Statistics as CaptureStatistics;
use crate::packet::decode::Result as DecodedPacket;

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
            .checked_add(frame.bytes.len())
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
    frames
        .into_iter()
        .try_fold(0_usize, |total, frame| total.checked_add(frame.bytes.len()))
}

pub(super) fn checked_sent_frame_bytes(frames: &[Frame]) -> Option<u64> {
    frames.iter().try_fold(0_u64, |total, frame| {
        total.checked_add(frame.bytes.len() as u64)
    })
}

pub(super) fn validate_frame(frame: &Frame, kind: &str) -> Result<(), String> {
    frame
        .validate()
        .map_err(|error| format!("{kind} frame is invalid: {error}"))
}

pub(super) fn validate_decoded_frame(decoded: &DecodedPacket, kind: &str) -> Result<(), String> {
    validate_frame(&decoded.frame, kind)?;
    if decoded.original != decoded.frame.bytes {
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

        let mut invalid = frame(&[1]);
        invalid.captured_length = 0;
        assert_eq!(
            validate_frame(&invalid, "sent"),
            Err(
                "sent frame is invalid: frame captured length says 0 bytes but contains 1"
                    .to_owned()
            )
        );
    }
}
