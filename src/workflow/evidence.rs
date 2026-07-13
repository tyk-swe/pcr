// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

use std::time::{Duration, SystemTime};

use crate::capture::Frame;

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
