// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Synchronized bounded capture queue and checked statistics accounting.

use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex, MutexGuard},
    time::Duration,
};

use crate::{
    Error as LiveIoError,
    capture::{CaptureOverflowPolicy, CaptureQueueLimits, CapturedFrame, Statistics},
};

use super::NativeCaptureStatistics;

pub(super) struct SharedCapture {
    pub(super) state: Mutex<CaptureState>,
    changed: Condvar,
    limits: CaptureQueueLimits,
}

impl SharedCapture {
    pub(super) fn new(limits: CaptureQueueLimits) -> Self {
        Self {
            state: Mutex::new(CaptureState::default()),
            changed: Condvar::new(),
            limits,
        }
    }

    pub(super) fn lock(&self) -> Result<MutexGuard<'_, CaptureState>, LiveIoError> {
        self.state.lock().map_err(|_| LiveIoError::Capture {
            message: "native capture queue mutex was poisoned".to_owned(),
        })
    }

    pub(super) fn wait_timeout<'a>(
        &self,
        state: MutexGuard<'a, CaptureState>,
        timeout: Duration,
    ) -> Result<(MutexGuard<'a, CaptureState>, bool), LiveIoError> {
        self.changed
            .wait_timeout(state, timeout)
            .map(|(state, result)| (state, result.timed_out()))
            .map_err(|_| LiveIoError::Capture {
                message: "native capture queue mutex was poisoned".to_owned(),
            })
    }

    pub(super) fn set_ready(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.ready = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn set_error(&self, error: LiveIoError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.error.is_none() {
            state.error = Some(error);
        }
        state.closed = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn enqueue(&self, captured: CapturedFrame) -> Result<(), LiveIoError> {
        let mut state = self.lock()?;
        let frame_bytes = captured.frame.bytes().len();
        let mut queued_bytes = state.queued_bytes;
        let mut statistics = state.statistics;
        let mut drop_count = 0usize;
        let would_exceed_frames = state.queue.len() >= self.limits.max_frames;
        let would_exceed_bytes = state
            .queued_bytes
            .checked_add(frame_bytes)
            .is_none_or(|bytes| bytes > self.limits.max_bytes);
        if would_exceed_frames || would_exceed_bytes {
            match self.limits.overflow_policy {
                policy @ (CaptureOverflowPolicy::Fail | CaptureOverflowPolicy::DropNewest) => {
                    record_overflow(&mut statistics, 1, frame_bytes as u64)?;
                    state.statistics = statistics;
                    return if policy == CaptureOverflowPolicy::Fail {
                        Err(LiveIoError::CaptureQueueOverflow {
                            dropped_frames: statistics.dropped_frames,
                            dropped_bytes: statistics.dropped_bytes,
                            overflow_events: statistics.overflow_events,
                        })
                    } else {
                        Ok(())
                    };
                }
                CaptureOverflowPolicy::DropOldest => {
                    let mut retained_frames = state.queue.len();
                    let mut retained_bytes = state.queued_bytes;
                    let mut drop_bytes = 0usize;
                    for dropped in &state.queue {
                        if retained_frames < self.limits.max_frames
                            && retained_bytes
                                .checked_add(frame_bytes)
                                .is_some_and(|bytes| bytes <= self.limits.max_bytes)
                        {
                            break;
                        }
                        let bytes = dropped.frame.bytes().len();
                        retained_frames -= 1;
                        retained_bytes = retained_bytes.checked_sub(bytes).ok_or_else(|| {
                            LiveIoError::InvalidCaptureStatistics {
                                message: "native capture queue byte accounting underflowed"
                                    .to_owned(),
                            }
                        })?;
                        drop_count += 1;
                        drop_bytes = drop_bytes.checked_add(bytes).ok_or_else(|| {
                            LiveIoError::InvalidCaptureStatistics {
                                message: "native capture dropped-byte accounting overflowed"
                                    .to_owned(),
                            }
                        })?;
                    }
                    if retained_frames >= self.limits.max_frames
                        || retained_bytes
                            .checked_add(frame_bytes)
                            .is_none_or(|bytes| bytes > self.limits.max_bytes)
                    {
                        record_overflow(&mut statistics, 1, frame_bytes as u64)?;
                        state.statistics = statistics;
                        return Ok(());
                    }
                    record_overflow(&mut statistics, drop_count as u64, drop_bytes as u64)?;
                    queued_bytes = retained_bytes;
                }
            }
        }
        queued_bytes = queued_bytes.checked_add(frame_bytes).ok_or_else(|| {
            LiveIoError::InvalidCaptureStatistics {
                message: "native capture queue byte accounting overflowed".to_owned(),
            }
        })?;
        record_received(&mut statistics, frame_bytes as u64)?;
        for _ in 0..drop_count {
            state.queue.pop_front();
        }
        state.queued_bytes = queued_bytes;
        state.statistics = statistics;
        state.queue.push_back(captured);
        drop(state);
        self.changed.notify_one();
        Ok(())
    }

    pub(super) fn add_native_drop_deltas(
        &self,
        previous: NativeCaptureStatistics,
        current: NativeCaptureStatistics,
    ) -> Result<(), LiveIoError> {
        let capture_drop_delta = current
            .capture_dropped_frames
            .wrapping_sub(previous.capture_dropped_frames) as u64;
        let network_drop_delta = current
            .network_dropped_frames
            .wrapping_sub(previous.network_dropped_frames) as u64;
        let interface_drop_delta = current
            .interface_dropped_frames
            .wrapping_sub(previous.interface_dropped_frames)
            as u64;
        let total_drop_delta = capture_drop_delta
            .checked_add(network_drop_delta)
            .and_then(|total| total.checked_add(interface_drop_delta))
            .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                message: "native receiver drop delta overflowed".to_owned(),
            })?;
        if total_drop_delta == 0 {
            return Ok(());
        }
        let mut state = self.lock()?;
        let mut statistics = state.statistics;
        increment(
            &mut statistics.dropped_frames,
            total_drop_delta,
            "dropped frames",
        )?;
        increment(
            &mut statistics.receiver_dropped_frames,
            total_drop_delta,
            "receiver-dropped frames",
        )?;
        state.statistics = statistics;
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct CaptureState {
    pub(super) ready: bool,
    pub(super) closed: bool,
    pub(super) error_observed: bool,
    pub(super) error: Option<LiveIoError>,
    pub(super) queue: VecDeque<CapturedFrame>,
    pub(super) queued_bytes: usize,
    pub(super) statistics: Statistics,
}

fn record_overflow(
    statistics: &mut Statistics,
    dropped_frames: u64,
    dropped_bytes: u64,
) -> Result<(), LiveIoError> {
    increment(&mut statistics.overflow_events, 1, "overflow events")?;
    increment(
        &mut statistics.dropped_frames,
        dropped_frames,
        "dropped frames",
    )?;
    increment(
        &mut statistics.dropped_bytes,
        dropped_bytes,
        "dropped bytes",
    )
}

fn record_received(statistics: &mut Statistics, received_bytes: u64) -> Result<(), LiveIoError> {
    increment(&mut statistics.received_frames, 1, "received frames")?;
    increment(
        &mut statistics.received_bytes,
        received_bytes,
        "received bytes",
    )
}

fn increment(counter: &mut u64, value: u64, label: &str) -> Result<(), LiveIoError> {
    *counter = counter
        .checked_add(value)
        .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
            message: format!("native capture {label} counter overflowed"),
        })?;
    Ok(())
}
