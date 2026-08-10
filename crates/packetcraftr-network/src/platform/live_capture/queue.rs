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
        let would_exceed_frames = state.queue.len() >= self.limits.max_frames;
        let would_exceed_bytes = state
            .queued_bytes
            .checked_add(frame_bytes)
            .is_none_or(|bytes| bytes > self.limits.max_bytes);
        if would_exceed_frames || would_exceed_bytes {
            match self.limits.overflow_policy {
                CaptureOverflowPolicy::Fail => {
                    let mut statistics = state.statistics;
                    increment(&mut statistics.overflow_events, 1, "overflow events")?;
                    increment(&mut statistics.dropped_frames, 1, "dropped frames")?;
                    increment(
                        &mut statistics.dropped_bytes,
                        frame_bytes as u64,
                        "dropped bytes",
                    )?;
                    state.statistics = statistics;
                    return Err(LiveIoError::CaptureQueueOverflow {
                        dropped_frames: statistics.dropped_frames,
                        dropped_bytes: statistics.dropped_bytes,
                        overflow_events: statistics.overflow_events,
                    });
                }
                CaptureOverflowPolicy::DropNewest => {
                    let mut statistics = state.statistics;
                    increment(&mut statistics.overflow_events, 1, "overflow events")?;
                    increment(&mut statistics.dropped_frames, 1, "dropped frames")?;
                    increment(
                        &mut statistics.dropped_bytes,
                        frame_bytes as u64,
                        "dropped bytes",
                    )?;
                    state.statistics = statistics;
                    return Ok(());
                }
                CaptureOverflowPolicy::DropOldest => {
                    let mut retained_frames = state.queue.len();
                    let mut retained_bytes = state.queued_bytes;
                    let mut drop_count = 0usize;
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
                        let mut statistics = state.statistics;
                        increment(&mut statistics.overflow_events, 1, "overflow events")?;
                        increment(&mut statistics.dropped_frames, 1, "dropped frames")?;
                        increment(
                            &mut statistics.dropped_bytes,
                            frame_bytes as u64,
                            "dropped bytes",
                        )?;
                        state.statistics = statistics;
                        return Ok(());
                    }

                    let mut statistics = state.statistics;
                    increment(&mut statistics.overflow_events, 1, "overflow events")?;
                    increment(
                        &mut statistics.dropped_frames,
                        drop_count as u64,
                        "dropped frames",
                    )?;
                    increment(
                        &mut statistics.dropped_bytes,
                        drop_bytes as u64,
                        "dropped bytes",
                    )?;
                    increment(&mut statistics.received_frames, 1, "received frames")?;
                    increment(
                        &mut statistics.received_bytes,
                        frame_bytes as u64,
                        "received bytes",
                    )?;
                    for _ in 0..drop_count {
                        state.queue.pop_front();
                    }
                    state.queued_bytes = retained_bytes + frame_bytes;
                    state.statistics = statistics;
                    state.queue.push_back(captured);
                    drop(state);
                    self.changed.notify_one();
                    return Ok(());
                }
            }
        }
        let queued_bytes = state.queued_bytes.checked_add(frame_bytes).ok_or_else(|| {
            LiveIoError::InvalidCaptureStatistics {
                message: "native capture queue byte accounting overflowed".to_owned(),
            }
        })?;
        let mut statistics = state.statistics;
        increment(&mut statistics.received_frames, 1, "received frames")?;
        increment(
            &mut statistics.received_bytes,
            frame_bytes as u64,
            "received bytes",
        )?;
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
        let (capture_drop_delta, network_drop_delta, interface_drop_delta) =
            native_drop_deltas(previous, current)?;
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

fn native_drop_deltas(
    previous: NativeCaptureStatistics,
    current: NativeCaptureStatistics,
) -> Result<(u64, u64, u64), LiveIoError> {
    if current.generation == previous.generation {
        return Ok((
            u64::from(
                current
                    .capture_dropped_frames
                    .wrapping_sub(previous.capture_dropped_frames),
            ),
            u64::from(
                current
                    .network_dropped_frames
                    .wrapping_sub(previous.network_dropped_frames),
            ),
            u64::from(
                current
                    .interface_dropped_frames
                    .wrapping_sub(previous.interface_dropped_frames),
            ),
        ));
    }
    let expected_generation = previous.generation.checked_add(1).ok_or_else(|| {
        LiveIoError::InvalidCaptureStatistics {
            message: "native receiver counter generation overflowed".to_owned(),
        }
    })?;
    if current.generation != expected_generation {
        return Err(LiveIoError::InvalidCaptureStatistics {
            message: format!(
                "native receiver counter generation changed from {} to {}, expected reset generation {expected_generation}",
                previous.generation, current.generation
            ),
        });
    }
    Ok((
        u64::from(current.capture_dropped_frames),
        u64::from(current.network_dropped_frames),
        u64::from(current.interface_dropped_frames),
    ))
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

fn increment(counter: &mut u64, value: u64, label: &str) -> Result<(), LiveIoError> {
    *counter = counter
        .checked_add(value)
        .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
            message: format!("native capture {label} counter overflowed"),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(generation: u64, values: [u32; 3]) -> NativeCaptureStatistics {
        NativeCaptureStatistics {
            generation,
            capture_dropped_frames: values[0],
            network_dropped_frames: values[1],
            interface_dropped_frames: values[2],
        }
    }

    #[test]
    fn native_drop_deltas_distinguish_increment_wrap_reset_and_generation_change() {
        assert_eq!(
            native_drop_deltas(sample(3, [1, 2, 3]), sample(3, [4, 6, 8]))
                .expect("same-generation increments"),
            (3, 4, 5)
        );
        assert_eq!(
            native_drop_deltas(sample(3, [u32::MAX, u32::MAX - 1, 4]), sample(3, [1, 1, 4]),)
                .expect("same-generation native counter wrap"),
            (2, 3, 0)
        );

        assert_eq!(
            native_drop_deltas(sample(3, [u32::MAX - 2, 100, 8]), sample(4, [2, 3, 0]),)
                .expect("explicit provider reset"),
            (2, 3, 0)
        );

        assert!(matches!(
            native_drop_deltas(sample(3, [10, 0, 0]), sample(5, [2, 0, 0])),
            Err(LiveIoError::InvalidCaptureStatistics { ref message })
                if message.contains("expected reset generation 4")
        ));
        assert!(matches!(
            native_drop_deltas(sample(3, [10, 0, 0]), sample(2, [2, 0, 0])),
            Err(LiveIoError::InvalidCaptureStatistics { ref message })
                if message.contains("expected reset generation 4")
        ));
        assert!(matches!(
            native_drop_deltas(
                sample(u64::MAX, [10, 0, 0]),
                sample(0, [0, 0, 0]),
            ),
            Err(LiveIoError::InvalidCaptureStatistics { ref message })
                if message.contains("generation overflowed")
        ));
    }

    #[test]
    fn native_drop_counter_overflow_does_not_partially_mutate_statistics() {
        let capture = SharedCapture::new(CaptureQueueLimits::default());
        {
            let mut state = capture.lock().expect("capture queue lock");
            state.statistics.dropped_frames = u64::MAX;
            state.statistics.receiver_dropped_frames = u64::MAX;
        }
        let before = capture.lock().expect("capture queue lock").statistics;
        assert!(matches!(
            capture.add_native_drop_deltas(sample(0, [0, 0, 0]), sample(0, [1, 0, 0])),
            Err(LiveIoError::InvalidCaptureStatistics { ref message })
                if message.contains("dropped frames counter overflowed")
        ));
        assert_eq!(
            capture.lock().expect("capture queue lock").statistics,
            before
        );
    }
}
