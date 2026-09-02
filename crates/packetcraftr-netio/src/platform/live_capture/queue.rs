// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Synchronized bounded capture queue and checked statistics accounting.

use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex, MutexGuard},
    time::Duration,
};

use crate::{
    Error,
    capture::{Captured, Limits, OverflowPolicy, Statistics},
};

use super::NativeCaptureStatistics;

pub(super) struct CaptureQueue {
    state: Mutex<CaptureState>,
    changed: Condvar,
    limits: Limits,
}

impl CaptureQueue {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            state: Mutex::new(CaptureState::default()),
            changed: Condvar::new(),
            limits,
        }
    }

    /// Poisoning is always recovered from rather than reported.
    ///
    /// `CaptureState` is plain data with no cross-field invariant to break
    /// halfway: every mutation below computes into locals and commits each
    /// counter, the queue, and the terminal error in one step, so a panic
    /// while the lock is held cannot leave a partially applied update. A
    /// worker that panics has already recorded its terminal error through
    /// `set_error`, and refusing the lock afterwards would hide that evidence
    /// from the reader instead of surfacing it.
    pub(super) fn lock(&self) -> MutexGuard<'_, CaptureState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Waits for a state change, returning the guard and whether it timed out.
    ///
    /// Poisoning is recovered from for the reason given on [`Self::lock`].
    pub(super) fn wait_timeout<'a>(
        &self,
        state: MutexGuard<'a, CaptureState>,
        timeout: Duration,
    ) -> (MutexGuard<'a, CaptureState>, bool) {
        let (state, result) = self
            .changed
            .wait_timeout(state, timeout)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state, result.timed_out())
    }

    pub(super) fn set_ready(&self) {
        let mut state = self.lock();
        state.ready = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn set_error(&self, error: Error) {
        let mut state = self.lock();
        if state.error.is_none() {
            state.error = Some(error);
        }
        state.closed = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        drop(state);
        self.changed.notify_all();
    }

    pub(super) fn enqueue(&self, captured: Captured) -> Result<(), Error> {
        let mut state = self.lock();
        let frame_bytes = captured.frame.bytes().len();
        let mut statistics = state.statistics;
        let eviction = if self.admits(state.queue.len(), state.queued_bytes, frame_bytes) {
            Eviction::none(state.queued_bytes)
        } else {
            match self.limits.overflow_policy {
                OverflowPolicy::Fail => {
                    record_overflow(&mut statistics, 1, frame_bytes as u64)?;
                    state.statistics = statistics;
                    return Err(Error::CaptureQueueOverflow {
                        dropped_frames: statistics.dropped_frames,
                        dropped_bytes: statistics.dropped_bytes,
                        overflow_events: statistics.overflow_events,
                    });
                }
                OverflowPolicy::DropNewest => {
                    record_overflow(&mut statistics, 1, frame_bytes as u64)?;
                    state.statistics = statistics;
                    return Ok(());
                }
                OverflowPolicy::DropOldest => {
                    let Some(eviction) = self.plan_eviction(&state, frame_bytes)? else {
                        record_overflow(&mut statistics, 1, frame_bytes as u64)?;
                        state.statistics = statistics;
                        return Ok(());
                    };
                    record_overflow(
                        &mut statistics,
                        eviction.frames as u64,
                        eviction.bytes as u64,
                    )?;
                    eviction
                }
            }
        };
        let queued_bytes = eviction
            .retained_bytes
            .checked_add(frame_bytes)
            .ok_or_else(|| accounting_error("native capture queue byte accounting overflowed"))?;
        record_received(&mut statistics, frame_bytes as u64)?;
        for _ in 0..eviction.frames {
            state.queue.pop_front();
        }
        state.queued_bytes = queued_bytes;
        state.statistics = statistics;
        state.queue.push_back(captured);
        drop(state);
        self.changed.notify_one();
        Ok(())
    }

    /// Whether a frame of `frame_bytes` fits beside `frames` queued frames
    /// that already hold `queued_bytes`.
    fn admits(&self, frames: usize, queued_bytes: usize, frame_bytes: usize) -> bool {
        frames < self.limits.max_frames
            && queued_bytes
                .checked_add(frame_bytes)
                .is_some_and(|bytes| bytes <= self.limits.max_bytes)
    }

    /// Plans the oldest-first eviction that makes room for `frame_bytes`, or
    /// `None` when the frame would not fit even in an empty queue.
    fn plan_eviction(
        &self,
        state: &CaptureState,
        frame_bytes: usize,
    ) -> Result<Option<Eviction>, Error> {
        let mut eviction = Eviction::none(state.queued_bytes);
        let mut retained_frames = state.queue.len();
        for dropped in &state.queue {
            if self.admits(retained_frames, eviction.retained_bytes, frame_bytes) {
                break;
            }
            let bytes = dropped.frame.bytes().len();
            retained_frames = retained_frames.saturating_sub(1);
            eviction.retained_bytes =
                eviction.retained_bytes.checked_sub(bytes).ok_or_else(|| {
                    accounting_error("native capture queue byte accounting underflowed")
                })?;
            eviction.frames = eviction.frames.saturating_add(1);
            eviction.bytes = eviction.bytes.checked_add(bytes).ok_or_else(|| {
                accounting_error("native capture dropped-byte accounting overflowed")
            })?;
        }
        Ok(self
            .admits(retained_frames, eviction.retained_bytes, frame_bytes)
            .then_some(eviction))
    }

    pub(super) fn add_native_drop_deltas(
        &self,
        previous: NativeCaptureStatistics,
        current: NativeCaptureStatistics,
    ) -> Result<(), Error> {
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
            .ok_or_else(|| Error::InvalidCaptureStatistics {
                message: "native receiver drop delta overflowed".to_owned(),
            })?;
        if total_drop_delta == 0 {
            return Ok(());
        }
        let mut state = self.lock();
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

/// Oldest frames to discard before a new frame is admitted.
struct Eviction {
    frames: usize,
    bytes: usize,
    /// Queue bytes that remain once the planned frames are gone.
    retained_bytes: usize,
}

impl Eviction {
    const fn none(retained_bytes: usize) -> Self {
        Self {
            frames: 0,
            bytes: 0,
            retained_bytes,
        }
    }
}

#[derive(Default)]
pub(super) struct CaptureState {
    pub(super) ready: bool,
    pub(super) closed: bool,
    pub(super) error_observed: bool,
    pub(super) error: Option<Error>,
    pub(super) queue: VecDeque<Captured>,
    pub(super) queued_bytes: usize,
    pub(super) statistics: Statistics,
}

fn accounting_error(message: &str) -> Error {
    Error::InvalidCaptureStatistics {
        message: message.to_owned(),
    }
}

fn record_overflow(
    statistics: &mut Statistics,
    dropped_frames: u64,
    dropped_bytes: u64,
) -> Result<(), Error> {
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

fn record_received(statistics: &mut Statistics, received_bytes: u64) -> Result<(), Error> {
    increment(&mut statistics.received_frames, 1, "received frames")?;
    increment(
        &mut statistics.received_bytes,
        received_bytes,
        "received bytes",
    )
}

fn increment(counter: &mut u64, value: u64, label: &str) -> Result<(), Error> {
    *counter = counter
        .checked_add(value)
        .ok_or_else(|| Error::InvalidCaptureStatistics {
            message: format!("native capture {label} counter overflowed"),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use std::time::SystemTime;

    use packetcraftr_core::frame::{Frame, LinkType};

    use super::*;

    fn captured(bytes: &[u8]) -> Captured {
        Captured::without_ingress_time(
            Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes.to_vec())
                .expect("fixture frame"),
        )
    }

    fn queue(policy: OverflowPolicy, max_frames: usize, max_bytes: usize) -> CaptureQueue {
        CaptureQueue::new(Limits {
            max_frames,
            max_bytes,
            snap_length: max_bytes,
            overflow_policy: policy,
        })
    }

    #[test]
    fn overflow_policies_distinguish_failure_drop_and_byte_bounded_eviction() {
        for policy in [
            OverflowPolicy::Fail,
            OverflowPolicy::DropNewest,
            OverflowPolicy::DropOldest,
        ] {
            let queue = queue(policy, 2, 4);
            queue.enqueue(captured(&[1, 1])).expect("first frame");
            queue.enqueue(captured(&[2, 2])).expect("second frame");
            let result = queue.enqueue(captured(&[3, 3, 3]));
            assert_eq!(result.is_err(), policy == OverflowPolicy::Fail);

            let state = queue.lock();
            let retained = state
                .queue
                .iter()
                .map(|frame| frame.frame.bytes().to_vec())
                .collect::<Vec<_>>();
            let expected = if policy == OverflowPolicy::DropOldest {
                (vec![vec![3, 3, 3]], 3, 7, 2, 4)
            } else {
                (vec![vec![1, 1], vec![2, 2]], 2, 4, 1, 3)
            };
            assert_eq!(retained, expected.0, "policy {policy:?}");
            assert_eq!(
                state.queued_bytes,
                retained.iter().map(Vec::len).sum::<usize>()
            );
            assert_eq!(state.statistics.received_frames, expected.1);
            assert_eq!(state.statistics.received_bytes, expected.2);
            assert_eq!(state.statistics.dropped_frames, expected.3);
            assert_eq!(state.statistics.dropped_bytes, expected.4);
            assert_eq!(state.statistics.overflow_events, 1);
        }
    }

    #[test]
    fn drop_oldest_retains_existing_frames_when_the_new_frame_cannot_fit_alone() {
        let queue = queue(OverflowPolicy::DropOldest, 2, 4);
        queue.enqueue(captured(&[1, 1])).expect("first frame");
        queue.enqueue(captured(&[2, 2])).expect("second frame");

        queue
            .enqueue(captured(&[3, 3, 3, 3, 3]))
            .expect("an individually oversized frame is dropped by policy");

        let state = queue.lock();
        assert_eq!(state.queue.len(), 2);
        assert_eq!(state.queued_bytes, 4);
        assert_eq!(state.statistics.received_frames, 2);
        assert_eq!(state.statistics.received_bytes, 4);
        assert_eq!(state.statistics.dropped_frames, 1);
        assert_eq!(state.statistics.dropped_bytes, 5);
        assert_eq!(state.statistics.overflow_events, 1);
    }

    #[test]
    fn queue_state_transitions_are_monotonic_and_preserve_the_first_error() {
        let queue = queue(OverflowPolicy::Fail, 1, 1);
        let state = queue.lock();
        let (state, _) = queue.wait_timeout(state, Duration::ZERO);
        assert!(!state.ready);
        assert!(!state.closed);
        assert!(state.error.is_none());
        assert!(state.queue.is_empty());
        drop(state);

        queue.set_ready();
        queue.set_error(Error::Capture {
            message: "first failure".to_owned(),
            source: None,
        });
        queue.set_error(Error::Capture {
            message: "later failure".to_owned(),
            source: None,
        });
        queue.close();

        let state = queue.lock();
        assert!(state.ready);
        assert!(state.closed);
        assert!(matches!(
            state.error.as_ref(),
            Some(Error::Capture { message, .. }) if message == "first failure"
        ));
    }

    #[test]
    fn queue_counter_overflow_does_not_partially_commit_a_frame_or_loss_event() {
        let received = queue(OverflowPolicy::Fail, 1, 1);
        received.lock().statistics.received_frames = u64::MAX;
        assert!(matches!(
            received.enqueue(captured(&[1])),
            Err(Error::InvalidCaptureStatistics { .. })
        ));
        {
            let state = received.lock();
            assert!(state.queue.is_empty());
            assert_eq!(state.queued_bytes, 0);
            assert_eq!(state.statistics.received_frames, u64::MAX);
            assert_eq!(state.statistics.received_bytes, 0);
        }

        let overflow = queue(OverflowPolicy::Fail, 1, 1);
        overflow.enqueue(captured(&[1])).expect("first frame");
        overflow.lock().statistics.overflow_events = u64::MAX;
        assert!(matches!(
            overflow.enqueue(captured(&[2])),
            Err(Error::InvalidCaptureStatistics { .. })
        ));
        let state = overflow.lock();
        assert_eq!(state.queue.len(), 1);
        assert_eq!(state.statistics.overflow_events, u64::MAX);
        assert_eq!(state.statistics.dropped_frames, 0);
        assert_eq!(state.statistics.dropped_bytes, 0);
    }

    #[test]
    fn native_drop_deltas_handle_counter_wrap_and_commit_atomically() {
        let queue = queue(OverflowPolicy::Fail, 1, 1);
        queue
            .add_native_drop_deltas(
                NativeCaptureStatistics {
                    capture_dropped_frames: u32::MAX,
                    network_dropped_frames: u32::MAX,
                    interface_dropped_frames: u32::MAX,
                },
                NativeCaptureStatistics::default(),
            )
            .expect("each wrapped counter advanced once");
        {
            let state = queue.lock();
            assert_eq!(state.statistics.dropped_frames, 3);
            assert_eq!(state.statistics.receiver_dropped_frames, 3);
        }

        queue.lock().statistics.dropped_frames = u64::MAX;
        let error = queue
            .add_native_drop_deltas(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    capture_dropped_frames: 1,
                    ..NativeCaptureStatistics::default()
                },
            )
            .expect_err("overflow must fail closed");
        assert!(matches!(error, Error::InvalidCaptureStatistics { .. }));
        let state = queue.lock();
        assert_eq!(state.statistics.dropped_frames, u64::MAX);
        assert_eq!(state.statistics.receiver_dropped_frames, 3);

        drop(state);
        queue.lock().statistics = Statistics {
            receiver_dropped_frames: u64::MAX,
            ..Statistics::default()
        };
        let error = queue
            .add_native_drop_deltas(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    network_dropped_frames: 1,
                    ..NativeCaptureStatistics::default()
                },
            )
            .expect_err("the second counter overflow must not commit the first");
        assert!(matches!(error, Error::InvalidCaptureStatistics { .. }));
        let state = queue.lock();
        assert_eq!(state.statistics.dropped_frames, 0);
        assert_eq!(state.statistics.receiver_dropped_frames, u64::MAX);
    }
}
