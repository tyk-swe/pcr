// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::io::{
    CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CaptureStatistics, CapturedFrame,
    InterfaceId, LinkType, LiveIoError,
};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);

pub(super) struct NativeCapturedPacket {
    pub timestamp: SystemTime,
    pub captured_length: u32,
    pub original_length: u32,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeCaptureStatistics {
    pub dropped: u32,
    pub interface_dropped: u32,
}

pub(super) enum NativeCaptureEvent {
    Packet(NativeCapturedPacket),
    Timeout,
    Closed,
}

pub(super) trait NativeCaptureSource: Send {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError>;
    fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError>;
}

pub(super) trait CaptureInterrupt: Send + Sync {
    fn interrupt(&self);
}

pub(super) struct NativeCaptureParts {
    pub source: Box<dyn NativeCaptureSource>,
    pub interrupt: Arc<dyn CaptureInterrupt>,
    pub interface: InterfaceId,
    pub link_type: LinkType,
}

pub(super) struct NativeCaptureSession {
    shared: Arc<SharedCapture>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn CaptureInterrupt>>,
    worker: Option<JoinHandle<()>>,
    shutdown_result: Option<Result<(), LiveIoError>>,
}

impl NativeCaptureSession {
    pub(super) fn spawn(
        parts: NativeCaptureParts,
        limits: CaptureQueueLimits,
    ) -> Result<Self, LiveIoError> {
        let limits = limits.validate()?;
        let shared = Arc::new(SharedCapture::new(limits));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop);
        let interface_index = parts.interface.index;
        let link_type = parts.link_type;
        let mut source = parts.source;
        let worker = thread::Builder::new()
            .name(format!("packetcraftr-capture-{}", parts.interface.name))
            .spawn(move || {
                capture_worker(
                    source.as_mut(),
                    worker_shared,
                    worker_stop,
                    interface_index,
                    link_type,
                );
            })
            .map_err(|error| LiveIoError::Capture {
                message: format!("could not start the owned capture worker: {error}"),
            })?;
        Ok(Self {
            shared,
            stop,
            interrupt: Some(parts.interrupt),
            worker: Some(worker),
            shutdown_result: None,
        })
    }
}

impl CaptureSession for NativeCaptureSession {
    fn wait_ready(&mut self) -> Result<(), LiveIoError> {
        let mut state = self.shared.lock()?;
        while !state.ready && !state.closed && state.error.is_none() {
            state = self.shared.wait(state)?;
        }
        if let Some(error) = state.error.clone() {
            state.error_observed = true;
            return Err(error);
        }
        if state.ready {
            Ok(())
        } else {
            Err(LiveIoError::CaptureReadiness {
                message: "native capture worker closed before reporting readiness".to_owned(),
            })
        }
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self.shared.lock()?;
        loop {
            if let Some(error) = state.error.clone() {
                state.error_observed = true;
                return Err(error);
            }
            if let Some(frame) = state.queue.pop_front() {
                state.queued_bytes = state
                    .queued_bytes
                    .checked_sub(frame.bytes.len())
                    .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                        message: "native capture queue byte accounting underflowed".to_owned(),
                    })?;
                return Ok(Some(frame));
            }
            if state.closed || timeout.is_zero() {
                return Ok(None);
            }
            let Some(deadline) = deadline else {
                return Ok(None);
            };
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            let (next_state, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next_state;
            if timed_out {
                return Ok(None);
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        if let Some(result) = &self.shutdown_result {
            return result.clone();
        }
        self.stop.store(true, Ordering::Release);
        if let Some(interrupt) = &self.interrupt {
            interrupt.interrupt();
        }
        let join_result = self.worker.take().map_or(Ok(()), |worker| {
            worker.join().map_err(|_| LiveIoError::Capture {
                message: "native capture worker panicked during shutdown".to_owned(),
            })
        });
        self.interrupt.take();

        let result = join_result.and_then(|()| {
            let mut state = self.shared.lock()?;
            state.closed = true;
            if state.error_observed {
                Ok(())
            } else if let Some(error) = state.error.clone() {
                state.error_observed = true;
                Err(error)
            } else {
                Ok(())
            }
        });
        self.shutdown_result = Some(result.clone());
        result
    }

    fn statistics(&self) -> CaptureStatistics {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .statistics
    }
}

impl Drop for NativeCaptureSession {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct SharedCapture {
    state: Mutex<CaptureState>,
    changed: Condvar,
    limits: CaptureQueueLimits,
}

impl SharedCapture {
    fn new(limits: CaptureQueueLimits) -> Self {
        Self {
            state: Mutex::new(CaptureState::default()),
            changed: Condvar::new(),
            limits,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, CaptureState>, LiveIoError> {
        self.state.lock().map_err(|_| LiveIoError::Capture {
            message: "native capture queue mutex was poisoned".to_owned(),
        })
    }

    fn wait<'a>(
        &self,
        state: MutexGuard<'a, CaptureState>,
    ) -> Result<MutexGuard<'a, CaptureState>, LiveIoError> {
        self.changed.wait(state).map_err(|_| LiveIoError::Capture {
            message: "native capture readiness mutex was poisoned".to_owned(),
        })
    }

    fn wait_timeout<'a>(
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

    fn set_ready(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.ready = true;
        self.changed.notify_all();
    }

    fn set_error(&self, error: LiveIoError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.error.is_none() {
            state.error = Some(error);
        }
        state.closed = true;
        self.changed.notify_all();
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        self.changed.notify_all();
    }

    fn enqueue(&self, frame: CapturedFrame) -> Result<bool, LiveIoError> {
        let mut state = self.lock()?;
        let frame_bytes = frame.bytes.len();
        let would_exceed_frames = state.queue.len() >= self.limits.max_frames;
        let would_exceed_bytes = state
            .queued_bytes
            .checked_add(frame_bytes)
            .is_none_or(|bytes| bytes > self.limits.max_bytes);
        if would_exceed_frames || would_exceed_bytes {
            increment(&mut state.statistics.overflow_events, 1, "overflow events")?;
            match self.limits.overflow_policy {
                CaptureOverflowPolicy::Fail => {
                    increment(&mut state.statistics.dropped_frames, 1, "dropped frames")?;
                    increment(
                        &mut state.statistics.dropped_bytes,
                        frame_bytes as u64,
                        "dropped bytes",
                    )?;
                    return Err(LiveIoError::CaptureQueueOverflow {
                        dropped_frames: state.statistics.dropped_frames,
                        dropped_bytes: state.statistics.dropped_bytes,
                        overflow_events: state.statistics.overflow_events,
                    });
                }
                CaptureOverflowPolicy::DropNewest => {
                    increment(&mut state.statistics.dropped_frames, 1, "dropped frames")?;
                    increment(
                        &mut state.statistics.dropped_bytes,
                        frame_bytes as u64,
                        "dropped bytes",
                    )?;
                    return Ok(true);
                }
                CaptureOverflowPolicy::DropOldest => {
                    while state.queue.len() >= self.limits.max_frames
                        || state
                            .queued_bytes
                            .checked_add(frame_bytes)
                            .is_none_or(|bytes| bytes > self.limits.max_bytes)
                    {
                        let Some(dropped) = state.queue.pop_front() else {
                            increment(&mut state.statistics.dropped_frames, 1, "dropped frames")?;
                            increment(
                                &mut state.statistics.dropped_bytes,
                                frame_bytes as u64,
                                "dropped bytes",
                            )?;
                            return Ok(true);
                        };
                        state.queued_bytes = state
                            .queued_bytes
                            .checked_sub(dropped.bytes.len())
                            .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                                message: "native capture queue byte accounting underflowed"
                                    .to_owned(),
                            })?;
                        increment(&mut state.statistics.dropped_frames, 1, "dropped frames")?;
                        increment(
                            &mut state.statistics.dropped_bytes,
                            dropped.bytes.len() as u64,
                            "dropped bytes",
                        )?;
                    }
                }
            }
        }
        state.queued_bytes = state.queued_bytes.checked_add(frame_bytes).ok_or_else(|| {
            LiveIoError::InvalidCaptureStatistics {
                message: "native capture queue byte accounting overflowed".to_owned(),
            }
        })?;
        increment(&mut state.statistics.received_frames, 1, "received frames")?;
        increment(
            &mut state.statistics.received_bytes,
            frame_bytes as u64,
            "received bytes",
        )?;
        state.queue.push_back(frame);
        self.changed.notify_one();
        Ok(false)
    }

    fn add_native_drops(
        &self,
        previous: NativeCaptureStatistics,
        current: NativeCaptureStatistics,
    ) -> Result<(), LiveIoError> {
        let dropped = current.dropped.wrapping_sub(previous.dropped) as u64;
        let interface_dropped = current
            .interface_dropped
            .wrapping_sub(previous.interface_dropped) as u64;
        let total = dropped.checked_add(interface_dropped).ok_or_else(|| {
            LiveIoError::InvalidCaptureStatistics {
                message: "native receiver drop delta overflowed".to_owned(),
            }
        })?;
        if total == 0 {
            return Ok(());
        }
        let mut state = self.lock()?;
        increment(
            &mut state.statistics.dropped_frames,
            total,
            "dropped frames",
        )?;
        Ok(())
    }
}

#[derive(Default)]
struct CaptureState {
    ready: bool,
    closed: bool,
    error_observed: bool,
    error: Option<LiveIoError>,
    queue: VecDeque<CapturedFrame>,
    queued_bytes: usize,
    statistics: CaptureStatistics,
}

fn capture_worker(
    source: &mut dyn NativeCaptureSource,
    shared: Arc<SharedCapture>,
    stop: Arc<AtomicBool>,
    interface_index: u32,
    link_type: LinkType,
) {
    let mut native_statistics = match source.statistics() {
        Ok(statistics) => statistics,
        Err(error) => {
            shared.set_error(error);
            return;
        }
    };
    let mut statistics_checked_at = Instant::now();
    shared.set_ready();

    while !stop.load(Ordering::Acquire) {
        match source.next_event() {
            Ok(NativeCaptureEvent::Packet(packet)) => {
                let mut frame = match CapturedFrame::try_with_lengths(
                    packet.timestamp,
                    link_type,
                    packet.captured_length,
                    packet.original_length,
                    packet.bytes,
                ) {
                    Ok(frame) => frame,
                    Err(error) => {
                        shared.set_error(LiveIoError::Capture {
                            message: format!("native capture returned an invalid frame: {error}"),
                        });
                        return;
                    }
                };
                frame.interface = Some(interface_index);
                if let Err(error) = shared.enqueue(frame) {
                    shared.set_error(error);
                    return;
                }
            }
            Ok(NativeCaptureEvent::Timeout) => {}
            Ok(NativeCaptureEvent::Closed) if stop.load(Ordering::Acquire) => break,
            Ok(NativeCaptureEvent::Closed) => {
                shared.set_error(LiveIoError::Capture {
                    message: "native capture source closed unexpectedly".to_owned(),
                });
                return;
            }
            Err(error) => {
                shared.set_error(error);
                return;
            }
        }

        if statistics_checked_at.elapsed() >= STATISTICS_INTERVAL {
            let current = match source.statistics() {
                Ok(statistics) => statistics,
                Err(error) => {
                    shared.set_error(error);
                    return;
                }
            };
            if let Err(error) = shared.add_native_drops(native_statistics, current) {
                shared.set_error(error);
                return;
            }
            native_statistics = current;
            statistics_checked_at = Instant::now();
        }
    }

    match source.statistics() {
        Ok(current) => {
            if let Err(error) = shared.add_native_drops(native_statistics, current) {
                shared.set_error(error);
                return;
            }
        }
        Err(error) => {
            shared.set_error(error);
            return;
        }
    }
    shared.close();
}

fn increment(counter: &mut u64, value: u64, label: &str) -> Result<(), LiveIoError> {
    *counter = counter
        .checked_add(value)
        .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
            message: format!("native capture {label} counter overflowed"),
        })?;
    Ok(())
}

pub(super) fn system_time(seconds: i64, microseconds: i64) -> Result<SystemTime, LiveIoError> {
    if !(0..1_000_000).contains(&microseconds) {
        return Err(LiveIoError::Capture {
            message: format!("native capture timestamp has invalid microseconds {microseconds}"),
        });
    }
    let fractional = Duration::from_micros(microseconds as u64);
    if seconds >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds as u64))
            .and_then(|time| time.checked_add(fractional))
    } else {
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            .and_then(|time| time.checked_add(fractional))
    }
    .ok_or_else(|| LiveIoError::Capture {
        message: "native capture timestamp is outside SystemTime range".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct MockInterrupt(Arc<AtomicUsize>);

    impl CaptureInterrupt for MockInterrupt {
        fn interrupt(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockSource {
        events: VecDeque<NativeCaptureEvent>,
        drops: NativeCaptureStatistics,
        failure: Option<LiveIoError>,
    }

    impl NativeCaptureSource for MockSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
            if let Some(event) = self.events.pop_front() {
                Ok(event)
            } else if let Some(error) = self.failure.take() {
                Err(error)
            } else {
                Ok(NativeCaptureEvent::Timeout)
            }
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
            Ok(self.drops)
        }
    }

    fn packet(byte: u8, length: usize) -> NativeCaptureEvent {
        NativeCaptureEvent::Packet(NativeCapturedPacket {
            timestamp: UNIX_EPOCH,
            captured_length: length as u32,
            original_length: length as u32,
            bytes: Bytes::from(vec![byte; length]),
        })
    }

    fn session(
        events: Vec<NativeCaptureEvent>,
        limits: CaptureQueueLimits,
        interrupts: Arc<AtomicUsize>,
    ) -> NativeCaptureSession {
        NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(MockSource {
                    events: events.into(),
                    drops: NativeCaptureStatistics::default(),
                    failure: None,
                }),
                interrupt: Arc::new(MockInterrupt(interrupts)),
                interface: InterfaceId {
                    name: "mock0".to_owned(),
                    index: 7,
                },
                link_type: LinkType::ETHERNET,
            },
            limits,
        )
        .unwrap()
    }

    #[test]
    fn readiness_precedes_delivery_and_shutdown_joins() {
        let interrupts = Arc::new(AtomicUsize::new(0));
        let mut session = session(
            vec![packet(1, 4)],
            CaptureQueueLimits {
                max_frames: 2,
                max_bytes: 8,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::Fail,
            },
            Arc::clone(&interrupts),
        );
        session.wait_ready().unwrap();
        let frame = session.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(frame.interface, Some(7));
        assert_eq!(frame.bytes.as_ref(), &[1, 1, 1, 1]);
        session.shutdown().unwrap();
        assert_eq!(interrupts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fail_policy_reports_queue_loss() {
        let mut session = session(
            vec![packet(1, 4), packet(2, 4)],
            CaptureQueueLimits {
                max_frames: 1,
                max_bytes: 4,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::Fail,
            },
            Arc::new(AtomicUsize::new(0)),
        );
        let error = match session.wait_ready() {
            Err(error) => error,
            Ok(()) => loop {
                match session.next_frame(Duration::from_secs(1)) {
                    Err(error) => break error,
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("capture closed without its overflow error"),
                }
            },
        };
        assert!(matches!(error, LiveIoError::CaptureQueueOverflow { .. }));
        assert!(session.statistics().has_loss());
        session.shutdown().unwrap();
    }

    #[test]
    fn drop_oldest_preserves_the_newest_bounded_frame() {
        let mut session = session(
            vec![packet(1, 4), packet(2, 4)],
            CaptureQueueLimits {
                max_frames: 1,
                max_bytes: 4,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::DropOldest,
            },
            Arc::new(AtomicUsize::new(0)),
        );
        session.wait_ready().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let frame = loop {
            if session.statistics().dropped_frames == 1 {
                break session.next_frame(Duration::ZERO).unwrap().unwrap();
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(frame.bytes.as_ref(), &[2, 2, 2, 2]);
        assert_eq!(session.statistics().received_frames, 2);
        assert_eq!(session.statistics().dropped_frames, 1);
        session.shutdown().unwrap();
    }

    #[test]
    fn drop_newest_preserves_the_oldest_bounded_frame() {
        let mut session = session(
            vec![packet(1, 4), packet(2, 4)],
            CaptureQueueLimits {
                max_frames: 1,
                max_bytes: 4,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::DropNewest,
            },
            Arc::new(AtomicUsize::new(0)),
        );
        session.wait_ready().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let frame = loop {
            if session.statistics().dropped_frames == 1 {
                break session.next_frame(Duration::ZERO).unwrap().unwrap();
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(frame.bytes.as_ref(), &[1, 1, 1, 1]);
        assert_eq!(session.statistics().received_frames, 1);
        assert_eq!(session.statistics().overflow_events, 1);
        session.shutdown().unwrap();
    }

    #[test]
    fn source_failure_propagates_once_and_shutdown_still_joins() {
        let interrupts = Arc::new(AtomicUsize::new(0));
        let mut session = NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(MockSource {
                    events: VecDeque::new(),
                    drops: NativeCaptureStatistics::default(),
                    failure: Some(LiveIoError::Capture {
                        message: "injected receive failure".to_owned(),
                    }),
                }),
                interrupt: Arc::new(MockInterrupt(Arc::clone(&interrupts))),
                interface: InterfaceId {
                    name: "mock0".to_owned(),
                    index: 7,
                },
                link_type: LinkType::ETHERNET,
            },
            CaptureQueueLimits {
                max_frames: 1,
                max_bytes: 4,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::Fail,
            },
        )
        .unwrap();
        assert!(matches!(
            session.wait_ready(),
            Err(LiveIoError::Capture { .. })
        ));
        session.shutdown().unwrap();
        assert_eq!(interrupts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_drop_counters_do_not_masquerade_as_queue_overflows() {
        let shared = SharedCapture::new(CaptureQueueLimits {
            max_frames: 1,
            max_bytes: 4,
            snap_length: 4,
            overflow_policy: CaptureOverflowPolicy::Fail,
        });
        shared
            .add_native_drops(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    dropped: 2,
                    interface_dropped: 1,
                },
            )
            .unwrap();
        let statistics = shared.lock().unwrap().statistics;
        assert_eq!(statistics.dropped_frames, 3);
        assert_eq!(statistics.overflow_events, 0);
    }

    #[test]
    fn timestamp_conversion_validates_fractional_range() {
        assert_eq!(
            system_time(1, 2).unwrap(),
            UNIX_EPOCH + Duration::from_micros(1_000_002)
        );
        assert!(system_time(0, 1_000_000).is_err());
    }
}
