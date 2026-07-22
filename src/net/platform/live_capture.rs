// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::capture::{Frame, LinkType};
use crate::net::{
    Error as LiveIoError,
    capture::{
        CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CaptureStatistics,
        CapturedFrame, validate_timeout,
    },
    route::InterfaceId,
};

const STATISTICS_INTERVAL: Duration = Duration::from_millis(250);

pub(super) struct NativeCapturedPacket {
    pub timestamp: SystemTime,
    /// Conservative monotonic time derived from the kernel packet timestamp.
    pub received_at: Option<Instant>,
    pub captured_length: u32,
    pub original_length: u32,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeCaptureStatistics {
    pub capture_dropped_frames: u32,
    pub network_dropped_frames: u32,
    pub interface_dropped_frames: u32,
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
        let validated_limits = limits.validate()?;
        let shared = Arc::new(SharedCapture::new(validated_limits));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop);
        let interface_index = parts.interface.index;
        let link_type = parts.link_type;
        let mut source = parts.source;
        let worker = thread::Builder::new()
            .name(format!("packetcraftr-capture-{}", parts.interface.name))
            .spawn(move || {
                let panic_shared = Arc::clone(&worker_shared);
                if catch_unwind(AssertUnwindSafe(|| {
                    capture_worker(
                        source.as_mut(),
                        worker_shared,
                        worker_stop,
                        interface_index,
                        link_type,
                    );
                }))
                .is_err()
                {
                    panic_shared.set_error(LiveIoError::Capture {
                        message: "native capture worker panicked".to_owned(),
                    });
                }
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
    fn supports_monotonic_ingress_time(&self) -> bool {
        true
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), LiveIoError> {
        validate_timeout(timeout)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("validated bounded capture timeout must fit Instant");
        let mut state = self.shared.lock()?;
        while !state.ready && !state.closed && state.error.is_none() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(LiveIoError::CaptureReadiness {
                    message: "capture readiness deadline expired".to_owned(),
                });
            };
            let (next, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next;
            if timed_out && !state.ready && !state.closed && state.error.is_none() {
                return Err(LiveIoError::CaptureReadiness {
                    message: "capture readiness deadline expired".to_owned(),
                });
            }
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

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        self.next_captured_frame(timeout)
            .map(|captured| captured.map(|captured| captured.frame))
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        validate_timeout(timeout)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("validated bounded capture timeout must fit Instant");
        let mut state = self.shared.lock()?;
        loop {
            if let Some(error) = state.error.clone() {
                state.error_observed = true;
                return Err(error);
            }
            if let Some(captured) = state.queue.pop_front() {
                state.queued_bytes = state
                    .queued_bytes
                    .checked_sub(captured.frame.bytes().len())
                    .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
                        message: "native capture queue byte accounting underflowed".to_owned(),
                    })?;
                return Ok(Some(captured));
            }
            if state.closed || timeout.is_zero() {
                return Ok(None);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            let (next_state, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next_state;
            if timed_out {
                // Re-enter the loop once so an error, closure, or frame that
                // raced the timeout wins over an apparently empty result. If
                // state is still unchanged, the expired deadline returns None.
                continue;
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
        drop(state);
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
        drop(state);
        self.changed.notify_all();
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closed = true;
        drop(state);
        self.changed.notify_all();
    }

    fn enqueue(&self, captured: CapturedFrame) -> Result<bool, LiveIoError> {
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
                    return Ok(true);
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
                        return Ok(true);
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
                    return Ok(false);
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
        Ok(false)
    }

    fn add_native_drop_deltas(
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
                let mut frame = match Frame::try_with_lengths(
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
                if let Err(error) =
                    shared.enqueue(CapturedFrame::with_ingress_time(frame, packet.received_at))
                {
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
            if let Err(error) = shared.add_native_drop_deltas(native_statistics, current) {
                shared.set_error(error);
                return;
            }
            native_statistics = current;
            statistics_checked_at = Instant::now();
        }
    }

    match source.statistics() {
        Ok(current) => {
            if let Err(error) = shared.add_native_drop_deltas(native_statistics, current) {
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

/// Projects a kernel wall-clock packet timestamp onto the monotonic clock.
/// Future timestamps and packet ages older than the monotonic clock can
/// represent are deliberately left unmarked.
pub(super) fn monotonic_packet_time(
    packet_timestamp: SystemTime,
    observed_wall: SystemTime,
    observed_at: Instant,
) -> Option<Instant> {
    let age = observed_wall.duration_since(packet_timestamp).ok()?;
    monotonic_time_for_age(age, observed_at)
}

fn monotonic_time_for_age(age: Duration, observed_at: Instant) -> Option<Instant> {
    observed_at.checked_sub(age)
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
            match self.events.pop_front() {
                Some(event) => Ok(event),
                None => match self.failure.take() {
                    Some(error) => Err(error),
                    None => Ok(NativeCaptureEvent::Timeout),
                },
            }
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
            Ok(self.drops)
        }
    }

    struct PanicBeforeReadySource;

    impl NativeCaptureSource for PanicBeforeReadySource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
            unreachable!("statistics panic must happen before receive")
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
            panic!("scripted statistics panic")
        }
    }

    struct PanicAfterReadySource {
        proceed: Arc<AtomicBool>,
    }

    impl NativeCaptureSource for PanicAfterReadySource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
            while !self.proceed.load(Ordering::Acquire) {
                thread::yield_now();
            }
            panic!("scripted receive panic")
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    fn panic_session(source: Box<dyn NativeCaptureSource>) -> NativeCaptureSession {
        NativeCaptureSession::spawn(
            NativeCaptureParts {
                source,
                interrupt: Arc::new(MockInterrupt(Arc::new(AtomicUsize::new(0)))),
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
        .unwrap()
    }

    fn packet(byte: u8, length: usize) -> NativeCaptureEvent {
        NativeCaptureEvent::Packet(NativeCapturedPacket {
            timestamp: UNIX_EPOCH,
            received_at: Some(Instant::now()),
            captured_length: length as u32,
            original_length: length as u32,
            bytes: Bytes::from(vec![byte; length]),
        })
    }

    fn captured(byte: u8, length: usize) -> CapturedFrame {
        CapturedFrame::new(
            Frame::new(
                UNIX_EPOCH,
                LinkType::ETHERNET,
                Bytes::from(vec![byte; length]),
            )
            .unwrap(),
            Instant::now(),
        )
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
        session.wait_ready(Duration::from_secs(1)).unwrap();
        let frame = session.next_frame(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(frame.interface, Some(7));
        assert_eq!(frame.bytes().as_ref(), &[1, 1, 1, 1]);
        session.shutdown().unwrap();
        assert_eq!(interrupts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_session_defends_direct_timeout_entry_points() {
        let mut session = session(
            Vec::new(),
            CaptureQueueLimits {
                max_frames: 1,
                max_bytes: 4,
                snap_length: 4,
                overflow_policy: CaptureOverflowPolicy::Fail,
            },
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(matches!(
            session.wait_ready(Duration::MAX),
            Err(LiveIoError::InvalidCaptureTimeout { .. })
        ));
        assert!(matches!(
            session.next_frame(Duration::MAX),
            Err(LiveIoError::InvalidCaptureTimeout { .. })
        ));
        session.shutdown().unwrap();
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
        // Do not drain the first frame before the worker observes the second;
        // otherwise there is no overflow to assert. This synchronizes on the
        // backend counter rather than scheduler timing.
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.statistics().overflow_events == 0 {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let error = loop {
            match session.next_frame(Duration::from_millis(50)) {
                Err(error) => break error,
                Ok(_) if Instant::now() < deadline => thread::yield_now(),
                Ok(_) => panic!("capture did not surface its overflow error"),
            }
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
        session.wait_ready(Duration::from_secs(1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let frame = loop {
            if session.statistics().dropped_frames == 1 {
                break session.next_frame(Duration::ZERO).unwrap().unwrap();
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(frame.bytes().as_ref(), &[2, 2, 2, 2]);
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
        session.wait_ready(Duration::from_secs(1)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let frame = loop {
            if session.statistics().dropped_frames == 1 {
                break session.next_frame(Duration::ZERO).unwrap().unwrap();
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(frame.bytes().as_ref(), &[1, 1, 1, 1]);
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
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = match session.wait_ready(Duration::from_secs(1)) {
            Err(error) => error,
            Ok(()) => loop {
                match session.next_frame(Duration::from_millis(50)) {
                    Err(error) => break error,
                    Ok(_) if Instant::now() < deadline => thread::yield_now(),
                    Ok(_) => panic!("capture did not propagate its injected source failure"),
                }
            },
        };
        assert!(matches!(error, LiveIoError::Capture { .. }));
        session.shutdown().unwrap();
        assert_eq!(interrupts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_panic_before_readiness_wakes_waiter_and_shutdown_joins() {
        let mut session = panic_session(Box::new(PanicBeforeReadySource));
        let error = session.wait_ready(Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, LiveIoError::Capture { .. }));
        session.shutdown().unwrap();
    }

    #[test]
    fn worker_panic_after_readiness_wakes_receiver_and_shutdown_joins() {
        let proceed = Arc::new(AtomicBool::new(false));
        let mut session = panic_session(Box::new(PanicAfterReadySource {
            proceed: Arc::clone(&proceed),
        }));
        session.wait_ready(Duration::from_secs(1)).unwrap();
        proceed.store(true, Ordering::Release);
        let error = session.next_frame(Duration::from_secs(1)).unwrap_err();
        assert!(matches!(error, LiveIoError::Capture { .. }));
        session.shutdown().unwrap();
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
            .add_native_drop_deltas(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    capture_dropped_frames: 2,
                    network_dropped_frames: 0,
                    interface_dropped_frames: 1,
                },
            )
            .unwrap();
        let statistics = shared.lock().unwrap().statistics;
        assert_eq!(statistics.dropped_frames, 3);
        assert_eq!(statistics.receiver_dropped_frames, 3);
        assert_eq!(statistics.overflow_events, 0);
        assert_eq!(
            statistics.evidence_completeness(),
            crate::net::capture::CaptureEvidenceCompleteness::Incomplete
        );
    }

    #[test]
    fn native_drop_components_are_widened_before_aggregation() {
        let shared = SharedCapture::new(CaptureQueueLimits {
            max_frames: 1,
            max_bytes: 4,
            snap_length: 4,
            overflow_policy: CaptureOverflowPolicy::Fail,
        });
        shared
            .add_native_drop_deltas(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    capture_dropped_frames: u32::MAX,
                    network_dropped_frames: 1,
                    interface_dropped_frames: 2,
                },
            )
            .unwrap();
        let statistics = shared.lock().unwrap().statistics;
        assert_eq!(statistics.receiver_dropped_frames, (1_u64 << 32) + 2);
        assert_eq!(statistics.dropped_frames, (1_u64 << 32) + 2);

        let wrapped = SharedCapture::new(CaptureQueueLimits {
            max_frames: 1,
            max_bytes: 4,
            snap_length: 4,
            overflow_policy: CaptureOverflowPolicy::Fail,
        });
        wrapped
            .add_native_drop_deltas(
                NativeCaptureStatistics {
                    capture_dropped_frames: u32::MAX - 1,
                    network_dropped_frames: 7,
                    interface_dropped_frames: 0,
                },
                NativeCaptureStatistics {
                    capture_dropped_frames: 1,
                    network_dropped_frames: 9,
                    interface_dropped_frames: 0,
                },
            )
            .unwrap();
        assert_eq!(wrapped.lock().unwrap().statistics.dropped_frames, 5);
    }

    #[test]
    fn queue_statistic_overflow_leaves_queue_and_counters_unchanged() {
        let shared = SharedCapture::new(CaptureQueueLimits {
            max_frames: 1,
            max_bytes: 4,
            snap_length: 4,
            overflow_policy: CaptureOverflowPolicy::DropNewest,
        });
        shared.enqueue(captured(1, 1)).unwrap();
        {
            let mut state = shared.lock().unwrap();
            state.statistics.dropped_frames = u64::MAX;
        }
        let before = {
            let state = shared.lock().unwrap();
            (state.statistics, state.queue.len(), state.queued_bytes)
        };

        assert!(matches!(
            shared.enqueue(captured(2, 1)),
            Err(LiveIoError::InvalidCaptureStatistics { .. })
        ));
        let after = shared.lock().unwrap();
        assert_eq!(after.statistics, before.0);
        assert_eq!(after.queue.len(), before.1);
        assert_eq!(after.queued_bytes, before.2);
    }

    #[test]
    fn receiver_statistic_overflow_is_fail_atomic() {
        let shared = SharedCapture::new(CaptureQueueLimits {
            max_frames: 1,
            max_bytes: 4,
            snap_length: 4,
            overflow_policy: CaptureOverflowPolicy::Fail,
        });
        {
            let mut state = shared.lock().unwrap();
            state.statistics.dropped_frames = 17;
            state.statistics.receiver_dropped_frames = u64::MAX;
        }
        let before = shared.lock().unwrap().statistics;

        assert!(matches!(
            shared.add_native_drop_deltas(
                NativeCaptureStatistics::default(),
                NativeCaptureStatistics {
                    capture_dropped_frames: 1,
                    ..NativeCaptureStatistics::default()
                },
            ),
            Err(LiveIoError::InvalidCaptureStatistics { .. })
        ));
        assert_eq!(shared.lock().unwrap().statistics, before);
    }

    #[test]
    fn timestamp_conversion_validates_fractional_range() {
        assert_eq!(
            system_time(1, 2).unwrap(),
            UNIX_EPOCH + Duration::from_micros(1_000_002)
        );
        assert!(system_time(0, 1_000_000).is_err());
    }

    #[test]
    fn old_kernel_timestamp_maps_before_dequeue_observation() {
        let observed_wall = SystemTime::now();
        let observed_at = Instant::now();
        let packet_timestamp = observed_wall
            .checked_sub(Duration::from_millis(250))
            .unwrap();

        let received_at =
            monotonic_packet_time(packet_timestamp, observed_wall, observed_at).unwrap();

        assert_eq!(
            received_at,
            observed_at.checked_sub(Duration::from_millis(250)).unwrap()
        );
        assert!(received_at < observed_at);
    }

    #[test]
    fn future_or_unrepresentable_kernel_timestamp_has_no_monotonic_marker() {
        let observed_wall = SystemTime::now();
        let observed_at = Instant::now();
        let future = observed_wall.checked_add(Duration::from_secs(1)).unwrap();

        assert_eq!(
            monotonic_packet_time(future, observed_wall, observed_at),
            None
        );
        assert_eq!(monotonic_time_for_age(Duration::MAX, observed_at), None);
    }
}
