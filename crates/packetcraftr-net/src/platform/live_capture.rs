// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned native capture worker and bounded queue shared by libpcap and Npcap.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;

use crate::{Error as LiveIoError, route::InterfaceId};
use packetcraftr_capture::LinkType;

pub(super) use session::NativeCaptureSession;
pub(super) use time::{monotonic_packet_time, system_time};

mod queue;
mod session;
mod time;
mod worker;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use crate::capture::{
        CaptureOverflowPolicy, CaptureQueueLimits, CaptureSession, CapturedFrame,
    };
    use bytes::Bytes;
    use packetcraftr_capture::{Frame, LinkType};

    use super::{queue::SharedCapture, time::monotonic_time_for_age};

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

    struct BlockingSource {
        release: Arc<AtomicBool>,
        exited: Arc<AtomicBool>,
    }

    impl NativeCaptureSource for BlockingSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
            while !self.release.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
            Ok(NativeCaptureEvent::Closed)
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    impl Drop for BlockingSource {
        fn drop(&mut self) {
            self.exited.store(true, Ordering::Release);
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
            captured_length: u32::try_from(length).unwrap(),
            original_length: u32::try_from(length).unwrap(),
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
        let frame = session
            .next_captured_frame(Duration::from_secs(1))
            .unwrap()
            .unwrap()
            .frame;
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
            session.next_captured_frame(Duration::MAX),
            Err(LiveIoError::InvalidCaptureTimeout { .. })
        ));
        session.shutdown().unwrap();
    }

    #[test]
    fn shutdown_is_bounded_when_capture_source_ignores_interrupt() {
        let release = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let mut session = NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    release: Arc::clone(&release),
                    exited: Arc::clone(&exited),
                }),
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
        .unwrap();
        session.wait_ready(Duration::from_secs(1)).unwrap();

        assert!(matches!(
            session.shutdown(),
            Err(LiveIoError::DeadlineExceeded {
                operation: "shutting down native capture"
            })
        ));
        release.store(true, Ordering::Release);
        session.shutdown().unwrap();
        assert!(exited.load(Ordering::Acquire));
        session.shutdown().unwrap();
    }

    #[test]
    fn drop_joins_a_capture_worker_retained_after_shutdown_timeout() {
        let release = Arc::new(AtomicBool::new(false));
        let exited = Arc::new(AtomicBool::new(false));
        let mut session = NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    release: Arc::clone(&release),
                    exited: Arc::clone(&exited),
                }),
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
        .unwrap();
        session.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            session.shutdown(),
            Err(LiveIoError::DeadlineExceeded { .. })
        ));

        release.store(true, Ordering::Release);
        drop(session);
        assert!(exited.load(Ordering::Acquire));
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
            match session.next_captured_frame(Duration::from_millis(50)) {
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
                break session
                    .next_captured_frame(Duration::ZERO)
                    .unwrap()
                    .unwrap()
                    .frame;
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
                break session
                    .next_captured_frame(Duration::ZERO)
                    .unwrap()
                    .unwrap()
                    .frame;
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
    fn source_failure_drains_queued_frame_before_propagating() {
        let interrupts = Arc::new(AtomicUsize::new(0));
        let mut session = NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(MockSource {
                    events: VecDeque::from([packet(9, 4)]),
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
        session.wait_ready(Duration::from_secs(1)).unwrap();
        let frame = session
            .next_captured_frame(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(frame.frame.bytes().as_ref(), &[9, 9, 9, 9]);
        let error = session
            .next_captured_frame(Duration::from_secs(1))
            .unwrap_err();
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
        let error = session
            .next_captured_frame(Duration::from_secs(1))
            .unwrap_err();
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
