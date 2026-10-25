// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(native_layer2)]
mod activation;
#[cfg(any(native_layer2, test))]
#[cfg_attr(not(native_layer2), allow(dead_code))]
mod filter;
mod group;
mod limits;
#[cfg(native_layer2)]
pub(crate) mod live;
mod record;
mod settings;
mod system;

use std::time::Instant;

use super::Error;
use super::interface::Id as InterfaceId;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::LinkType;

pub use group::{Group, GroupRequest, MAX_SOURCES, Phase, Source};
pub use limits::{
    Limits, MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES, MAX_SNAP_LENGTH, OverflowPolicy,
};
pub use record::{Captured, RecordIdentity, Stats};
pub use settings::{
    MAX_NATIVE_BUFFER_SIZE, MAX_TIMESTAMP_TYPES, NativeSettings, Realized, RealizedSettings,
    TimestampPrecision, TimestampSource, TimestampType,
};

/// Independent allowance for an entire cooperative capture cleanup, including groups.
pub const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

pub const MAX_FILTER_BYTES: usize = 64 * 1024;

const ARMING: &str = "arming capture";
const DISCOVERING_TIMESTAMP_TYPES: &str = "discovering timestamp types";

/// Owned capture session: arm through [`Provider`] (or compose a [`Group`]),
/// pass [`Session::wait_ready`] before transmission, read records, then call
/// [`Session::shutdown`] to join every backend.
pub trait Session: Send {
    /// A multi-source session reports its first source here.
    fn metadata(&self) -> &Metadata;
    fn source_count(&self) -> usize {
        1
    }
    fn source_metadata(&self, source: usize) -> Option<&Metadata> {
        (source == 0).then(|| self.metadata())
    }
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), Error>;
    /// Waits until `deadline` for a record. `Ok(None)` means no record was
    /// delivered during this wait, not that none was captured or that the
    /// session ended.
    fn next_captured_frame(&mut self, deadline: &Deadline) -> Result<Option<Captured>, Error>;
    /// Requests stop without waiting for completion. Cooperative implementations
    /// must make this idempotent and return promptly. The legacy default does
    /// nothing; it does not promise that a custom shutdown can be interrupted.
    fn request_stop(&mut self) -> Result<(), Error> {
        Ok(())
    }
    /// Joins stopped capture under a shared, independent cleanup deadline.
    /// Implementations retaining unfinished work must keep its resources charged.
    /// The legacy adapter calls `shutdown` and cannot bound a blocking callback.
    fn shutdown_until(&mut self, _deadline: &Deadline) -> Result<(), Error> {
        self.shutdown()
    }
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
    fn stats(&self) -> Stats;
    /// Quality of this source's local acquisition reporting. The default
    /// preserves unknown quality for legacy providers. A zero drop count alone
    /// does not opt a provider into reporting loss, or prove network visibility.
    fn observation_quality(&self) -> ObservationQuality {
        ObservationQuality::Unknown.with_statistics(self.stats())
    }
}

/// Local acquisition quality, never a guarantee of end-to-end visibility.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObservationQuality {
    #[default]
    Unknown,
    /// The provider reports its supported local loss counters and none reports
    /// loss. It must not use this for unsupported or failed statistics queries.
    NoReportedLoss,
    Incomplete,
}

impl ObservationQuality {
    pub fn with_statistics(self, statistics: Stats) -> Self {
        if statistics.evidence_loss_error().is_some() {
            Self::Incomplete
        } else if statistics.validate().is_err() {
            Self::Unknown
        } else {
            self
        }
    }

    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Incomplete, _) | (_, Self::Incomplete) => Self::Incomplete,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::NoReportedLoss,
        }
    }
}

impl<T: Session + ?Sized> Session for Box<T> {
    fn metadata(&self) -> &Metadata {
        (**self).metadata()
    }

    fn source_count(&self) -> usize {
        (**self).source_count()
    }

    fn source_metadata(&self, source: usize) -> Option<&Metadata> {
        (**self).source_metadata(source)
    }

    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), Error> {
        (**self).wait_ready(deadline)
    }

    fn next_captured_frame(&mut self, deadline: &Deadline) -> Result<Option<Captured>, Error> {
        (**self).next_captured_frame(deadline)
    }

    fn request_stop(&mut self) -> Result<(), Error> {
        (**self).request_stop()
    }

    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
        (**self).shutdown_until(deadline)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        (**self).shutdown()
    }

    fn stats(&self) -> Stats {
        (**self).stats()
    }

    fn observation_quality(&self) -> ObservationQuality {
        (**self).observation_quality()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub interface: InterfaceId,
    pub limits: Limits,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub native: NativeSettings,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        validate_filter_length(self.filter.as_deref())?;
        if self.interface.name.is_empty() || self.interface.index == 0 {
            return Err(Error::Device {
                interface: self.interface.name.clone(),
                message: "capture requires a non-empty interface name and nonzero index".to_owned(),
                source: None,
            });
        }
        self.limits.validate()?;
        self.native.validate(&self.limits)
    }
}

fn validate_filter_length(filter: Option<&str>) -> Result<(), Error> {
    match filter {
        Some(filter) if filter.contains('\0') => Err(Error::InvalidCaptureFilter {
            interface: String::new(),
            message: "capture filter contains an interior NUL byte".to_owned(),
        }),
        Some(filter) if filter.len() > MAX_FILTER_BYTES => Err(Error::CaptureFilterTooLong {
            length: filter.len(),
            maximum: MAX_FILTER_BYTES,
        }),
        _ => Ok(()),
    }
}

fn admit(deadline: &Deadline, operation: &'static str) -> Result<(), Error> {
    deadline
        .live_remaining()
        .map(drop)
        .map_err(|interrupted| Error::interrupted(interrupted, operation))
}

pub(crate) fn wait_end(deadline: &Deadline) -> Result<Option<Instant>, Error> {
    deadline.check_cancelled()?;
    let Some(timeout) = deadline
        .remaining()
        .ok()
        .filter(|remaining| !remaining.is_zero())
    else {
        return Ok(None);
    };
    if timeout > crate::deadline::MAX_WAIT {
        return Err(Error::InvalidCaptureTimeout {
            timeout,
            maximum: crate::deadline::MAX_WAIT,
        });
    }
    Instant::now()
        .checked_add(timeout)
        .map(Some)
        .ok_or(Error::InvalidCaptureTimeout {
            timeout,
            maximum: crate::deadline::MAX_WAIT,
        })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub interface: InterfaceId,
    pub link_type: LinkType,
    pub snap_length: usize,
    pub native: RealizedSettings,
}

pub trait Provider: Send + Sync {
    type Capture: Session;

    fn arm_capture(&self, request: &Request, deadline: &Deadline) -> Result<Self::Capture, Error>;

    fn timestamp_types(
        &self,
        _interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Vec<TimestampType>, Error> {
        admit(deadline, DISCOVERING_TIMESTAMP_TYPES)?;
        Err(crate::Unsupported::new(
            crate::NativeCapability::Capture,
            "this capture provider cannot enumerate timestamp types",
        )
        .into())
    }
}

pub type SystemSession = Box<dyn Session>;

/// Target-selected native capture provider; requires `native-layer2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, request: &Request, deadline: &Deadline) -> Result<Self::Capture, Error> {
        system::open(request, deadline)
    }

    fn timestamp_types(
        &self,
        interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Vec<TimestampType>, Error> {
        system::timestamp_types(interface, deadline)
    }
}

#[cfg(test)]
mod network_improvements {
    use super::*;
    use packetcraftr_core::{budget::Cancellation, frame::Frame};
    use std::time::Duration;
    fn request() -> Request {
        Request {
            interface: InterfaceId {
                name: "test0".into(),
                index: 1,
            },
            limits: Limits::default(),
            filter: None,
            promiscuous: false,
            native: Default::default(),
        }
    }
    #[test]
    fn invalid_group_never_calls_injected_capture_provider() {
        struct RefuseCalls;
        impl Provider for RefuseCalls {
            type Capture = Box<dyn Session>;
            fn arm_capture(&self, _: &Request, _: &Deadline) -> Result<Self::Capture, Error> {
                panic!("invalid capture group activated its provider")
            }
        }
        for identity in [
            InterfaceId {
                name: String::new(),
                index: 1,
            },
            InterfaceId {
                name: "test0".into(),
                index: 0,
            },
        ] {
            let provider = RefuseCalls;
            let request = request();
            let group = GroupRequest {
                interfaces: vec![identity],
                limits: request.limits,
                filter: None,
                promiscuous: false,
                native: Default::default(),
            };
            let result = Group::new(&group).and_then(|mut group| {
                group.arm(&provider, &Deadline::new(std::time::Duration::from_secs(1)))
            });
            assert!(matches!(result, Err(Error::InvalidCaptureGroup { .. })));
        }
    }
    #[test]
    fn incomplete_capture_identities_and_nul_are_rejected() {
        let valid = request();
        valid.validate().unwrap();
        Group::<Box<dyn Session>>::new(&GroupRequest {
            interfaces: vec![valid.interface],
            limits: valid.limits,
            filter: None,
            promiscuous: false,
            native: valid.native,
        })
        .unwrap();
        for id in [
            InterfaceId {
                name: String::new(),
                index: 1,
            },
            InterfaceId {
                name: "test0".into(),
                index: 0,
            },
        ] {
            let mut request = request();
            request.interface = id.clone();
            assert!(matches!(request.validate(), Err(Error::Device { .. })));
            let group = GroupRequest {
                interfaces: vec![id],
                limits: request.limits,
                filter: None,
                promiscuous: false,
                native: Default::default(),
            };
            assert!(matches!(
                Group::<Box<dyn Session>>::new(&group),
                Err(Error::InvalidCaptureGroup { .. })
            ));
        }
        let mut request = request();
        request.filter = Some("tcp\0 or udp".into());
        assert!(matches!(
            request.validate(),
            Err(Error::InvalidCaptureFilter { .. })
        ));
        let group = GroupRequest {
            interfaces: vec![request.interface],
            limits: request.limits,
            filter: request.filter,
            promiscuous: false,
            native: Default::default(),
        };
        assert!(matches!(
            Group::<Box<dyn Session>>::new(&group),
            Err(Error::InvalidCaptureFilter { .. })
        ));
    }

    struct ControlledSession {
        metadata: [Metadata; 2],
        queued: Option<Captured>,
        statistics: Stats,
        quality: ObservationQuality,
        failure: Option<Error>,
    }

    impl ControlledSession {
        fn check(&self) -> Result<(), Error> {
            self.failure.clone().map_or(Ok(()), Err)
        }
    }

    impl Session for ControlledSession {
        fn metadata(&self) -> &Metadata {
            &self.metadata[0]
        }

        fn source_count(&self) -> usize {
            self.metadata.len()
        }

        fn source_metadata(&self, source: usize) -> Option<&Metadata> {
            self.metadata.get(source)
        }

        fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), Error> {
            deadline.check_cancelled()?;
            self.check()
        }

        fn next_captured_frame(&mut self, deadline: &Deadline) -> Result<Option<Captured>, Error> {
            deadline.check_cancelled()?;
            self.check()?;
            Ok(self.queued.take())
        }

        fn request_stop(&mut self) -> Result<(), Error> {
            self.check()
        }

        fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
            deadline.check_cancelled()?;
            self.check()
        }

        fn shutdown(&mut self) -> Result<(), Error> {
            self.check()
        }

        fn stats(&self) -> Stats {
            self.statistics
        }

        fn observation_quality(&self) -> ObservationQuality {
            self.quality
        }
    }

    fn controlled_session(received_at: Instant, failure: Option<Error>) -> ControlledSession {
        let metadata = [("first", 11, 64), ("second", 12, 128)].map(
            |(name, index, snap_length): (&str, u32, usize)| Metadata {
                interface: InterfaceId {
                    name: name.to_owned(),
                    index,
                },
                link_type: LinkType::RAW,
                snap_length,
                native: RealizedSettings::default(),
            },
        );
        let mut captured = Captured::new(
            Frame::without_timestamp(LinkType::RAW, vec![0xa1, 0xb2, 0xc3]).unwrap(),
            received_at,
        );
        captured.source = 1;
        ControlledSession {
            metadata,
            queued: Some(captured),
            statistics: Stats {
                received_frames: 3,
                received_bytes: 9,
                dropped_frames: 2,
                dropped_bytes: 6,
                overflow_events: 1,
                receiver_dropped_frames: 1,
            },
            quality: ObservationQuality::Incomplete,
            failure,
        }
    }

    fn controlled_deadline(now: Instant, cancellation: Option<Cancellation>) -> Deadline {
        Deadline::with_time_source(Duration::from_secs(5), move || now)
            .with_cancellation(cancellation)
    }

    #[test]
    fn boxed_capture_preserves_source_and_record_evidence_after_cancelled_waits() {
        let received_at = Instant::now();
        let backend = controlled_session(received_at, None);
        let metadata = backend.metadata.clone();
        let statistics = backend.statistics;
        let quality = backend.quality;
        let expected = backend.queued.as_ref().unwrap().clone();
        let mut capture: SystemSession = Box::new(backend);
        assert_eq!(capture.metadata(), &metadata[0]);
        assert_eq!(capture.source_count(), metadata.len());
        for (source, expected) in metadata.iter().enumerate() {
            assert_eq!(capture.source_metadata(source), Some(expected));
        }
        assert!(capture.source_metadata(metadata.len()).is_none());
        assert_eq!(capture.stats(), statistics);
        assert_eq!(capture.observation_quality(), quality);

        let cancellation = Cancellation::default();
        cancellation.cancel();
        let cancelled = controlled_deadline(received_at, Some(cancellation));
        let live = controlled_deadline(received_at, None);
        assert!(matches!(
            capture.wait_ready(&cancelled),
            Err(Error::Cancelled(_))
        ));
        capture.wait_ready(&live).unwrap();
        assert!(matches!(
            capture.next_captured_frame(&cancelled),
            Err(Error::Cancelled(_))
        ));
        let received = capture.next_captured_frame(&live).unwrap().unwrap();
        assert_eq!(received.identity(), expected.identity());
        assert_eq!(received.source, expected.source);
        assert_eq!(received.frame, expected.frame);
        assert_eq!(received.received_at, Some(received_at));
        assert!(capture.next_captured_frame(&live).unwrap().is_none());
        capture.request_stop().unwrap();
        assert!(matches!(
            capture.shutdown_until(&cancelled),
            Err(Error::Cancelled(_))
        ));
        capture.shutdown_until(&live).unwrap();
        capture.shutdown().unwrap();
        assert_eq!(capture.stats(), statistics);
        assert_eq!(capture.observation_quality(), quality);
    }

    #[test]
    fn boxed_capture_preserves_backend_failures_from_readiness_read_stop_and_cleanup() {
        let now = Instant::now();
        let failure = Error::Capture {
            message: "controlled backend failure".to_owned(),
            source: None,
        };
        let mut capture: SystemSession = Box::new(controlled_session(now, Some(failure)));
        let deadline = controlled_deadline(now, None);
        let expect_failure = |result: Result<(), Error>| {
            let Err(Error::Capture { message, source }) = result else {
                panic!("the boxed capture must preserve the backend's failure")
            };
            assert_eq!(message, "controlled backend failure");
            assert!(source.is_none());
        };
        expect_failure(capture.wait_ready(&deadline));
        expect_failure(capture.next_captured_frame(&deadline).map(drop));
        expect_failure(capture.request_stop());
        expect_failure(capture.shutdown_until(&deadline));
        expect_failure(capture.shutdown());
    }
}
