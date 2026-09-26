// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned live-capture sessions and bounded queue configuration.

pub mod group;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::Error;
use super::interface::Id as InterfaceId;
use crate::deadline::POLL_INTERVAL;
use packetcraftr_core::frame::{Frame as CaptureFrame, LinkType};

/// Aggregate backend capture-queue frame ceiling; also the value
/// [`Limits::default`] uses.
pub const MAX_CAPTURE_QUEUE_FRAMES: usize = 4_096;
/// Aggregate backend capture-queue byte ceiling; also the value
/// [`Limits::default`] uses.
pub const MAX_CAPTURE_QUEUE_BYTES: usize = 256 * 1024 * 1024;
/// Largest per-frame snapshot a capture session will retain (16 MiB), matching
/// the default captured-frame size limit in `packetcraftr-core`; also the value
/// [`Limits::default`] uses.
pub const MAX_SNAP_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum blocking wait accepted by an owned capture session.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Capture counters for accepted frames and pre-delivery loss. Native receiver
/// drops are a subset; overflow events are bounded-queue observations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Statistics {
    pub received_frames: u64,
    pub received_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    pub overflow_events: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub receiver_dropped_frames: u64,
}

impl Statistics {
    /// Returns the fieldwise sum, or `None` if any counter would overflow.
    pub fn checked_add(self, value: Self) -> Option<Self> {
        Some(Self {
            received_frames: self.received_frames.checked_add(value.received_frames)?,
            received_bytes: self.received_bytes.checked_add(value.received_bytes)?,
            dropped_frames: self.dropped_frames.checked_add(value.dropped_frames)?,
            dropped_bytes: self.dropped_bytes.checked_add(value.dropped_bytes)?,
            overflow_events: self.overflow_events.checked_add(value.overflow_events)?,
            receiver_dropped_frames: self
                .receiver_dropped_frames
                .checked_add(value.receiver_dropped_frames)?,
        })
    }

    /// Validates required frame/byte counter relationships.
    pub fn validate(&self) -> Result<(), Error> {
        if self.dropped_frames == 0 && self.dropped_bytes != 0 {
            return Err(Error::InvalidCaptureStatistics {
                message: "dropped bytes were reported without a dropped frame".to_owned(),
            });
        }
        if self.receiver_dropped_frames > self.dropped_frames {
            return Err(Error::InvalidCaptureStatistics {
                message: "receiver-dropped frames exceed total dropped frames".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the typed loss error these counters describe, or `None` when the
    /// backend reported no drop and no queue overflow.
    pub fn evidence_loss_error(self) -> Option<Error> {
        if self.overflow_events != 0 {
            Some(Error::CaptureQueueOverflow {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                overflow_events: self.overflow_events,
            })
        } else if self.dropped_frames != 0
            || self.dropped_bytes != 0
            || self.receiver_dropped_frames != 0
        {
            Some(Error::CaptureEvidenceLoss {
                dropped_frames: self.dropped_frames,
                dropped_bytes: self.dropped_bytes,
                receiver_dropped_frames: self.receiver_dropped_frames,
            })
        } else {
            None
        }
    }
}

/// Owned capture session: arm through [`Provider`], pass
/// [`Session::wait_ready`] before transmission, read records, then call
/// [`Session::shutdown`] to join the backend exactly once. Statistics are final
/// only after successful shutdown.
pub trait Session: Send {
    /// Returns the backend-confirmed properties fixed when the session was activated.
    fn metadata(&self) -> &Metadata;
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error>;
    /// Waits up to `timeout` for a record. `Ok(None)` means no record was
    /// delivered during this wait, not that none was captured or that the
    /// session ended. Only [`Session::shutdown`] ends the session;
    /// [`Session::statistics`] reports loss.
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error>;
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
    /// Returns cumulative counters, including undelivered queue loss.
    fn statistics(&self) -> Statistics;
}

impl<T: Session + ?Sized> Session for Box<T> {
    fn metadata(&self) -> &Metadata {
        (**self).metadata()
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        (**self).wait_ready(timeout)
    }

    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        (**self).next_captured_frame(timeout)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        (**self).shutdown()
    }

    fn statistics(&self) -> Statistics {
        (**self).statistics()
    }
}

/// Capture adapter that polls cooperatively for user cancellation. Provider
/// readiness and shutdown retain their original bounded lifecycle contracts.
/// A provider must honor each requested wait; arbitrary blocked provider code
/// cannot be preempted by this adapter.
pub struct Cancellable<C> {
    inner: C,
    cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl<C: Session> Cancellable<C> {
    pub fn new(inner: C, cancellation: Option<packetcraftr_core::budget::Cancellation>) -> Self {
        Self {
            inner,
            cancellation,
        }
    }

    fn check(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}

impl<C: Session> Session for Cancellable<C> {
    fn metadata(&self) -> &Metadata {
        self.inner.metadata()
    }
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        self.check()?;
        self.inner.wait_ready(timeout)?;
        self.check()
    }
    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        let start = Instant::now();
        // Validate the original request before slicing it into polls: otherwise
        // cancellation would accidentally admit waits beyond the provider contract.
        if timeout > MAX_TIMEOUT || start.checked_add(timeout).is_none() {
            return Err(Error::InvalidCaptureTimeout {
                timeout,
                maximum: MAX_TIMEOUT,
            });
        }
        if self.cancellation.is_none() {
            return self.inner.next_captured_frame(timeout);
        }
        loop {
            self.check()?;
            let poll_started = Instant::now();
            let remaining = timeout.saturating_sub(poll_started.duration_since(start));
            let poll_timeout = remaining.min(POLL_INTERVAL);
            let frame = self.inner.next_captured_frame(poll_timeout)?;
            self.check()?;
            if frame.is_none() {
                // Empty polls may return early, including after a backend stops.
                std::thread::sleep(poll_timeout.saturating_sub(poll_started.elapsed()));
                self.check()?;
            }
            if frame.is_some() || start.elapsed() >= timeout {
                return Ok(frame);
            }
        }
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown()
    }
    fn statistics(&self) -> Statistics {
        self.inner.statistics()
    }
}

/// Timestamp fraction precision a native backend delivers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPrecision {
    /// Microsecond fractions; the libpcap and Npcap default.
    #[default]
    Micro,
    Nano,
}

impl TimestampPrecision {
    /// The one spelling this precision is named by, in help text, in the
    /// `--timestamp-precision` values a caller passes, and in reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Nano => "nano",
        }
    }
}

impl std::fmt::Display for TimestampPrecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Timestamp sources synchronized with the host system clock. Unsynchronized
/// sources cannot be converted to host monotonic or Unix time; discovery
/// reports them with [`TimestampType::source`] set to `None`.
///
/// Serialized names match libpcap and `--timestamp-source` spellings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum TimestampSource {
    /// Host-provided timestamps of unspecified characteristics
    /// (`PCAP_TSTAMP_HOST`, the backend default).
    #[serde(rename = "host")]
    Host,
    /// Low-precision host timestamps synchronized with the system clock
    /// (`PCAP_TSTAMP_HOST_LOWPREC`).
    #[serde(rename = "host_lowprec")]
    HostLowPrec,
    /// High-precision host timestamps synchronized with the system clock
    /// (`PCAP_TSTAMP_HOST_HIPREC`).
    #[serde(rename = "host_hiprec")]
    HostHighPrec,
    /// Adapter-provided high-precision timestamps synchronized with the
    /// system clock (`PCAP_TSTAMP_ADAPTER`).
    #[serde(rename = "adapter")]
    Adapter,
}

impl TimestampSource {
    /// The libpcap-canonical name of this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::HostLowPrec => "host_lowprec",
            Self::HostHighPrec => "host_hiprec",
            Self::Adapter => "adapter",
        }
    }
}

impl std::fmt::Display for TimestampSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One packet timestamp type a native backend advertises for an interface.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TimestampType {
    /// The backend's numeric timestamp-type value.
    pub value: i32,
    /// The backend's canonical name for the type, when it assigns one.
    pub name: Option<String>,
    /// The backend's description of the type, when it assigns one.
    pub description: Option<String>,
    /// The [`TimestampSource`] selecting this type; `None` when the type's
    /// clock domain cannot be represented safely by the frame-time contract.
    pub source: Option<TimestampSource>,
}

/// Upper bound on a backend's advertised timestamp-type list. Real backends
/// enumerate a handful of types; a larger answer is a broken backend.
pub const MAX_TIMESTAMP_TYPES: usize = 64;

/// Per-interface driver settings applied before activation; `None` keeps
/// backend defaults. These are independent of PacketcraftR's capture-queue
/// [`Limits`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NativeSettings {
    /// Kernel/driver capture-buffer size in bytes (`pcap_set_buffer_size`).
    /// The backend accepts the request during configuration; neither backend
    /// can report the size the kernel actually allocated.
    pub buffer_size: Option<usize>,
    /// Packet timestamp source (`pcap_set_tstamp_type`).
    pub timestamp_source: Option<TimestampSource>,
    /// Packet timestamp fraction precision (`pcap_set_tstamp_precision`).
    pub timestamp_precision: Option<TimestampPrecision>,
}

/// Largest driver-buffer request the pcap-family ABI can express; both
/// backends take the size as a C `int`.
pub const MAX_NATIVE_BUFFER_SIZE: usize = i32::MAX as usize;

impl NativeSettings {
    /// Validates finite ranges and the buffer/snapshot relationship before
    /// any backend is configured or activated.
    pub fn validate(&self, limits: &Limits) -> Result<(), Error> {
        if let Some(buffer_size) = self.buffer_size {
            if buffer_size == 0 {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: "must be greater than zero".to_owned(),
                });
            }
            if buffer_size > MAX_NATIVE_BUFFER_SIZE {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: format!(
                        "exceeds the native maximum of {MAX_NATIVE_BUFFER_SIZE} bytes"
                    ),
                });
            }
            if buffer_size < limits.snap_length {
                return Err(Error::InvalidCaptureSetting {
                    field: "buffer_size",
                    message: format!("must hold one snapshot of {} bytes", limits.snap_length),
                });
            }
        }
        Ok(())
    }
}

/// Requested, applied, and confirmed values of a [`NativeSettings`] field.
/// Configuration acceptance alone does not confirm the effective value.
/// `effective = None` means unknown, not zero or default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Realized<T> {
    /// The explicit request echoed back; `None` when the caller asked for the
    /// backend default.
    pub requested: Option<T>,
    /// The value the backend's configuration call accepted; `None` when no
    /// explicit value was applied.
    pub applied: Option<T>,
    /// The value independently confirmed after activation; `None` when the
    /// backend cannot report it.
    pub effective: Option<T>,
}

impl<T> Default for Realized<T> {
    fn default() -> Self {
        Self {
            requested: None,
            applied: None,
            effective: None,
        }
    }
}

impl<T: PartialEq> Realized<T> {
    /// Checks that requested and applied values match the request. Backends
    /// must reject a confirmed effective mismatch before reporting a session.
    pub(crate) fn consistent_with(&self, request: Option<T>) -> bool {
        self.requested == request && self.applied == request
    }
}

/// Backend-realized values for each [`NativeSettings`] field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RealizedSettings {
    /// Both backends accept a request but cannot report the allocated size.
    pub buffer_size: Realized<usize>,
    /// Both backends apply a request at configuration time but cannot report
    /// the source in effect afterwards.
    pub timestamp_source: Realized<TimestampSource>,
    /// Precision is confirmed after activation: the read path must interpret
    /// the native timestamp fraction with the delivered unit.
    pub timestamp_precision: Realized<TimestampPrecision>,
}

impl RealizedSettings {
    /// Whether any requested, applied, or effective value is present; an
    /// all-default realization is omitted from serialized reports.
    pub fn reported(&self) -> bool {
        fn present<T>(realized: &Realized<T>) -> bool {
            realized.requested.is_some()
                || realized.applied.is_some()
                || realized.effective.is_some()
        }
        present(&self.buffer_size)
            || present(&self.timestamp_source)
            || present(&self.timestamp_precision)
    }
}

/// Configuration for one single-interface capture session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub interface: InterfaceId,
    pub limits: Limits,
    /// Native filter that the provider must install before delivery or reject.
    pub filter: Option<String>,
    pub promiscuous: bool,
    /// Optional native-driver settings; defaults preserve backend behavior.
    pub native: NativeSettings,
}

/// Backend-confirmed properties of an activated capture session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub interface: InterfaceId,
    pub link_type: LinkType,
    pub snap_length: usize,
    /// What the backend made of the session's [`NativeSettings`].
    pub native: RealizedSettings,
}

/// Opaque identity assigned exactly once when a record enters capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordIdentity(u64);

static NEXT_RECORD_ID: AtomicU64 = AtomicU64::new(1);

/// Capture evidence with an optional monotonic ingress marker. Wall-clock time is
/// output-only; freshness and latency use `received_at` to avoid reordering.
#[derive(Clone, Debug)]
pub struct Captured {
    identity: RecordIdentity,
    pub frame: CaptureFrame,
    /// Monotonic ingress time; `None` cannot prove freshness.
    pub received_at: Option<Instant>,
}

impl Captured {
    pub fn new(frame: CaptureFrame, received_at: Instant) -> Self {
        Self::with_ingress_time(frame, Some(received_at))
    }

    /// Retains an optional provider-supplied monotonic ingress marker.
    ///
    /// # Panics
    ///
    /// Panics only if the process exhausts the non-reusable capture-record
    /// identity space.
    pub fn with_ingress_time(frame: CaptureFrame, received_at: Option<Instant>) -> Self {
        let identity = NEXT_RECORD_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("capture record identity space exhausted");
        Self {
            identity: RecordIdentity(identity),
            frame,
            received_at,
        }
    }

    /// Evidence without an ingress marker cannot satisfy freshness correlation.
    pub fn without_ingress_time(frame: CaptureFrame) -> Self {
        Self::with_ingress_time(frame, None)
    }

    pub fn identity(&self) -> RecordIdentity {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverflowPolicy {
    #[default]
    Fail,
    DropNewest,
    DropOldest,
}

impl OverflowPolicy {
    /// The one spelling this policy is named by, in help text, in the
    /// `--overflow-policy` values a caller passes, and in the diagnostics that
    /// report which policy was in force.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::DropNewest => "drop-newest",
            Self::DropOldest => "drop-oldest",
        }
    }
}

impl std::fmt::Display for OverflowPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_frames: usize,
    pub max_bytes: usize,
    pub snap_length: usize,
    pub overflow_policy: OverflowPolicy,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_bytes: MAX_CAPTURE_QUEUE_BYTES,
            snap_length: MAX_SNAP_LENGTH,
            overflow_policy: OverflowPolicy::Fail,
        }
    }
}

impl Limits {
    /// Validates bounded nonzero limits and byte/snap consistency before capture.
    pub fn validate(&self) -> Result<(), Error> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("snap_length", self.snap_length),
        ] {
            if value == 0 {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "must be greater than zero",
                });
            }
        }
        for (field, value, maximum) in [
            ("max_frames", self.max_frames, MAX_CAPTURE_QUEUE_FRAMES),
            ("max_bytes", self.max_bytes, MAX_CAPTURE_QUEUE_BYTES),
            ("snap_length", self.snap_length, MAX_SNAP_LENGTH),
        ] {
            if value > maximum {
                return Err(Error::InvalidCaptureQueueLimit {
                    field,
                    value,
                    reason: "exceeds the stable configured maximum",
                });
            }
        }
        if self.snap_length > self.max_bytes {
            return Err(Error::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: self.snap_length,
                reason: "cannot exceed max_bytes",
            });
        }
        Ok(())
    }
}

/// Starts an owned capture stream using platform-neutral interface data.
pub trait Provider: Send + Sync {
    type Capture: Session;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error>;

    /// The packet timestamp types this provider's backend advertises for
    /// `interface`, in backend order. Providers without native timestamp-type
    /// discovery reject with [`Error::Unsupported`].
    fn timestamp_types(&self, _interface: &InterfaceId) -> Result<Vec<TimestampType>, Error> {
        Err(Error::Unsupported {
            message: "this capture provider cannot enumerate timestamp types".to_owned(),
            source: None,
        })
    }
}

/// Platform-native capture session with private handle and worker.
pub type SystemSession = Box<dyn Session>;

/// Target-selected native capture provider; requires `native-layer2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Capture = SystemSession;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error> {
        super::platform::system_capture(request)
    }

    fn timestamp_types(&self, interface: &InterfaceId) -> Result<Vec<TimestampType>, Error> {
        super::platform::capture_timestamp_types(interface)
    }
}

impl<S, C> Provider for crate::PacketIo<S, C>
where
    S: Send + Sync,
    C: Provider,
{
    type Capture = C::Capture;

    fn arm_capture(&self, request: &Request) -> Result<Self::Capture, Error> {
        self.capture.arm_capture(request)
    }

    fn timestamp_types(&self, interface: &InterfaceId) -> Result<Vec<TimestampType>, Error> {
        self.capture.timestamp_types(interface)
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::budget::Cancellation;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Capture {
        metadata: Metadata,
        signal: Cancellation,
        stopped: Arc<AtomicBool>,
    }
    impl Session for Capture {
        fn metadata(&self) -> &Metadata {
            &self.metadata
        }
        fn wait_ready(&mut self, _: Duration) -> Result<(), Error> {
            Ok(())
        }
        fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
            assert!(timeout <= Duration::from_millis(25));
            self.signal.cancel();
            Ok(None)
        }
        fn shutdown(&mut self) -> Result<(), Error> {
            self.stopped.store(true, Ordering::Release);
            Ok(())
        }
        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }
    #[test]
    fn cancellation_during_capture_wait_still_allows_explicit_shutdown() {
        let signal = Cancellation::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let capture = Capture {
            metadata: Metadata {
                interface: InterfaceId {
                    name: "fixture".to_owned(),
                    index: 1,
                },
                link_type: LinkType::IPV4,
                snap_length: 128,
                native: Default::default(),
            },
            signal: signal.clone(),
            stopped: stopped.clone(),
        };
        let mut capture = Cancellable::new(capture, Some(signal));
        capture.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            capture.next_captured_frame(Duration::MAX),
            Err(Error::InvalidCaptureTimeout { .. })
        ));
        assert!(matches!(
            capture.next_captured_frame(Duration::from_secs(60)),
            Err(Error::Cancelled(_))
        ));
        capture.shutdown().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }

    fn limits() -> Limits {
        Limits {
            snap_length: 64,
            ..Limits::default()
        }
    }

    #[test]
    fn native_settings_validate_finite_ranges_before_activation() {
        let limits = limits();
        // Defaults and a buffer that holds one snapshot pass.
        NativeSettings::default().validate(&limits).unwrap();
        NativeSettings {
            buffer_size: Some(64),
            ..Default::default()
        }
        .validate(&limits)
        .unwrap();
        NativeSettings {
            buffer_size: Some(MAX_NATIVE_BUFFER_SIZE),
            timestamp_source: Some(TimestampSource::Adapter),
            timestamp_precision: Some(TimestampPrecision::Nano),
        }
        .validate(&limits)
        .unwrap();

        for (buffer_size, check) in [
            (0usize, "zero is rejected" as &str),
            (63, "smaller than one snapshot is rejected"),
            (
                MAX_NATIVE_BUFFER_SIZE + 1,
                "above the native int range is rejected",
            ),
            (usize::MAX, "overflow is rejected"),
        ] {
            let error = NativeSettings {
                buffer_size: Some(buffer_size),
                ..Default::default()
            }
            .validate(&limits)
            .expect_err(check);
            assert!(
                matches!(
                    error,
                    Error::InvalidCaptureSetting {
                        field: "buffer_size",
                        ..
                    }
                ),
                "{check}: {error:?}"
            );
        }
    }

    #[test]
    fn realizations_echo_requests_and_keep_unknown_effective_unknown() {
        let mut realized = RealizedSettings::default();
        assert!(!realized.reported());
        assert!(realized.buffer_size.consistent_with(None));
        realized.buffer_size = Realized {
            requested: Some(1024),
            applied: Some(1024),
            effective: None,
        };
        assert!(realized.reported());
        assert!(realized.buffer_size.consistent_with(Some(1024)));
        // A backend echoing a different applied value fails the check, and an
        // effective value the backend could not query stays None — never a
        // fabricated default.
        realized.buffer_size.applied = Some(2048);
        assert!(!realized.buffer_size.consistent_with(Some(1024)));
        assert_eq!(realized.buffer_size.effective, None);
    }
}
