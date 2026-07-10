// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, policy-gated capture replay over injectable timing and I/O seams.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureError, CaptureFileFormat, CaptureInterface, CaptureReader, CapturedFrame, InterfaceId,
    IoSendReport, LinkMode, LinkType, LiveIoError, ReplayTiming, DEFAULT_CAPTURE_SIZE_LIMIT,
    DEFAULT_CAPTURE_STREAM_BYTES, DEFAULT_CAPTURE_STREAM_FRAMES, MAX_CAPTURE_TIMEOUT,
};

/// Maximum cumulative intentional delay accepted by one replay operation.
pub const MAX_REPLAY_DURATION: Duration = MAX_CAPTURE_TIMEOUT;

/// Finite resource ceilings applied before authorizing or transmitting a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayLimits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_duration: Duration,
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_CAPTURE_STREAM_FRAMES,
            max_bytes: DEFAULT_CAPTURE_STREAM_BYTES,
            max_frame_bytes: DEFAULT_CAPTURE_SIZE_LIMIT,
            max_duration: MAX_REPLAY_DURATION,
        }
    }
}

impl ReplayLimits {
    pub fn validate(self) -> Result<Self, ReplayError> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
        ] {
            if value == 0 {
                return Err(ReplayError::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(ReplayError::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_REPLAY_DURATION {
            return Err(ReplayError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_REPLAY_DURATION,
            });
        }
        Ok(self)
    }
}

/// Complete replay request after the caller has selected an interface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayOptions {
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub timing: ReplayTiming,
    pub limits: ReplayLimits,
}

/// Per-frame evidence emitted only after exact transmission is confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayFrameEvidence {
    pub source_sequence: u64,
    pub source_interface_id: Option<u32>,
    pub capture_interface: CaptureInterface,
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: CapturedFrame,
}

/// Terminal counters for a completed replay stream.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplaySummary {
    pub source_format: CaptureFileFormat,
    pub timing: ReplayTiming,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
}

/// Policy decision returned before a replay transmitter can observe a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl ReplayAuthorizationError {
    pub fn new(
        message: impl Into<String>,
        classification: ErrorClassification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
        }
    }
}

impl fmt::Display for ReplayAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ReplayAuthorizationError {}

impl ClassifiedError for ReplayAuthorizationError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

/// Explicit policy seam invoked before delay or transmission.
pub trait ReplayAuthorizer {
    fn authorize(
        &mut self,
        frame: &CapturedFrame,
        mode: LinkMode,
    ) -> Result<(), ReplayAuthorizationError>;
}

/// Exact-frame transmitter seam used by native adapters and deterministic tests.
pub trait ReplayTransmitter {
    /// Resolve and validate the concrete interface before any intentional delay.
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<InterfaceId, LiveIoError>;

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<ReplayTransmission, LiveIoError>;
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTransmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}

/// Injectable delay seam. Production uses [`SystemReplayClock`].
pub trait ReplayClock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemReplayClock;

impl ReplayClock for SystemReplayClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        std::thread::sleep(delay);
        Ok(())
    }
}

/// Failure from a bounded replay operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayError {
    #[error("invalid replay limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    #[error("replay duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("invalid replay timing: {0}")]
    InvalidTiming(#[source] CaptureError),
    #[error("replay timing failed at source frame {sequence}: {source}")]
    Timing {
        sequence: u64,
        #[source]
        source: CaptureError,
    },
    #[error("capture read failed at source frame {sequence}: {source}")]
    Capture {
        sequence: u64,
        #[source]
        source: CaptureError,
    },
    #[error("replay frame count {actual} exceeds the configured limit of {limit} at source frame {sequence}")]
    FrameLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error("replay byte count {actual} exceeds the configured limit of {limit} at source frame {sequence}")]
    ByteLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "source frame {sequence} contains {actual} bytes, exceeding the per-frame limit of {limit}"
    )]
    FrameSizeLimit {
        sequence: u64,
        actual: usize,
        limit: usize,
    },
    #[error("replay schedule {actual:?} exceeds the configured duration of {limit:?} at source frame {sequence}")]
    DurationLimit {
        sequence: u64,
        actual: Duration,
        limit: Duration,
    },
    #[error(
        "capture link type {link_type} is not supported for live replay at source frame {sequence}"
    )]
    UnsupportedLinkType { sequence: u64, link_type: u32 },
    #[error("capture link type {link_type} is incompatible with requested {requested:?} replay at source frame {sequence}")]
    LinkModeMismatch {
        sequence: u64,
        link_type: u32,
        requested: LinkMode,
    },
    #[error("replay policy denied source frame {sequence}: {source}")]
    Authorization {
        sequence: u64,
        #[source]
        source: ReplayAuthorizationError,
    },
    #[error("replay transmission failed at source frame {sequence}: {source}")]
    Transmission {
        sequence: u64,
        #[source]
        source: LiveIoError,
    },
    #[error("replay transmitter returned invalid evidence at source frame {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("replay clock failed at source frame {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("replay output failed at source frame {sequence}: {message}")]
    Output { sequence: u64, message: String },
}

impl ReplayError {
    pub fn output(sequence: u64, message: impl Into<String>) -> Self {
        Self::Output {
            sequence,
            message: message.into(),
        }
    }

    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Capture { sequence, .. }
            | Self::FrameLimit { sequence, .. }
            | Self::ByteLimit { sequence, .. }
            | Self::FrameSizeLimit { sequence, .. }
            | Self::DurationLimit { sequence, .. }
            | Self::UnsupportedLinkType { sequence, .. }
            | Self::LinkModeMismatch { sequence, .. }
            | Self::Timing { sequence, .. }
            | Self::Authorization { sequence, .. }
            | Self::Transmission { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::Output { sequence, .. } => Some(*sequence),
            _ => None,
        }
    }
}

impl ClassifiedError for ReplayError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. } | Self::InvalidDuration { .. } | Self::InvalidTiming(_) => {
                ErrorClassification::new(
                    "cli.replay_limit",
                    FailureKind::Cli,
                    Some("use finite non-zero replay limits and a valid positive timing value"),
                )
            }
            Self::Capture { source, .. } => source.classification(),
            Self::FrameLimit { .. } | Self::ByteLimit { .. } | Self::DurationLimit { .. } => {
                ErrorClassification::new(
                    "policy.replay_limit",
                    FailureKind::Policy,
                    Some("reduce the replay input or deliberately raise the finite operation budget"),
                )
            }
            Self::FrameSizeLimit { .. } => ErrorClassification::new(
                "packet.capture_size",
                FailureKind::Packet,
                Some("reduce the captured frame size or deliberately raise the bounded frame limit"),
            ),
            Self::Timing { .. } => ErrorClassification::new(
                "packet.replay_timing",
                FailureKind::Packet,
                Some("reduce the captured interval or select a bounded fixed/immediate replay timing"),
            ),
            Self::UnsupportedLinkType { .. } | Self::LinkModeMismatch { .. } => {
                ErrorClassification::new(
                    "capability.replay_link_type",
                    FailureKind::Capability,
                    Some("replay complete Ethernet frames through Layer 2 or raw IPv4/IPv6 datagrams through Layer 3"),
                )
            }
            Self::Authorization { source, .. } => source.classification(),
            Self::Transmission { source, .. } => source.classification(),
            Self::InvalidEvidence { .. } => ErrorClassification::new(
                "internal.replay_evidence",
                FailureKind::Internal,
                Some("treat the operation as incomplete; the backend did not confirm the exact submitted bytes"),
            ),
            Self::Clock { .. } | Self::Output { .. } => ErrorClassification::new(
                "io.replay",
                FailureKind::Io,
                Some("inspect the replay timer or output sink and account for frames already transmitted"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization { source, .. } => source.causes(),
            Self::Transmission { source, .. } => source.causes(),
            Self::Capture { source, .. }
            | Self::InvalidTiming(source)
            | Self::Timing { source, .. } => {
                vec![source.to_string()]
            }
            _ => Vec::new(),
        }
    }
}

/// Streams, authorizes, schedules, and transmits a capture without retaining
/// more than the current frame.
pub fn replay_capture<R, A, T, C, F>(
    reader: &mut CaptureReader<R>,
    options: &ReplayOptions,
    authorizer: &mut A,
    transmitter: &mut T,
    clock: &mut C,
    mut emit: F,
) -> Result<ReplaySummary, ReplayError>
where
    R: Read,
    A: ReplayAuthorizer,
    T: ReplayTransmitter,
    C: ReplayClock,
    F: FnMut(ReplayFrameEvidence) -> Result<(), ReplayError>,
{
    let limits = options.limits.validate()?;
    let timing = options
        .timing
        .validate()
        .map_err(ReplayError::InvalidTiming)?;
    let source_format = reader.format();
    let mut previous_timestamp = None;
    let mut frames_attempted = 0_u64;
    let mut frames_completed = 0_u64;
    let mut bytes_completed = 0_u64;
    let mut scheduled_duration = Duration::ZERO;

    loop {
        let sequence = frames_attempted;
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| ReplayError::Capture { sequence, source })?
        else {
            break;
        };
        let capture_interface = frame
            .interface
            .and_then(|interface| reader.interfaces().get(interface as usize))
            .or_else(|| {
                (reader.format() == CaptureFileFormat::Pcap)
                    .then(|| reader.interfaces().first())
                    .flatten()
            })
            .copied()
            .ok_or_else(|| ReplayError::InvalidEvidence {
                sequence,
                message: "capture frame has no matching interface metadata".to_owned(),
            })?;

        let next_frames = frames_attempted
            .checked_add(1)
            .ok_or(ReplayError::FrameLimit {
                sequence,
                actual: u64::MAX,
                limit: limits.max_frames,
            })?;
        if next_frames > limits.max_frames {
            return Err(ReplayError::FrameLimit {
                sequence,
                actual: next_frames,
                limit: limits.max_frames,
            });
        }
        if frame.bytes.len() > limits.max_frame_bytes {
            return Err(ReplayError::FrameSizeLimit {
                sequence,
                actual: frame.bytes.len(),
                limit: limits.max_frame_bytes,
            });
        }
        let next_bytes = bytes_completed
            .checked_add(u64::from(frame.captured_length))
            .ok_or(ReplayError::ByteLimit {
                sequence,
                actual: u64::MAX,
                limit: limits.max_bytes,
            })?;
        if next_bytes > limits.max_bytes {
            return Err(ReplayError::ByteLimit {
                sequence,
                actual: next_bytes,
                limit: limits.max_bytes,
            });
        }
        frames_attempted = next_frames;

        let mode = replay_link_mode(sequence, frame.link_type, options.link_mode)?;
        let delay = match previous_timestamp {
            Some(previous) => timing
                .delay_between(previous, frame.timestamp)
                .map_err(|source| ReplayError::Timing { sequence, source })?,
            None => Duration::ZERO,
        };
        let next_duration =
            scheduled_duration
                .checked_add(delay)
                .ok_or(ReplayError::DurationLimit {
                    sequence,
                    actual: Duration::MAX,
                    limit: limits.max_duration,
                })?;
        if next_duration > limits.max_duration {
            return Err(ReplayError::DurationLimit {
                sequence,
                actual: next_duration,
                limit: limits.max_duration,
            });
        }
        authorizer
            .authorize(&frame, mode)
            .map_err(|source| ReplayError::Authorization { sequence, source })?;
        let concrete_interface = transmitter
            .validate_interface(&options.interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        clock.sleep(delay).map_err(|source| ReplayError::Clock {
            sequence,
            message: source.to_string(),
        })?;

        let transmission = transmitter
            .transmit(&concrete_interface, mode, &frame)
            .map_err(|source| ReplayError::Transmission { sequence, source })?;
        validate_transmission_evidence(sequence, &frame, &transmission.report)?;

        frames_completed = frames_completed
            .checked_add(1)
            .expect("completed frames cannot exceed validated attempted frames");
        bytes_completed = next_bytes;
        scheduled_duration = next_duration;
        previous_timestamp = Some(frame.timestamp);
        emit(ReplayFrameEvidence {
            source_sequence: sequence,
            source_interface_id: frame.interface,
            capture_interface,
            interface: transmission.interface,
            link_mode: mode,
            scheduled_delay: delay,
            bytes_sent: transmission.report.bytes_sent as u64,
            frame,
        })?;
    }

    Ok(ReplaySummary {
        source_format,
        timing,
        frames_attempted,
        frames_completed,
        bytes_completed,
        scheduled_duration,
    })
}

fn replay_link_mode(
    sequence: u64,
    link_type: LinkType,
    requested: LinkMode,
) -> Result<LinkMode, ReplayError> {
    let supported = match link_type.0 {
        1 => LinkMode::Layer2,
        12 | 101 | 228 | 229 => LinkMode::Layer3,
        _ => {
            return Err(ReplayError::UnsupportedLinkType {
                sequence,
                link_type: link_type.0,
            })
        }
    };
    match requested {
        LinkMode::Auto => Ok(supported),
        requested if requested == supported => Ok(requested),
        requested => Err(ReplayError::LinkModeMismatch {
            sequence,
            link_type: link_type.0,
            requested,
        }),
    }
}

fn validate_transmission_evidence(
    sequence: u64,
    frame: &CapturedFrame,
    report: &IoSendReport,
) -> Result<(), ReplayError> {
    if report.bytes_sent != frame.bytes.len() {
        return Err(ReplayError::Transmission {
            sequence,
            source: LiveIoError::PartialSend {
                expected: frame.bytes.len(),
                actual: report.bytes_sent,
            },
        });
    }
    let wire_bytes = report
        .wire_bytes
        .as_ref()
        .ok_or_else(|| ReplayError::InvalidEvidence {
            sequence,
            message: "backend omitted exact wire bytes".to_owned(),
        })?;
    if wire_bytes != &frame.bytes {
        return Err(ReplayError::InvalidEvidence {
            sequence,
            message: format!(
                "backend returned {} wire bytes that differ from the {} submitted bytes",
                wire_bytes.len(),
                frame.bytes.len()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::io::CaptureWriter;

    #[derive(Default)]
    struct Allow {
        calls: usize,
        deny: bool,
    }

    impl ReplayAuthorizer for Allow {
        fn authorize(
            &mut self,
            _frame: &CapturedFrame,
            _mode: LinkMode,
        ) -> Result<(), ReplayAuthorizationError> {
            self.calls += 1;
            if self.deny {
                Err(ReplayAuthorizationError::new(
                    "denied by test policy",
                    ErrorClassification::new("policy.test", FailureKind::Policy, None),
                    Vec::new(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct Transmitter {
        calls: usize,
        partial: bool,
        omit_evidence: bool,
    }

    impl ReplayTransmitter for Transmitter {
        fn validate_interface(
            &mut self,
            interface: &InterfaceId,
            _mode: LinkMode,
            _frame: &CapturedFrame,
        ) -> Result<InterfaceId, LiveIoError> {
            Ok(interface.clone())
        }

        fn transmit(
            &mut self,
            _interface: &InterfaceId,
            _mode: LinkMode,
            frame: &CapturedFrame,
        ) -> Result<ReplayTransmission, LiveIoError> {
            self.calls += 1;
            Ok(ReplayTransmission {
                interface: _interface.clone(),
                report: IoSendReport {
                    bytes_sent: if self.partial {
                        frame.bytes.len().saturating_sub(1)
                    } else {
                        frame.bytes.len()
                    },
                    wire_bytes: (!self.omit_evidence).then(|| frame.bytes.clone()),
                },
            })
        }
    }

    #[derive(Default)]
    struct Clock(Vec<Duration>);

    impl ReplayClock for Clock {
        type Error = Infallible;

        fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.0.push(delay);
            Ok(())
        }
    }

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        }
    }

    fn capture(
        link_type: LinkType,
        frames: &[(Duration, &[u8])],
    ) -> CaptureReader<Cursor<Vec<u8>>> {
        let mut writer = CaptureWriter::pcap(Vec::new(), link_type).unwrap();
        for (timestamp, bytes) in frames {
            writer
                .write_frame(
                    &CapturedFrame::new(UNIX_EPOCH + *timestamp, link_type, bytes.to_vec())
                        .unwrap(),
                )
                .unwrap();
        }
        CaptureReader::new(Cursor::new(writer.into_inner())).unwrap()
    }

    fn options(timing: ReplayTiming) -> ReplayOptions {
        ReplayOptions {
            interface: interface(),
            link_mode: LinkMode::Auto,
            timing,
            limits: ReplayLimits::default(),
        }
    }

    #[test]
    fn replay_is_streaming_timed_and_exact() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[
                (Duration::from_secs(1), &[1, 2]),
                (Duration::from_millis(1_250), &[3, 4, 5]),
            ],
        );
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let mut evidence = Vec::new();
        let summary = replay_capture(
            &mut reader,
            &options(ReplayTiming::Scaled(2.0)),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |event| {
                evidence.push(event);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(clock.0, [Duration::ZERO, Duration::from_millis(500)]);
        assert_eq!(authorizer.calls, 2);
        assert_eq!(transmitter.calls, 2);
        assert_eq!(summary.frames_attempted, 2);
        assert_eq!(summary.frames_completed, 2);
        assert_eq!(summary.bytes_completed, 5);
        assert_eq!(summary.scheduled_duration, Duration::from_millis(500));
        assert_eq!(evidence[1].frame.bytes, Bytes::from_static(&[3, 4, 5]));
        assert_eq!(evidence[1].link_mode, LinkMode::Layer2);
    }

    #[test]
    fn policy_denial_precedes_delay_and_transmission() {
        let mut reader = capture(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
        let mut authorizer = Allow {
            deny: true,
            ..Allow::default()
        };
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ReplayError::Authorization { sequence: 0, .. }
        ));
        assert_eq!(error.classification().code, "policy.test");
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 0);
        assert!(clock.0.is_empty());
    }

    #[test]
    fn unsupported_roots_and_explicit_mode_mismatches_are_typed() {
        for (link_type, requested, expected_code) in [
            (
                LinkType::NULL,
                LinkMode::Auto,
                "capability.replay_link_type",
            ),
            (
                LinkType::ETHERNET,
                LinkMode::Layer3,
                "capability.replay_link_type",
            ),
        ] {
            let mut reader = capture(link_type, &[(Duration::ZERO, &[1])]);
            let mut request = options(ReplayTiming::Immediate);
            request.link_mode = requested;
            let mut authorizer = Allow::default();
            let mut transmitter = Transmitter::default();
            let mut clock = Clock::default();
            let error = replay_capture(
                &mut reader,
                &request,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |_| Ok(()),
            )
            .unwrap_err();
            assert_eq!(error.classification().code, expected_code);
            assert_eq!(authorizer.calls, 0);
            assert_eq!(transmitter.calls, 0);
        }

        let mut writer = CaptureWriter::pcapng(Vec::new()).unwrap();
        let ethernet = writer.add_interface(LinkType::ETHERNET).unwrap();
        let null = writer.add_interface(LinkType::NULL).unwrap();
        let mut first = CapturedFrame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap();
        first.interface = Some(ethernet);
        let mut second = CapturedFrame::new(UNIX_EPOCH, LinkType::NULL, vec![2]).unwrap();
        second.interface = Some(null);
        writer.write_frame(&first).unwrap();
        writer.write_frame(&second).unwrap();
        let mut reader = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.sequence(), Some(1));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
    }

    #[test]
    fn aggregate_limits_use_checked_arithmetic_before_the_next_send() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
        );
        let mut request = options(ReplayTiming::Immediate);
        request.limits.max_frames = 1;
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &request,
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReplayError::FrameLimit {
                sequence: 1,
                actual: 2,
                limit: 1
            }
        ));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);

        let mut reader = capture(
            LinkType::ETHERNET,
            &[(Duration::ZERO, &[1, 2]), (Duration::ZERO, &[3])],
        );
        let mut request = options(ReplayTiming::Immediate);
        request.limits.max_bytes = 2;
        request.limits.max_frame_bytes = 2;
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &request,
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReplayError::ByteLimit {
                sequence: 1,
                actual: 3,
                limit: 2
            }
        ));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
    }

    #[test]
    fn replay_duration_limit_precedes_policy_clock_and_next_send() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[
                (Duration::ZERO, &[1]),
                (MAX_REPLAY_DURATION + Duration::from_millis(1), &[2]),
            ],
        );
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Original),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, ReplayError::DurationLimit { .. }));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
        assert_eq!(clock.0, [Duration::ZERO]);
    }

    #[test]
    fn partial_send_and_missing_wire_evidence_are_failures() {
        for transmitter in [
            Transmitter {
                partial: true,
                ..Transmitter::default()
            },
            Transmitter {
                omit_evidence: true,
                ..Transmitter::default()
            },
        ] {
            let mut reader = capture(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
            let mut authorizer = Allow::default();
            let mut transmitter = transmitter;
            let mut clock = Clock::default();
            let error = replay_capture(
                &mut reader,
                &options(ReplayTiming::Immediate),
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |_| Ok(()),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                ReplayError::Transmission { .. } | ReplayError::InvalidEvidence { .. }
            ));
        }
    }

    #[test]
    fn malformed_tail_is_not_clean_end_of_stream() {
        let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer
            .write_frame(
                &CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap(),
            )
            .unwrap();
        let mut bytes = writer.into_inner();
        bytes.extend_from_slice(&[0_u8; 8]);
        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, ReplayError::Capture { sequence: 1, .. }));
    }
}
