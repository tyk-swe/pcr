// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The capture contract: a [`Provider`] arms an owned [`Session`] for one
//! interface, and the native [`SystemProvider`] does so through the backend
//! compiled in for this target.
//!
//! A [`Session`] reads one or more sources. A provider arms a single-interface
//! session; a [`Group`] composes up to [`MAX_SOURCES`] of them into one
//! session, and each [`Captured`] record names the source that delivered it.
//! Queue limits are in [`Limits`], native driver settings in
//! [`NativeSettings`] and what the backend made of them in
//! [`RealizedSettings`].

#[cfg(native_layer2)]
mod activation;
#[cfg(native_layer2)]
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

/// Longest native capture filter, in bytes, that a single session or a group
/// accepts.
pub const MAX_FILTER_BYTES: usize = 64 * 1024;

/// Owned capture session: arm through [`Provider`] (or compose a [`Group`]),
/// pass [`Session::wait_ready`] before transmission, read records, then call
/// [`Session::shutdown`] to join every backend. Stats are final only
/// after successful shutdown.
///
/// A session reads [`Session::source_count`] sources, numbered from zero; a
/// provider's single-interface session has exactly one. Every record carries
/// its source number in [`Captured::source`].
///
/// Waits follow the [deadline convention](crate::deadline): they end at the
/// caller's deadline and stop with [`Error::Cancelled`] once its cancellation
/// is signaled. Shutdown keeps its own bounded lifecycle so cleanup still runs
/// after cancellation.
pub trait Session: Send {
    /// Returns the backend-confirmed properties fixed when the session was
    /// activated. A multi-source session reports its first source here.
    fn metadata(&self) -> &Metadata;
    /// Number of activated sources.
    fn source_count(&self) -> usize {
        1
    }
    /// Activation metadata of `source`, the number a record carries in
    /// [`Captured::source`]; `None` outside `0..source_count()`.
    fn source_metadata(&self, source: usize) -> Option<&Metadata> {
        (source == 0).then(|| self.metadata())
    }
    /// Readiness is an explicit barrier. No exchange frame may be sent first.
    /// A session not ready by `deadline` fails.
    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), Error>;
    /// Waits until `deadline` for a record. `Ok(None)` means no record was
    /// delivered during this wait, not that none was captured or that the
    /// session ended. A spent deadline waits for nothing: it delivers a record
    /// that is already queued, or `Ok(None)`. Only [`Session::shutdown`] ends
    /// the session; [`Session::stats`] reports loss.
    fn next_captured_frame(&mut self, deadline: &Deadline) -> Result<Option<Captured>, Error>;
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
    /// Returns cumulative counters, including undelivered queue loss, summed
    /// over every source.
    fn stats(&self) -> Stats;
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

    fn shutdown(&mut self) -> Result<(), Error> {
        (**self).shutdown()
    }

    fn stats(&self) -> Stats {
        (**self).stats()
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

impl Request {
    /// Checks everything that needs no interface: queue limits, native
    /// settings, and the [`MAX_FILTER_BYTES`] filter limit.
    pub fn validate(&self) -> Result<(), Error> {
        validate_filter_length(self.filter.as_deref())?;
        self.limits.validate()?;
        self.native.validate(&self.limits)
    }
}

/// The filter-size limit single sessions and groups share.
fn validate_filter_length(filter: Option<&str>) -> Result<(), Error> {
    match filter {
        Some(filter) if filter.len() > MAX_FILTER_BYTES => Err(Error::CaptureFilterTooLong {
            length: filter.len(),
            maximum: MAX_FILTER_BYTES,
        }),
        _ => Ok(()),
    }
}

/// The instant a capture wait ends: `None` once the caller's deadline is
/// spent, so the wait takes only what is already queued. A remainder above
/// [`deadline::MAX_WAIT`](crate::deadline::MAX_WAIT) is refused as
/// [`Error::InvalidCaptureTimeout`] rather than clipped, and a signaled
/// cancellation stops the wait. Single sessions and groups share this rule.
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

/// Backend-confirmed properties of an activated capture session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub interface: InterfaceId,
    pub link_type: LinkType,
    pub snap_length: usize,
    /// What the backend made of the session's [`NativeSettings`].
    pub native: RealizedSettings,
}

/// Starts an owned capture stream using platform-neutral interface data.
pub trait Provider: Send + Sync {
    type Capture: Session;

    /// Arms and activates one session, following the
    /// [deadline convention](crate::deadline).
    fn arm_capture(&self, request: &Request, deadline: &Deadline) -> Result<Self::Capture, Error>;

    /// The packet timestamp types this provider's backend advertises for
    /// `interface`, in backend order. Providers without native timestamp-type
    /// discovery reject with [`Error::Unsupported`]. Discovery follows the
    /// [deadline convention](crate::deadline).
    fn timestamp_types(
        &self,
        _interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Vec<TimestampType>, Error> {
        crate::deadline::remaining(deadline).map_err(|interrupted| {
            Error::interrupted(interrupted, "discovering timestamp types")
        })?;
        Err(crate::Unsupported::new(
            crate::NativeCapability::Capture,
            "this capture provider cannot enumerate timestamp types",
        )
        .into())
    }
}

/// Platform-native capture session with private handle and worker.
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
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::deadline::MAX_WAIT;

    #[test]
    fn capture_waits_reject_timeouts_above_the_public_maximum() {
        let frozen = Instant::now();
        let fixed = |limit| Deadline::with_time_source(limit, move || frozen);
        assert!(wait_end(&fixed(MAX_WAIT)).unwrap().is_some());
        assert!(matches!(
            wait_end(&fixed(MAX_WAIT + Duration::from_nanos(1))),
            Err(Error::InvalidCaptureTimeout {
                maximum: MAX_WAIT,
                ..
            })
        ));
        assert!(wait_end(&fixed(Duration::ZERO)).unwrap().is_none());
    }
}
