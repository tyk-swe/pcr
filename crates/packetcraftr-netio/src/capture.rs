// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
    Direction, MAX_NATIVE_BUFFER_SIZE, MAX_TIMESTAMP_TYPES, NativeSettings, Realized,
    RealizedSettings, TimestampPrecision, TimestampSource, TimestampType,
};

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
    /// Stops and joins capture; errors leave cleanup unconfirmed.
    fn shutdown(&mut self) -> Result<(), Error>;
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
        self.limits.validate()?;
        self.native.validate(&self.limits)
    }
}

fn validate_filter_length(filter: Option<&str>) -> Result<(), Error> {
    match filter {
        Some(filter) if filter.len() > MAX_FILTER_BYTES => Err(Error::CaptureFilterTooLong {
            length: filter.len(),
            maximum: MAX_FILTER_BYTES,
        }),
        _ => Ok(()),
    }
}

fn admit(deadline: &Deadline, operation: &'static str) -> Result<(), Error> {
    crate::deadline::remaining(deadline)
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
    /// Validates all source settings before a group activates its first source.
    fn validate_capture(&self, request: &Request, _deadline: &Deadline) -> Result<(), Error> {
        request.validate()
    }

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

    fn validate_capture(&self, request: &Request, deadline: &Deadline) -> Result<(), Error> {
        system::validate_capture(request, deadline)
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
