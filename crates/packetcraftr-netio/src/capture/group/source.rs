// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{MAX_INTERFACE_NAME_BYTES, Phase, Source};
use crate::capture::{Captured, Metadata, Request, Session, Stats};
use crate::{Error, interface::Id};
use packetcraftr_core::budget::Deadline;
use std::time::Instant;

pub(super) struct Owned<C: Session> {
    capture: C,
    pub(super) source: Source,
    shutdown_attempted: bool,
}

impl<C: Session> Owned<C> {
    pub(super) fn new(index: usize, request: &Request, capture: C) -> Self {
        let metadata = capture.metadata();
        let native = &metadata.native;
        let valid = capture.source_count() == 1
            && metadata.interface == request.interface
            && metadata.snap_length > 0
            && metadata.snap_length <= request.limits.snap_length
            && native
                .buffer_size
                .consistent_with(request.native.buffer_size)
            && native
                .timestamp_source
                .consistent_with(request.native.timestamp_source)
            && native
                .timestamp_precision
                .consistent_with(request.native.timestamp_precision);
        // Keep reported identity even on a contract failure, while bounding
        // an injected provider's invalid name before copying it.
        let reported_name = if metadata.interface.name.len() > MAX_INTERFACE_NAME_BYTES {
            format!(
                "{}... [truncated]",
                metadata
                    .interface
                    .name
                    .chars()
                    .take(512)
                    .collect::<String>()
            )
        } else {
            metadata.interface.name.clone()
        };
        let metadata = Metadata {
            interface: Id {
                index: metadata.interface.index,
                name: reported_name,
            },
            link_type: metadata.link_type,
            snap_length: metadata.snap_length,
            native: metadata.native,
        };
        let limits = request.limits;
        Self {
            capture,
            source: Source {
                index,
                metadata,
                limits,
                metadata_valid: valid,
                ready: false,
                shutdown_confirmed: false,
                statistics_valid: false,
                statistics: Stats::default(),
                delivered_frames: 0,
                delivered_bytes: 0,
            },
            shutdown_attempted: false,
        }
    }

    pub(super) fn snapshot(&self) -> Source {
        let mut source = self.source.clone();
        if !self.shutdown_attempted {
            source.statistics = self.capture.stats();
            source.statistics_valid = source.statistics.validate().is_ok();
        }
        source
    }

    pub(super) fn wait_ready(&mut self, caller: &Deadline, deadline: Instant) -> Result<(), Error> {
        caller.check_cancelled()?;
        if crate::deadline::remaining_before(deadline).is_none() {
            return Err(self.failure(
                Phase::Ready,
                Error::CaptureReadiness {
                    message: "shared capture readiness deadline expired".to_owned(),
                },
            ));
        }
        self.capture
            .wait_ready(caller)
            .map_err(|source| self.failure(Phase::Ready, source))?;
        if Instant::now() > deadline {
            return Err(self.failure(
                Phase::Ready,
                Error::CaptureReadiness {
                    message: "provider exceeded shared readiness timeout".to_owned(),
                },
            ));
        }
        self.source.ready = true;
        Ok(())
    }

    pub(super) fn poll(
        &mut self,
        wait: &Deadline,
        caller: &Deadline,
    ) -> Result<Option<Captured>, Error> {
        let index = self.source.index;
        let Some(mut captured) = self
            .capture
            .next_captured_frame(wait)
            .map_err(|source| self.failure(Phase::Receive, source))?
        else {
            return Ok(None);
        };
        caller.check_cancelled()?;
        let source = &mut self.source;
        if captured.frame.link_type != source.metadata.link_type
            || captured.frame.bytes().len() > source.metadata.snap_length
            || captured
                .frame
                .interface
                .is_some_and(|interface| interface != source.metadata.interface.index)
        {
            return Err(Error::CaptureSourceContract {
                index,
                reason: "captured frame disagrees with activated source metadata",
            });
        }
        let (Some(frames), Some(bytes)) = (
            source.delivered_frames.checked_add(1),
            source
                .delivered_bytes
                .checked_add(u64::from(captured.frame.captured_length())),
        ) else {
            return Err(Error::CaptureSourceContract {
                index,
                reason: "delivery counters overflowed",
            });
        };
        source.delivered_frames = frames;
        source.delivered_bytes = bytes;
        captured.source = index;
        Ok(Some(captured))
    }

    pub(super) fn shutdown(&mut self, cleanup: &mut Vec<Error>) {
        if self.shutdown_attempted {
            return;
        }
        self.shutdown_attempted = true;
        match self.capture.shutdown() {
            Ok(()) => self.source.shutdown_confirmed = true,
            Err(source) => cleanup.push(self.failure(Phase::Shutdown, source)),
        }
        self.source.statistics = self.capture.stats();
        match self.source.statistics.validate() {
            Ok(()) => self.source.statistics_valid = true,
            Err(source) => cleanup.push(self.failure(Phase::Stats, source)),
        }
    }

    fn failure(&self, phase: Phase, source: Error) -> Error {
        Error::CaptureSource {
            index: self.source.index,
            interface: self.source.metadata.interface.clone(),
            phase,
            source: Box::new(source),
        }
    }
}
