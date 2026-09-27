// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Request validation and the initial policy budget, before native I/O.

use super::error::failure;
use super::{Cause, Error, Report, StopReason};
use crate::{Client, Stats, clock::Clock, policy::CaptureBudget, providers::Providers};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::capture::GroupRequest;
use std::time::{Duration, Instant};

impl<P: Providers, K: Clock> Client<P, K> {
    /// Validates the request before any provider is consulted, and returns
    /// the report skeleton every later failure carries.
    pub(super) fn plan_capture(
        &self,
        request: &GroupRequest,
        window: Duration,
        started: Instant,
        deadline: &Deadline,
    ) -> Result<Report, Error> {
        let validated = request.validate();
        let report = Report {
            requested_interfaces: if validated.is_ok() {
                request.interfaces.clone()
            } else {
                Vec::new()
            },
            sources: Vec::new(),
            frames_delivered: 0,
            stats: Stats::default(),
            budget: CaptureBudget::new(&self.policy),
            stop: StopReason::Failure,
            capture_statistics_complete: false,
            diagnostics: Vec::new(),
        };
        if let Err(error) = validated {
            return Err(failure(Cause::Native(error), report, None));
        }
        if window > packetcraftr_netio::deadline::MAX_WAIT || started.checked_add(window).is_none()
        {
            return Err(failure(
                Cause::Invalid("capture window exceeds the supported range"),
                report,
                None,
            ));
        }
        if let Err(cancelled) = deadline.check_cancelled() {
            return Err(failure(Cause::Cancelled(cancelled), report, None));
        }
        Ok(report)
    }
}
