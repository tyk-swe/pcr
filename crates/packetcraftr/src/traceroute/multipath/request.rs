// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::MAX_FLOWS;
use crate::engine::execution::rate_delay;
use crate::probe::{check_probe_count, check_probe_duration};
use crate::traceroute::{Error, MAX_PROBES_PER_HOP, error::probe_error, request::check_collection};

#[derive(Clone, Debug)]
pub struct Request {
    /// `probes_per_hop` counts complete sweeps in this mode. Payload size is
    /// padding in addition to the mandatory correlation payload.
    pub trace: crate::traceroute::Request,
    pub flows: u16,
}

impl Request {
    pub fn validate(&self) -> Result<(), Error> {
        // Attempts are sweeps, not the number of responses in a hop batch.
        let mut trace = self.trace.clone();
        trace.probes_per_hop = 1;
        trace.validate()?;
        if !(1..=MAX_PROBES_PER_HOP).contains(&self.trace.probes_per_hop) {
            return Err(Error::InvalidLimit {
                field: "attempts",
                value: self.trace.probes_per_hop.into(),
                reason: format!("must be within 1..={MAX_PROBES_PER_HOP}"),
            });
        }
        if !(1..=MAX_FLOWS).contains(&self.flows) {
            return Err(Error::InvalidLimit {
                field: "flows",
                value: u64::from(self.flows),
                reason: format!("must be within 1..={MAX_FLOWS}"),
            });
        }
        if self
            .trace
            .source_port
            .is_some_and(|base| base.checked_add(self.flows - 1).is_none())
        {
            return Err(Error::InvalidProbeOption {
                option: "source_port",
                reason: "the source port range for all flows exceeds 65535".to_owned(),
            });
        }
        check_collection(
            &self.trace.collection,
            &self.trace.limits,
            u32::from(self.flows),
        )?;
        check_probe_count(
            probe_error,
            self.probe_count(),
            self.trace.limits.max_probes,
        )?;
        let windows = self.trace.hop_count() as u32 * self.trace.probes_per_hop;
        let delay = rate_delay(
            probe_error,
            "probes_per_second",
            usize::from(self.flows),
            self.trace.probes_per_second,
        )?;
        let duration = self
            .trace
            .timeout
            .checked_mul(windows)
            .and_then(|time| {
                delay
                    .checked_mul(windows.saturating_sub(1))
                    .and_then(|paced| time.checked_add(paced))
            })
            .ok_or(Error::DurationLimit {
                actual: std::time::Duration::MAX,
                limit: self.trace.limits.max_duration,
            })?;
        check_probe_duration(probe_error, duration, self.trace.limits.max_duration)
    }

    pub fn probe_count(&self) -> usize {
        // Saturation also makes this safe before validate() checks hop ordering.
        usize::from(self.trace.max_hops.saturating_sub(self.trace.first_hop))
            .saturating_add(1)
            .saturating_mul(self.trace.probes_per_hop as usize)
            .saturating_mul(usize::from(self.flows))
    }
}
