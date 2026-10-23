// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Finite, flow-preserving traceroute sweeps. Adjacencies are observations
//! from separate probes, not proof of physical links or exhaustive ECMP discovery.

mod engine;
mod packet;
mod report;
#[cfg(test)]
mod tests;
mod topology;

pub use report::{
    Aggregate, Change, Collector, Edge, Event, Flow, FlowCompletion, FlowSummary, Node, NodeKey,
    ProbeEvidence, Reply, Report, Rtt, Summary, TopologyUpdate,
};
pub const DEFAULT_FLOWS: u16 = 16;
pub const MAX_FLOWS: u16 = 64;

#[derive(Clone, Debug)]
pub struct Request {
    /// `probes_per_hop` counts complete sweeps in this mode. Payload size is
    /// padding in addition to the mandatory correlation payload.
    pub trace: super::Request,
    pub flows: u16,
}

impl Request {
    pub fn validate(&self) -> Result<(), super::Error> {
        // Attempts are sweeps, not the number of responses in a hop batch.
        let mut trace = self.trace.clone();
        trace.probes_per_hop = 1;
        trace.validate()?;
        if !(1..=super::MAX_PROBES_PER_HOP).contains(&self.trace.probes_per_hop) {
            return Err(super::Error::InvalidLimit {
                field: "attempts",
                value: self.trace.probes_per_hop.into(),
                reason: format!("must be within 1..={}", super::MAX_PROBES_PER_HOP),
            });
        }
        if !(1..=MAX_FLOWS).contains(&self.flows) {
            return Err(super::Error::InvalidLimit {
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
            return Err(super::Error::InvalidProbeOption {
                option: "source_port",
                reason: "the source port range for all flows exceeds 65535".to_owned(),
            });
        }
        super::request::check_collection(
            &self.trace.collection,
            &self.trace.limits,
            u32::from(self.flows),
        )?;
        crate::probe::check_probe_count(
            super::error::probe_error,
            self.probe_count(),
            self.trace.limits.max_probes,
        )?;
        let windows = self.trace.hop_count() as u32 * self.trace.probes_per_hop;
        let delay = crate::engine::execution::rate_delay(
            super::error::probe_error,
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
            .ok_or(super::Error::DurationLimit {
                actual: std::time::Duration::MAX,
                limit: self.trace.limits.max_duration,
            })?;
        crate::probe::check_probe_duration(
            super::error::probe_error,
            duration,
            self.trace.limits.max_duration,
        )
    }

    pub fn probe_count(&self) -> usize {
        // Saturation also makes this safe before validate() checks hop ordering.
        usize::from(self.trace.max_hops.saturating_sub(self.trace.first_hop))
            .saturating_add(1)
            .saturating_mul(self.trace.probes_per_hop as usize)
            .saturating_mul(usize::from(self.flows))
    }
}
