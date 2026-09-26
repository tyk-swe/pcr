// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;

use packetcraftr_core::packet::Packet;

use crate::BoundaryError;
use crate::probe::ProbeEndpoint;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub endpoint: ProbeEndpoint,
    pub attempt: u32,
    /// Shared exact UDP payload from the validated request.
    pub udp_payload: bytes::Bytes,
    pub udp_profile: Option<std::sync::Arc<super::profile::UdpProfile>>,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    #[must_use]
    pub fn packet(&self) -> Packet {
        crate::scan::plan::packet::probe_packet(self)
    }
}

impl crate::probe::runner::Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// One correlated scan probe and its admitted execution context. Scan
/// executes exactly one probe per batch.
pub type Batch = crate::probe::Batch<Probe>;

impl Batch {
    /// Plans the batch that executes `probe` alone.
    pub(super) fn single(probe: Probe, timeout: std::time::Duration) -> Self {
        Self {
            sequence: probe.sequence,
            probes: vec![probe],
            timeout,
            permit: crate::evidence::ExecutionPermit::new(),
        }
    }

    /// The batch's only probe. Scan plans every batch with exactly one, so
    /// only a batch reshaped outside the planner is rejected.
    pub(crate) fn probe(&self) -> Result<&Probe, BoundaryError> {
        match self.probes.as_slice() {
            [probe] => Ok(probe),
            _ => Err(super::executor::EXECUTOR_FAULT.invalid(format!(
                "scan batch at probe {} carries {} probes instead of one",
                self.sequence,
                self.probes.len()
            ))),
        }
    }
}
