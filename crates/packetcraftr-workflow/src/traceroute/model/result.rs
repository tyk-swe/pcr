// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use packetcraftr_capture::Frame;
use packetcraftr_packet::diagnostic::Diagnostic;

use crate::Stats;

use super::request::TracerouteStrategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl TracerouteResponseKind {
    pub(in crate::traceroute) const fn rank(self) -> u8 {
        match self {
            Self::Intermediate => 1,
            Self::Unreachable => 2,
            Self::DestinationReached => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteCompletion {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct TracerouteProbeEvidence {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub status: TracerouteProbeStatus,
    pub response_kind: Option<TracerouteResponseKind>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct TracerouteHopResult {
    pub hop_limit: u8,
    pub probes: Vec<TracerouteProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct TracerouteUndecodedEvidence {
    pub hop_limit: u8,
    pub frame: Frame,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::AddressFamily;
    use crate::kernel::probe::Transport as ProbeTransport;
    use crate::kernel::target::Target;

    use super::super::super::error::TracerouteError;
    use super::super::super::{MAX_TRACEROUTE_DURATION, MAX_TRACEROUTE_PROBES_PER_HOP};
    use super::super::request::{TracerouteLimits, TracerouteRequest, TracerouteStrategy};
    use super::TracerouteResponseKind;
    use crate::scan::{MAX_SCAN_PROBES, MAX_SCAN_RATE};
    use packetcraftr_net::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

    fn request(strategy: TracerouteStrategy, destination_port: Option<u16>) -> TracerouteRequest {
        TracerouteRequest {
            target: Target::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            strategy,
            address_family: AddressFamily::Any,
            destination_port,
            first_hop: 1,
            max_hops: 3,
            probes_per_hop: 2,
            timeout: Duration::from_millis(1),
            probes_per_second: None,
            limits: TracerouteLimits::default(),
        }
    }

    #[test]
    fn strategies_have_stable_names_displays_and_probe_mappings() {
        assert_eq!(TracerouteStrategy::default(), TracerouteStrategy::Udp);
        for (strategy, name, probe) in [
            (TracerouteStrategy::Udp, "udp", ProbeTransport::Udp),
            (TracerouteStrategy::Icmp, "icmp", ProbeTransport::Icmp),
            (TracerouteStrategy::Tcp, "tcp", ProbeTransport::Tcp),
        ] {
            assert_eq!(strategy.as_str(), name);
            assert_eq!(strategy.to_string(), name);
            assert_eq!(strategy.probe_transport(), probe);
        }
    }

    #[test]
    fn traceroute_limits_reject_each_zero_and_above_maximum_resource() {
        let mut cases = Vec::new();
        for field in 0..3 {
            let mut limits = TracerouteLimits::default();
            match field {
                0 => limits.max_probes = 0,
                1 => limits.max_evidence_frames = 0,
                2 => limits.max_evidence_bytes = 0,
                _ => unreachable!(),
            }
            cases.push(limits);
        }
        cases.extend([
            TracerouteLimits {
                max_probes: MAX_SCAN_PROBES + 1,
                ..TracerouteLimits::default()
            },
            TracerouteLimits {
                max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES + 1,
                ..TracerouteLimits::default()
            },
            TracerouteLimits {
                max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES + 1,
                ..TracerouteLimits::default()
            },
        ]);
        for limits in cases {
            assert!(matches!(
                limits.validate(),
                Err(TracerouteError::InvalidLimit { .. })
            ));
        }
    }

    #[test]
    fn traceroute_limits_reject_inconsistent_and_duration_bounds() {
        let mut limits = TracerouteLimits::default();
        limits.max_undecoded = limits.max_evidence_frames + 1;
        assert!(matches!(
            limits.validate(),
            Err(TracerouteError::InvalidLimit {
                field: "max_undecoded",
                ..
            })
        ));
        for duration in [
            Duration::ZERO,
            MAX_TRACEROUTE_DURATION.saturating_add(Duration::from_nanos(1)),
        ] {
            let limits = TracerouteLimits {
                max_duration: duration,
                ..TracerouteLimits::default()
            };
            assert!(matches!(
                limits.validate(),
                Err(TracerouteError::InvalidDuration { .. })
            ));
        }
        assert!(TracerouteLimits::default().validate().is_ok());
    }

    #[test]
    fn traceroute_request_validates_hops_probes_timeout_and_rate() {
        let mut value = request(TracerouteStrategy::Udp, Some(33434));
        value.first_hop = 0;
        assert!(matches!(
            value.validate(),
            Err(TracerouteError::InvalidLimit {
                field: "first_hop",
                ..
            })
        ));
        value.first_hop = 3;
        value.max_hops = 2;
        assert!(matches!(
            value.validate(),
            Err(TracerouteError::InvalidLimit {
                field: "max_hops",
                ..
            })
        ));

        for probes in [0, MAX_TRACEROUTE_PROBES_PER_HOP + 1] {
            let mut value = request(TracerouteStrategy::Udp, Some(33434));
            value.probes_per_hop = probes;
            assert!(matches!(
                value.validate(),
                Err(TracerouteError::InvalidLimit {
                    field: "probes_per_hop",
                    ..
                })
            ));
        }
        let mut value = request(TracerouteStrategy::Udp, Some(33434));
        value.probes_per_hop = 2;
        value.limits.max_evidence_frames = 1;
        value.limits.max_undecoded = 1;
        assert!(matches!(
            value.validate(),
            Err(TracerouteError::InvalidLimit {
                field: "probes_per_hop",
                ..
            })
        ));

        let mut value = request(TracerouteStrategy::Udp, Some(33434));
        value.timeout = Duration::ZERO;
        assert!(matches!(
            value.validate(),
            Err(TracerouteError::InvalidTimeout { .. })
        ));
        value.timeout = packetcraftr_net::capture::MAX_TIMEOUT + Duration::from_nanos(1);
        assert!(matches!(
            value.validate(),
            Err(TracerouteError::InvalidTimeout { .. })
        ));

        for rate in [0, MAX_SCAN_RATE + 1] {
            let mut value = request(TracerouteStrategy::Udp, Some(33434));
            value.probes_per_second = Some(rate);
            assert!(matches!(
                value.validate(),
                Err(TracerouteError::InvalidLimit {
                    field: "probes_per_second",
                    ..
                })
            ));
        }
    }

    #[test]
    fn traceroute_request_enforces_strategy_ports_and_counts_probes() {
        for strategy in [TracerouteStrategy::Udp, TracerouteStrategy::Tcp] {
            assert!(matches!(
                request(strategy, None).validate(),
                Err(TracerouteError::InvalidPort { .. })
            ));
            assert!(matches!(
                request(strategy, Some(0)).validate(),
                Err(TracerouteError::InvalidPort { .. })
            ));
            assert!(request(strategy, Some(1)).validate().is_ok());
        }
        assert!(matches!(
            request(TracerouteStrategy::Icmp, Some(1)).validate(),
            Err(TracerouteError::InvalidPort { .. })
        ));
        let value = request(TracerouteStrategy::Icmp, None);
        assert!(value.validate().is_ok());
        assert_eq!(value.hop_count(), 3);
        assert_eq!(value.total_probe_count().unwrap(), 6);
    }

    #[test]
    fn traceroute_response_ranks_are_strictly_ordered() {
        assert_eq!(TracerouteResponseKind::Intermediate.rank(), 1);
        assert_eq!(TracerouteResponseKind::Unreachable.rank(), 2);
        assert_eq!(TracerouteResponseKind::DestinationReached.rank(), 3);
    }
}

#[derive(Clone, Debug)]
pub struct TracerouteResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hops: Vec<TracerouteHopResult>,
    pub undecoded: Vec<TracerouteUndecodedEvidence>,
    pub completion: TracerouteCompletion,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
