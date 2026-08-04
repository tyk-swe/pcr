// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_capture::Frame;
use packetcraftr_packet::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use crate::Stats;

use super::request::ScanTransport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub attempt: u32,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::AddressFamily;
    use crate::kernel::target::Target;

    use super::super::super::error::ScanError;
    use super::super::super::{
        MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
    };
    use super::super::request::{ScanLimits, ScanRequest, ScanTransport};
    use super::super::result::ScanClassification;
    use super::ScanProbe;
    use packetcraftr_net::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

    fn request(transport: ScanTransport, ports: Vec<u16>) -> ScanRequest {
        ScanRequest {
            target: Target::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            transport,
            address_family: AddressFamily::Any,
            ports,
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: None,
            limits: ScanLimits::default(),
        }
    }

    #[test]
    fn transports_have_stable_names_displays_and_probe_mappings() {
        for (transport, name, probe) in [
            (
                ScanTransport::Tcp,
                "tcp",
                crate::kernel::probe::Transport::Tcp,
            ),
            (
                ScanTransport::Udp,
                "udp",
                crate::kernel::probe::Transport::Udp,
            ),
            (
                ScanTransport::Icmp,
                "icmp",
                crate::kernel::probe::Transport::Icmp,
            ),
        ] {
            assert_eq!(transport.as_str(), name);
            assert_eq!(transport.to_string(), name);
            assert_eq!(transport.probe_transport(), probe);
        }
    }

    #[test]
    fn udp_retries_use_distinct_source_ports() {
        let mut probe = ScanProbe {
            sequence: 0,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            transport: ScanTransport::Udp,
            port: Some(53),
            attempt: 1,
        };
        let first = probe
            .packet()
            .get::<packetcraftr_protocol::transport::Udp>()
            .unwrap()
            .source_port;
        probe.sequence = 1;
        probe.attempt = 2;
        let second = probe
            .packet()
            .get::<packetcraftr_protocol::transport::Udp>()
            .unwrap()
            .source_port;

        assert_ne!(first, second);
    }

    #[test]
    fn scan_limits_reject_each_zero_and_above_maximum_resource() {
        let mut cases = Vec::new();
        for field in 0..5 {
            let mut limits = ScanLimits::default();
            match field {
                0 => limits.max_ports = 0,
                1 => limits.max_probes = 0,
                2 => limits.batch_size = 0,
                3 => limits.max_evidence_frames = 0,
                4 => limits.max_evidence_bytes = 0,
                _ => unreachable!(),
            }
            cases.push(limits);
        }
        cases.extend([
            ScanLimits {
                max_ports: u16::MAX as usize + 2,
                ..ScanLimits::default()
            },
            ScanLimits {
                max_probes: MAX_SCAN_PROBES + 1,
                ..ScanLimits::default()
            },
            ScanLimits {
                batch_size: MAX_SCAN_PROBES + 1,
                ..ScanLimits::default()
            },
            ScanLimits {
                max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES + 1,
                ..ScanLimits::default()
            },
            ScanLimits {
                max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES + 1,
                ..ScanLimits::default()
            },
        ]);

        for limits in cases {
            assert!(matches!(
                limits.validate(),
                Err(ScanError::InvalidLimit { .. })
            ));
        }
    }

    #[test]
    fn scan_limits_reject_inconsistent_and_invalid_duration_bounds() {
        let limits = ScanLimits {
            batch_size: 2,
            max_probes: 1,
            ..ScanLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(ScanError::InvalidLimit {
                field: "batch_size",
                ..
            })
        ));

        let limits = ScanLimits {
            batch_size: 2,
            max_evidence_frames: 1,
            ..ScanLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(ScanError::InvalidLimit {
                field: "batch_size",
                ..
            })
        ));

        let mut limits = ScanLimits::default();
        limits.max_undecoded = limits.max_evidence_frames + 1;
        assert!(matches!(
            limits.validate(),
            Err(ScanError::InvalidLimit {
                field: "max_undecoded",
                ..
            })
        ));

        for duration in [
            Duration::ZERO,
            MAX_SCAN_DURATION.saturating_add(Duration::from_nanos(1)),
        ] {
            let limits = ScanLimits {
                max_duration: duration,
                ..ScanLimits::default()
            };
            assert!(matches!(
                limits.validate(),
                Err(ScanError::InvalidDuration { .. })
            ));
        }
        assert!(ScanLimits::default().validate().is_ok());
    }

    #[test]
    fn scan_request_validates_attempt_timeout_and_rate_bounds() {
        let mut value = request(ScanTransport::Tcp, vec![80]);
        value.attempts = 0;
        assert!(matches!(
            value.validate(),
            Err(ScanError::InvalidLimit {
                field: "attempts",
                ..
            })
        ));
        value.attempts = MAX_SCAN_ATTEMPTS + 1;
        assert!(matches!(
            value.validate(),
            Err(ScanError::InvalidLimit {
                field: "attempts",
                ..
            })
        ));

        let mut value = request(ScanTransport::Tcp, vec![80]);
        value.timeout = Duration::ZERO;
        assert!(matches!(
            value.validate(),
            Err(ScanError::InvalidTimeout { .. })
        ));
        value.timeout = packetcraftr_net::capture::MAX_TIMEOUT + Duration::from_nanos(1);
        assert!(matches!(
            value.validate(),
            Err(ScanError::InvalidTimeout { .. })
        ));

        for rate in [0, MAX_SCAN_RATE + 1] {
            let mut value = request(ScanTransport::Tcp, vec![80]);
            value.probes_per_second = Some(rate);
            assert!(matches!(
                value.validate(),
                Err(ScanError::InvalidLimit {
                    field: "probes_per_second",
                    ..
                })
            ));
        }
    }

    #[test]
    fn scan_request_enforces_transport_ports_and_stable_deduplication() {
        for transport in [ScanTransport::Tcp, ScanTransport::Udp] {
            assert!(matches!(
                request(transport, Vec::new()).validate(),
                Err(ScanError::InvalidPorts { .. })
            ));
        }
        assert!(matches!(
            request(ScanTransport::Icmp, vec![1]).validate(),
            Err(ScanError::InvalidPorts { .. })
        ));
        assert_eq!(
            request(ScanTransport::Tcp, vec![443, 80, 443, 80, 53])
                .validate()
                .unwrap(),
            vec![443, 80, 53]
        );
        assert!(
            request(ScanTransport::Icmp, Vec::new())
                .validate()
                .unwrap()
                .is_empty()
        );

        let mut value = request(ScanTransport::Tcp, vec![80, 443]);
        value.limits.max_ports = 1;
        assert!(matches!(
            value.validate(),
            Err(ScanError::InvalidLimit { field: "ports", .. })
        ));
    }

    #[test]
    fn scan_classification_ranks_are_strictly_ordered() {
        assert_eq!(ScanClassification::Open.rank(), 6);
        assert_eq!(ScanClassification::Closed.rank(), 5);
        assert_eq!(ScanClassification::Filtered.rank(), 4);
        assert_eq!(ScanClassification::Unreachable.rank(), 3);
        assert_eq!(ScanClassification::Unknown.rank(), 2);
        assert_eq!(ScanClassification::Timeout.rank(), 1);
    }
}

impl ScanProbe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        super::super::engine::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanBatch {
    pub probes: Vec<ScanProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<Frame>,
    pub responses: Vec<ScanMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub trait ScanExecutor {
    fn execute(
        &mut self,
        batch: &ScanBatch,
    ) -> std::result::Result<ScanBatchExecution, crate::BoundaryError>;
}
