// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use packetcraftr_net::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};
use packetcraftr_packet::template::DEFAULT_MAX_TEMPLATE_PACKETS;

use crate::AddressFamily;
use crate::target::Target;

use super::super::error::ScanError;
use super::super::{
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES, DEFAULT_SCAN_BATCH_SIZE,
    MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTransport {
    Tcp,
    Udp,
    Icmp,
}

impl ScanTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }

    pub(in crate::scan) const fn probe_transport(self) -> crate::probe::Transport {
        match self {
            Self::Tcp => crate::probe::Transport::Tcp,
            Self::Udp => crate::probe::Transport::Udp,
            Self::Icmp => crate::probe::Transport::Icmp,
        }
    }
}

impl fmt::Display for ScanTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanLimits {
    pub max_ports: usize,
    pub max_probes: usize,
    pub batch_size: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_ports: DEFAULT_MAX_SCAN_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            batch_size: DEFAULT_SCAN_BATCH_SIZE,
            max_duration: MAX_SCAN_DURATION,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_SCAN_FRAMES,
        }
    }
}

impl ScanLimits {
    pub fn validate(self) -> std::result::Result<Self, ScanError> {
        for (field, value, maximum) in [
            ("max_ports", self.max_ports, u16::MAX as usize + 1),
            ("max_probes", self.max_probes, MAX_SCAN_PROBES),
            ("batch_size", self.batch_size, MAX_SCAN_PROBES),
            (
                "max_evidence_frames",
                self.max_evidence_frames,
                DEFAULT_CAPTURE_QUEUE_FRAMES,
            ),
            (
                "max_evidence_bytes",
                self.max_evidence_bytes,
                DEFAULT_CAPTURE_QUEUE_BYTES,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(ScanError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.batch_size > self.max_probes {
            return Err(ScanError::InvalidLimit {
                field: "batch_size",
                value: self.batch_size as u64,
                reason: "cannot exceed max_probes".to_owned(),
            });
        }
        if self.batch_size > self.max_evidence_frames {
            return Err(ScanError::InvalidLimit {
                field: "batch_size",
                value: self.batch_size as u64,
                reason:
                    "cannot exceed max_evidence_frames because every probe may receive a response"
                        .to_owned(),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(ScanError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_SCAN_DURATION {
            return Err(ScanError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_SCAN_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: Target,
    pub transport: ScanTransport,
    pub address_family: AddressFamily,
    /// TCP or UDP destination ports. ICMP scans require this to be empty and
    /// produce one portless endpoint per selected address.
    pub ports: Vec<u16>,
    pub attempts: u32,
    pub timeout: Duration,
    /// Maximum average probe rate. Batches are deliberate bursts and the
    /// clock spaces their start times by the preceding batch's probe count.
    pub probes_per_second: Option<u32>,
    pub limits: ScanLimits,
}

impl ScanRequest {
    pub(in crate::scan) fn validate(&self) -> std::result::Result<Vec<u16>, ScanError> {
        self.limits.validate()?;
        if !(1..=MAX_SCAN_ATTEMPTS).contains(&self.attempts) {
            return Err(ScanError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_SCAN_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > packetcraftr_net::capture::MAX_TIMEOUT {
            return Err(ScanError::InvalidTimeout {
                value: self.timeout,
                maximum: packetcraftr_net::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.probes_per_second
            && (rate == 0 || rate > MAX_SCAN_RATE)
        {
            return Err(ScanError::InvalidLimit {
                field: "probes_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_SCAN_RATE}"),
            });
        }
        match self.transport {
            ScanTransport::Tcp | ScanTransport::Udp if self.ports.is_empty() => {
                return Err(ScanError::InvalidPorts {
                    message: "TCP and UDP scans require at least one destination port".to_owned(),
                });
            }
            ScanTransport::Icmp if !self.ports.is_empty() => {
                return Err(ScanError::InvalidPorts {
                    message: "ICMP scans are portless and do not accept destination ports"
                        .to_owned(),
                });
            }
            _ => {}
        }
        let mut ports = Vec::with_capacity(self.ports.len());
        let mut seen_ports = HashSet::with_capacity(self.ports.len());
        for port in &self.ports {
            if seen_ports.insert(*port) {
                ports.push(*port);
            }
        }
        if ports.len() > self.limits.max_ports {
            return Err(ScanError::InvalidLimit {
                field: "ports",
                value: ports.len() as u64,
                reason: format!("exceeds max_ports={}", self.limits.max_ports),
            });
        }
        Ok(ports)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use packetcraftr_net::capture::{DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES};

    use super::{ScanLimits, ScanRequest, ScanTransport};
    use crate::AddressFamily;
    use crate::probe::Transport as ProbeTransport;
    use crate::scan::error::ScanError;
    use crate::scan::{MAX_SCAN_ATTEMPTS, MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE};
    use crate::target::Target;

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
            (ScanTransport::Tcp, "tcp", ProbeTransport::Tcp),
            (ScanTransport::Udp, "udp", ProbeTransport::Udp),
            (ScanTransport::Icmp, "icmp", ProbeTransport::Icmp),
        ] {
            assert_eq!(transport.as_str(), name);
            assert_eq!(transport.to_string(), name);
            assert_eq!(transport.probe_transport(), probe);
        }
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
                max_ports: usize::from(u16::MAX) + 2,
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
}
