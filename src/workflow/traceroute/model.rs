#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteStrategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl TracerouteStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
        }
    }

    pub(super) const fn probe_transport(self) -> ProbeTransport {
        match self {
            Self::Udp => ProbeTransport::Udp,
            Self::Icmp => ProbeTransport::Icmp,
            Self::Tcp => ProbeTransport::Tcp,
        }
    }
}

impl fmt::Display for TracerouteStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerouteLimits {
    pub max_probes: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for TracerouteLimits {
    fn default() -> Self {
        Self {
            max_probes: crate::packet::internal::DEFAULT_MAX_TEMPLATE_PACKETS,
            max_duration: MAX_TRACEROUTE_DURATION,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES,
        }
    }
}

impl TracerouteLimits {
    pub fn validate(self) -> Result<Self, TracerouteError> {
        for (field, value, maximum) in [
            ("max_probes", self.max_probes, MAX_SCAN_PROBES),
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
                return Err(TracerouteError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(TracerouteError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_TRACEROUTE_DURATION {
            return Err(TracerouteError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_TRACEROUTE_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerouteRequest {
    pub target: Target,
    pub strategy: TracerouteStrategy,
    pub address_family: AddressFamily,
    /// UDP base destination port or fixed TCP destination port. ICMP requires
    /// this to be absent.
    pub destination_port: Option<u16>,
    pub first_hop: u8,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    pub limits: TracerouteLimits,
}

impl TracerouteRequest {
    pub fn validate(&self) -> Result<(), TracerouteError> {
        self.limits.validate()?;
        if self.first_hop == 0 {
            return Err(TracerouteError::InvalidLimit {
                field: "first_hop",
                value: 0,
                reason: "must be within 1..=255".to_owned(),
            });
        }
        if self.max_hops < self.first_hop {
            return Err(TracerouteError::InvalidLimit {
                field: "max_hops",
                value: u64::from(self.max_hops),
                reason: format!("must be at least first_hop={}", self.first_hop),
            });
        }
        if !(1..=MAX_TRACEROUTE_PROBES_PER_HOP).contains(&self.probes_per_hop) {
            return Err(TracerouteError::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!("must be within 1..={MAX_TRACEROUTE_PROBES_PER_HOP}"),
            });
        }
        if self.probes_per_hop as usize > self.limits.max_evidence_frames {
            return Err(TracerouteError::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!(
                    "cannot exceed max_evidence_frames={} because every probe may receive a response",
                    self.limits.max_evidence_frames
                ),
            });
        }
        if self.timeout.is_zero() || self.timeout > crate::net::capture::MAX_TIMEOUT {
            return Err(TracerouteError::InvalidTimeout {
                value: self.timeout,
                maximum: crate::net::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.probes_per_second
            && (rate == 0 || rate > MAX_SCAN_RATE)
        {
            return Err(TracerouteError::InvalidLimit {
                field: "probes_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_SCAN_RATE}"),
            });
        }
        match (self.strategy, self.destination_port) {
            (TracerouteStrategy::Udp | TracerouteStrategy::Tcp, None) => {
                return Err(TracerouteError::InvalidPort {
                    message: "UDP and TCP traceroute require a destination port".to_owned(),
                });
            }
            (TracerouteStrategy::Icmp, Some(_)) => {
                return Err(TracerouteError::InvalidPort {
                    message: "ICMP traceroute is portless".to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn hop_count(&self) -> usize {
        usize::from(self.max_hops - self.first_hop) + 1
    }

    pub(super) fn total_probe_count(&self) -> Result<usize, TracerouteError> {
        self.hop_count()
            .checked_mul(self.probes_per_hop as usize)
            .ok_or(TracerouteError::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe-count arithmetic overflowed".to_owned(),
            })
    }
}

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
    pub(super) const fn rank(self) -> u8 {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl TracerouteProbe {
    pub fn packet(&self) -> Packet {
        super::engine::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteBatch {
    pub probes: Vec<TracerouteProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<Frame>,
    pub responses: Vec<TracerouteMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub use crate::workflow::BoundaryError as TracerouteExecutionError;

pub trait TracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError>;
}
use super::{
    AddressFamily, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES, DecodedPacket, Diagnostic, Duration, Frame, IpAddr,
    MAX_SCAN_PROBES, MAX_SCAN_RATE, MAX_TRACEROUTE_DURATION, MAX_TRACEROUTE_PROBES_PER_HOP, Packet,
    ProbeTransport, Serialize, Stats, SystemTime, Target, TracerouteError, fmt,
};
use serde::Deserialize;
