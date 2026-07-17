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

    pub(super) const fn probe_transport(self) -> crate::workflow::probe::Transport {
        match self {
            Self::Tcp => crate::workflow::probe::Transport::Tcp,
            Self::Udp => crate::workflow::probe::Transport::Udp,
            Self::Icmp => crate::workflow::probe::Transport::Icmp,
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
    pub fn validate(self) -> Result<Self, ScanError> {
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
    pub(super) fn validate(&self) -> Result<Vec<u16>, ScanError> {
        self.limits.validate()?;
        if !(1..=MAX_SCAN_ATTEMPTS).contains(&self.attempts) {
            return Err(ScanError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_SCAN_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > crate::net::capture::MAX_TIMEOUT {
            return Err(ScanError::InvalidTimeout {
                value: self.timeout,
                maximum: crate::net::capture::MAX_TIMEOUT,
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
        for port in &self.ports {
            if !ports.contains(port) {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanClassification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
    Timeout,
}

impl ScanClassification {
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::Open => 6,
            Self::Closed => 5,
            Self::Filtered => 4,
            Self::Unreachable => 3,
            Self::Unknown => 2,
            Self::Timeout => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct ScanProbeEvidence {
    pub attempt: u32,
    pub status: ScanProbeStatus,
    pub classification: ScanClassification,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ScanEndpointResult {
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub classification: ScanClassification,
    pub evidence: Vec<ScanProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<ScanEndpointResult>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub attempt: u32,
}

impl ScanProbe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        super::engine::probe_packet(self)
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
    ) -> Result<ScanBatchExecution, crate::workflow::BoundaryError>;
}
use super::{
    AddressFamily, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    DEFAULT_MAX_SCAN_PORTS, DEFAULT_MAX_TEMPLATE_PACKETS, DEFAULT_MAX_UNDECODED_SCAN_FRAMES,
    DEFAULT_SCAN_BATCH_SIZE, DecodedPacket, Diagnostic, Duration, Frame, IpAddr, MAX_SCAN_ATTEMPTS,
    MAX_SCAN_DURATION, MAX_SCAN_PROBES, MAX_SCAN_RATE, Packet, ScanError, Serialize, Stats,
    SystemTime, Target, fmt,
};
use serde::Deserialize;
