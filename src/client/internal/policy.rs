#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficPolicy {
    pub allow_public_destinations: bool,
    /// Hostname resolution is a separate opt-in because a name has no stable
    /// address scope until after a resolver side effect.
    pub allow_hostname_resolution: bool,
    pub allow_permissive_packets: bool,
    pub max_packets_per_operation: u64,
    pub max_bytes_per_operation: u64,
    pub max_resolved_addresses: usize,
}

pub const DEFAULT_MAX_RESOLVED_ADDRESSES: usize = 64;
pub const MAX_RESOLVED_ADDRESSES: usize = 4_096;

impl Default for TrafficPolicy {
    fn default() -> Self {
        Self {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            allow_permissive_packets: false,
            max_packets_per_operation: 10_000,
            max_bytes_per_operation: 256 * 1024 * 1024,
            max_resolved_addresses: DEFAULT_MAX_RESOLVED_ADDRESSES,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficPolicyError {
    #[error("traffic policy denies public destination {destination}")]
    PublicDestination { destination: IpAddr },
    #[error("traffic policy cannot authorize {reason}")]
    InvalidIpv4Options { reason: String },
    #[error("traffic policy denies hostname resolution for {hostname}")]
    HostnameResolution { hostname: String },
    #[error("traffic policy denies permissively built packets")]
    PermissivePacket,
    #[error("operation packet count {actual} exceeds policy limit {limit}")]
    PacketLimit { actual: u64, limit: u64 },
    #[error("operation byte count {actual} exceeds policy limit {limit}")]
    ByteLimit { actual: u64, limit: u64 },
}

impl Classified for TrafficPolicyError {
    fn classification(&self) -> Classification {
        let (code, remediation) = match self {
            Self::PublicDestination { .. } => (
                "policy.public_destination",
                "explicitly authorize public destinations only for networks you are permitted to test",
            ),
            Self::InvalidIpv4Options { .. } => (
                "policy.invalid_ipv4_options",
                "repair malformed IPv4 source-route options before live transmission",
            ),
            Self::HostnameResolution { .. } => (
                "policy.hostname_resolution",
                "explicitly authorize hostname resolution, then independently authorize every resolved address",
            ),
            Self::PermissivePacket => (
                "policy.permissive_packet",
                "authorize permissive live traffic in both build options and traffic policy",
            ),
            Self::PacketLimit { .. } => (
                "policy.packet_limit",
                "reduce the operation packet count or deliberately raise the configured traffic budget",
            ),
            Self::ByteLimit { .. } => (
                "policy.byte_limit",
                "reduce the operation byte count or deliberately raise the configured traffic budget",
            ),
        };
        Classification::new(code, Kind::Policy, Some(remediation))
    }
}
