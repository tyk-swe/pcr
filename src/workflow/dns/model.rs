#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    #[default]
    Udp,
}

impl DnsTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for DnsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryType {
    #[default]
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
}

impl DnsQueryType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Any => 255,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Cname => "cname",
            Self::Mx => "mx",
            Self::Ns => "ns",
            Self::Ptr => "ptr",
            Self::Soa => "soa",
            Self::Srv => "srv",
            Self::Txt => "txt",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for DnsQueryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
    pub max_rejected_records: usize,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
    pub max_duration: Duration,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_DNS_MESSAGE_BYTES,
            max_records: DEFAULT_MAX_DNS_RECORDS,
            max_name_pointers: DEFAULT_MAX_DNS_NAME_POINTERS,
            max_txt_strings: DEFAULT_MAX_DNS_TXT_STRINGS,
            max_txt_bytes: DEFAULT_MAX_DNS_TXT_BYTES,
            max_rejected_records: DEFAULT_MAX_REJECTED_DNS_RECORDS,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_DNS_FRAMES,
            max_duration: MAX_DNS_DURATION,
        }
    }
}

impl DnsLimits {
    pub fn validate(self) -> Result<Self, DnsError> {
        for (field, value, maximum) in [
            (
                "max_message_bytes",
                self.max_message_bytes,
                MAX_DNS_MESSAGE_BYTES,
            ),
            ("max_records", self.max_records, MAX_DNS_RECORDS),
            (
                "max_name_pointers",
                self.max_name_pointers,
                MAX_DNS_NAME_POINTERS,
            ),
            ("max_txt_strings", self.max_txt_strings, MAX_DNS_RECORDS),
            ("max_txt_bytes", self.max_txt_bytes, MAX_DNS_MESSAGE_BYTES),
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
                return Err(DnsError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_rejected_records > self.max_records {
            return Err(DnsError::InvalidLimit {
                field: "max_rejected_records",
                value: self.max_rejected_records as u64,
                reason: "cannot exceed max_records".to_owned(),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(DnsError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_DNS_DURATION {
            return Err(DnsError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DNS_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRequest {
    pub server: Target,
    pub address_family: AddressFamily,
    pub server_port: u16,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub recursion_desired: bool,
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: DnsLimits,
}

impl DnsRequest {
    pub fn validate(&self) -> Result<String, DnsError> {
        self.limits.validate()?;
        if self.server_port == 0 {
            return Err(DnsError::InvalidPort);
        }
        if self.source_port == 0 {
            return Err(DnsError::InvalidSourcePort);
        }
        if !(1..=MAX_DNS_ATTEMPTS).contains(&self.attempts) {
            return Err(DnsError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_DNS_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > crate::net::capture::MAX_TIMEOUT {
            return Err(DnsError::InvalidTimeout {
                value: self.timeout,
                maximum: crate::net::capture::MAX_TIMEOUT,
            });
        }
        if let Some(rate) = self.queries_per_second
            && (rate == 0 || rate > MAX_SCAN_RATE)
        {
            return Err(DnsError::InvalidLimit {
                field: "queries_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_SCAN_RATE}"),
            });
        }
        canonical_query_name(&self.query_name).map_err(DnsError::Query)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

/// A lossless DNS wire name. Labels retain their exact octets; DNS semantic
/// equality folds ASCII letters only, and presentation escaping is deferred
/// to [`fmt::Display`].
#[derive(Clone, Debug, Eq)]
pub struct DnsName {
    pub(super) labels: Vec<Bytes>,
}

impl DnsName {
    pub(super) fn root() -> Self {
        Self { labels: Vec::new() }
    }

    pub(super) fn from_canonical_ascii(value: &str) -> Self {
        if value == "." {
            return Self::root();
        }
        Self {
            labels: value
                .trim_end_matches('.')
                .split('.')
                .map(|label| Bytes::copy_from_slice(label.as_bytes()))
                .collect(),
        }
    }

    pub fn from_labels<I, B>(labels: I) -> Result<Self, DnsWireError>
    where
        I: IntoIterator<Item = B>,
        B: Into<Bytes>,
    {
        let labels = labels.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut wire_length = 1usize;
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsWireError::InvalidName {
                    message: "wire labels must contain 1..=63 octets".to_owned(),
                });
            }
            wire_length = wire_length
                .checked_add(label.len() + 1)
                .ok_or(DnsWireError::NameTooLong)?;
        }
        if wire_length > 255 {
            return Err(DnsWireError::NameTooLong);
        }
        Ok(Self { labels })
    }

    pub fn labels(&self) -> &[Bytes] {
        &self.labels
    }

    pub(super) fn is_root(&self) -> bool {
        self.labels.is_empty()
    }
}

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self.labels.iter().zip(&other.labels).all(|(left, right)| {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right.iter())
                        .all(|(left, right)| left.eq_ignore_ascii_case(right))
            })
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return formatter.write_str(".");
        }
        for (label_index, label) in self.labels.iter().enumerate() {
            if label_index != 0 {
                formatter.write_str(".")?;
            }
            for byte in label {
                if byte.is_ascii_graphic() && !matches!(*byte, b'.' | b'\\') {
                    formatter.write_str(&char::from(*byte).to_string())?;
                } else {
                    write!(formatter, "\\{byte:03}")?;
                }
            }
        }
        formatter.write_str(".")
    }
}

impl Serialize for DnsName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOption {
    pub code: u16,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdns {
    pub udp_payload_size: u16,
    pub extended_response_code: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub flags: u16,
    pub options: Vec<DnsEdnsOption>,
}

impl fmt::Display for DnsSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Answer => "answer",
            Self::Authority => "authority",
            Self::Additional => "additional",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DnsName),
    Mx {
        preference: u16,
        exchange: DnsName,
    },
    Ns(DnsName),
    Ptr(DnsName),
    Soa {
        primary_name_server: DnsName,
        responsible_mailbox: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    Txt(Vec<Bytes>),
    Opt(DnsEdns),
    Unknown {
        type_code: u16,
        rdata: Bytes,
    },
}

impl DnsRecordValue {
    pub const fn type_code(&self) -> u16 {
        match self {
            Self::A(_) => 1,
            Self::Ns(_) => 2,
            Self::Cname(_) => 5,
            Self::Soa { .. } => 6,
            Self::Ptr(_) => 12,
            Self::Mx { .. } => 15,
            Self::Txt(_) => 16,
            Self::Aaaa(_) => 28,
            Self::Srv { .. } => 33,
            Self::Opt(_) => DNS_TYPE_OPT,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }

    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::A(_) => "a",
            Self::Aaaa(_) => "aaaa",
            Self::Cname(_) => "cname",
            Self::Mx { .. } => "mx",
            Self::Ns(_) => "ns",
            Self::Ptr(_) => "ptr",
            Self::Soa { .. } => "soa",
            Self::Srv { .. } => "srv",
            Self::Txt(_) => "txt",
            Self::Opt(_) => "opt",
            Self::Unknown { .. } => "unknown",
        }
    }

    pub(super) fn referenced_name(&self) -> Option<&DnsName> {
        match self {
            Self::Cname(value) | Self::Ns(value) => Some(value),
            Self::Mx { exchange, .. } => Some(exchange),
            Self::Srv { target, .. } => Some(target),
            Self::A(_)
            | Self::Aaaa(_)
            | Self::Ptr(_)
            | Self::Soa { .. }
            | Self::Txt(_)
            | Self::Opt(_)
            | Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub owner: DnsName,
    pub class: u16,
    pub ttl: u32,
    pub value: DnsRecordValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRejectedRecord {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDnsResponse {
    pub transaction_id: u16,
    pub response_code: u16,
    pub edns: Option<DnsEdns>,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rejected_records: Vec<DnsRejectedRecord>,
    pub rejected_record_count: usize,
}

impl ValidatedDnsResponse {
    pub fn response_code_name(&self) -> &'static str {
        response_code_name(self.response_code)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsAttemptStatus {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

#[derive(Clone, Debug)]
pub struct DnsAttemptEvidence {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsAttemptStatus,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<Frame>,
    pub response_code: Option<u16>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct DnsUndecodedEvidence {
    pub attempt: u32,
    pub frame: Frame,
}

#[derive(Clone, Debug)]
pub struct DnsResult {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub transport: DnsTransport,
    pub outcome: DnsOutcome,
    pub response: Option<ValidatedDnsResponse>,
    pub attempts: Vec<DnsAttemptEvidence>,
    pub undecoded: Vec<DnsUndecodedEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsProbe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub query: Bytes,
}

impl DnsProbe {
    pub fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.server_address {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    destination,
                    identification: nonzero_ipv4_identification(u64::from(self.attempt)),
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    destination,
                    flow_label: u32::from(self.transaction_id),
                    ..Ipv6::default()
                });
            }
        }
        packet
            .push(Udp {
                source_port: self.source_port,
                destination_port: self.server_port,
                ..Udp::default()
            })
            .push(Raw::new(self.query.clone()));
        packet
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsExchange {
    pub probe: DnsProbe,
    pub timeout: Duration,
    pub max_responses: usize,
}

#[derive(Clone, Debug)]
pub struct DnsMatchedResponse {
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct DnsExchangeExecution {
    pub sent: Packet,
    pub sent_evidence: Frame,
    pub responses: Vec<DnsMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

pub use crate::workflow::BoundaryError as DnsExecutionError;

pub trait DnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError>;
}
use super::{
    AddressFamily, Bytes, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    DEFAULT_MAX_DNS_NAME_POINTERS, DEFAULT_MAX_DNS_RECORDS, DEFAULT_MAX_DNS_TXT_BYTES,
    DEFAULT_MAX_DNS_TXT_STRINGS, DEFAULT_MAX_REJECTED_DNS_RECORDS,
    DEFAULT_MAX_UNDECODED_DNS_FRAMES, DNS_TYPE_OPT, DecodedPacket, Diagnostic, DnsError,
    DnsWireError, Duration, Frame, IpAddr, Ipv4, Ipv4Addr, Ipv6, Ipv6Addr, MAX_DNS_ATTEMPTS,
    MAX_DNS_DURATION, MAX_DNS_MESSAGE_BYTES, MAX_DNS_NAME_POINTERS, MAX_DNS_RECORDS, MAX_SCAN_RATE,
    Packet, Raw, Serialize, Stats, SystemTime, Target, Udp, canonical_query_name, fmt,
    nonzero_ipv4_identification, response_code_name,
};
use serde::Deserialize;
