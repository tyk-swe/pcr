// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{BoundaryError, Classification, Classified, Duration, Error, Kind};

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsWireError {
    #[error("DNS name is invalid: {message}")]
    InvalidName { message: String },
    #[error("DNS message is {actual} bytes; expected at least {minimum}")]
    MessageTooShort { actual: usize, minimum: usize },
    #[error("DNS message is {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
    #[error("DNS message is a query, not a response")]
    NotResponse,
    #[error("DNS opcode {opcode} is unsupported for a standard query response")]
    UnsupportedOpcode { opcode: u8 },
    #[error("DNS reserved header bits are non-zero")]
    ReservedHeaderBits,
    #[error("DNS response transaction ID {actual} does not match {expected}")]
    TransactionIdMismatch { expected: u16, actual: u16 },
    #[error("DNS response contains {actual} questions; expected exactly one")]
    QuestionCount { actual: u16 },
    #[error("DNS response question name {actual} does not match {expected}")]
    QuestionNameMismatch { expected: String, actual: String },
    #[error("DNS response question type {actual} does not match {expected}")]
    QuestionTypeMismatch { expected: u16, actual: u16 },
    #[error("DNS response question class {actual} is not IN")]
    QuestionClassMismatch { actual: u16 },
    #[error("DNS record count {actual} exceeds limit {limit}")]
    RecordLimit { actual: usize, limit: usize },
    #[error("DNS field {field} is truncated at byte {offset}")]
    TruncatedField { field: &'static str, offset: usize },
    #[error("DNS name compression pointer at byte {offset} is truncated")]
    TruncatedPointer { offset: usize },
    #[error("DNS name compression pointer {pointer} is outside the {length}-byte message")]
    PointerOutOfBounds { pointer: usize, length: usize },
    #[error("DNS name compression pointer at byte {offset} points forward to byte {pointer}")]
    ForwardPointer { offset: usize, pointer: usize },
    #[error("DNS name compression pointer loop was detected at byte {offset}")]
    PointerLoop { offset: usize },
    #[error("DNS name uses more than {limit} compression pointers")]
    PointerLimit { limit: usize },
    #[error("DNS label at byte {offset} uses a reserved length encoding")]
    ReservedLabelLength { offset: usize },
    #[error("DNS label at byte {offset} is {actual} bytes; maximum is 63")]
    LabelTooLong { offset: usize, actual: usize },
    #[error("DNS response contains more than one EDNS OPT pseudo-record")]
    DuplicateEdns,
    #[error("DNS EDNS version {version} is unsupported")]
    UnsupportedEdnsVersion { version: u8 },
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS name exceeds the 255-byte wire limit")]
    NameTooLong,
    #[error("DNS {record_type} RDATA at byte {offset} is invalid: {message}")]
    InvalidRdata {
        record_type: u16,
        offset: usize,
        message: String,
    },
    #[error("DNS TXT record exceeds {limit} string(s)")]
    TxtStringLimit { limit: usize },
    #[error("DNS TXT record exceeds {limit} aggregate byte(s)")]
    TxtByteLimit { limit: usize },
    #[error("DNS message has {remaining} trailing byte(s) after declared sections")]
    TrailingBytes { remaining: usize },
    #[error("DNS-over-TCP frame length {declared} does not match {actual} payload byte(s)")]
    TcpFrameLength { declared: usize, actual: usize },
}

impl DnsWireError {
    pub const fn is_unrelated(&self) -> bool {
        matches!(
            self,
            Self::TransactionIdMismatch { .. }
                | Self::QuestionNameMismatch { .. }
                | Self::QuestionTypeMismatch { .. }
                | Self::QuestionClassMismatch { .. }
        )
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsError {
    #[error("invalid DNS limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("DNS server port must be non-zero")]
    InvalidPort,
    #[error("DNS source port must be non-zero")]
    InvalidSourcePort,
    #[error("DNS timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("DNS duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("DNS query construction failed: {0}")]
    Query(DnsWireError),
    #[error("DNS authorization failed: {0}")]
    Authorization(#[from] BoundaryError),
    #[error("resolved DNS server has no {family} address selected")]
    AddressFamily { family: &'static str },
    #[error("DNS worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("DNS execution failed on attempt {attempt}: {source}")]
    Execution {
        attempt: u32,
        #[source]
        source: BoundaryError,
    },
    #[error("DNS retry clock failed before attempt {attempt}: {message}")]
    Clock { attempt: u32, message: String },
    #[error("DNS executor returned invalid evidence on attempt {attempt}: {message}")]
    InvalidEvidence { attempt: u32, message: String },
    #[error("DNS statistic accounting overflowed on attempt {attempt}")]
    StatisticsOverflow { attempt: u32 },
}

impl DnsError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { attempt, .. }
            | Self::Clock { attempt, .. }
            | Self::InvalidEvidence { attempt, .. }
            | Self::StatisticsOverflow { attempt } => Some(u64::from(attempt.saturating_sub(1))),
            _ => None,
        }
    }
}

impl Classified for DnsError {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort
            | Self::InvalidSourcePort
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.dns_limit",
                Kind::Cli,
                Some(
                    "use a valid query and finite non-zero DNS attempt, timeout, rate, message, record, and evidence limits",
                ),
            ),
            Self::Query(_) => Classification::new(
                "packet.dns_query",
                Kind::Packet,
                Some("use a bounded ASCII DNS name and a supported query type"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a DNS server address family returned by the authorized resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.dns_duration_limit",
                Kind::Policy,
                Some(
                    "reduce attempts, timeout, or retry delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.dns_clock",
                Kind::Io,
                Some("inspect the DNS retry timer and account for queries already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.dns_evidence",
                Kind::Internal,
                Some(
                    "treat the DNS operation as incomplete because executor evidence was inconsistent",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_error::{BoundaryError, Classification, Classified, Kind};

    use super::{DnsError, DnsWireError};
    use std::time::Duration;

    fn boundary() -> BoundaryError {
        BoundaryError::new(
            "controlled failure",
            Classification::new("io.test", Kind::Io, Some("retry safely")),
            vec!["root cause".to_owned()],
        )
    }

    #[test]
    fn dns_wire_unrelated_detection_is_exact() {
        let unrelated = [
            DnsWireError::TransactionIdMismatch {
                expected: 1,
                actual: 2,
            },
            DnsWireError::QuestionNameMismatch {
                expected: "a.test".to_owned(),
                actual: "b.test".to_owned(),
            },
            DnsWireError::QuestionTypeMismatch {
                expected: 1,
                actual: 28,
            },
            DnsWireError::QuestionClassMismatch { actual: 3 },
        ];
        for error in unrelated {
            assert!(error.is_unrelated());
            assert!(!error.to_string().is_empty());
        }
        for error in [
            DnsWireError::NotResponse,
            DnsWireError::PointerLoop { offset: 12 },
            DnsWireError::InvalidRdata {
                record_type: 1,
                offset: 12,
                message: "invalid".to_owned(),
            },
        ] {
            assert!(!error.is_unrelated());
        }
    }

    #[test]
    fn dns_error_classifications_and_sequences_cover_every_family() {
        let cases = [
            (
                DnsError::InvalidLimit {
                    field: "attempts",
                    value: 0,
                    reason: "must be non-zero".to_owned(),
                },
                "cli.dns_limit",
                Kind::Cli,
                None,
            ),
            (DnsError::InvalidPort, "cli.dns_limit", Kind::Cli, None),
            (
                DnsError::InvalidSourcePort,
                "cli.dns_limit",
                Kind::Cli,
                None,
            ),
            (
                DnsError::InvalidTimeout {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.dns_limit",
                Kind::Cli,
                None,
            ),
            (
                DnsError::InvalidDuration {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.dns_limit",
                Kind::Cli,
                None,
            ),
            (
                DnsError::Query(DnsWireError::NameTooLong),
                "packet.dns_query",
                Kind::Packet,
                None,
            ),
            (
                DnsError::AddressFamily { family: "IPv6" },
                "packet.target_address_family",
                Kind::Packet,
                None,
            ),
            (
                DnsError::DurationLimit {
                    actual: Duration::from_secs(2),
                    limit: Duration::from_secs(1),
                },
                "policy.dns_duration_limit",
                Kind::Policy,
                None,
            ),
            (
                DnsError::Clock {
                    attempt: 0,
                    message: "clock failed".to_owned(),
                },
                "io.dns_clock",
                Kind::Io,
                Some(0),
            ),
            (
                DnsError::InvalidEvidence {
                    attempt: 2,
                    message: "invalid".to_owned(),
                },
                "internal.dns_evidence",
                Kind::Internal,
                Some(1),
            ),
            (
                DnsError::StatisticsOverflow { attempt: 3 },
                "internal.dns_evidence",
                Kind::Internal,
                Some(2),
            ),
        ];

        for (error, code, kind, sequence) in cases {
            assert_eq!(error.sequence(), sequence);
            let classification = error.classification();
            assert_eq!(classification.code, code);
            assert_eq!(classification.kind, kind);
            assert!(classification.remediation.is_some());
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn dns_boundary_errors_delegate_classification_and_causes() {
        for error in [
            DnsError::Authorization(boundary()),
            DnsError::Execution {
                attempt: 7,
                source: boundary(),
            },
        ] {
            assert_eq!(error.classification().code, "io.test");
            assert_eq!(error.causes(), vec!["root cause".to_owned()]);
        }
    }
}
