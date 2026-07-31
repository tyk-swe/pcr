// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_analysis::stats::{
    ConversationStat, EndpointStat, IoBucketStat, LengthBucketStat, LengthsStat, PortStat,
    ProtocolStat, ServiceResponseTimeBucketStat, ServiceResponseTimeStat, StatsReport,
    TransportKind,
};

use super::super::contract::OutputContractError;
use super::super::frame::OutputTimestamp;

/// Which statistics table a result carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsTableName {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
    ServiceResponseTime,
    Lengths,
}

impl StatsTableName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conversations => "conversations",
            Self::Endpoints => "endpoints",
            Self::Protocols => "protocols",
            Self::Ports => "ports",
            Self::Io => "io",
            Self::ServiceResponseTime => "service_response_time",
            Self::Lengths => "lengths",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsTransport {
    Tcp,
    Udp,
}

impl From<TransportKind> for StatsTransport {
    fn from(value: TransportKind) -> Self {
        match value {
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsProtocolOutput {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsConversationOutput {
    pub transport: StatsTransport,
    pub stream: u64,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub frames_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub frames_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub first_timestamp: OutputTimestamp,
    pub last_timestamp: OutputTimestamp,
    pub duration: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsEndpointOutput {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsPortOutput {
    pub transport: StatsTransport,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsIoBucketOutput {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

/// The I/O series with the bucket width it was computed under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsIoOutput {
    pub interval: Duration,
    pub buckets: Vec<StatsIoBucketOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsLengthBucketOutput {
    pub lower_bound: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper_bound: Option<u64>,
    pub frames: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsLengthsOutput {
    pub frames: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean: Option<u64>,
    pub buckets: Vec<StatsLengthBucketOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsServiceResponseTimeBucketOutput {
    pub lower_bound: Duration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upper_bound: Option<Duration>,
    pub samples: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsServiceResponseTimeOutput {
    pub transport: StatsTransport,
    pub service_port: u16,
    pub request_bursts: u64,
    pub samples: u64,
    pub unanswered_requests: u64,
    pub orphan_responses: u64,
    pub timestamp_regressions: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean: Option<Duration>,
    pub buckets: Vec<StatsServiceResponseTimeBucketOutput>,
}

/// Aggregate result of `stats`, carrying exactly the requested table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StatsCommandResult {
    pub table: StatsTableName,
    /// Frames the capture yielded, matched or not, and the frames the
    /// filter kept; the tables describe only the matched frames.
    pub frames_read: u64,
    pub frames_matched: u64,
    pub bytes_matched: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversations: Option<Vec<StatsConversationOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<StatsEndpointOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<StatsProtocolOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<StatsPortOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<StatsIoOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_response_time: Option<Vec<StatsServiceResponseTimeOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lengths: Option<StatsLengthsOutput>,
}

impl StatsCommandResult {
    /// Builds the result for one requested table from a finished report.
    pub fn try_from_report(
        table: StatsTableName,
        report: &StatsReport,
        frames_read: u64,
    ) -> Result<Self, OutputContractError> {
        let mut result = Self {
            table,
            frames_read,
            frames_matched: report.frames,
            bytes_matched: report.bytes,
            first_timestamp: convert_timestamp(report.first_timestamp)?,
            last_timestamp: convert_timestamp(report.last_timestamp)?,
            conversations: None,
            endpoints: None,
            protocols: None,
            ports: None,
            io: None,
            service_response_time: None,
            lengths: None,
        };
        match table {
            StatsTableName::Conversations => {
                result.conversations = Some(
                    report
                        .conversations
                        .iter()
                        .map(convert_conversation)
                        .collect::<Result<_, _>>()?,
                );
            }
            StatsTableName::Endpoints => {
                result.endpoints = Some(report.endpoints.iter().map(convert_endpoint).collect());
            }
            StatsTableName::Protocols => {
                result.protocols = Some(report.protocols.iter().map(convert_protocol).collect());
            }
            StatsTableName::Ports => {
                result.ports = Some(report.ports.iter().map(convert_port).collect());
            }
            StatsTableName::Io => {
                result.io = Some(StatsIoOutput {
                    interval: report.interval,
                    buckets: report.io.iter().map(convert_bucket).collect(),
                });
            }
            StatsTableName::ServiceResponseTime => {
                result.service_response_time = Some(
                    report
                        .service_response_time
                        .iter()
                        .map(convert_service_response_time)
                        .collect(),
                );
            }
            StatsTableName::Lengths => {
                result.lengths = Some(convert_lengths(&report.lengths));
            }
        }
        Ok(result)
    }
}

fn convert_timestamp(
    value: Option<std::time::SystemTime>,
) -> Result<Option<OutputTimestamp>, OutputContractError> {
    value.map(OutputTimestamp::try_from).transpose()
}

fn convert_conversation(
    row: &ConversationStat,
) -> Result<StatsConversationOutput, OutputContractError> {
    Ok(StatsConversationOutput {
        transport: row.transport.into(),
        stream: row.stream,
        address_a: row.address_a,
        port_a: row.port_a,
        address_b: row.address_b,
        port_b: row.port_b,
        frames_a_to_b: row.frames_a_to_b,
        bytes_a_to_b: row.bytes_a_to_b,
        frames_b_to_a: row.frames_b_to_a,
        bytes_b_to_a: row.bytes_b_to_a,
        first_timestamp: row.first_timestamp.try_into()?,
        last_timestamp: row.last_timestamp.try_into()?,
        duration: row.duration(),
    })
}

fn convert_endpoint(row: &EndpointStat) -> StatsEndpointOutput {
    StatsEndpointOutput {
        address: row.address,
        tx_frames: row.tx_frames,
        tx_bytes: row.tx_bytes,
        rx_frames: row.rx_frames,
        rx_bytes: row.rx_bytes,
    }
}

fn convert_protocol(row: &ProtocolStat) -> StatsProtocolOutput {
    StatsProtocolOutput {
        protocol: row.protocol.clone(),
        frames: row.frames,
        bytes: row.bytes,
    }
}

fn convert_port(row: &PortStat) -> StatsPortOutput {
    StatsPortOutput {
        transport: row.transport.into(),
        port: row.port,
        frames: row.frames,
        bytes: row.bytes,
    }
}

fn convert_bucket(row: &IoBucketStat) -> StatsIoBucketOutput {
    StatsIoBucketOutput {
        offset: row.offset,
        frames: row.frames,
        bytes: row.bytes,
    }
}

fn convert_lengths(row: &LengthsStat) -> StatsLengthsOutput {
    StatsLengthsOutput {
        frames: row.frames,
        minimum: row.minimum,
        maximum: row.maximum,
        mean: row.mean,
        buckets: row.buckets.iter().map(convert_length_bucket).collect(),
    }
}

fn convert_length_bucket(row: &LengthBucketStat) -> StatsLengthBucketOutput {
    StatsLengthBucketOutput {
        lower_bound: row.lower_bound,
        upper_bound: row.upper_bound,
        frames: row.frames,
    }
}

fn convert_service_response_time(row: &ServiceResponseTimeStat) -> StatsServiceResponseTimeOutput {
    StatsServiceResponseTimeOutput {
        transport: row.transport.into(),
        service_port: row.service_port,
        request_bursts: row.request_bursts,
        samples: row.samples,
        unanswered_requests: row.unanswered_requests,
        orphan_responses: row.orphan_responses,
        timestamp_regressions: row.timestamp_regressions,
        minimum: row.minimum,
        maximum: row.maximum,
        mean: row.mean,
        buckets: row
            .buckets
            .iter()
            .map(convert_service_response_time_bucket)
            .collect(),
    }
}

fn convert_service_response_time_bucket(
    row: &ServiceResponseTimeBucketStat,
) -> StatsServiceResponseTimeBucketOutput {
    StatsServiceResponseTimeBucketOutput {
        lower_bound: row.lower_bound,
        upper_bound: row.upper_bound,
        samples: row.samples,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, UNIX_EPOCH};

    use packetcraftr_analysis::stats::{
        ConversationStat, EndpointStat, IoBucketStat, LengthBucketStat, LengthsStat, PortStat,
        ProtocolStat, ServiceResponseTimeBucketStat, ServiceResponseTimeStat, StatsReport,
        TransportKind,
    };

    use super::{StatsCommandResult, StatsTableName, StatsTransport};

    fn report() -> StatsReport {
        StatsReport {
            interval: Duration::from_millis(250),
            frames: 3,
            bytes: 300,
            first_timestamp: Some(UNIX_EPOCH + Duration::from_secs(2)),
            last_timestamp: Some(UNIX_EPOCH + Duration::from_secs(5)),
            protocols: vec![ProtocolStat {
                protocol: "tcp".to_owned(),
                frames: 3,
                bytes: 300,
            }],
            conversations: vec![ConversationStat {
                transport: TransportKind::Tcp,
                stream: 7,
                address_a: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port_a: 12_345,
                address_b: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port_b: 443,
                frames_a_to_b: 2,
                bytes_a_to_b: 200,
                frames_b_to_a: 1,
                bytes_b_to_a: 100,
                first_timestamp: UNIX_EPOCH + Duration::from_secs(2),
                last_timestamp: UNIX_EPOCH + Duration::from_secs(5),
            }],
            endpoints: vec![EndpointStat {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                tx_frames: 2,
                tx_bytes: 200,
                rx_frames: 1,
                rx_bytes: 100,
            }],
            ports: vec![PortStat {
                transport: TransportKind::Udp,
                port: 53,
                frames: 3,
                bytes: 300,
            }],
            io: vec![IoBucketStat {
                offset: Duration::from_millis(250),
                frames: 2,
                bytes: 200,
            }],
            lengths: LengthsStat {
                frames: 3,
                minimum: Some(40),
                maximum: Some(80),
                mean: Some(60),
                buckets: vec![LengthBucketStat {
                    lower_bound: 0,
                    upper_bound: Some(64),
                    frames: 3,
                }],
            },
            service_response_time: vec![ServiceResponseTimeStat {
                transport: TransportKind::Tcp,
                service_port: 443,
                request_bursts: 2,
                samples: 1,
                unanswered_requests: 1,
                orphan_responses: 0,
                timestamp_regressions: 0,
                minimum: Some(Duration::from_secs(1)),
                maximum: Some(Duration::from_secs(1)),
                mean: Some(Duration::from_secs(1)),
                buckets: vec![ServiceResponseTimeBucketStat {
                    lower_bound: Duration::from_secs(1),
                    upper_bound: Some(Duration::from_secs(2)),
                    samples: 1,
                }],
            }],
        }
    }

    #[test]
    fn stats_table_names_have_stable_wire_names() {
        for (table, expected) in [
            (StatsTableName::Conversations, "conversations"),
            (StatsTableName::Endpoints, "endpoints"),
            (StatsTableName::Protocols, "protocols"),
            (StatsTableName::Ports, "ports"),
            (StatsTableName::Io, "io"),
            (StatsTableName::ServiceResponseTime, "service_response_time"),
            (StatsTableName::Lengths, "lengths"),
        ] {
            assert_eq!(table.as_str(), expected);
        }
    }

    #[test]
    fn stats_transport_conversion_covers_tcp_and_udp() {
        assert_eq!(
            StatsTransport::from(TransportKind::Tcp),
            StatsTransport::Tcp
        );
        assert_eq!(
            StatsTransport::from(TransportKind::Udp),
            StatsTransport::Udp
        );
    }

    #[test]
    fn conversation_table_converts_directional_counts_and_duration() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::Conversations, &report(), 8)
                .unwrap();
        assert_eq!(result.frames_read, 8);
        assert_eq!(result.frames_matched, 3);
        assert_eq!(result.bytes_matched, 300);
        let rows = result.conversations.unwrap();
        assert_eq!(rows[0].stream, 7);
        assert_eq!(rows[0].transport, StatsTransport::Tcp);
        assert_eq!(rows[0].frames_a_to_b, 2);
        assert_eq!(rows[0].bytes_b_to_a, 100);
        assert_eq!(rows[0].duration, Duration::from_secs(3));
        assert!(result.endpoints.is_none());
        assert!(result.protocols.is_none());
        assert!(result.ports.is_none());
        assert!(result.io.is_none());
    }

    #[test]
    fn endpoint_table_converts_all_directional_totals() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::Endpoints, &report(), 3).unwrap();
        let rows = result.endpoints.unwrap();
        assert_eq!(rows[0].tx_frames, 2);
        assert_eq!(rows[0].tx_bytes, 200);
        assert_eq!(rows[0].rx_frames, 1);
        assert_eq!(rows[0].rx_bytes, 100);
        assert!(result.conversations.is_none());
    }

    #[test]
    fn protocol_table_clones_names_and_counts() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::Protocols, &report(), 3).unwrap();
        let rows = result.protocols.unwrap();
        assert_eq!(rows[0].protocol, "tcp");
        assert_eq!(rows[0].frames, 3);
        assert_eq!(rows[0].bytes, 300);
        assert!(result.ports.is_none());
    }

    #[test]
    fn port_table_converts_transport_and_counts() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::Ports, &report(), 3).unwrap();
        let rows = result.ports.unwrap();
        assert_eq!(rows[0].transport, StatsTransport::Udp);
        assert_eq!(rows[0].port, 53);
        assert_eq!(rows[0].frames, 3);
        assert_eq!(rows[0].bytes, 300);
        assert!(result.io.is_none());
    }

    #[test]
    fn io_table_preserves_interval_offset_and_counts() {
        let result = StatsCommandResult::try_from_report(StatsTableName::Io, &report(), 3).unwrap();
        let io = result.io.unwrap();
        assert_eq!(io.interval, Duration::from_millis(250));
        assert_eq!(io.buckets[0].offset, Duration::from_millis(250));
        assert_eq!(io.buckets[0].frames, 2);
        assert_eq!(io.buckets[0].bytes, 200);
        assert!(result.protocols.is_none());
    }

    #[test]
    fn stats_conversion_preserves_absent_timestamps() {
        let mut report = report();
        report.first_timestamp = None;
        report.last_timestamp = None;
        let result = StatsCommandResult::try_from_report(StatsTableName::Io, &report, 3).unwrap();
        assert_eq!(result.first_timestamp, None);
        assert_eq!(result.last_timestamp, None);
    }

    #[test]
    fn lengths_table_converts_summary_and_buckets() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::Lengths, &report(), 3).unwrap();
        let lengths = result.lengths.unwrap();
        assert_eq!(lengths.frames, 3);
        assert_eq!(lengths.mean, Some(60));
        assert_eq!(lengths.buckets[0].upper_bound, Some(64));
        assert!(result.service_response_time.is_none());
    }

    #[test]
    fn service_response_time_table_converts_summary_and_buckets() {
        let result =
            StatsCommandResult::try_from_report(StatsTableName::ServiceResponseTime, &report(), 3)
                .unwrap();
        let rows = result.service_response_time.unwrap();
        assert_eq!(rows[0].service_port, 443);
        assert_eq!(rows[0].samples, 1);
        assert_eq!(rows[0].buckets[0].lower_bound, Duration::from_secs(1));
        assert!(result.lengths.is_none());
    }
}
