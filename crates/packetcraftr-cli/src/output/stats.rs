// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-statistics output.

use packetcraftr_core::analysis::stats::IoBucketStat as IoBucket;

use packetcraftr_core::analysis::stats::PortStat as Port;

use packetcraftr_core::analysis::stats::EndpointStat as Endpoint;

use packetcraftr_core::analysis::stats::ProtocolStat as Protocol;

use packetcraftr_core::analysis::StreamTransport as Transport;

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::analysis::stats::ConversationStat;

use super::contract::Error;
use super::frame::Timestamp;

/// Which statistics table a result carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
    Fragments,
}

impl From<Table> for packetcraftr_core::analysis::stats::Table {
    fn from(value: Table) -> Self {
        match value {
            Table::Conversations => Self::Conversations,
            Table::Endpoints => Self::Endpoints,
            Table::Protocols => Self::Protocols,
            Table::Ports => Self::Ports,
            Table::Io => Self::Io,
            Table::Fragments => Self::Fragments,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conversation {
    pub transport: Transport,
    pub stream: u64,
    pub scope: packetcraftr_core::analysis::scope::Definition,
    pub address_a: IpAddr,
    pub port_a: u16,
    pub address_b: IpAddr,
    pub port_b: u16,
    pub frames_a_to_b: u64,
    pub bytes_a_to_b: u64,
    pub frames_b_to_a: u64,
    pub bytes_b_to_a: u64,
    pub first_timestamp: Timestamp,
    pub last_timestamp: Timestamp,
    pub duration: Duration,
}

/// The I/O series with the bucket width it was computed under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Io {
    pub origin: Option<Timestamp>,
    pub underflow_frames: u64,
    pub interval: Duration,
    pub buckets: Vec<IoBucket>,
}

/// One capture-source interface description, identified by the global
/// interface ID that frame records reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interface {
    pub id: u32,
    pub link_type: u32,
    pub snap_length: u32,
}

/// Aggregate result of `stats`, carrying exactly the requested table.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub clock: packetcraftr_core::analysis::ClockReport,
    #[serde(flatten)]
    pub table: TableData,
    /// Frames the capture yielded, matched or not, and the frames the
    /// filter kept. Physical tables describe matched frames; fragment
    /// reassembly accounting remains capture-global across the filter.
    pub frames_read: u64,
    pub frames_matched: u64,
    pub bytes_matched: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<Timestamp>,
    /// Earliest-to-latest matched-timestamp span; absent when nothing
    /// matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<Duration>,
    /// Mean captured length over matched frames; absent when the match set
    /// is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_packet_size: Option<f64>,
    /// Matched frames per second over `duration`; absent when the duration
    /// is missing or zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets_per_second: Option<f64>,
    /// Matched captured bytes per second over `duration`; absent under the
    /// same rules as `packets_per_second`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_per_second: Option<f64>,
    /// Interface descriptions the capture source declared, in the global
    /// interface-ID order `interface` fields reference; empty when the
    /// source describes none.
    pub interfaces: Vec<Interface>,
}

/// Exactly one selected table. A report cannot publish several tables or omit
/// the selected one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "table", rename_all = "snake_case")]
pub enum TableData {
    Conversations {
        conversations: Vec<Conversation>,
    },
    Endpoints {
        endpoints: Vec<Endpoint>,
    },
    Protocols {
        protocols: Vec<Protocol>,
    },
    Ports {
        ports: Vec<Port>,
    },
    Io {
        io: Io,
    },
    Fragments {
        fragments: super::reassembly::Report,
    },
}

impl Report {
    pub fn try_from_report(
        table: Table,
        report: packetcraftr_core::analysis::stats::Report,
        frames_read: u64,
    ) -> Result<Self, Error> {
        let duration = report.duration();
        let average_packet_size = report.average_packet_size();
        let packets_per_second = report.packet_rate();
        let bytes_per_second = report.byte_rate();
        let interfaces = report
            .interfaces
            .iter()
            .enumerate()
            .map(|(id, interface)| Interface {
                id: u32::try_from(id).unwrap_or(u32::MAX),
                link_type: interface.link_type.0,
                snap_length: interface.snap_len,
            })
            .collect();
        let table = match table {
            Table::Conversations => TableData::Conversations {
                conversations: report
                    .conversations
                    .into_iter()
                    .map(convert_conversation)
                    .collect::<Result<_, _>>()?,
            },
            Table::Endpoints => TableData::Endpoints {
                endpoints: report.endpoints,
            },
            Table::Protocols => TableData::Protocols {
                protocols: report.protocols,
            },
            Table::Ports => TableData::Ports {
                ports: report.ports,
            },
            Table::Io => TableData::Io {
                io: Io {
                    origin: convert_timestamp(report.io_origin)?,
                    underflow_frames: report.io_underflow_frames,
                    interval: report.interval,
                    buckets: report.io,
                },
            },
            Table::Fragments => TableData::Fragments {
                fragments: super::reassembly::Report::from_analysis(&report.ip_reassembly),
            },
        };
        Ok(Self {
            clock: report.clock,
            table,
            frames_read,
            frames_matched: report.frames,
            bytes_matched: report.bytes,
            first_timestamp: convert_timestamp(report.first_timestamp)?,
            last_timestamp: convert_timestamp(report.last_timestamp)?,
            duration,
            average_packet_size,
            packets_per_second,
            bytes_per_second,
            interfaces,
        })
    }
}

fn convert_timestamp(value: Option<std::time::SystemTime>) -> Result<Option<Timestamp>, Error> {
    value.map(Timestamp::try_from).transpose()
}

fn convert_conversation(row: ConversationStat) -> Result<Conversation, Error> {
    let duration = row.duration();
    Ok(Conversation {
        transport: row.transport,
        stream: row.stream,
        scope: row.scope,
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
        duration,
    })
}
