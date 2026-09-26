// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-statistics output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::analysis::stats as library;

use super::analysis::{Clock, Scope, StreamTransport as Transport};
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

/// Traffic one IP address sent and received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

impl From<library::EndpointStat> for Endpoint {
    fn from(value: library::EndpointStat) -> Self {
        Self {
            address: value.address,
            tx_frames: value.tx_frames,
            tx_bytes: value.tx_bytes,
            rx_frames: value.rx_frames,
            rx_bytes: value.rx_bytes,
        }
    }
}

/// Frames and bytes one protocol appeared in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Protocol {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
}

impl From<library::ProtocolStat> for Protocol {
    fn from(value: library::ProtocolStat) -> Self {
        Self {
            protocol: value.protocol,
            frames: value.frames,
            bytes: value.bytes,
        }
    }
}

/// Frames and bytes one transport port carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Port {
    pub transport: Transport,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

impl From<library::PortStat> for Port {
    fn from(value: library::PortStat) -> Self {
        Self {
            transport: value.transport.into(),
            port: value.port,
            frames: value.frames,
            bytes: value.bytes,
        }
    }
}

/// One I/O interval's frames and bytes, offset from the series origin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IoBucket {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

impl From<library::IoBucketStat> for IoBucket {
    fn from(value: library::IoBucketStat) -> Self {
        Self {
            offset: value.offset,
            frames: value.frames,
            bytes: value.bytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conversation {
    pub transport: Transport,
    pub stream: u64,
    pub scope: Scope,
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
    pub clock: Clock,
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

/// The one requested table of a statistics report, with the number of
/// frames the capture yielded.
impl TryFrom<(Table, library::Report, u64)> for Report {
    type Error = Error;

    fn try_from(
        (table, report, frames_read): (Table, library::Report, u64),
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
                    .map(Conversation::try_from)
                    .collect::<Result<_, _>>()?,
            },
            Table::Endpoints => TableData::Endpoints {
                endpoints: report.endpoints.into_iter().map(Into::into).collect(),
            },
            Table::Protocols => TableData::Protocols {
                protocols: report.protocols.into_iter().map(Into::into).collect(),
            },
            Table::Ports => TableData::Ports {
                ports: report.ports.into_iter().map(Into::into).collect(),
            },
            Table::Io => TableData::Io {
                io: Io {
                    origin: convert_timestamp(report.io_origin)?,
                    underflow_frames: report.io_underflow_frames,
                    interval: report.interval,
                    buckets: report.io.into_iter().map(Into::into).collect(),
                },
            },
            Table::Fragments => TableData::Fragments {
                fragments: (&report.ip_reassembly).into(),
            },
        };
        Ok(Self {
            clock: report.clock.into(),
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

impl TryFrom<library::ConversationStat> for Conversation {
    type Error = Error;

    fn try_from(row: library::ConversationStat) -> Result<Self, Error> {
        let duration = row.duration();
        Ok(Self {
            transport: row.transport.into(),
            stream: row.stream,
            scope: row.scope.try_into()?,
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
}
