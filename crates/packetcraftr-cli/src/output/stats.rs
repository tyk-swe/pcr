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
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Table {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
    Fragments,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conversation {
    pub transport: Transport,
    pub stream: u64,
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
    pub interval: Duration,
    pub buckets: Vec<IoBucket>,
}

/// Aggregate result of `stats`, carrying exactly the requested table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
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
                    interval: report.interval,
                    buckets: report.io,
                },
            },
            Table::Fragments => TableData::Fragments {
                fragments: super::reassembly::Report::from_analysis(&report.ip_reassembly),
            },
        };
        Ok(Self {
            table,
            frames_read,
            frames_matched: report.frames,
            bytes_matched: report.bytes,
            first_timestamp: convert_timestamp(report.first_timestamp)?,
            last_timestamp: convert_timestamp(report.last_timestamp)?,
        })
    }
}

fn convert_timestamp(value: Option<std::time::SystemTime>) -> Result<Option<Timestamp>, Error> {
    value.map(Timestamp::try_from).transpose()
}

fn convert_conversation(row: ConversationStat) -> Result<Conversation, Error> {
    Ok(Conversation {
        transport: row.transport,
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
