// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-statistics output.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr_core::analysis::stats::{
    ConversationStat, EndpointStat, IoBucketStat, PortStat, ProtocolStat, TransportKind,
};

use super::contract::Error;
use super::frame::Timestamp;

/// Which statistics table a result carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    Conversations,
    Endpoints,
    Protocols,
    Ports,
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

impl From<TransportKind> for Transport {
    fn from(value: TransportKind) -> Self {
        match value {
            TransportKind::Tcp => Self::Tcp,
            TransportKind::Udp => Self::Udp,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Protocol {
    pub protocol: String,
    pub frames: u64,
    pub bytes: u64,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub tx_frames: u64,
    pub tx_bytes: u64,
    pub rx_frames: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Port {
    pub transport: Transport,
    pub port: u16,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IoBucket {
    pub offset: Duration,
    pub frames: u64,
    pub bytes: u64,
}

/// The I/O series with the bucket width it was computed under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Io {
    pub interval: Duration,
    pub buckets: Vec<IoBucket>,
}

/// Aggregate result of `stats`, carrying exactly the requested table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub table: Table,
    /// Frames the capture yielded, matched or not, and the frames the
    /// filter kept; the tables describe only the matched frames.
    pub frames_read: u64,
    pub frames_matched: u64,
    pub bytes_matched: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversations: Option<Vec<Conversation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<Endpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<Protocol>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<Port>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io: Option<Io>,
}

impl Result {
    /// Builds the result for one requested table from a finished report.
    pub fn try_from_report(
        table: Table,
        report: &packetcraftr_core::analysis::stats::Report,
        frames_read: u64,
    ) -> std::result::Result<Self, Error> {
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
        };
        match table {
            Table::Conversations => {
                result.conversations = Some(
                    report
                        .conversations
                        .iter()
                        .map(convert_conversation)
                        .collect::<std::result::Result<_, _>>()?,
                );
            }
            Table::Endpoints => {
                result.endpoints = Some(report.endpoints.iter().map(convert_endpoint).collect());
            }
            Table::Protocols => {
                result.protocols = Some(report.protocols.iter().map(convert_protocol).collect());
            }
            Table::Ports => {
                result.ports = Some(report.ports.iter().map(convert_port).collect());
            }
            Table::Io => {
                result.io = Some(Io {
                    interval: report.interval,
                    buckets: report.io.iter().map(convert_bucket).collect(),
                });
            }
        }
        Ok(result)
    }
}

fn convert_timestamp(
    value: Option<std::time::SystemTime>,
) -> std::result::Result<Option<Timestamp>, Error> {
    value.map(Timestamp::try_from).transpose()
}

fn convert_conversation(row: &ConversationStat) -> std::result::Result<Conversation, Error> {
    Ok(Conversation {
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

fn convert_endpoint(row: &EndpointStat) -> Endpoint {
    Endpoint {
        address: row.address,
        tx_frames: row.tx_frames,
        tx_bytes: row.tx_bytes,
        rx_frames: row.rx_frames,
        rx_bytes: row.rx_bytes,
    }
}

fn convert_protocol(row: &ProtocolStat) -> Protocol {
    Protocol {
        protocol: row.protocol.clone(),
        frames: row.frames,
        bytes: row.bytes,
    }
}

fn convert_port(row: &PortStat) -> Port {
    Port {
        transport: row.transport.into(),
        port: row.port,
        frames: row.frames,
        bytes: row.bytes,
    }
}

fn convert_bucket(row: &IoBucketStat) -> IoBucket {
    IoBucket {
        offset: row.offset,
        frames: row.frames,
        bytes: row.bytes,
    }
}
