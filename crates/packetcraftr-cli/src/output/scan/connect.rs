// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Socket-only scan evidence; no packet counts or fabricated capture frames.

use crate::output::{contract::Error, frame::Timestamp, stream::StreamRecord};
use packetcraftr::scan::connect;
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use super::{Classification, Rtt};

published_enum! {
    /// How one connect attempt ended.
    pub enum Outcome from connect::Outcome {
        Connected => "connected",
        Refused => "refused",
        TimedOut => "timed_out",
        Unreachable => "unreachable",
        LocalError => "local_error",
        DeadlineExpired => "deadline_expired",
    }
}

/// Socket-level accounting for one connect scan.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub connections_scheduled: u64,
    pub connections_attempted: u64,
    pub connections_succeeded: u64,
    pub elapsed: Duration,
    pub rtt: Rtt,
}

impl From<connect::Stats> for Stats {
    fn from(value: connect::Stats) -> Self {
        Self {
            connections_scheduled: value.connections_scheduled,
            connections_attempted: value.connections_attempted,
            connections_succeeded: value.connections_succeeded,
            elapsed: value.elapsed,
            rtt: value.rtt.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SocketError {
    pub kind: String,
    pub os_code: Option<i32>,
    pub message: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Probe {
    pub sequence: u64,
    pub address: IpAddr,
    pub port: u16,
    pub attempt: u32,
    pub attempted: bool,
    pub connect_succeeded: Option<bool>,
    pub outcome: Outcome,
    pub classification: Classification,
    pub scheduled_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub elapsed: Duration,
    pub local: Option<SocketAddr>,
    pub error: Option<SocketError>,
}
impl TryFrom<connect::Probe> for Probe {
    type Error = Error;
    fn try_from(probe: connect::Probe) -> Result<Self, Error> {
        Ok(Self {
            sequence: probe.sequence,
            address: probe.endpoint.ip(),
            port: probe.endpoint.port(),
            attempt: probe.attempt,
            attempted: probe.attempted,
            connect_succeeded: probe.connect_succeeded,
            outcome: probe.outcome.into(),
            classification: probe.outcome.classification().into(),
            scheduled_at: probe.scheduled_at.try_into()?,
            finished_at: probe.finished_at.map(Timestamp::try_from).transpose()?,
            elapsed: probe.elapsed,
            local: probe.local,
            error: probe.error.map(|error| SocketError {
                kind: format!("{:?}", error.kind()),
                os_code: error.raw_os_error(),
                message: error.to_string(),
            }),
        })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    pub classification: Classification,
    pub probes: Vec<Probe>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    method: &'static str,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub planned_duration: Duration,
    pub socket_stats: Stats,
}
impl From<connect::Report> for Summary {
    fn from(report: connect::Report) -> Self {
        Self {
            method: "tcp_connect",
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            planned_duration: report.planned_duration,
            socket_stats: report.stats.into(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: Summary,
    pub endpoints: Vec<Endpoint>,
}
impl TryFrom<connect::Aggregate> for Report {
    type Error = Error;
    fn try_from(aggregate: connect::Aggregate) -> Result<Self, Error> {
        Ok(Self {
            summary: aggregate.report.into(),
            endpoints: aggregate
                .endpoints
                .into_iter()
                .map(|endpoint| {
                    Ok(Endpoint {
                        address: endpoint.address,
                        port: endpoint.port,
                        classification: endpoint.classification.into(),
                        probes: endpoint
                            .probes
                            .into_iter()
                            .map(Probe::try_from)
                            .collect::<Result<_, _>>()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
        })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ProbeEvent {
    method: &'static str,
    #[serde(flatten)]
    pub probe: Probe,
}
impl TryFrom<connect::Probe> for ProbeEvent {
    type Error = Error;
    fn try_from(probe: connect::Probe) -> Result<Self, Error> {
        Ok(Self {
            method: "tcp_connect",
            probe: probe.try_into()?,
        })
    }
}
impl StreamRecord for ProbeEvent {
    fn event_name(&self) -> &'static str {
        "connect_probe"
    }
}
