// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::{contract::Error, frame::Timestamp, stream::StreamRecord};
use packetcraftr::scan::connect;
use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use super::{Classification, Rtt};

published_enum! {
    pub enum Outcome from connect::Outcome {
        Connected => "connected",
        Refused => "refused",
        TimedOut => "timed_out",
        Unreachable => "unreachable",
        LocalError => "local_error",
        DeadlineExpired => "deadline_expired",
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub connections_scheduled: u64,
    pub connections_attempted: u64,
    pub connections_succeeded: u64,
    pub retained_evidence_bytes: usize,
    pub elapsed: Duration,
    pub rtt: Rtt,
}

impl From<connect::Stats> for Stats {
    fn from(value: connect::Stats) -> Self {
        Self {
            connections_scheduled: value.connections_scheduled,
            connections_attempted: value.connections_attempted,
            connections_succeeded: value.connections_succeeded,
            retained_evidence_bytes: value.retained_evidence_bytes,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<super::Scope>,
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
impl TryFrom<connect::ProbeEvidence> for Probe {
    type Error = Error;
    fn try_from(probe: connect::ProbeEvidence) -> Result<Self, Error> {
        Ok(Self {
            sequence: probe.sequence,
            address: probe.endpoint.ip(),
            scope: probe.scope.as_ref().map(super::Scope::from),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<super::Scope>,
    pub port: u16,
    /// The highest-ranked socket outcome, kept from v7.
    pub classification: Classification,
    /// The catalog's conventional TCP name for the port; a hint, never
    /// service identification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<&'static str>,
    pub inference: super::plan::Inference,
    pub probes: Vec<Probe>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    method: &'static str,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub planned_duration: Duration,
    pub plan: super::plan::Plan,
    pub socket_stats: Stats,
}
impl Summary {
    pub fn new(report: connect::Report, plan: super::plan::Plan) -> Self {
        Self {
            method: "tcp_connect",
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            planned_duration: report.planned_duration,
            plan,
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
impl Report {
    pub fn publish(aggregate: connect::Aggregate, plan: super::plan::Plan) -> Result<Self, Error> {
        Ok(Self {
            summary: Summary::new(aggregate.report, plan),
            endpoints: aggregate
                .endpoints
                .into_iter()
                .map(|endpoint| {
                    Ok(Endpoint {
                        address: endpoint.address,
                        scope: endpoint.scope.as_ref().map(super::Scope::from),
                        port: endpoint.port,
                        classification: endpoint.classification.into(),
                        port_hint: endpoint.port_hint,
                        inference: endpoint.inference.into(),
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
impl TryFrom<connect::ProbeEvidence> for ProbeEvent {
    type Error = Error;
    fn try_from(probe: connect::ProbeEvidence) -> Result<Self, Error> {
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

/// One per endpoint after the last probe, before `complete`: the inference
/// over attempts already published as `connect_probe` records.
#[derive(Clone, Debug, Serialize)]
pub struct EndpointEvent {
    method: &'static str,
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<super::Scope>,
    pub port: u16,
    pub classification: Classification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<&'static str>,
    pub inference: super::plan::Inference,
    pub probes: Vec<u64>,
}

impl From<connect::Endpoint> for EndpointEvent {
    fn from(endpoint: connect::Endpoint) -> Self {
        Self {
            method: "tcp_connect",
            address: endpoint.address,
            scope: endpoint.scope.as_ref().map(super::Scope::from),
            port: endpoint.port,
            classification: endpoint.classification.into(),
            port_hint: endpoint.port_hint,
            inference: endpoint.inference.into(),
            probes: endpoint.probes.iter().map(|probe| probe.sequence).collect(),
        }
    }
}

impl StreamRecord for EndpointEvent {
    fn event_name(&self) -> &'static str {
        "connect_endpoint"
    }
}
