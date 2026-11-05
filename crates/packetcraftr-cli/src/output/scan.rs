// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub mod connect;
pub mod event;
pub mod host;
pub mod list;
pub mod plan;
pub mod probe;

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::contract::Error;
use super::envelope::Published;
use super::frame::Captured;
use packetcraftr::probe::Transport;

use packetcraftr::scan as library;

pub use super::scan_failure::{Protocol, Scope, Sent, Stage};
pub use event::{EndpointSummary, Event};
pub use probe::{ApplicationEvidence, ApplicationStatus, Measurement, Probe, Qualification};

published_enum! {
    pub enum Classification from library::Classification {
        Open => "open",
        Closed => "closed",
        Filtered => "filtered",
        Unreachable => "unreachable",
        Unknown => "unknown",
        Timeout => "timeout",
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClassificationCounts {
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub unreachable: usize,
    pub unknown: usize,
    pub timeout: usize,
}

impl From<library::ClassificationCounts> for ClassificationCounts {
    fn from(value: library::ClassificationCounts) -> Self {
        Self {
            open: value.open,
            closed: value.closed,
            filtered: value.filtered,
            unreachable: value.unreachable,
            unknown: value.unknown,
            timeout: value.timeout,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Rtt {
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub unavailable: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<Duration>,
}

impl From<library::Rtt> for Rtt {
    fn from(value: library::Rtt) -> Self {
        Self {
            sent: value.sent,
            received: value.received,
            lost: value.lost,
            unavailable: value.unavailable,
            min: value.min,
            avg: value.avg,
            max: value.max,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_protocol: Option<u8>,
    /// The highest-ranked attempt observation.
    pub classification: Classification,
    /// The catalog's conventional name for this transport and port; a hint,
    /// never service identification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<&'static str>,
    /// Absent for portless ICMP echo endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference: Option<plan::Inference>,
    pub probes: Vec<Probe>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Scheduling {
    pub mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<Adaptive>,
    pub observed_peak_window: usize,
    pub retries_started: u64,
    pub conditions: Vec<Condition>,
    pub incomplete: Vec<HostId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_ceiling: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_ceiling: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Adaptive {
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    pub min_window: usize,
    pub initial_window: usize,
    pub host_timeout: Duration,
    pub retry_backoff: Duration,
    pub max_backoff: Duration,
}

impl From<library::Adaptive> for Adaptive {
    fn from(value: library::Adaptive) -> Self {
        Self {
            min_timeout: value.min_timeout,
            max_timeout: value.max_timeout,
            min_window: value.min_window,
            initial_window: value.initial_window,
            host_timeout: value.host_timeout,
            retry_backoff: value.retry_backoff,
            max_backoff: value.max_backoff,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostId {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
}

impl From<library::HostIdentity> for HostId {
    fn from(value: library::HostIdentity) -> Self {
        Self {
            address: value.address,
            scope: value.scope.as_ref().map(Scope::from),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Condition {
    pub kind: &'static str,
    pub host: HostId,
    pub control_responder: IpAddr,
    pub completed: u64,
    pub replies: u64,
    pub losses: u64,
    pub control_sequences: Vec<u64>,
    pub loss_sequences: Vec<u64>,
    pub caveat: &'static str,
}

impl From<library::Condition> for Condition {
    fn from(value: library::Condition) -> Self {
        Self {
            kind: value.kind.as_str(),
            host: value.host.into(),
            control_responder: value.control_responder,
            completed: value.completed,
            replies: value.replies,
            losses: value.losses,
            control_sequences: value.control_sequences,
            loss_sequences: value.loss_sequences,
            caveat: value.caveat,
        }
    }
}

impl From<library::Scheduling> for Scheduling {
    fn from(value: library::Scheduling) -> Self {
        Self {
            mode: value.mode.as_str(),
            adaptive: value.adaptive.map(Adaptive::from),
            observed_peak_window: value.observed_peak_window,
            retries_started: value.retries_started,
            conditions: value.conditions.into_iter().map(Into::into).collect(),
            incomplete: value.incomplete.into_iter().map(Into::into).collect(),
            operation_ceiling: value.operation_ceiling,
            process_ceiling: value.process_ceiling,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub planned_duration: Duration,
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub plan: plan::Plan,
    pub hosts: Vec<host::Host<Probe>>,
    pub endpoints: Vec<Endpoint>,
    pub undecoded: Vec<Captured>,
    pub unattributed: Vec<Unattributed>,
    pub retained_evidence_bytes: usize,
    pub rtt: Rtt,
    pub scheduling: Scheduling,
    /// Present only when the scan traced its hosts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceroute: Option<super::traceroute::hosts::Report>,
}

/// A correlated frame no probe outcome carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unattributed {
    pub attribution: &'static str,
    /// The probe the frame correlates with; absent when ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    pub frame: Captured,
}

impl TryFrom<library::Unattributed> for Unattributed {
    type Error = Error;

    fn try_from(unattributed: library::Unattributed) -> Result<Self, Error> {
        Ok(Self {
            attribution: unattributed.attribution.as_str(),
            sequence: unattributed.sequence,
            frame: unattributed.frame.try_into()?,
        })
    }
}

impl Report {
    /// `reverse_dns` holds each host's lookup by position; it is empty when
    /// none ran.
    pub fn publish(
        aggregate: library::Aggregate,
        plan: plan::Plan,
        reverse_dns: Vec<Option<host::ReverseDns>>,
        traceroute: Option<super::traceroute::hosts::Report>,
    ) -> Result<Published<Self>, Error> {
        let library::Aggregate {
            planned_duration,
            target,
            resolved_addresses,
            hosts,
            discovery,
            endpoints,
            undecoded,
            unattributed,
            diagnostics,
            retained_evidence_bytes,
            stats,
            rtt,
            scheduling,
        } = aggregate;
        let endpoint_outputs = endpoints
            .into_iter()
            .map(Endpoint::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Published::new(
            Self {
                planned_duration,
                target,
                resolved_addresses,
                plan,
                hosts: host::publish_all(
                    hosts,
                    discovery,
                    |probe| probe.sequence,
                    Probe::try_from,
                    reverse_dns,
                )?,
                endpoints: endpoint_outputs,
                undecoded: undecoded
                    .into_iter()
                    .map(Captured::try_from)
                    .collect::<Result<_, _>>()?,
                unattributed: unattributed
                    .into_iter()
                    .map(Unattributed::try_from)
                    .collect::<Result<_, _>>()?,
                retained_evidence_bytes,
                rtt: rtt.into(),
                scheduling: scheduling.into(),
                traceroute,
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}

impl TryFrom<library::Endpoint> for Endpoint {
    type Error = Error;

    fn try_from(endpoint: library::Endpoint) -> Result<Self, Error> {
        Ok(Self {
            address: endpoint.address,
            scope: endpoint.scope.as_ref().map(Scope::from),
            transport: endpoint.endpoint.transport(),
            port: endpoint.endpoint.port(),
            ip_protocol: endpoint.endpoint.ip_protocol(),
            classification: endpoint.classification.into(),
            port_hint: endpoint.port_hint,
            inference: endpoint.inference.map(plan::Inference::from),
            probes: endpoint
                .probes
                .into_iter()
                .map(Probe::try_from)
                .collect::<Result<_, Error>>()?,
        })
    }
}
