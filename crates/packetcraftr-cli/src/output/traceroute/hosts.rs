// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Multi-host traces published as the `traceroute` stage of a scan.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use packetcraftr::probe::Transport;
use packetcraftr::traceroute::hosts as library;

use super::{Completion, Hop, Probe};
use crate::output::contract::Error;
use crate::output::frame::{Captured, Timestamp};
use crate::output::scan::host::reply_name;
use crate::output::scan::{Scope, Stage};
use crate::output::stream::StreamRecord;

published_enum! {
    pub enum Reason from library::NotTraced {
        NoResponsiveProbe => "no_responsive_probe",
        ScopedTarget => "scoped_target",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    NotTraced,
}

impl Status {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
            Self::NotTraced => "not_traced",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Observed,
    Requested,
}

impl Basis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Requested => "requested",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StrategyPlan {
    pub strategy: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReusePlan {
    pub max_age: Duration,
}

/// The bounds the trace stage ran under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub first_hop: u8,
    pub max_hops: u8,
    pub attempts: u32,
    pub max_probes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<StrategyPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse: Option<ReusePlan>,
}

/// The scan probe a host's trace rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub stage: Stage,
    pub sequence: u64,
    pub reply: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Selection {
    pub strategy: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub basis: Basis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observation>,
}

impl TryFrom<&library::Selection> for Selection {
    type Error = Error;

    fn try_from(selection: &library::Selection) -> Result<Self, Error> {
        let (basis, observation) = match &selection.basis {
            library::Basis::Requested => (Basis::Requested, None),
            library::Basis::Observed(observed) => (
                Basis::Observed,
                Some(Observation {
                    stage: observed.stage.into(),
                    sequence: observed.sequence,
                    reply: reply_name(observed.reply),
                    observed_at: observed.observed_at.map(Timestamp::try_from).transpose()?,
                }),
            ),
        };
        Ok(Self {
            strategy: selection.strategy.transport,
            destination_port: selection.strategy.destination_port,
            basis,
            observation,
        })
    }
}

/// A hop another host's trace observed, claimed for this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReusedHop {
    pub hop_limit: u8,
    pub source: IpAddr,
    pub probes: Vec<u64>,
    pub responders: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Timestamp>,
    pub age: Duration,
}

impl TryFrom<&library::ReusedHop> for ReusedHop {
    type Error = Error;

    fn try_from(hop: &library::ReusedHop) -> Result<Self, Error> {
        Ok(Self {
            hop_limit: hop.hop_limit,
            source: hop.source,
            probes: hop.probes.clone(),
            responders: hop.responders.clone(),
            observed_at: hop.observed_at.map(Timestamp::try_from).transpose()?,
            age: hop.age,
        })
    }
}

/// A host's record without its probes, which the stream carries separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion: Option<Completion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<Selection>,
    pub reused_hops: Vec<ReusedHop>,
}

impl TryFrom<&library::Host> for Summary {
    type Error = Error;

    fn try_from(host: &library::Host) -> Result<Self, Error> {
        let (status, reason) = match host.state {
            library::State::Complete => (Status::Complete, None),
            library::State::Incomplete => (Status::Incomplete, None),
            library::State::NotTraced(reason) => (Status::NotTraced, Some(reason.into())),
        };
        Ok(Self {
            address: host.address,
            scope: host.scope.as_ref().map(Scope::from),
            status,
            reason,
            completion: host.termination.map(Into::into),
            selection: host
                .selection
                .as_ref()
                .map(Selection::try_from)
                .transpose()?,
            reused_hops: host
                .reused
                .iter()
                .map(ReusedHop::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Host {
    #[serde(flatten)]
    pub summary: Summary,
    pub hops: Vec<Hop>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Undecoded {
    pub destination: IpAddr,
    pub hop_limit: u8,
    pub frame: Captured,
}

impl TryFrom<library::UndecodedEvidence> for Undecoded {
    type Error = Error;

    fn try_from(evidence: library::UndecodedEvidence) -> Result<Self, Error> {
        Ok(Self {
            destination: evidence.destination,
            hop_limit: evidence.hop_limit,
            frame: evidence.frame.try_into()?,
        })
    }
}

/// The scan result's `traceroute` member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub plan: Plan,
    pub hosts: Vec<Host>,
    pub undecoded: Vec<Undecoded>,
    pub retained_evidence_bytes: usize,
}

impl Report {
    /// Statistics and diagnostics stay with the command's own accounting.
    pub fn new(plan: Plan, aggregate: library::Aggregate) -> Result<Self, Error> {
        let library::Aggregate {
            hosts,
            undecoded,
            retained_evidence_bytes,
            ..
        } = aggregate;
        Ok(Self {
            plan,
            hosts: hosts
                .into_iter()
                .map(|trace| {
                    Ok(Host {
                        summary: Summary::try_from(&trace.host)?,
                        hops: trace
                            .hops
                            .into_iter()
                            .map(|hop| {
                                Ok(Hop {
                                    hop_limit: hop.hop_limit,
                                    probes: hop
                                        .probes
                                        .into_iter()
                                        .map(Probe::try_from)
                                        .collect::<Result<_, Error>>()?,
                                })
                            })
                            .collect::<Result<_, Error>>()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
            undecoded: undecoded
                .into_iter()
                .map(Undecoded::try_from)
                .collect::<Result<_, _>>()?,
            retained_evidence_bytes,
        })
    }
}

/// The `traceroute` member of the stream's complete record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Complete {
    pub plan: Plan,
    pub retained_evidence_bytes: usize,
}

/// A trace record streamed while the stage runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Probe(Probe),
    Undecoded(Undecoded),
    Host {
        #[serde(flatten)]
        summary: Summary,
        probes: Vec<u64>,
    },
}

impl Event {
    /// A diagnostic is not a trace record; it streams as the scan's own.
    pub fn publish(event: library::Event) -> Result<Option<Self>, Error> {
        Ok(match event {
            library::Event::Probe(probe) => Some(Self::Probe(probe.try_into()?)),
            library::Event::Undecoded(evidence) => Some(Self::Undecoded(evidence.try_into()?)),
            library::Event::Host(host) => Some(Self::Host {
                summary: Summary::try_from(&host)?,
                probes: host.probes,
            }),
            library::Event::Diagnostic(_) => None,
        })
    }
}

impl StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Probe(_) => "traceroute_probe",
            Self::Undecoded(_) => "traceroute_undecoded",
            Self::Host { .. } => "traceroute_host",
        }
    }
}
