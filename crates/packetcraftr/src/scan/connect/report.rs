// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::Sink;
use crate::execution::Shared;
use crate::probe::index_or_push;
use packetcraftr_core::error::BoundaryError;

use super::super::{Classification, Error, Rtt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Connected,
    Refused,
    TimedOut,
    Unreachable,
    LocalError,
    DeadlineExpired,
}

impl Outcome {
    pub const fn classification(self) -> Classification {
        match self {
            Self::Connected => Classification::Open,
            Self::Refused => Classification::Closed,
            Self::TimedOut | Self::DeadlineExpired => Classification::Timeout,
            Self::Unreachable => Classification::Unreachable,
            Self::LocalError => Classification::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeEvidence {
    pub sequence: u64,
    pub stage: super::super::Stage,
    pub endpoint: SocketAddr,
    pub scope: Option<crate::target::ResolvedZone>,
    pub attempt: u32,
    pub attempted: bool,
    /// None means no socket-call result was available by the deadline.
    pub connect_succeeded: Option<bool>,
    pub outcome: Outcome,
    pub scheduled_at: SystemTime,
    pub finished_at: Option<SystemTime>,
    pub elapsed: Duration,
    pub local: Option<SocketAddr>,
    pub error: Option<Arc<io::Error>>,
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

#[derive(Clone, Debug)]
pub enum Event {
    Probe(ProbeEvidence),
}

#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    /// One record per selected target, in selection order. Their reasons
    /// are socket observations.
    pub hosts: Vec<super::super::discovery::Host>,
    pub diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    pub planned_duration: Duration,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    pub scope: Option<crate::target::ResolvedZone>,
    /// The highest-ranked attempt observation.
    pub classification: Classification,
    /// The bundled catalog's TCP name for the port: a hint, never service
    /// identification.
    pub port_hint: Option<&'static str>,
    pub inference: super::super::Inference,
    pub probes: Vec<ProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub report: Report,
    /// Discovery connections in sequence order, exactly those the hosts
    /// list; [`Self::endpoints`] holds only the scan stage's.
    pub discovery: Vec<ProbeEvidence>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<ProbeEvidence>>);

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|probes| match event {
            Event::Probe(probe) => probes.push(probe),
        });
        Ok(())
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let mut probes = self.0.take();
        let collected = u64::try_from(probes.len()).unwrap_or(u64::MAX);
        if collected != report.stats.connections_scheduled {
            return Err(Error::InvalidEvidence {
                sequence: collected,
                message: "connect events disagree with the scheduled connections".to_owned(),
            });
        }
        probes.sort_by_key(|probe| probe.sequence);
        let (discovery, probes): (Vec<_>, Vec<_>) = probes
            .into_iter()
            .partition(|probe| probe.stage == super::super::Stage::Discovery);
        super::super::discovery::check_probes(
            &report.hosts,
            discovery.iter().map(|probe| probe.sequence),
        )?;
        let mut endpoints: Vec<Endpoint> = Vec::new();
        let mut indices = HashMap::new();
        for probe in probes {
            let key = probe.endpoint;
            let endpoint = index_or_push(&mut endpoints, &mut indices, key, || Endpoint {
                address: key.ip(),
                port: key.port(),
                scope: probe.scope.clone(),
                classification: Classification::Timeout,
                port_hint: super::super::catalog::hint(crate::probe::Transport::Tcp, key.port()),
                inference: super::super::inference::connect([]),
                probes: Vec::new(),
            });
            endpoint
                .classification
                .promote(probe.outcome.classification());
            endpoint.probes.push(probe);
        }
        for endpoint in &mut endpoints {
            endpoint.inference = super::super::inference::connect(
                endpoint
                    .probes
                    .iter()
                    .map(|probe| (probe.sequence, probe.outcome)),
            );
        }
        Ok(Aggregate {
            report,
            discovery,
            endpoints,
        })
    }
}
