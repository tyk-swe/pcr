// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::execution::Shared;
use crate::{BoundaryError, Sink};

use super::super::{Classification, Error, Rtt};

/// How one connect attempt ended.
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

/// The socket evidence of one connect attempt.
#[derive(Clone, Debug)]
pub struct Probe {
    pub sequence: u64,
    pub endpoint: SocketAddr,
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
    pub elapsed: Duration,
    /// Round-trip accounting across the admitted connect attempts: a probe
    /// counts as sent once the kernel accepted its connect call, and as
    /// received when it finished with a connected, refused, or unreachable
    /// verdict before its deadline. Timed-out, deadline-expired, and
    /// local-error attempts count as lost and contribute no sample.
    pub rtt: Rtt,
}

/// What a connect scan publishes while it runs, in the order attempts
/// settle. Each event is answered before the scan continues.
#[derive(Clone, Debug)]
pub enum Event {
    /// One connect attempt settled.
    Probe(Probe),
}

/// The terminal result of one connect scan.
#[derive(Clone, Debug)]
pub struct Report {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub planned_duration: Duration,
    pub stats: Stats,
}

/// Every attempt against one endpoint, in sequence order, with the verdict
/// they support together.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    pub classification: Classification,
    pub probes: Vec<Probe>,
}

/// Every attempt of one connect scan, grouped by endpoint in first-scheduled
/// order, with its terminal report.
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub report: Report,
    pub endpoints: Vec<Endpoint>,
}

/// A sink that keeps every published attempt. Pass a clone to
/// [`Client::scan_connect`](crate::Client::scan_connect) and
/// [`finish`](Self::finish) the one kept with the report it returns.
#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<Probe>>);

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
    /// Groups the collected attempts by endpoint and joins them with the
    /// scan's terminal `report`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidEvidence`] when the collected attempts are not
    /// the ones the report scheduled.
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
        let mut endpoints: Vec<Endpoint> = Vec::new();
        let mut indices = HashMap::new();
        for probe in probes {
            let key = probe.endpoint;
            let index = *indices.entry(key).or_insert_with(|| {
                endpoints.push(Endpoint {
                    address: key.ip(),
                    port: key.port(),
                    classification: Classification::Timeout,
                    probes: Vec::new(),
                });
                endpoints.len() - 1
            });
            endpoints[index]
                .classification
                .promote(probe.outcome.classification());
            endpoints[index].probes.push(probe);
        }
        Ok(Aggregate { report, endpoints })
    }
}
