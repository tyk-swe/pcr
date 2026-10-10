// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::BoundaryError;

use crate::scan::{self, connect};
use crate::traceroute::hosts;
use crate::{Sink, Stats};

use super::Error;
use super::reverse::ReverseLookups;

/// What a scan with follow-ups publishes while it runs: the scan's events,
/// then the trace stage's.
#[derive(Clone, Debug)]
pub enum Event {
    Scan(scan::Event),
    Trace(hosts::Event),
}

/// The stage reports kept as each stage produced them, so each stage's
/// collector can still check them against its events.
#[derive(Debug)]
pub struct Report {
    pub scan: scan::Report,
    /// The inferences the scan's endpoints support.
    pub endpoints: Vec<scan::Endpoint>,
    pub trace: Option<hosts::Report>,
    /// Absent when no reverse lookup was requested.
    pub reverse_dns: Option<ReverseLookups>,
    /// The scan's, the trace's, and the lookups' statistics together.
    pub stats: Stats,
}

/// Collects a scan's follow-up events, then joins them with the
/// [`Report`] into an [`Aggregate`].
#[derive(Clone, Default)]
pub struct Collector {
    scan: scan::Collector,
    trace: hosts::Collector,
}

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        match event {
            Event::Scan(event) => self.scan.publish(event),
            Event::Trace(event) => self.trace.publish(event),
        }
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let Report {
            scan,
            trace,
            reverse_dns,
            stats,
            ..
        } = report;
        Ok(Aggregate {
            scan: self.scan.finish(scan)?,
            trace: trace.map(|trace| self.trace.finish(trace)).transpose()?,
            reverse_dns,
            stats,
        })
    }
}

#[derive(Debug)]
pub struct Aggregate {
    pub scan: scan::Aggregate,
    pub trace: Option<hosts::Aggregate>,
    pub reverse_dns: Option<ReverseLookups>,
    pub stats: Stats,
}

#[derive(Debug)]
pub struct ConnectReport {
    pub scan: connect::Report,
    pub endpoints: Vec<connect::Endpoint>,
    /// Absent when no reverse lookup was requested.
    pub reverse_dns: Option<ReverseLookups>,
}
