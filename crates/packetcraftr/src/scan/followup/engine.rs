// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{Arc, Mutex, PoisonError};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use crate::clock::Clock;
use crate::providers::{PacketProviders, TargetProviders, TcpProviders};
use crate::scan::{self, connect};
use crate::{Client, Sink};

use super::reverse::{Lookup, last_transmission, names};
use super::trace::{Retained, Stage};
use super::{ConnectReport, ConnectRequest, Error, Event, Report, Request};

impl<P, K> Client<P, K>
where
    P: PacketProviders + TargetProviders + TcpProviders,
    K: Clock,
{
    /// Scans the request's targets, then traces every scanned host and looks
    /// each up in reverse DNS as the request asks, all within the scan's own
    /// duration limit and the policy allowance the earlier stages left.
    /// Each stage's events reach `sink` as they settle.
    pub fn scan_with_followups<S>(&self, request: Request, sink: S) -> Result<Report, Error>
    where
        S: Sink<Event, Ack = ()>,
    {
        let Request {
            scan,
            trace,
            reverse_dns,
        } = request;
        let stage = trace
            .as_ref()
            .map(|trace| Stage::new(trace, &scan))
            .transpose()?;
        let lookup = reverse_dns
            .as_ref()
            .map(|reverse| Lookup::new(reverse, &scan))
            .transpose()?;
        // The same absolute deadline parents the streamed scan, trace, and
        // lookups, so their setup cannot extend its expiry; it starts before
        // the `started` marker so it cannot end later.
        let mut operation = crate::execution::Operation::new(self, scan.limits.max_duration);
        operation.neighbor_mode = crate::execution::NeighborMode::Authorized;
        if lookup.is_some() {
            operation.scan_neighbors(&scan)?;
        }
        let started = self.now();
        let delivery = sink.delivery();
        let sink = Arc::new(Mutex::new(sink));
        // Events stream as they settle; the tracker keeps each attempt
        // without its frame, for the endpoint inferences.
        let tracker = scan::Collector::default();
        let mut tracked = tracker.clone();
        // The tracker strips matched response frames, so the scan's retained
        // evidence is counted as events publish.
        let retained = Arc::new(Mutex::new(Retained::default()));
        let observing = Arc::clone(&retained);
        let scan_sink = Arc::clone(&sink);
        let scan_report = self.scan_in(
            scan,
            crate::execution::forwarding(delivery, move |event: scan::Event, control| {
                observing
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .observe(&event);
                match &event {
                    scan::Event::Probe { target, probe } => {
                        let probe = scan::ProbeEvidence {
                            response: None,
                            ..probe.clone()
                        };
                        Sink::publish(
                            &mut tracked,
                            scan::Event::Probe {
                                target: target.clone(),
                                probe,
                            },
                        )?;
                    }
                    scan::Event::Qualification(qualification) => {
                        Sink::publish(&mut tracked, scan::Event::Qualification(*qualification))?;
                    }
                    _ => {}
                }
                publish(&scan_sink, Event::Scan(event), control)
            }),
            &operation,
        )?;
        let aggregate = tracker.finish(scan_report.clone())?;
        // A scan that sent anything marks now: its probes' wall-clock
        // `sent_at` is evidence, not a pacing input.
        let scan_sent = last_transmission(
            aggregate.stats.packets_attempted > 0,
            std::iter::empty(),
            self.now(),
        );
        let mut stats = scan_report.stats.clone();
        let mut trace_report = None;
        let mut trace_sent = None;
        operation.spent = stats.clone();
        if let Some(stage) = &stage {
            let mut trace_operation = operation.isolated();
            if let Some(runtime) = trace.as_ref().and_then(|trace| trace.runtime.clone()) {
                trace_operation.runtime = runtime;
            }
            let retained = *retained.lock().unwrap_or_else(PoisonError::into_inner);
            let trace_sink = Arc::clone(&sink);
            let streamed = stage.stream(
                self,
                &trace_operation,
                &aggregate,
                retained,
                started,
                scan_sent,
                crate::execution::forwarding(delivery, move |event, control| {
                    publish(&trace_sink, Event::Trace(event), control)
                }),
            )?;
            stats.checked_add_assign(&streamed.report.stats)?;
            trace_sent = streamed.last_sent;
            trace_report = Some(streamed.report);
        }
        // The lookups' sends, bytes, and time count in this scan's reported
        // statistics, and run in the allowance the scan and trace left over.
        operation.spent = stats.clone();
        let reverse_dns = names(
            lookup.as_ref(),
            self,
            &operation,
            &scan_report.hosts,
            started,
            last_transmission(
                stats.packets_attempted > 0,
                scan_sent.into_iter().chain(trace_sent),
                self.now(),
            ),
        )?;
        if let Some(lookups) = reverse_dns
            .as_ref()
            .and_then(|lookups| lookups.stats.as_ref())
        {
            stats.checked_add_assign(lookups)?;
        }
        Ok(Report {
            scan: scan_report,
            endpoints: aggregate.endpoints,
            trace: trace_report,
            reverse_dns,
            stats,
        })
    }

    /// Scans the request's targets with kernel TCP connects, then looks each
    /// responding host up in reverse DNS as the request asks. The lookups'
    /// time is the caller's to add to the connect statistics, which have no
    /// packet counters for the lookups' exchanges.
    pub fn scan_connect_with_followups<S>(
        &self,
        request: ConnectRequest,
        mut sink: S,
    ) -> Result<ConnectReport, Error>
    where
        S: Sink<connect::Event, Ack = ()>,
    {
        let ConnectRequest { scan, reverse_dns } = request;
        let lookup = reverse_dns
            .as_ref()
            .map(|reverse| Lookup::new(reverse, &scan))
            .transpose()?;
        let mut operation = crate::execution::Operation::new(self, scan.limits.max_duration);
        if reverse_dns
            .as_ref()
            .is_some_and(|reverse| reverse.transport != crate::dns::TransportMode::Tcp)
        {
            operation.scan_neighbors(&scan)?;
        }
        let started = self.now();
        // Probe events stream as they settle; the tracker keeps only what
        // each endpoint's inference needs.
        let tracker = connect::Collector::default();
        let mut tracked = tracker.clone();
        let delivery = sink.delivery();
        let report = self.scan_connect_in(
            scan,
            crate::execution::forwarding(delivery, move |event: connect::Event, control| {
                Sink::publish(&mut tracked, event.clone())?;
                match control {
                    Some(control) => sink.publish_controlled(event, control),
                    None => sink.publish(event),
                }
            }),
            &operation,
        )?;
        let aggregate = tracker.finish(report.clone())?;
        // Wall-clock `scheduled_at` is evidence, never pacing: any attempted
        // connection conservatively marks now.
        let reverse_dns = names(
            lookup.as_ref(),
            self,
            &operation,
            &report.hosts,
            started,
            last_transmission(
                report.stats.connections_attempted > 0,
                std::iter::empty(),
                self.now(),
            ),
        )?;
        Ok(ConnectReport {
            scan: report,
            endpoints: aggregate.endpoints,
            reverse_dns,
        })
    }
}

fn publish<S: Sink<Event, Ack = ()>>(
    sink: &Mutex<S>,
    event: Event,
    control: Option<&Deadline>,
) -> Result<(), BoundaryError> {
    let mut sink = sink.lock().unwrap_or_else(PoisonError::into_inner);
    match control {
        Some(control) => sink.publish_controlled(event, control),
        None => sink.publish(event),
    }
}
