// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::net::IpAddr;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;

use crate::Sink;
use crate::execution::Shared;
use crate::probe::{Transport, index_or_push};
use crate::scan::{self, Coverage, Error, Measurement, Stage, inference};

use super::model::{
    Aggregate, Classification, Endpoint, Event, ProbeEvidence, Report, Unattributed,
};

#[derive(Clone, Default)]
pub struct Collector(Shared<Collected>);

/// Endpoint identity: TCP, UDP, SCTP, and IP protocol numbers on one address never merge.
pub(in crate::scan) type EndpointKey = (
    IpAddr,
    Transport,
    Option<u16>,
    Option<u8>,
    Option<packetcraftr_netio::interface::Id>,
);

#[derive(Default)]
struct Collected {
    discovery: Vec<ProbeEvidence>,
    endpoints: Vec<Endpoint>,
    endpoint_indices: HashMap<EndpointKey, usize>,
    probes: u64,
    provisional: std::collections::BTreeMap<u64, (Stage, Option<usize>, usize)>,
    undecoded: Vec<Frame>,
    unattributed: Vec<Unattributed>,
    diagnostics: Vec<Diagnostic>,
}

impl Sink<Event> for Collector {
    fn delivery(&self) -> crate::Delivery {
        crate::Delivery::Cooperative
    }

    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|collected| collected.observe(event));
        Ok(())
    }
}

impl Collected {
    fn qualify(&mut self, qualification: scan::Qualification) {
        // Collector residency belongs to its caller. Each provisional sequence
        // is retired once; later scopes never rescan completed history.
        let Self {
            provisional,
            endpoints,
            discovery,
            ..
        } = self;
        let range = qualification.first_sequence()..=qualification.last_sequence();
        for (_, (_, endpoint, probe)) in
            provisional.extract_if(range, |_, (stage, _, _)| *stage == qualification.stage())
        {
            let evidence = match endpoint {
                Some(endpoint) => &mut endpoints[endpoint].probes[probe],
                None => &mut discovery[probe],
            };
            if matches!(
                evidence.measurement,
                Measurement::NoReply(Coverage::Pending)
            ) {
                evidence.measurement = Measurement::NoReply(qualification.coverage());
            }
        }
    }

    fn observe(&mut self, event: Event) {
        match event {
            Event::Sent(_) => {}
            Event::Probe { target: _, probe } => self.observe_probe(probe),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Unattributed(unattributed) => self.unattributed.push(unattributed),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
            Event::Qualification(qualification) => self.qualify(qualification),
        }
    }

    fn observe_probe(&mut self, evidence: ProbeEvidence) {
        self.probes = self.probes.saturating_add(1);
        if evidence.stage == Stage::Discovery {
            if matches!(
                evidence.measurement,
                Measurement::NoReply(Coverage::Pending)
            ) {
                self.provisional.insert(
                    evidence.sequence,
                    (evidence.stage, None, self.discovery.len()),
                );
            }
            self.discovery.push(evidence);
            return;
        }
        let address = evidence.address;
        let transport = evidence.transport;
        let port = evidence.port;
        let ip_protocol = evidence.ip_protocol;
        let scope = evidence.scope.clone();
        let interface = scope.as_ref().map(|scope| scope.interface.clone());
        let endpoint_index = self
            .endpoint_indices
            .get(&(address, transport, port, ip_protocol, interface.clone()))
            .copied()
            .unwrap_or(self.endpoints.len());
        let endpoint = index_or_push(
            &mut self.endpoints,
            &mut self.endpoint_indices,
            (address, transport, port, ip_protocol, interface),
            || Endpoint {
                address,
                scope,
                transport,
                port,
                ip_protocol,
                classification: Classification::Timeout,
                port_hint: port.and_then(|port| scan::catalog::hint(transport, port)),
                inference: None,
                probes: Vec::new(),
            },
        );
        if matches!(
            evidence.measurement,
            Measurement::NoReply(Coverage::Pending)
        ) {
            self.provisional.insert(
                evidence.sequence,
                (evidence.stage, Some(endpoint_index), endpoint.probes.len()),
            );
        }
        endpoint.classification.promote(evidence.classification);
        endpoint.probes.push(evidence);
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let Collected {
            mut discovery,
            mut endpoints,
            probes,
            undecoded,
            unattributed,
            diagnostics,
            ..
        } = self.0.take();
        if probes != report.rtt.sent {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{probes} probe outcome(s) collected for {} sent probe(s)",
                    report.rtt.sent
                ),
            });
        }
        for endpoint in &mut endpoints {
            endpoint.probes.sort_by_key(|probe| probe.sequence);
            endpoint.inference = inference::raw(
                endpoint.transport,
                endpoint.probes.iter().map(|probe| inference::Attempt {
                    sequence: probe.sequence,
                    measurement: probe.measurement,
                    tcp_scan: probe.tcp_scan,
                    sctp_scan: probe.sctp_scan,
                    tcp_window: probe.tcp_window,
                }),
            );
        }
        endpoints.sort_by_key(|endpoint| endpoint.probes.first().map(|probe| probe.sequence));
        discovery.sort_by_key(|probe| probe.sequence);
        scan::discovery::check_probes(&report.hosts, discovery.iter().map(|probe| probe.sequence))?;
        Ok(Aggregate {
            planned_duration: report.planned_duration,
            target: report.target,
            resolved_addresses: report.resolved_addresses,
            hosts: report.hosts,
            discovery,
            endpoints,
            undecoded,
            unattributed,
            diagnostics,
            retained_evidence_bytes: report.retained_evidence_bytes,
            stats: report.stats,
            rtt: report.rtt,
            scheduling: report.scheduling,
        })
    }
}
