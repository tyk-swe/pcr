// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::net::IpAddr;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;

use crate::Sink;
use crate::probe::{Transport, index_or_push};
use crate::scan::{self, Coverage, Error, Measurement, Stage, inference};

use super::model::{
    Aggregate, Classification, Endpoint, Event, ProbeEvidence, Report, Unattributed,
};

#[derive(Default)]
pub struct Collector(Collected);

/// Endpoint identity: the probed endpoint and interface on one address never merge.
pub(in crate::scan) type EndpointKey = (
    IpAddr,
    crate::probe::Endpoint,
    Option<packetcraftr_netio::interface::Id>,
);

/// Classification winners stay keyed by the flattened endpoint parts.
pub(in crate::scan) type WinnerKey = (
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
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.observe(event);
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
        let endpoint_kind = evidence.endpoint;
        let scope = evidence.scope.clone();
        let interface = scope.as_ref().map(|scope| scope.interface.clone());
        let endpoint_index = self
            .endpoint_indices
            .get(&(address, endpoint_kind, interface.clone()))
            .copied()
            .unwrap_or(self.endpoints.len());
        let endpoint = index_or_push(
            &mut self.endpoints,
            &mut self.endpoint_indices,
            (address, endpoint_kind, interface),
            || Endpoint {
                address,
                scope,
                endpoint: endpoint_kind,
                classification: Classification::Timeout,
                port_hint: endpoint_kind
                    .port()
                    .and_then(|port| scan::catalog::hint(endpoint_kind.transport(), port)),
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
        self.finish_inner(report, None)
    }

    /// Finishes with endpoint ordering and inferences already computed from
    /// the same event stream, after checking that they describe the collected
    /// probes.
    pub fn finish_with_inferences(
        self,
        report: Report,
        inferred: Vec<Endpoint>,
    ) -> Result<Aggregate, Error> {
        self.finish_inner(report, Some(inferred))
    }

    fn finish_inner(
        self,
        report: Report,
        inferred: Option<Vec<Endpoint>>,
    ) -> Result<Aggregate, Error> {
        let Collected {
            mut discovery,
            mut endpoints,
            probes,
            undecoded,
            unattributed,
            diagnostics,
            ..
        } = self.0;
        if probes != report.rtt.sent {
            return Err(Error::IncoherentEvents {
                message: format!(
                    "{probes} probe outcome(s) collected for {} sent probe(s)",
                    report.rtt.sent
                ),
            });
        }
        let endpoints = match inferred {
            Some(inferred) => {
                let coherent = endpoints.len() == inferred.len()
                    && endpoints
                        .iter()
                        .zip(&inferred)
                        .all(|(collected, inferred)| {
                            collected.address == inferred.address
                                && collected.scope == inferred.scope
                                && collected.endpoint == inferred.endpoint
                                && collected.probes.len() == inferred.probes.len()
                                && collected.probes.iter().zip(&inferred.probes).all(
                                    |(collected, inferred)| collected.sequence == inferred.sequence,
                                )
                        });
                if !coherent {
                    return Err(Error::IncoherentEvents {
                        message: "scan endpoint inferences do not match the collected events"
                            .into(),
                    });
                }
                inferred
                    .into_iter()
                    .zip(endpoints)
                    .map(|(mut inferred, collected)| {
                        inferred.probes = collected.probes;
                        inferred
                    })
                    .collect()
            }
            None => {
                for endpoint in &mut endpoints {
                    endpoint.probes.sort_by_key(|probe| probe.sequence);
                    endpoint.inference = inference::raw(
                        endpoint.endpoint.transport(),
                        endpoint.probes.iter().map(|probe| inference::Attempt {
                            sequence: probe.sequence,
                            measurement: probe.measurement,
                            tcp_scan: probe.tcp_scan,
                            sctp_scan: probe.sctp_scan,
                            tcp_window: probe.tcp_window,
                        }),
                    );
                }
                endpoints
                    .sort_by_key(|endpoint| endpoint.probes.first().map(|probe| probe.sequence));
                endpoints
            }
        };
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, SystemTime};

    use packetcraftr_core::frame::{Frame, LinkType};

    use super::*;
    use crate::probe::{self, Reply, Status};
    use crate::{Sink, Stats};

    fn evidence(response: Option<Frame>) -> ProbeEvidence {
        ProbeEvidence {
            measurement: scan::Measurement::Response(Reply::TcpSynAck),
            sequence: 7,
            stage: Stage::Scan,
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            scope: None,
            endpoint: probe::Endpoint::Tcp { port: 80 },
            tcp_scan: Some(scan::TcpScan::Syn),
            sctp_scan: None,
            attempt: 1,
            status: Status::Response,
            classification: Classification::Open,
            reply: Some(Reply::TcpSynAck),
            responder: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            sent_at: SystemTime::UNIX_EPOCH,
            received_at: Some(SystemTime::UNIX_EPOCH),
            latency: Some(Duration::from_millis(1)),
            response,
            reason: "syn-ack".to_owned(),
            application: None,
            tcp_window: Some(4096),
        }
    }

    #[test]
    fn inferences_reuse_collected_reply_frames() {
        let frame = Frame::new(None, LinkType(1), &b"reply"[..]).unwrap();
        let mut collector = Collector::default();
        collector
            .publish(Event::Probe {
                target: "192.0.2.1".into(),
                probe: evidence(Some(frame.clone())),
            })
            .unwrap();
        let stripped = evidence(None);
        let inferred = vec![Endpoint {
            address: stripped.address,
            scope: stripped.scope.clone(),
            endpoint: stripped.endpoint,
            classification: stripped.classification,
            port_hint: None,
            inference: None,
            probes: vec![stripped],
        }];
        let report = Report {
            planned_duration: Duration::ZERO,
            target: "192.0.2.1".to_owned(),
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            hosts: Vec::new(),
            counts: Default::default(),
            retained_evidence_bytes: 0,
            stats: Stats::default(),
            rtt: crate::scan::Rtt {
                sent: 1,
                ..Default::default()
            },
            scheduling: Default::default(),
        };

        let aggregate = collector.finish_with_inferences(report, inferred).unwrap();

        assert_eq!(
            aggregate.endpoints[0].probes[0].response.as_ref(),
            Some(&frame)
        );
    }
}
