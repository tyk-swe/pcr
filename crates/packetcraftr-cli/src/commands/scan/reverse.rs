// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional PTR lookups for scanned hosts. They run through the DNS workflow,
//! so the policy authorizes the server and every query is bounded like any
//! other.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use packetcraftr::dns::{self, batch};
use packetcraftr::scan::discovery::{Host, State};

use crate::output::dns::QuestionStatus;
use crate::output::scan::host::ReverseDns;
use crate::system::Client;

/// One server for every question. The scan's attempts, timeout, rate, and
/// evidence limits bound each question, and its `--max-duration` bounds the
/// lookups together with the scan.
#[derive(Clone, Debug)]
pub(super) struct Lookup {
    template: dns::Request,
}

impl Lookup {
    pub(super) fn new(
        server: packetcraftr::target::Target,
        server_port: u16,
        transport: dns::TransportMode,
        scan: &packetcraftr::scan::Request,
    ) -> Self {
        Self {
            template: dns::Request {
                server,
                address_family: packetcraftr::target::Family::Any,
                server_port,
                source_port: 0,
                query_name: String::new(),
                query_type: dns::QueryType::PTR,
                transaction_id: 0,
                recursion_desired: true,
                edns: None,
                transport,
                attempts: scan.attempts,
                timeout: scan.timeout,
                queries_per_second: scan.probes_per_second,
                limits: dns::Limits {
                    message: dns::MessageLimits::default(),
                    max_evidence_frames: scan.limits.max_evidence_frames,
                    max_evidence_bytes: scan.limits.max_evidence_bytes,
                    max_undecoded: scan.limits.max_undecoded,
                    max_duration: scan.limits.max_duration,
                },
                route: scan.route.clone(),
                collection: scan.collection.clone(),
            },
        }
    }

    /// Looks up hosts that responded to discovery, or every host when
    /// discovery did not run; a host discovery found silent is not looked
    /// up. Returns one entry per host. A failed batch fails its questions
    /// rather than the scan, whose evidence is already measured.
    pub(super) fn run(
        &self,
        client: &Client,
        hosts: &[Host],
        started: Instant,
    ) -> Vec<Option<ReverseDns>> {
        let deadline = started.checked_add(self.template.limits.max_duration);
        let mut names: Vec<Option<ReverseDns>> = hosts.iter().map(|_| None).collect();
        let selected: Vec<usize> = hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| host.state != State::NoResponse)
            .map(|(index, _)| index)
            .collect();
        // A batch paces its own questions; this pause keeps the scan's rate
        // between the scan's last probe and each batch's first question.
        let pause = self
            .template
            .queries_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        let remaining = || {
            deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            })
        };
        for chunk in selected.chunks(batch::MAX_QUESTIONS) {
            std::thread::sleep(pause.min(remaining()));
            let remaining = remaining();
            let addresses: Vec<IpAddr> = chunk.iter().map(|&index| hosts[index].address).collect();
            for (&index, lookup) in chunk.iter().zip(self.lookup(client, &addresses, remaining)) {
                names[index] = Some(lookup);
            }
        }
        names
    }

    fn lookup(
        &self,
        client: &Client,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> Vec<ReverseDns> {
        let ended = |status, error: Option<String>| {
            addresses
                .iter()
                .map(|address| {
                    ReverseDns::ended(dns::reverse_name(*address), status, error.clone())
                })
                .collect()
        };
        if remaining.is_zero() {
            return ended(QuestionStatus::Unattempted, None);
        }
        let questions = match addresses
            .iter()
            .map(|address| self.question(*address, remaining))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(questions) => questions,
            Err(error) => return ended(QuestionStatus::Failed, Some(error.to_string())),
        };
        let collector = batch::Collector::default();
        match client
            .dns_batch(batch::Request { questions }, collector.clone())
            .and_then(|report| collector.finish(report))
        {
            Ok(aggregate) => aggregate
                .questions
                .into_iter()
                .map(ReverseDns::from)
                .collect(),
            Err(error) => ended(QuestionStatus::Failed, Some(error.to_string())),
        }
    }

    fn question(
        &self,
        address: IpAddr,
        max_duration: Duration,
    ) -> Result<dns::Request, packetcraftr_core::error::BoundaryError> {
        let source_port = if self.template.transport == dns::TransportMode::Tcp {
            0
        } else {
            dns::unpredictable_source_port()?
        };
        Ok(dns::Request {
            query_name: dns::reverse_name(address),
            transaction_id: dns::unpredictable_transaction_id()?,
            source_port,
            limits: dns::Limits {
                max_duration,
                ..self.template.limits
            },
            ..self.template.clone()
        })
    }
}

/// Each host's lookup by position, or nothing when no server was requested.
pub(super) fn names(
    lookup: Option<&Lookup>,
    client: &Client,
    hosts: &[Host],
    started: Instant,
) -> Vec<Option<ReverseDns>> {
    lookup.map_or_else(Vec::new, |lookup| lookup.run(client, hosts, started))
}
