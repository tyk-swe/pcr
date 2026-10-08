// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional PTR lookups for scanned hosts. They run through the DNS workflow,
//! so the policy authorizes the server and every query is bounded like any
//! other.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use packetcraftr::dns::{self, batch};
use packetcraftr::scan::discovery::{Host, State};
use packetcraftr_core::budget::Cancellation;

use crate::errors::CliError;
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
    /// Rejects a template no question could use, such as a zero server
    /// port, before the scan sends anything.
    pub(super) fn new(
        server: packetcraftr::target::Target,
        server_port: u16,
        transport: dns::TransportMode,
        scan: &packetcraftr::scan::Request,
    ) -> Result<Self, CliError> {
        let lookup = Self {
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
        };
        lookup
            .question(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                lookup.template.limits.max_duration,
            )
            .map_err(CliError::classified)?
            .validate()
            .map_err(CliError::classified)?;
        Ok(lookup)
    }

    /// Looks up hosts that responded to discovery, or every host when
    /// discovery did not run; a host discovery found silent is not looked
    /// up. Returns one entry per host plus the exchanges' statistics for
    /// the command's own accounting. A failed batch fails its questions
    /// rather than the scan, whose evidence is already measured. The scan's
    /// evidence byte limit bounds the names kept across every lookup.
    pub(super) fn run(
        &self,
        client: &Client,
        hosts: &[Host],
        started: Instant,
    ) -> (Vec<Option<ReverseDns>>, packetcraftr::Stats) {
        let deadline = started.checked_add(self.template.limits.max_duration);
        // A batch paces its own questions; this pause keeps the scan's rate
        // between the scan's last probe and each batch's first question.
        let pause = self
            .template
            .queries_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        batched(
            hosts,
            pause,
            deadline,
            crate::cancellation::signal(),
            self.template.limits.max_evidence_bytes,
            |addresses, remaining| self.lookup(client, addresses, remaining),
        )
    }

    fn lookup(
        &self,
        client: &Client,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> (Vec<ReverseDns>, packetcraftr::Stats) {
        let ended = |status, error: Option<String>| {
            (
                addresses
                    .iter()
                    .map(|address| {
                        ReverseDns::ended(dns::reverse_name(*address), status, error.clone())
                    })
                    .collect(),
                packetcraftr::Stats::default(),
            )
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
            Ok(aggregate) => (
                aggregate
                    .questions
                    .into_iter()
                    .map(ReverseDns::from)
                    .collect(),
                aggregate.stats,
            ),
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

/// Looks `hosts` up in batches spaced by `pause` until `deadline`, keeping
/// their names within `name_budget` bytes. Once `cancellation` fires no batch
/// waits or sends: each remaining question has no time left and is
/// unattempted.
fn batched(
    hosts: &[Host],
    pause: Duration,
    deadline: Option<Instant>,
    cancellation: &Cancellation,
    mut name_budget: usize,
    mut lookup: impl FnMut(&[IpAddr], Duration) -> (Vec<ReverseDns>, packetcraftr::Stats),
) -> (Vec<Option<ReverseDns>>, packetcraftr::Stats) {
    let mut names: Vec<Option<ReverseDns>> = hosts.iter().map(|_| None).collect();
    let mut statistics = packetcraftr::Stats::default();
    let selected: Vec<usize> = hosts
        .iter()
        .enumerate()
        .filter(|(_, host)| host.state != State::NoResponse)
        .map(|(index, _)| index)
        .collect();
    let remaining = || {
        if cancellation.is_cancelled() {
            return Duration::ZERO;
        }
        deadline.map_or(Duration::ZERO, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        })
    };
    for chunk in selected.chunks(batch::MAX_QUESTIONS) {
        let waited = pause.min(remaining());
        if !waited.is_zero() {
            std::thread::sleep(waited);
            statistics.elapsed = statistics.elapsed.saturating_add(waited);
        }
        let addresses: Vec<IpAddr> = chunk.iter().map(|&index| hosts[index].address).collect();
        let (lookups, stats) = lookup(&addresses, remaining());
        for (&index, mut lookup) in chunk.iter().zip(lookups) {
            retain_names(&mut lookup, &mut name_budget);
            names[index] = Some(lookup);
        }
        // A failed batch reports no statistics; the bounded questions
        // cannot overflow these counters.
        let _ = statistics.checked_add_assign(&stats);
    }
    (names, statistics)
}

/// Keeps `lookup`'s names while what they occupy fits `budget`, marking the
/// lookup when later names were dropped.
fn retain_names(lookup: &mut ReverseDns, budget: &mut usize) {
    let kept = lookup
        .names
        .iter()
        .take_while(|name| {
            let held = size_of::<String>().saturating_add(name.len());
            budget
                .checked_sub(held)
                .map(|left| *budget = left)
                .is_some()
        })
        .count();
    if kept < lookup.names.len() {
        lookup.names.truncate(kept);
        lookup.names_truncated = true;
    }
}

/// Each host's lookup by position, or nothing when no server was requested,
/// plus the lookups' exchange statistics.
pub(super) fn names(
    lookup: Option<&Lookup>,
    client: &Client,
    hosts: &[Host],
    started: Instant,
) -> (Vec<Option<ReverseDns>>, packetcraftr::Stats) {
    lookup.map_or_else(Default::default, |lookup| {
        lookup.run(client, hosts, started)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answered(names: &[&str]) -> ReverseDns {
        ReverseDns {
            names: names.iter().map(|name| (*name).to_owned()).collect(),
            ..ReverseDns::ended(
                "10.2.0.192.in-addr.arpa.".to_owned(),
                QuestionStatus::Completed,
                None,
            )
        }
    }

    #[test]
    fn a_cancelled_scan_waits_for_and_sends_no_further_batch() {
        let hosts: Vec<Host> = (0..=batch::MAX_QUESTIONS)
            .map(|index| Host {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(index % 256).unwrap())),
                scope: None,
                state: State::Responded,
                reasons: Vec::new(),
                neighbor: None,
                scan: packetcraftr::scan::discovery::Scan::Scanned,
                probes: Vec::new(),
            })
            .collect();
        let hour = Duration::from_secs(3600);
        let run = |cancellation: &Cancellation, pause| {
            let mut windows = Vec::new();
            let (names, _) = batched(
                &hosts,
                pause,
                Instant::now().checked_add(hour),
                cancellation,
                usize::MAX,
                |addresses, remaining| {
                    windows.push(remaining);
                    let lookups = addresses.iter().map(|_| answered(&[])).collect();
                    (lookups, packetcraftr::Stats::default())
                },
            );
            assert!(
                names.iter().all(Option::is_some),
                "every host keeps a record"
            );
            windows
        };

        let live = run(&Cancellation::default(), Duration::ZERO);
        assert_eq!(live.len(), 2);
        assert!(live.iter().all(|remaining| !remaining.is_zero()));

        // An hour's pause before the second batch would hold the test.
        let cancelled = Cancellation::default();
        cancelled.cancel();
        assert_eq!(run(&cancelled, hour), [Duration::ZERO, Duration::ZERO]);
    }

    #[test]
    fn names_beyond_the_scans_evidence_bytes_are_dropped_and_marked() {
        let held = |name: &str| size_of::<String>() + name.len();
        let mut budget = held("a.example.") + held("b.example.");
        let mut first = answered(&["a.example."]);
        retain_names(&mut first, &mut budget);
        assert_eq!(first.names, ["a.example."]);
        assert!(!first.names_truncated);

        // The budget spans lookups: the next host keeps only what remains.
        let mut second = answered(&["b.example.", "c.example."]);
        retain_names(&mut second, &mut budget);
        assert_eq!(second.names, ["b.example."]);
        assert!(second.names_truncated);
        assert_eq!(budget, 0);

        let mut third = answered(&["d.example."]);
        retain_names(&mut third, &mut budget);
        assert!(third.names.is_empty());
        assert!(third.names_truncated);

        // A lookup without names drops nothing.
        let mut empty = answered(&[]);
        retain_names(&mut empty, &mut budget);
        assert!(!empty.names_truncated);
    }
}
