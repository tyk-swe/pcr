// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Optional PTR lookups for scanned hosts. They run through the DNS workflow,
//! so the policy authorizes the server and every query is bounded like any
//! other.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

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
    /// port or a scoped server, before the scan sends anything.
    pub(super) fn new(
        server: packetcraftr::target::Target,
        server_port: u16,
        transport: dns::TransportMode,
        scan: &packetcraftr::scan::Request,
    ) -> Result<Self, CliError> {
        if let packetcraftr::target::Target::ScopedAddress(scoped) = &server {
            return Err(CliError::classified(dns::Error::ScopedServer {
                server: scoped.to_string(),
            }));
        }
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
        last_sent: Option<SystemTime>,
    ) -> (Vec<Option<ReverseDns>>, packetcraftr::Stats) {
        let deadline = started.checked_add(self.template.limits.max_duration);
        // A batch paces its own questions; this pause keeps the scan's rate
        // between the last transmission before a batch, `last_sent` by the scan
        // or sent by an earlier batch, and the batch's first question.
        let pause = self
            .template
            .queries_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        let authorized = self.authorize(client, hosts);
        // Questions the policy refused are never sent, so no batch waits for
        // them.
        let pause = if authorized.is_ok() {
            pause
        } else {
            Duration::ZERO
        };
        batched(
            hosts,
            pause,
            self.batch_size(),
            last_sent,
            deadline,
            crate::cancellation::signal(),
            self.template.limits.max_evidence_bytes,
            |addresses, remaining| match &authorized {
                Ok(()) => self.lookup(client, addresses, remaining),
                Err(error) => (
                    addresses
                        .iter()
                        .map(|address| {
                            ReverseDns::ended(
                                dns::reverse_name(*address),
                                QuestionStatus::Failed,
                                Some(error.clone()),
                            )
                        })
                        .collect(),
                    packetcraftr::Stats::default(),
                    None,
                ),
            },
        )
    }

    /// Authorizes every lookup `hosts` may need as one operation, so that
    /// splitting them into batches never restarts the policy's packet and
    /// byte budgets.
    fn authorize(&self, client: &Client, hosts: &[Host]) -> Result<(), String> {
        let mut failure = None;
        let questions = hosts
            .iter()
            .filter(|host| host.state != State::NoResponse)
            .map_while(|host| {
                self.question(host.address, self.template.limits.max_duration)
                    .map_err(|error| failure = Some(error.to_string()))
                    .ok()
            });
        let limits = client
            .dns_limits(questions)
            .map_err(|error| error.to_string());
        if let Some(error) = failure {
            return Err(error);
        }
        client
            .policy()
            .authorize(packetcraftr::policy::Operation::Dns(limits?))
            .map_err(|error| error.to_string())
    }

    fn lookup(
        &self,
        client: &Client,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> (Vec<ReverseDns>, packetcraftr::Stats, Option<SystemTime>) {
        let ended = |status, error: Option<String>| {
            (
                addresses
                    .iter()
                    .map(|address| {
                        ReverseDns::ended(dns::reverse_name(*address), status, error.clone())
                    })
                    .collect(),
                packetcraftr::Stats::default(),
                None,
            )
        };
        if remaining.is_zero() {
            return ended(QuestionStatus::Unattempted, None);
        }
        let questions = match self.questions(addresses, remaining) {
            Ok(questions) => questions,
            Err(error) => return ended(QuestionStatus::Failed, Some(error.to_string())),
        };
        let collector = batch::Collector::default();
        match client
            .dns_batch(batch::Request { questions }, collector.clone())
            .and_then(|report| collector.finish(report))
        {
            Ok(aggregate) => {
                let sent = last_batch_send(&aggregate.questions, &aggregate.stats);
                (
                    aggregate
                        .questions
                        .into_iter()
                        .map(ReverseDns::from)
                        .collect(),
                    aggregate.stats,
                    sent,
                )
            }
            // A window too short for one question's planned attempts sends
            // none of them.
            Err(dns::Error::DurationLimit { .. }) => ended(QuestionStatus::Unattempted, None),
            Err(error) => ended(QuestionStatus::Failed, Some(error.to_string())),
        }
    }

    /// One batch's questions. A batch retains every question's evidence
    /// until it ends, so they share the scan's evidence limits rather than
    /// each taking them whole.
    fn questions(
        &self,
        addresses: &[IpAddr],
        remaining: Duration,
    ) -> Result<Vec<dns::Request>, packetcraftr_core::error::BoundaryError> {
        let share = addresses.len().max(1);
        addresses
            .iter()
            .map(|address| {
                self.question(*address, remaining).map(|mut question| {
                    question.limits.max_evidence_frames /= share;
                    question.limits.max_evidence_bytes /= share;
                    question
                })
            })
            .collect()
    }

    /// The most lookups one batch holds, so that each question's share of
    /// the scan's evidence limits still holds a frame.
    fn batch_size(&self) -> usize {
        let limits = &self.template.limits;
        let snap_length = self.template.collection.capture.snap_length.max(1);
        batch::MAX_QUESTIONS
            .min(limits.max_evidence_frames)
            .min(limits.max_evidence_bytes / snap_length)
            .max(1)
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
#[allow(clippy::too_many_arguments)]
fn batched(
    hosts: &[Host],
    pause: Duration,
    batch_size: usize,
    last_sent: Option<SystemTime>,
    deadline: Option<Instant>,
    cancellation: &Cancellation,
    mut name_budget: usize,
    mut lookup: impl FnMut(
        &[IpAddr],
        Duration,
    ) -> (Vec<ReverseDns>, packetcraftr::Stats, Option<SystemTime>),
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
    let mut last_sent = last_sent;
    for chunk in selected.chunks(batch_size) {
        // Only what remains of the pause since the last transmission is owed;
        // its replies' wait already spaced it from this batch.
        let owed = last_sent.map_or(Duration::ZERO, |sent| {
            pause.saturating_sub(SystemTime::now().duration_since(sent).unwrap_or_default())
        });
        let waited = owed.min(remaining());
        if !waited.is_zero() {
            std::thread::sleep(waited);
            statistics.elapsed = statistics.elapsed.saturating_add(waited);
        }
        let addresses: Vec<IpAddr> = chunk.iter().map(|&index| hosts[index].address).collect();
        let (lookups, stats, sent) = lookup(&addresses, remaining());
        // A TCP lookup counts no packets but still reports when it sent.
        if sent.is_some() || stats.packets_attempted > 0 {
            last_sent = Some(sent.unwrap_or_else(SystemTime::now));
        }
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
/// plus the lookups' exchange statistics, absent when no host was looked up.
pub(super) fn names(
    lookup: Option<&Lookup>,
    client: &Client,
    hosts: &[Host],
    started: Instant,
    last_sent: Option<SystemTime>,
) -> (Vec<Option<ReverseDns>>, Option<packetcraftr::Stats>) {
    let Some(lookup) = lookup else {
        return Default::default();
    };
    let (names, stats) = lookup.run(client, hosts, started, last_sent);
    let looked_up = names.iter().any(Option::is_some);
    (names, looked_up.then_some(stats))
}

/// When a batch last sent. A failed question keeps no attempt evidence, so a
/// batch that failed one after sending anything is taken to have sent last as
/// it ended, which spaces the next batch at least as far as its rate needs.
fn last_batch_send(
    questions: &[batch::Question<dns::Aggregate>],
    stats: &packetcraftr::Stats,
) -> Option<SystemTime> {
    let failed = questions
        .iter()
        .any(|question| question.status == batch::QuestionStatus::Failed);
    if failed && (stats.bytes > 0 || stats.packets_attempted > 0) {
        return Some(SystemTime::now());
    }
    questions
        .iter()
        .filter_map(|question| question.result.as_ref())
        .flat_map(dns::Aggregate::attempts)
        .filter_map(dns::AttemptEvidence::sent_at)
        .max()
}

/// When the transmission before the lookups was sent: the latest of `sent`,
/// or now when packets were `attempted` at no known time.
pub(super) fn last_transmission(
    attempted: bool,
    sent: impl IntoIterator<Item = SystemTime>,
) -> Option<SystemTime> {
    attempted.then(|| sent.into_iter().max().unwrap_or_else(SystemTime::now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn responding(count: usize) -> Vec<Host> {
        (0..count)
            .map(|index| Host {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(index % 256).unwrap())),
                scope: None,
                state: State::Responded,
                reasons: Vec::new(),
                neighbor: None,
                scan: packetcraftr::scan::discovery::Scan::Scanned,
                probes: Vec::new(),
            })
            .collect()
    }

    /// A UDP lookup of a documentation server over `link_mode`.
    fn udp_lookup(link_mode: packetcraftr_netio::link::Mode) -> Lookup {
        Lookup {
            template: dns::Request {
                server: packetcraftr::target::Target::Address(IpAddr::V4(Ipv4Addr::new(
                    192, 0, 2, 53,
                ))),
                address_family: packetcraftr::target::Family::Any,
                server_port: dns::DEFAULT_SERVER_PORT,
                source_port: 0,
                query_name: String::new(),
                query_type: dns::QueryType::PTR,
                transaction_id: 0,
                recursion_desired: true,
                edns: None,
                transport: dns::TransportMode::Udp,
                attempts: 1,
                timeout: Duration::from_millis(20),
                queries_per_second: None,
                limits: dns::Limits::default(),
                route: packetcraftr::route::Options {
                    link_mode,
                    ..packetcraftr::route::Options::default()
                },
                collection: packetcraftr::exchange::Collection::default(),
            },
        }
    }

    fn packet_budget(packets: usize) -> packetcraftr::policy::Policy {
        packetcraftr::policy::Policy {
            max_packets_per_operation: u64::try_from(packets).unwrap(),
            ..packetcraftr::policy::Policy::default()
        }
    }

    /// A client whose policy allows `packets` per operation and whose
    /// resolver sends up to `neighbor_attempts` requests per resolution.
    fn budget_client(packets: usize, neighbor_attempts: u32) -> Client {
        crate::system::client(
            packetcraftr_core::protocol::builtin::registry(),
            packet_budget(packets),
            crate::system::Runtime::Client,
        )
        .with_neighbor_options(packetcraftr::neighbor::Options {
            max_attempts: neighbor_attempts,
            ..packetcraftr::neighbor::Options::default()
        })
        .expect("valid resolver options")
    }

    #[test]
    fn every_batch_of_lookups_shares_one_policy_budget() {
        let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
        let client = budget_client(batch::MAX_QUESTIONS, 3);
        assert_eq!(
            lookup.authorize(&client, &responding(batch::MAX_QUESTIONS)),
            Ok(())
        );
        // Two batches, each within the budget alone, exceed it together.
        assert!(
            lookup
                .authorize(&client, &responding(2 * batch::MAX_QUESTIONS))
                .is_err()
        );
    }

    #[test]
    fn link_layer_lookups_budget_every_neighbor_attempt_per_query() {
        let lookup = udp_lookup(packetcraftr_netio::link::Mode::Auto);
        // Enough for the queries alone, not for the requests before each.
        let budget = batch::MAX_QUESTIONS;
        for (attempts, fits) in [(1, budget / 2), (3, budget / 4)] {
            let client = budget_client(budget, attempts);
            assert_eq!(
                lookup.authorize(&client, &responding(fits)),
                Ok(()),
                "{attempts}"
            );
            assert!(
                lookup.authorize(&client, &responding(fits + 1)).is_err(),
                "{attempts}"
            );
        }
    }

    #[test]
    fn hosts_that_never_responded_report_no_lookup_statistics() {
        let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
        let client = crate::system::client(
            packetcraftr_core::protocol::builtin::registry(),
            packet_budget(1),
            crate::system::Runtime::Client,
        );
        let silent: Vec<Host> = responding(2)
            .into_iter()
            .map(|host| Host {
                state: State::NoResponse,
                ..host
            })
            .collect();
        let (records, stats) = names(
            Some(&lookup),
            &client,
            &silent,
            Instant::now(),
            Some(SystemTime::now()),
        );
        assert_eq!(records, [None, None]);
        assert_eq!(stats, None, "no lookup ran, so none has statistics");
        // A refused lookup still leaves a record, and its statistics.
        let (records, stats) = names(
            Some(&lookup),
            &client,
            &responding(1),
            Instant::now(),
            Some(SystemTime::now()),
        );
        assert!(records[0].is_some());
        assert!(stats.is_some());
    }

    #[test]
    fn refused_lookups_wait_for_no_batch() {
        let mut lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
        lookup.template.queries_per_second = Some(1);
        // The policy refuses the lookups, so nothing is sent.
        let client = crate::system::client(
            packetcraftr_core::protocol::builtin::registry(),
            packet_budget(1),
            crate::system::Runtime::Client,
        );
        let (names, stats) = lookup.run(
            &client,
            &responding(batch::MAX_QUESTIONS + 1),
            Instant::now(),
            Some(SystemTime::now()),
        );
        assert!(
            names
                .iter()
                .flatten()
                .all(|name| name.status == QuestionStatus::Failed)
        );
        assert_eq!(
            stats.elapsed,
            Duration::ZERO,
            "no batch waits for questions that are never sent"
        );
    }

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
    fn a_batch_waits_only_what_remains_of_the_pause() {
        let hour = Duration::from_secs(3600);
        let waited = |last_sent, pause| {
            let (_, stats) = batched(
                &responding(1),
                pause,
                batch::MAX_QUESTIONS,
                last_sent,
                Instant::now().checked_add(hour),
                &Cancellation::default(),
                usize::MAX,
                |addresses, _| {
                    let lookups = addresses.iter().map(|_| answered(&[])).collect();
                    (lookups, packetcraftr::Stats::default(), None)
                },
            );
            stats.elapsed
        };

        let pause = Duration::from_millis(50);
        assert_eq!(waited(None, pause), Duration::ZERO);
        // A transmission a whole pause ago, such as a probe whose reply took
        // that long, already satisfied the rate.
        assert_eq!(
            waited(SystemTime::now().checked_sub(pause), pause),
            Duration::ZERO
        );
        let owed = waited(Some(SystemTime::now()), pause);
        assert!(!owed.is_zero() && owed <= pause, "{owed:?}");
    }

    #[test]
    fn a_batch_counting_no_packets_still_spaces_the_next_from_its_sends() {
        let hosts = responding(batch::MAX_QUESTIONS + 1);
        let pause = Duration::from_millis(50);
        let (_, stats) = batched(
            &hosts,
            pause,
            batch::MAX_QUESTIONS,
            None,
            Instant::now().checked_add(Duration::from_secs(60)),
            &Cancellation::default(),
            usize::MAX,
            // A TCP lookup reports its send but no packets.
            |addresses, _| {
                let lookups = addresses.iter().map(|_| answered(&[])).collect();
                (
                    lookups,
                    packetcraftr::Stats::default(),
                    Some(SystemTime::now()),
                )
            },
        );
        assert!(
            stats.elapsed > Duration::ZERO,
            "the second batch waits for the first's send"
        );
    }

    #[test]
    fn a_window_too_short_for_one_question_leaves_its_lookups_unattempted() {
        let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
        let client = budget_client(batch::MAX_QUESTIONS, 1);
        let addresses = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))];
        let (records, stats, sent) = lookup.lookup(&client, &addresses, Duration::from_millis(1));
        assert_eq!(
            records[0].status,
            QuestionStatus::Unattempted,
            "{:?}",
            records[0]
        );
        assert_eq!((stats.packets_attempted, sent), (0, None));
    }

    #[test]
    fn a_batchs_questions_share_the_scans_evidence_limits() {
        let mut lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
        let snap_length = lookup.template.collection.capture.snap_length;
        lookup.template.limits.max_evidence_frames = 1_000;
        lookup.template.limits.max_evidence_bytes = 4 * snap_length;
        assert_eq!(lookup.batch_size(), 4, "each share still holds a frame");
        lookup.template.limits.max_evidence_bytes = 1_000 * snap_length;
        lookup.template.limits.max_evidence_frames = 3;
        assert_eq!(lookup.batch_size(), 3);

        lookup.template.limits.max_evidence_frames = 1_000;
        let addresses: Vec<IpAddr> = (1..=4)
            .map(|host| IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)))
            .collect();
        let questions = lookup
            .questions(&addresses, Duration::from_secs(1))
            .expect("questions build");
        let frames: usize = questions.iter().map(|q| q.limits.max_evidence_frames).sum();
        let bytes: usize = questions.iter().map(|q| q.limits.max_evidence_bytes).sum();
        assert_eq!((frames, bytes), (1_000, 1_000 * snap_length));
    }

    #[test]
    fn a_question_that_failed_after_sending_paces_from_the_batchs_end() {
        let failed = batch::Question::<dns::Aggregate> {
            query_name: dns::reverse_name(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            query_type: dns::QueryType::PTR,
            transaction_id: 0,
            status: batch::QuestionStatus::Failed,
            result: None,
            error: None,
        };
        let before = SystemTime::now();
        let sent_tcp = packetcraftr::Stats {
            bytes: 64,
            ..packetcraftr::Stats::default()
        };
        let sent = last_batch_send(std::slice::from_ref(&failed), &sent_tcp);
        assert!(sent.is_some_and(|sent| sent >= before), "{sent:?}");
        assert_eq!(
            last_batch_send(&[failed], &packetcraftr::Stats::default()),
            None,
            "a question that failed before sending paces nothing"
        );
    }

    #[test]
    fn a_cancelled_scan_waits_for_and_sends_no_further_batch() {
        let hosts = responding(batch::MAX_QUESTIONS + 1);
        let hour = Duration::from_secs(3600);
        let run = |cancellation: &Cancellation, pause| {
            let mut windows = Vec::new();
            let (names, _) = batched(
                &hosts,
                pause,
                batch::MAX_QUESTIONS,
                Some(SystemTime::now()),
                Instant::now().checked_add(hour),
                cancellation,
                usize::MAX,
                |addresses, remaining| {
                    windows.push(remaining);
                    let lookups = addresses.iter().map(|_| answered(&[])).collect();
                    (lookups, packetcraftr::Stats::default(), None)
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
