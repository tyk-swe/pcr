// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The optional trace stage of a scan: every scanned host, traced under one
//! plan with the probes the scan saw it answer.

use std::time::{Duration, Instant};

use packetcraftr::probe::Transport;
use packetcraftr::target::{ScopedAddress, Selection, Specification, Target};
use packetcraftr::traceroute::hosts;

use crate::commands::traceroute::arguments::Strategy;
use crate::errors::CliError;
use crate::output;
use crate::system::Client;
use packetcraftr_core::error::Kind;

/// The `--traceroute-*` options.
pub(super) struct Options {
    pub(super) strategy: Option<Strategy>,
    pub(super) port: Option<u16>,
    pub(super) first_hop: u8,
    pub(super) max_hops: u8,
    pub(super) attempts: u32,
    pub(super) max_probes: usize,
    pub(super) reuse_max_age: Option<Duration>,
}

/// The trace request every scanned host shares, validated before any probe.
pub(super) struct Stage {
    template: hosts::Request,
    plan: output::traceroute::hosts::Plan,
}

/// The evidence the scan already holds against the shared budget, as scalar
/// counts: streaming keeps the counts even though its tracker strips the
/// matched response frames. Retained bytes stay authoritative on
/// `scan::Aggregate::retained_evidence_bytes`.
#[derive(Clone, Copy, Default)]
pub(super) struct Retained {
    frames: usize,
    undecoded: usize,
}

impl Retained {
    /// Counts the retained evidence a complete aggregate describes: the
    /// matched response frames, the undecoded frames, and the unattributed
    /// frames. A host's probe references name the same discovery evidence and
    /// are not counted again.
    fn of(scan: &packetcraftr::scan::Aggregate) -> Self {
        Self {
            frames: scan
                .discovery
                .iter()
                .chain(scan.endpoints.iter().flat_map(|endpoint| &endpoint.probes))
                .filter(|probe| probe.response.is_some())
                .count()
                .saturating_add(scan.undecoded.len())
                .saturating_add(scan.unattributed.len()),
            undecoded: scan.undecoded.len(),
        }
    }

    /// Counts one published scan event's retained evidence: a probe's
    /// response frame, or one undecoded or unattributed frame. A metadata
    /// `reply` without a `response` frame holds none, and `Sent` and
    /// `Diagnostic` events retain nothing.
    pub(super) fn observe(&mut self, event: &packetcraftr::scan::Event) {
        match event {
            packetcraftr::scan::Event::Probe { probe, .. } if probe.response.is_some() => {
                self.frames = self.frames.saturating_add(1);
            }
            packetcraftr::scan::Event::Undecoded { .. } => {
                self.frames = self.frames.saturating_add(1);
                self.undecoded = self.undecoded.saturating_add(1);
            }
            packetcraftr::scan::Event::Unattributed { .. } => {
                self.frames = self.frames.saturating_add(1);
            }
            _ => {}
        }
    }
}

/// What one run of the stage published.
pub(super) struct Traced {
    pub(super) aggregate: hosts::Aggregate,
    pub(super) last_sent: Option<Instant>,
}

pub(super) struct Streamed {
    pub(super) report: hosts::Report,
    pub(super) last_sent: Option<Instant>,
}

impl Stage {
    pub(super) fn new(
        options: &Options,
        scan: &packetcraftr::scan::Request,
    ) -> Result<Self, CliError> {
        let strategy = match (options.strategy, options.port) {
            (None, Some(_)) => {
                return Err(CliError::new(
                    Kind::Usage,
                    "--traceroute-port requires --traceroute-strategy",
                ));
            }
            (None, None) => None,
            (Some(strategy), port) => {
                let transport = Transport::from(strategy);
                let destination_port = match transport {
                    Transport::Udp => {
                        Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_UDP_PORT))
                    }
                    Transport::Tcp => {
                        Some(port.unwrap_or(packetcraftr::traceroute::DEFAULT_TCP_PORT))
                    }
                    Transport::Icmp => {
                        if port.is_some() {
                            return Err(CliError::new(
                                Kind::Usage,
                                "--traceroute-port does not apply to portless ICMP",
                            ));
                        }
                        None
                    }
                };
                Some(hosts::Strategy {
                    transport,
                    destination_port,
                })
            }
        };
        let template = hosts::Request {
            targets: scan.targets.clone(),
            max_targets: scan.limits.max_targets,
            address_family: scan.address_family,
            strategy,
            observed: Vec::new(),
            source_port: None,
            payload_size: 0,
            dont_fragment: false,
            dscp: 0,
            first_hop: options.first_hop,
            max_hops: options.max_hops,
            probes_per_hop: options.attempts,
            timeout: scan.timeout,
            probes_per_second: scan.probes_per_second,
            paced_after: None,
            reuse: options
                .reuse_max_age
                .map(|max_age| hosts::Reuse { max_age }),
            limits: packetcraftr::traceroute::Limits {
                max_probes: options.max_probes,
                max_duration: scan.limits.max_duration,
                max_evidence_frames: scan.limits.max_evidence_frames,
                max_evidence_bytes: scan.limits.max_evidence_bytes,
                max_undecoded: scan.limits.max_undecoded,
            },
            route: scan.route.clone(),
            collection: scan.collection.clone(),
        };
        template.validate().map_err(CliError::classified)?;
        let plan = output::traceroute::hosts::Plan {
            first_hop: options.first_hop,
            max_hops: options.max_hops,
            attempts: options.attempts,
            max_probes: options.max_probes,
            strategy: strategy.map(|strategy| output::traceroute::hosts::StrategyPlan {
                strategy: strategy.transport,
                destination_port: strategy.destination_port,
            }),
            reuse: options
                .reuse_max_age
                .map(|max_age| output::traceroute::hosts::ReusePlan { max_age }),
        };
        Ok(Self { template, plan })
    }

    pub(super) const fn plan(&self) -> output::traceroute::hosts::Plan {
        self.plan
    }

    /// Takes the route and collection the prepared workflow selected, then
    /// revalidates the finalized template: a queue or evidence configuration
    /// the trace cannot run under fails before the scan sends a probe.
    pub(super) fn with_workflow(
        mut self,
        route: packetcraftr::route::Options,
        collection: packetcraftr::exchange::Collection,
    ) -> Result<Self, CliError> {
        self.template.route = route;
        self.template.collection = collection;
        self.template.validate().map_err(CliError::classified)?;
        Ok(self)
    }

    /// The request for the scan's hosts: one exact declaration each, in host
    /// order, the scan's own observations, what remains of its duration, and
    /// the evidence budget the scan has not already retained.
    fn request(
        &self,
        scan: &packetcraftr::scan::Aggregate,
        retained: Retained,
        started: Instant,
        last_sent: Option<Instant>,
    ) -> Result<hosts::Request, CliError> {
        let include = scan
            .hosts
            .iter()
            .map(|host| {
                Ok(Specification::from(match (&host.scope, host.address) {
                    (Some(scope), std::net::IpAddr::V6(address)) => Target::ScopedAddress(
                        ScopedAddress::new(address, scope.zone.clone())
                            .map_err(CliError::classified)?,
                    ),
                    _ => Target::Address(host.address),
                }))
            })
            .collect::<Result<_, CliError>>()?;
        let observed = hosts::observed(scan);
        let covered: std::collections::HashSet<_> =
            observed.iter().map(|observed| observed.address).collect();
        // A host only sends trace probes when it is unscoped and an
        // observation or the fallback strategy covers it. When no host can
        // send, the trace retains nothing, so the scan's evidence stays
        // available to report the not_traced outcomes instead of erroring.
        let sends = scan.hosts.iter().any(|host| {
            host.scope.is_none()
                && (covered.contains(&host.address) || self.template.strategy.is_some())
        });
        let (limits, collection) = if sends {
            let limits = packetcraftr::traceroute::Limits {
                max_evidence_frames: self
                    .template
                    .limits
                    .max_evidence_frames
                    .saturating_sub(retained.frames),
                max_evidence_bytes: self
                    .template
                    .limits
                    .max_evidence_bytes
                    .saturating_sub(scan.retained_evidence_bytes),
                max_undecoded: self
                    .template
                    .limits
                    .max_undecoded
                    .saturating_sub(retained.undecoded),
                ..self.template.limits
            };
            let limits = packetcraftr::traceroute::Limits {
                max_undecoded: limits.max_undecoded.min(limits.max_evidence_frames),
                ..limits
            };
            // The queues keep only what the shared budget leaves, never more
            // than the workflow configured.
            let mut collection = self.template.collection.clone();
            collection.capture.max_frames = collection
                .capture
                .max_frames
                .min(limits.max_evidence_frames);
            collection.capture.max_bytes =
                collection.capture.max_bytes.min(limits.max_evidence_bytes);
            collection.max_responses = collection.max_responses.min(collection.capture.max_frames);
            collection.max_unmatched_frames = collection
                .max_unmatched_frames
                .min(collection.capture.max_frames);
            (limits, collection)
        } else {
            (self.template.limits, self.template.collection.clone())
        };
        // The marker is monotonic from the sending stage: a scan that sent
        // anything marks now, so the first trace batch conservatively owes a
        // full --rate interval.
        let request = hosts::Request {
            targets: Selection {
                include,
                exclude: Vec::new(),
            },
            observed,
            paced_after: last_sent,
            limits: packetcraftr::traceroute::Limits {
                max_duration: limits
                    .max_duration
                    .saturating_sub(started.elapsed())
                    .max(Duration::from_nanos(1)),
                ..limits
            },
            collection,
            ..self.template.clone()
        };
        request.validate().map_err(CliError::classified)?;
        Ok(request)
    }

    pub(super) fn collect(
        &self,
        client: &Client,
        scan: &packetcraftr::scan::Aggregate,
        started: Instant,
        last_sent: Option<Instant>,
    ) -> Result<Traced, CliError> {
        let request = self.request(scan, Retained::of(scan), started, last_sent)?;
        let collector = hosts::Collector::default();
        let report = client
            .trace_hosts(request, collector.clone())
            .map_err(CliError::classified)?;
        let aggregate = collector.finish(report).map_err(CliError::classified)?;
        // A probe's wire time is wall-clock evidence, not a pacing marker:
        // anything sent conservatively marks the trace's end.
        let last_sent = (aggregate.stats.packets_attempted > 0).then(Instant::now);
        Ok(Traced {
            aggregate,
            last_sent,
        })
    }

    pub(super) fn stream(
        &self,
        client: &Client,
        scan: &packetcraftr::scan::Aggregate,
        retained: Retained,
        started: Instant,
        last_sent: Option<Instant>,
        emit: impl FnMut(hosts::Event) -> Result<(), packetcraftr_core::error::BoundaryError>
        + Send
        + 'static,
    ) -> Result<Streamed, CliError> {
        let request = self.request(scan, retained, started, last_sent)?;
        let latest = std::sync::Arc::new(std::sync::Mutex::new(None::<Instant>));
        let observed = std::sync::Arc::clone(&latest);
        let mut emit = emit;
        let report = client
            .trace_hosts(request, move |event: hosts::Event| {
                // The probe's wall-clock sent_at is evidence, not a pacing
                // marker: the monotonic marker is when its event settled.
                if let hosts::Event::Probe(_) = &event {
                    let mut latest = observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *latest = Some(Instant::now());
                }
                emit(event)
            })
            .map_err(CliError::classified)?;
        let last_sent = *latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(Streamed { report, last_sent })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr::Stats;
    use packetcraftr::scan;
    use packetcraftr::scan::discovery::{Host, Scan, State};
    use packetcraftr_core::frame::{Frame, LinkType};

    use super::*;

    fn scan_request() -> packetcraftr::scan::Request {
        packetcraftr::scan::Request {
            max_in_flight: 1,
            targets: Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).into(),
            target_sources: Vec::new(),
            endpoints: vec![packetcraftr::probe::ProbeEndpoint::Icmp],
            discovery: Default::default(),
            adaptive: None,
            udp_payload: Default::default(),
            udp_profiles: Default::default(),
            address_family: packetcraftr::target::Family::Any,
            attempts: 1,
            timeout: Duration::from_millis(100),
            probes_per_second: Some(10),
            limits: packetcraftr::scan::Limits {
                max_duration: Duration::from_secs(60),
                ..Default::default()
            },
            route: Default::default(),
            collection: Default::default(),
        }
    }

    fn options() -> Options {
        Options {
            strategy: Some(Strategy::Icmp),
            port: None,
            first_hop: 1,
            max_hops: 8,
            attempts: 1,
            max_probes: 1000,
            reuse_max_age: Some(Duration::from_secs(5)),
        }
    }

    fn host(address: IpAddr, scope: Option<packetcraftr::target::ResolvedZone>) -> Host {
        Host {
            address,
            scope,
            state: State::Responded,
            reasons: Vec::new(),
            neighbor: None,
            scan: Scan::Scanned,
            probes: Vec::new(),
        }
    }

    fn frame(byte: u8) -> Frame {
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte, 0, 0, 20]).expect("fixture frame")
    }

    fn probe_evidence(
        sequence: u64,
        address: IpAddr,
        reply: Option<scan::Reply>,
    ) -> scan::ProbeEvidence {
        // The evidence names the probe it could have answered.
        let (transport, port) = match reply {
            Some(scan::Reply::IcmpEchoReply) => (Transport::Icmp, None),
            _ => (Transport::Tcp, Some(80)),
        };
        scan::ProbeEvidence {
            sequence,
            stage: scan::Stage::Scan,
            address,
            scope: None,
            transport,
            port,
            attempt: 1,
            status: if reply.is_some() {
                packetcraftr::probe::ProbeStatus::Response
            } else {
                packetcraftr::probe::ProbeStatus::Timeout
            },
            classification: scan::Classification::Open,
            reply,
            responder: reply.map(|_| address),
            sent_at: UNIX_EPOCH,
            received_at: reply.map(|_| UNIX_EPOCH),
            latency: None,
            response: reply.map(|_| frame(0x45)),
            reason: String::new(),
            application: None,
        }
    }

    fn endpoint(address: IpAddr, probes: Vec<scan::ProbeEvidence>) -> scan::Endpoint {
        scan::Endpoint {
            address,
            scope: None,
            transport: Transport::Tcp,
            port: Some(80),
            classification: scan::Classification::Open,
            port_hint: None,
            inference: None,
            probes,
        }
    }

    fn aggregate(
        hosts: Vec<Host>,
        discovery: Vec<scan::ProbeEvidence>,
        endpoints: Vec<scan::Endpoint>,
        undecoded: Vec<Frame>,
        unattributed: Vec<scan::Unattributed>,
        retained_evidence_bytes: usize,
    ) -> scan::Aggregate {
        scan::Aggregate {
            planned_duration: Duration::ZERO,
            target: String::new(),
            resolved_addresses: Vec::new(),
            hosts,
            discovery,
            endpoints,
            undecoded,
            unattributed,
            diagnostics: Vec::new(),
            retained_evidence_bytes,
            stats: Stats::default(),
            rtt: scan::Rtt::default(),
            scheduling: Default::default(),
        }
    }

    #[test]
    fn the_request_follows_the_scan_hosts_and_what_remains_of_its_duration() {
        let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
        let zone = packetcraftr::target::ResolvedZone {
            zone: "eth0".parse().unwrap(),
            interface: packetcraftr_netio::interface::Id {
                name: "eth0".to_owned(),
                index: 2,
            },
        };
        let aggregate = aggregate(
            vec![
                host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None),
                host("fe80::1".parse().unwrap(), Some(zone)),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );
        let started = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("an instant ten seconds ago");

        let request = stage
            .request(
                &aggregate,
                Retained::of(&aggregate),
                started,
                Some(Instant::now()),
            )
            .expect("a request");

        let include: Vec<_> = request
            .targets
            .include
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(include, ["192.0.2.7", "fe80::1%eth0"]);
        assert!(request.paced_after.is_some());
        assert!(request.limits.max_duration <= Duration::from_secs(50));
        assert!(request.limits.max_duration > Duration::from_secs(49));
        assert_eq!(request.max_targets, scan_request().limits.max_targets);
        assert_eq!(
            request.strategy,
            Some(hosts::Strategy {
                transport: Transport::Icmp,
                destination_port: None
            })
        );
    }

    #[test]
    fn a_spent_duration_leaves_the_trace_a_typed_limit_to_fail() {
        let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
        let started = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .expect("an instant an hour ago");
        let aggregate = aggregate(
            vec![host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );

        let request = stage
            .request(&aggregate, Retained::of(&aggregate), started, None)
            .unwrap();

        assert_eq!(request.limits.max_duration, Duration::from_nanos(1));
        assert!(request.paced_after.is_none());
    }

    #[test]
    fn the_trace_request_deducts_the_scans_retained_evidence() {
        let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        // The host record names the same discovery probe; it must not be
        // charged twice.
        let mut scanned = host(address, None);
        scanned.probes = vec![0];
        let discovery = vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))];
        let aggregate = aggregate(
            vec![scanned],
            discovery,
            vec![endpoint(
                address,
                vec![probe_evidence(1, address, Some(scan::Reply::TcpReset))],
            )],
            vec![frame(0x02)],
            vec![scan::Unattributed {
                attribution: scan::Attribution::Late,
                sequence: Some(1),
                frame: frame(0x03),
            }],
            1_024,
        );
        let limits = stage.template.limits;
        let template = stage.template.collection.clone();

        let request = stage
            .request(&aggregate, Retained::of(&aggregate), Instant::now(), None)
            .expect("the narrowed request validates");

        // Two answered probes, one undecoded frame, one unattributed frame.
        assert_eq!(
            request.limits.max_evidence_frames,
            limits.max_evidence_frames - 4
        );
        assert_eq!(
            request.limits.max_evidence_bytes,
            limits.max_evidence_bytes - 1_024
        );
        assert_eq!(request.limits.max_undecoded, limits.max_undecoded - 1);
        assert!(request.limits.max_undecoded <= request.limits.max_evidence_frames);
        assert_eq!(
            request.collection.capture.max_frames,
            request.limits.max_evidence_frames
        );
        assert_eq!(
            request.collection.capture.max_bytes,
            request.limits.max_evidence_bytes
        );
        assert!(request.collection.max_responses <= request.collection.capture.max_frames);
        assert!(request.collection.max_unmatched_frames <= request.collection.capture.max_frames);
        // The collection is narrowed, never widened; snap/decode sizes stay.
        assert!(request.collection.capture.max_frames <= template.capture.max_frames);
        assert_eq!(
            request.collection.capture.snap_length,
            template.capture.snap_length
        );
        assert!(request.validate().is_ok());
    }

    #[test]
    fn an_exhausted_evidence_budget_fails_with_a_typed_limit_before_tracing() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        // Scan and trace share the queue: the template pairs a four-frame
        // evidence budget with a four-frame collection, like the CLI builds.
        let mut scan = scan_request();
        scan.limits.max_evidence_frames = 4;
        scan.limits.max_undecoded = 4;
        scan.collection.capture.max_frames = 4;
        scan.collection.max_responses = 4;
        scan.collection.max_unmatched_frames = 4;
        let held = |count: usize| {
            aggregate(
                vec![host(address, None)],
                vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))],
                Vec::new(),
                (0..count).map(|byte| frame(byte as u8 + 1)).collect(),
                Vec::new(),
                0,
            )
        };
        for (options, held_frames, name) in [
            (
                Options {
                    attempts: 3,
                    ..options()
                },
                2usize,
                "fewer frames left than one hop's responses",
            ),
            (options(), 4usize, "no frames left"),
        ] {
            let stage = Stage::new(&options, &scan).expect("the template itself is valid");
            let aggregate = held(held_frames);
            let error = stage
                .request(&aggregate, Retained::of(&aggregate), Instant::now(), None)
                .expect_err("the trace cannot retain a hop's responses");
            assert_eq!(
                error.classification.code, "cli.traceroute_limit",
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn a_byte_budget_under_one_snap_length_is_rejected() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        // The scan's retained frames leave less than one snapshot length.
        let retained = scan_request().limits.max_evidence_bytes
            - (scan_request().collection.capture.snap_length - 1);
        let stage = Stage::new(&options(), &scan_request()).expect("the template itself is valid");
        let aggregate = aggregate(
            vec![host(address, None)],
            vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            retained,
        );

        let error = stage
            .request(&aggregate, Retained::of(&aggregate), Instant::now(), None)
            .expect_err("no response fits inside the remaining bytes");

        assert_eq!(error.classification.kind, Kind::Usage, "{error}");
    }

    #[test]
    fn an_untraceable_scan_keeps_the_whole_evidence_budget() {
        let mut silent = options();
        silent.strategy = None;
        let stage = Stage::new(&silent, &scan_request()).expect("a valid stage");
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        // The scan retained undecoded and unattributed traffic and no host
        // answered anything the trace could rest on; nothing is deducted
        // because the trace keeps no evidence for a host it will not probe.
        let aggregate = aggregate(
            vec![host(address, None)],
            vec![probe_evidence(0, address, None)],
            Vec::new(),
            vec![frame(0x02)],
            vec![scan::Unattributed {
                attribution: scan::Attribution::Ambiguous,
                sequence: None,
                frame: frame(0x03),
            }],
            usize::MAX,
        );

        let request = stage
            .request(&aggregate, Retained::of(&aggregate), Instant::now(), None)
            .expect("a plan of only not_traced hosts needs no evidence budget");

        assert_eq!(
            request.limits.max_evidence_frames,
            stage.template.limits.max_evidence_frames
        );
        assert_eq!(
            request.limits.max_evidence_bytes,
            stage.template.limits.max_evidence_bytes
        );
        assert_eq!(
            request.limits.max_undecoded,
            stage.template.limits.max_undecoded
        );
        assert_eq!(request.collection, stage.template.collection);
    }

    #[test]
    fn the_scan_pacing_marker_passes_through_monotonic() {
        let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
        let aggregate = aggregate(
            vec![host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );
        for last_sent in [
            Instant::now().checked_sub(Duration::from_secs(3600)),
            Some(Instant::now() + Duration::from_secs(3600)),
        ] {
            let request = stage
                .request(
                    &aggregate,
                    Retained::of(&aggregate),
                    Instant::now(),
                    last_sent,
                )
                .expect("a request");
            // The monotonic marker is carried through exactly: a far-future
            // one still owes its interval under the runner's saturating wait.
            assert_eq!(request.paced_after, last_sent);
        }
        let request = stage
            .request(&aggregate, Retained::of(&aggregate), Instant::now(), None)
            .expect("a request");
        assert!(request.paced_after.is_none());
    }

    #[test]
    fn the_finalized_queue_configuration_is_validated() {
        let mut scan = scan_request();
        scan.collection.capture.max_frames = 1;
        scan.collection.max_responses = 1;
        scan.collection.max_unmatched_frames = 1;
        let attempts = Options {
            attempts: 3,
            ..options()
        };
        let error = Stage::new(&attempts, &scan)
            .err()
            .expect("three attempts a hop cannot retain in one queue slot");
        assert_eq!(error.classification.code, "cli.traceroute_limit", "{error}");
        let stage = Stage::new(&options(), &scan).expect("one attempt fits");
        stage
            .with_workflow(scan.route.clone(), scan.collection.clone())
            .expect("an equivalent workflow collection still validates");
    }

    #[test]
    fn streamed_events_count_what_a_stripped_aggregate_no_longer_holds() {
        let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let responded = probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply));
        let mut retained = Retained::default();
        retained.observe(&scan::Event::Probe {
            target: std::sync::Arc::from("192.0.2.7"),
            probe: responded.clone(),
        });
        retained.observe(&scan::Event::Undecoded { frame: frame(0x02) });
        retained.observe(&scan::Event::Unattributed(scan::Unattributed {
            attribution: scan::Attribution::Late,
            sequence: Some(0),
            frame: frame(0x03),
        }));
        retained.observe(&scan::Event::Diagnostic(
            packetcraftr_core::diagnostic::Diagnostic::info("test.retained", "holds nothing"),
        ));
        // A metadata reply with no retained frame is not held evidence.
        let mut untimed = probe_evidence(1, address, Some(scan::Reply::IcmpEchoReply));
        untimed.response = None;
        retained.observe(&scan::Event::Probe {
            target: std::sync::Arc::from("192.0.2.7"),
            probe: untimed,
        });

        // The tracker keeps the outcome but strips the frame, and keeps no
        // undecoded or unattributed events at all.
        let mut stripped = responded;
        stripped.response = None;
        let aggregate = aggregate(
            vec![host(address, None)],
            vec![stripped],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            512,
        );

        let request = stage
            .request(&aggregate, retained, Instant::now(), None)
            .expect("the narrowed request validates");

        assert_eq!(
            request.limits.max_evidence_frames,
            stage.template.limits.max_evidence_frames - 3
        );
        assert_eq!(
            request.limits.max_undecoded,
            stage.template.limits.max_undecoded - 1
        );
        assert_eq!(
            request.limits.max_evidence_bytes,
            stage.template.limits.max_evidence_bytes - 512
        );
    }

    #[test]
    fn an_exactly_full_frame_budget_fails_with_a_typed_limit() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let mut scan = scan_request();
        scan.limits.max_evidence_frames = 1;
        scan.limits.max_undecoded = 1;
        scan.collection.capture.max_frames = 1;
        scan.collection.max_responses = 1;
        scan.collection.max_unmatched_frames = 1;
        let stage = Stage::new(&options(), &scan).expect("the template itself is valid");
        let aggregate = aggregate(
            vec![host(address, None)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );
        let retained = Retained {
            frames: 1,
            undecoded: 0,
        };

        let error = stage
            .request(&aggregate, retained, Instant::now(), None)
            .expect_err("the scan used the whole shared frame budget");

        assert_eq!(error.classification.code, "cli.traceroute_limit", "{error}");
    }

    #[test]
    fn invalid_options_fail_before_any_scan() {
        let mut invalid = options();
        invalid.port = Some(80);
        assert!(Stage::new(&invalid, &scan_request()).is_err());
        let mut invalid = options();
        invalid.strategy = None;
        invalid.port = Some(80);
        assert!(Stage::new(&invalid, &scan_request()).is_err());
        let mut invalid = options();
        invalid.first_hop = 9;
        assert!(Stage::new(&invalid, &scan_request()).is_err());
    }
}
