// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The optional trace stage of a scan: every scanned host, traced under one
//! plan with the probes the scan saw it answer.

use std::time::{Duration, Instant, SystemTime};

use packetcraftr::probe::Transport;
use packetcraftr::scan::discovery::Host;
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

/// What one run of the stage published.
pub(super) struct Traced {
    pub(super) aggregate: hosts::Aggregate,
    pub(super) last_sent: Option<SystemTime>,
}

pub(super) struct Streamed {
    pub(super) report: hosts::Report,
    pub(super) last_sent: Option<SystemTime>,
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

    /// Takes the route and collection the prepared workflow selected.
    pub(super) fn with_workflow(
        mut self,
        route: packetcraftr::route::Options,
        collection: packetcraftr::exchange::Collection,
    ) -> Self {
        self.template.route = route;
        self.template.collection = collection;
        self
    }

    /// The request for the scan's hosts: one exact declaration each, in host
    /// order, the scan's own observations, and what remains of its duration.
    fn request(
        &self,
        hosts: &[Host],
        observed: Vec<hosts::Observed>,
        started: Instant,
        last_sent: Option<SystemTime>,
    ) -> Result<hosts::Request, CliError> {
        let include = hosts
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
        let now = Instant::now();
        Ok(hosts::Request {
            targets: Selection {
                include,
                exclude: Vec::new(),
            },
            observed,
            paced_after: last_sent.map(|sent| {
                let elapsed = SystemTime::now().duration_since(sent).unwrap_or_default();
                now.checked_sub(elapsed).unwrap_or(now)
            }),
            limits: packetcraftr::traceroute::Limits {
                max_duration: self
                    .template
                    .limits
                    .max_duration
                    .saturating_sub(started.elapsed())
                    .max(Duration::from_nanos(1)),
                ..self.template.limits
            },
            ..self.template.clone()
        })
    }

    pub(super) fn collect(
        &self,
        client: &Client,
        scan: &packetcraftr::scan::Aggregate,
        started: Instant,
        last_sent: Option<SystemTime>,
    ) -> Result<Traced, CliError> {
        let request = self.request(&scan.hosts, hosts::observed(scan), started, last_sent)?;
        let collector = hosts::Collector::default();
        let report = client
            .trace_hosts(request, collector.clone())
            .map_err(CliError::classified)?;
        let aggregate = collector.finish(report).map_err(CliError::classified)?;
        let last_sent = aggregate
            .hosts
            .iter()
            .flat_map(|trace| &trace.hops)
            .flat_map(|hop| &hop.probes)
            .map(|probe| probe.sent_at)
            .max();
        Ok(Traced {
            aggregate,
            last_sent,
        })
    }

    pub(super) fn stream(
        &self,
        client: &Client,
        scan: &packetcraftr::scan::Aggregate,
        started: Instant,
        last_sent: Option<SystemTime>,
        emit: impl FnMut(hosts::Event) -> Result<(), packetcraftr_core::error::BoundaryError>
        + Send
        + 'static,
    ) -> Result<Streamed, CliError> {
        let request = self.request(&scan.hosts, hosts::observed(scan), started, last_sent)?;
        let latest = std::sync::Arc::new(std::sync::Mutex::new(None::<SystemTime>));
        let observed = std::sync::Arc::clone(&latest);
        let mut emit = emit;
        let report = client
            .trace_hosts(request, move |event: hosts::Event| {
                if let hosts::Event::Probe(probe) = &event {
                    let mut latest = observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *latest = (*latest).max(Some(probe.sent_at));
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

    use packetcraftr::scan::discovery::{Scan, State};

    use super::*;

    fn scan_request() -> packetcraftr::scan::Request {
        packetcraftr::scan::Request {
            max_in_flight: 1,
            targets: Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).into(),
            target_sources: Vec::new(),
            endpoints: vec![packetcraftr::probe::ProbeEndpoint::Icmp],
            discovery: Default::default(),
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
        let hosts = [
            host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None),
            host("fe80::1".parse().unwrap(), Some(zone)),
        ];
        let started = Instant::now()
            .checked_sub(Duration::from_secs(10))
            .expect("an instant ten seconds ago");

        let request = stage
            .request(&hosts, Vec::new(), started, Some(SystemTime::now()))
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
        let hosts = [host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None)];

        let request = stage.request(&hosts, Vec::new(), started, None).unwrap();

        assert_eq!(request.limits.max_duration, Duration::from_nanos(1));
        assert!(request.paced_after.is_none());
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
