// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[allow(dead_code)]
#[path = "../tests/common/scanner_fixture/conditions.rs"]
mod conditions;
#[allow(dead_code)]
#[path = "../tests/common/scanner_fixture/providers.rs"]
mod providers;

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::target::{Family, Selection, Specification, Target};
use packetcraftr::{Client, scan, traceroute};
use serde::Serialize;

use providers::{Condition, FamilyAddresses, Io, Providers};

const PORT: u16 = 443;
const TIMEOUT: Duration = Duration::from_millis(20);
const MAX_DURATION: Duration = Duration::from_secs(2);
const MAX_PROBES: usize = 1;
const MAX_EVIDENCE_BYTES: usize = 65536;

#[derive(Clone, Copy)]
enum Workflow {
    RawScan,
    Traceroute,
}

struct Arguments {
    condition: Condition,
    family_label: &'static str,
    addresses: FamilyAddresses,
    transport: packetcraftr::probe::Transport,
    window: usize,
    workflow: Workflow,
}

fn parse_arguments(arguments: &[String]) -> Result<Arguments, String> {
    let usage = "usage: scanner_fixture CONDITION FAMILY TRANSPORT WINDOW [traceroute]";
    match arguments {
        [condition, family, transport, window] | [condition, family, transport, window, ..]
            if arguments.len() == 4 || (arguments.len() == 5 && arguments[4] == "traceroute") =>
        {
            let traceroute = arguments.len() == 5;
            let (family_label, addresses) = FamilyAddresses::parse(family)?;
            let transport = match transport.as_str() {
                "tcp" => packetcraftr::probe::Transport::Tcp,
                "udp" => packetcraftr::probe::Transport::Udp,
                "icmp" => packetcraftr::probe::Transport::Icmp,
                other => {
                    return Err(format!(
                        "unknown transport `{other}`; expected tcp, udp, or icmp"
                    ));
                }
            };
            let window = match window.as_str() {
                "1" => 1,
                "2" => 2,
                other => {
                    return Err(format!(
                        "unknown window `{other}`; expected 1 or 2 as defined by the corpus"
                    ));
                }
            };
            if traceroute && window != 1 {
                return Err("the traceroute workflow accepts window 1 only".to_owned());
            }
            Ok(Arguments {
                condition: Condition::parse(condition)?,
                family_label,
                addresses,
                transport,
                window,
                workflow: if traceroute {
                    Workflow::Traceroute
                } else {
                    Workflow::RawScan
                },
            })
        }
        _ => Err(usage.to_owned()),
    }
}

#[derive(Serialize)]
struct Observation {
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination: Option<&'static str>,
    status: &'static str,
    attributed_response: bool,
}

#[derive(Serialize)]
struct Record {
    schema: &'static str,
    scenario: &'static str,
    family: &'static str,
    transport: &'static str,
    window: usize,
    workflow: &'static str,
    execution: &'static str,
    observation: Observation,
    packets_attempted: u64,
    packets_completed: u64,
    retained_evidence_bytes: usize,
    retained_frames_hex: Vec<String>,
    delivered_frames_hex: Vec<String>,
    workflow_elapsed_ns: u64,
}

fn client(providers: Providers) -> Client<Providers> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy::default(),
        providers,
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn scan_request(arguments: &Arguments) -> scan::Request {
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    scan::Request {
        targets: Selection {
            include: vec![Specification::Target(Target::Address(
                arguments.addresses.destination,
            ))],
            exclude: Vec::new(),
        },
        transport: arguments.transport,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: match arguments.addresses.destination {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        },
        ports: match arguments.transport {
            packetcraftr::probe::Transport::Icmp => Vec::new(),
            _ => vec![PORT],
        },
        attempts: 1,
        timeout: TIMEOUT,
        probes_per_second: None,
        max_in_flight: arguments.window,
        limits: scan::Limits {
            max_duration: MAX_DURATION,
            max_probes: MAX_PROBES,
            max_evidence_bytes: MAX_EVIDENCE_BYTES,
            ..scan::Limits::default()
        },
        route,
        collection: collection(),
    }
}

fn collection() -> packetcraftr::exchange::Collection {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 65535;
    collection.capture.max_bytes = MAX_EVIDENCE_BYTES;
    collection
}

fn traceroute_request(arguments: &Arguments) -> traceroute::Request {
    let route = packetcraftr::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..packetcraftr::route::Options::default()
    };
    traceroute::Request {
        target: Target::Address(arguments.addresses.destination),
        strategy: arguments.transport,
        address_family: match arguments.addresses.destination {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        },
        destination_port: match arguments.transport {
            packetcraftr::probe::Transport::Icmp => None,
            _ => Some(PORT),
        },
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 1,
        probes_per_hop: 1,
        timeout: TIMEOUT,
        probes_per_second: None,
        limits: traceroute::Limits {
            max_probes: MAX_PROBES,
            max_duration: MAX_DURATION,
            max_evidence_bytes: MAX_EVIDENCE_BYTES,
            ..traceroute::Limits::default()
        },
        route,
        collection: collection(),
    }
}

fn run(arguments: &Arguments) -> Result<Record, String> {
    let io = Io::default();
    let addresses = arguments.addresses;
    let condition = arguments.condition;
    let providers = Providers::new(
        io.clone(),
        addresses,
        Arc::new(move |sent: &[u8]| conditions::respond(condition, addresses, sent)),
    );
    let client = client(providers);
    let transport_id = match arguments.transport {
        packetcraftr::probe::Transport::Tcp => "tcp",
        packetcraftr::probe::Transport::Udp => "udp",
        packetcraftr::probe::Transport::Icmp => "icmp",
    };
    let (observation, attempted, completed, retained, frames, elapsed) = match arguments.workflow {
        Workflow::RawScan => {
            let collector = scan::Collector::default();
            let aggregate = client
                .scan(scan_request(arguments), collector.clone())
                .and_then(|report| collector.finish(report))
                .map_err(|error| format!("fixture scan failed: {error:?}"))?;
            let [endpoint] = aggregate.endpoints.as_slice() else {
                return Err(format!(
                    "fixture scan produced {} endpoints, expected exactly one",
                    aggregate.endpoints.len()
                ));
            };
            let [probe] = endpoint.probes.as_slice() else {
                return Err(format!(
                    "fixture scan produced {} attempts, expected exactly one",
                    endpoint.probes.len()
                ));
            };
            let mut frames = Vec::new();
            if let Some(frame) = &probe.response {
                frames.push(hex(frame.bytes()));
            }
            frames.extend(aggregate.undecoded.iter().map(|frame| hex(frame.bytes())));
            (
                Observation {
                    classification: Some(probe.classification.as_str()),
                    termination: None,
                    status: probe.status.as_str(),
                    attributed_response: probe.response.is_some(),
                },
                aggregate.stats.packets_attempted,
                aggregate.stats.packets_completed,
                aggregate.retained_evidence_bytes,
                frames,
                aggregate.stats.elapsed.as_nanos(),
            )
        }
        Workflow::Traceroute => {
            let collector = traceroute::Collector::default();
            let aggregate = client
                .traceroute(traceroute_request(arguments), collector.clone())
                .and_then(|report| collector.finish(report))
                .map_err(|error| format!("fixture traceroute failed: {error:?}"))?;
            let [hop] = aggregate.hops.as_slice() else {
                return Err(format!(
                    "fixture traceroute produced {} hops, expected exactly one",
                    aggregate.hops.len()
                ));
            };
            let [probe] = hop.probes.as_slice() else {
                return Err(format!(
                    "fixture traceroute produced {} probes, expected exactly one",
                    hop.probes.len()
                ));
            };
            let mut frames = Vec::new();
            if let Some(frame) = &probe.response {
                frames.push(hex(frame.bytes()));
            }
            frames.extend(
                aggregate
                    .undecoded
                    .iter()
                    .map(|entry| hex(entry.frame.bytes())),
            );
            (
                Observation {
                    classification: None,
                    termination: Some(aggregate.termination.as_str()),
                    status: probe.status.as_str(),
                    attributed_response: probe.response.is_some(),
                },
                aggregate.stats.packets_attempted,
                aggregate.stats.packets_completed,
                aggregate.retained_evidence_bytes,
                frames,
                aggregate.stats.elapsed.as_nanos(),
            )
        }
    };
    let (armed, readied, shutdowns) = io.counts();
    if armed != readied || shutdowns != armed {
        return Err(format!(
            "fixture capture lifecycle incoherent: armed={armed} ready={readied} shutdowns={shutdowns}"
        ));
    }
    let elapsed =
        u64::try_from(elapsed).map_err(|_| "workflow elapsed time does not fit u64".to_owned())?;
    Ok(Record {
        schema: "packetcraftr.scanner-fixture/v1",
        scenario: arguments.condition.id(),
        family: arguments.family_label,
        transport: transport_id,
        window: arguments.window,
        workflow: match arguments.workflow {
            Workflow::RawScan => "raw_scan",
            Workflow::Traceroute => "traceroute",
        },
        execution: "injected_provider",
        observation,
        packets_attempted: attempted,
        packets_completed: completed,
        retained_evidence_bytes: retained,
        retained_frames_hex: frames,
        delivered_frames_hex: io
            .delivered()
            .into_iter()
            .map(|(_, bytes)| hex(&bytes))
            .collect(),
        workflow_elapsed_ns: elapsed,
    })
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match parse_arguments(&arguments).and_then(|arguments| run(&arguments)) {
        Ok(record) => {
            let line =
                serde_json::to_string(&record).expect("the fixture record is always serializable");
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("scanner_fixture: {message}");
            ExitCode::from(2)
        }
    }
}
