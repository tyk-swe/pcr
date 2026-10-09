#[allow(dead_code)]
#[path = "../tests/common/scanner_fixture/conditions.rs"]
mod conditions;
#[allow(dead_code)]
#[path = "../tests/common/scanner_fixture/providers.rs"]
mod providers;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr::probe::ProbeEndpoint;
use packetcraftr::target::{Family, Selection, Specification, Target};
use packetcraftr::{Client, scan};
use packetcraftr_core::error::Classified;
use serde_json::{Value, json};

use providers::{Condition, FamilyAddresses, Io, Providers};

fn run(scenario: &str, family: &str, mode: &str) -> Result<Value, String> {
    let (_, addresses) = FamilyAddresses::parse(family)?;
    let adaptive = match mode {
        "fixed" => false,
        "adaptive" => true,
        _ => return Err("mode must be fixed or adaptive".to_owned()),
    };
    let (ports, attempts, timeout_ms, min_timeout_ms, duration_ms, prepared_bytes) = match scenario
    {
        "responsive-many" => (16u16, 3, 20, 1, 2_000, 1_048_576),
        "selective-silence" => (2, 3, 20, 1, 2_000, 1_048_576),
        "plan-retention" => (128, 32, 5, 5, 60_000, 131_072),
        _ => return Err("unknown scheduling scenario".to_owned()),
    };
    let io = Io::default();
    let selective_silence = scenario == "selective-silence";
    let responder = Arc::new(move |sent: &[u8]| {
        let offset = if addresses.source.is_ipv4() { 20 } else { 40 };
        let destination_port = sent
            .get(offset + 2..offset + 4)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
        let condition = if selective_silence && destination_port == Some(9000) {
            Condition::Silent
        } else {
            Condition::Responsive
        };
        conditions::respond(condition, addresses, sent)
    });
    let providers = Providers::new(io.clone(), addresses, responder);
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy::default(),
        providers,
    );
    let request = scan::Request {
        target_sources: Vec::new(),
        targets: Selection {
            include: vec![Specification::Target(Target::Address(
                addresses.destination,
            ))],
            exclude: Vec::new(),
        },
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: if addresses.source.is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        },
        endpoints: (9000..9000 + ports)
            .map(|port| ProbeEndpoint::Tcp { port })
            .collect(),
        discovery: Default::default(),
        attempts,
        adaptive: adaptive.then_some(scan::Adaptive {
            min_timeout: Duration::from_millis(min_timeout_ms),
            max_timeout: Duration::from_millis(timeout_ms),
            min_window: 1,
            initial_window: 1,
            host_timeout: Duration::from_millis(duration_ms),
            retry_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(if scenario == "plan-retention" { 1 } else { 2 }),
        }),
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: None,
        max_in_flight: 2,
        limits: scan::Limits {
            max_probes: usize::from(ports) * attempts as usize,
            max_duration: Duration::from_millis(duration_ms),
            max_prepared_bytes: prepared_bytes,
            max_evidence_bytes: 1_048_576,
            ..scan::Limits::default()
        },
        route: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        collection: Default::default(),
    };
    let settings = json!({
        "hosts": 1, "ports": ports, "attempts": attempts,
        "timeout_ms": timeout_ms, "max_in_flight": 2,
        "max_duration_ms": duration_ms, "max_prepared_bytes": prepared_bytes,
        "max_probes": usize::from(ports) * attempts as usize,
        "max_evidence_bytes": 1_048_576
    });
    let collector = scan::Collector::default();
    let started = Instant::now();
    let result = client
        .scan(request, collector.clone())
        .and_then(|report| collector.finish(report));
    let operation_elapsed_ns = u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| "operation elapsed time overflow".to_owned())?;
    let (armed, ready, shutdown) = io.counts();
    if armed != ready || armed != shutdown {
        return Err("fixture capture cleanup is incoherent".to_owned());
    }
    let mut record = json!({
        "schema": "packetcraftr.scheduling-fixture/v1",
        "scenario": scenario, "family": family, "scheduling_mode": mode,
        "execution": "injected_provider_real_clock",
        "settings": settings, "operation_elapsed_ns": operation_elapsed_ns,
        "work_sent": io.sent().len(), "capture_sessions": armed
    });
    match result {
        Err(error) => {
            record["status"] = json!("rejected");
            record["error_code"] = json!(error.classification().code);
            record["error"] = json!(error.to_string());
            record["error_cause"] =
                json!(std::error::Error::source(&error).map(ToString::to_string));
            record["retained_evidence_charged_bytes"] = json!(0);
        }
        Ok(aggregate) => {
            if aggregate.stats.packets_attempted != io.sent().len() as u64
                || aggregate.stats.packets_completed != aggregate.stats.packets_attempted
            {
                return Err("fixture traffic counters disagree".to_owned());
            }
            let endpoints: BTreeMap<_, _> = aggregate
                .endpoints
                .iter()
                .map(|endpoint| {
                    (
                        endpoint.port.expect("fixture TCP port"),
                        json!({
                            "classification": endpoint.classification.as_str(),
                            "attempts": endpoint.probes.iter().map(|probe| probe.attempt).collect::<Vec<_>>()
                        }),
                    )
                })
                .collect();
            record["status"] = json!("success");
            record["endpoints"] = json!(endpoints);
            record["retained_evidence_charged_bytes"] = json!(aggregate.retained_evidence_bytes);
            record["workflow_elapsed_ns"] = json!(
                u64::try_from(aggregate.stats.elapsed.as_nanos())
                    .map_err(|_| "workflow elapsed time overflow".to_owned())?
            );
            record["observed_peak_window"] = json!(aggregate.scheduling.observed_peak_window);
            record["retries_started"] = json!(aggregate.scheduling.retries_started);
            record["conditions"] = json!(
                aggregate
                    .scheduling
                    .conditions
                    .iter()
                    .map(|condition| condition.kind.as_str())
                    .collect::<Vec<_>>()
            );
            record["incomplete"] = json!(
                aggregate
                    .scheduling
                    .incomplete
                    .iter()
                    .map(|host| host.address.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }
    Ok(record)
}

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [scenario, family, mode] => run(scenario, family, mode),
        _ => Err("usage: scheduling_fixture SCENARIO ipv4|ipv6 fixed|adaptive".to_owned()),
    };
    match result {
        Ok(record) => {
            println!("{record}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
