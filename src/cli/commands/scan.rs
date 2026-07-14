// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Scan command execution and presentation.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::{client, net, output, packet, workflow};

use super::arguments::ScanArgs;
use super::capture::render_diagnostics_text;
use super::errors::CliError;
use super::rendering::{
    NdjsonStream, emit_json, output_timestamp_text, spaced_hex, write_stdout_line,
};
use super::runtime::{
    DeferredInterface, default_registry_arc, system_client, validate_interface_selector,
};

pub(super) fn run_scan(
    arguments: ScanArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ScanArgs {
        target,
        transport,
        family,
        ports,
        attempts,
        timeout_ms,
        rate,
        batch_size,
        max_ports,
        max_probes,
        max_duration_ms,
        max_undecoded,
        interface,
        source,
        link_mode,
        limits,
        policy,
    } = arguments;
    let target = match target
        .parse::<client::target::Target>()
        .map_err(CliError::classified)?
    {
        client::target::Target::Address(address) => workflow::target::Target::Address(address),
        client::target::Target::Hostname(hostname) => {
            workflow::target::Target::Hostname(hostname.to_string())
        }
    };
    let queue_limits = limits.into_limits();
    let scan_limits = workflow::scan::Limits {
        max_ports,
        max_probes,
        batch_size,
        max_duration: Duration::from_millis(max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(scan_cli_error)?;
    let policy = policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    validate_live_interface_selector("scan", interface.as_deref())?;
    let request = workflow::scan::Request {
        target,
        transport: transport.into(),
        address_family: family.into(),
        ports,
        attempts,
        timeout: Duration::from_millis(timeout_ms),
        probes_per_second: rate,
        limits: scan_limits,
    };
    let registry = default_registry_arc()?;
    let mut exchange = client::exchange::Options {
        send: client::send::Options {
            destination: None,
            plan: net::route::Options {
                link_mode: link_mode.into(),
                interface: None,
                preferred_source: source,
            },
            build: packet::build::Options::default(),
            allow_permissive_live: false,
        },
        timeout: request.timeout,
        max_template_packets: batch_size,
        max_unsolicited: queue_limits.max_frames,
        max_responses: queue_limits.max_frames,
        max_capture_queue_frames: queue_limits.max_frames,
        max_captured_bytes: queue_limits.max_bytes,
        capture_overflow_policy: queue_limits.overflow_policy,
        decode: packet::decode::Options::default(),
    };
    exchange.decode.max_packet_size = queue_limits.snap_length;
    exchange.validate().map_err(CliError::classified)?;

    let mut executor = CliScanExecutor {
        registry: Arc::clone(&registry),
        policy: policy.clone(),
        exchange,
        interface: DeferredInterface::new(interface),
    };
    let resolver = client::target::SystemResolver;
    let mut authorizer = workflow::scan::PolicyAuthorizer::new(&policy, &resolver);
    let mut clock = workflow::clock::System;
    if output == output::contract::Format::Ndjson {
        let stdout = io::stdout();
        let mut stream = NdjsonStream::new(stdout.lock(), output::contract::Command::Scan);
        let result = {
            let mut observer = ScanStreamObserver {
                stream: &mut stream,
            };
            workflow::scan::run_observed(
                &request,
                &mut authorizer,
                &registry,
                &mut executor,
                &mut clock,
                &mut observer,
            )
        };
        let result = match result {
            Ok(result) => result,
            Err(workflow::scan::ObservedError::Operation(error)) => {
                let error = scan_cli_error(error).at_sequence(stream.next_sequence());
                drop(stream);
                return Err(error);
            }
            Err(workflow::scan::ObservedError::Observer(error)) => {
                drop(stream);
                return Err(error);
            }
        };
        let workflow::scan::Result {
            target,
            resolved_addresses,
            endpoints: _,
            undecoded: _,
            diagnostics,
            stats,
        } = result;
        return stream.emit_terminal(
            output::scan::Event::Complete {
                target,
                resolved_addresses,
            },
            diagnostics,
            stats.into(),
        );
    }
    let result = workflow::scan::run(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .map_err(scan_cli_error)?;
    let (result, diagnostics, stats) =
        output::scan::Result::try_from_scan(result).map_err(CliError::classified)?;

    match output {
        output::contract::Format::Text => render_scan_text(result, diagnostics, stats),
        output::contract::Format::Json => emit_json(
            &output::envelope::Aggregate::success(
                output::contract::Command::Scan,
                result,
                diagnostics,
            )
            .with_stats(stats),
        ),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Scan,
                format: output,
            },
        )),
    }
}

struct ScanStreamObserver<'a, W: Write> {
    stream: &'a mut NdjsonStream<W>,
}

impl<W: Write> workflow::scan::ProgressObserver for ScanStreamObserver<'_, W> {
    type Error = CliError;

    fn observe(&mut self, progress: workflow::scan::Progress<'_>) -> Result<(), Self::Error> {
        let event = match progress {
            workflow::scan::Progress::EndpointComplete { target, endpoint } => {
                output::scan::Event::Port {
                    target: target.to_owned(),
                    resolved_address: endpoint.address,
                    port: output::scan::Port::try_from_endpoint_ref(endpoint).map_err(|error| {
                        CliError::classified(error).at_sequence(self.stream.next_sequence())
                    })?,
                }
            }
            workflow::scan::Progress::Undecoded { frame } => output::scan::Event::Undecoded {
                frame: output::frame::Captured::try_from_frame_ref(frame).map_err(|error| {
                    CliError::classified(error).at_sequence(self.stream.next_sequence())
                })?,
            },
        };
        self.stream.emit(event, Vec::new())
    }
}

pub(super) fn validate_live_interface_selector(
    command: &str,
    selector: Option<&str>,
) -> Result<(), CliError> {
    validate_interface_selector(command, selector).map(|_| ())
}

struct CliScanExecutor {
    registry: Arc<packet::registry::Registry>,
    policy: client::policy::Policy,
    exchange: client::exchange::Options,
    interface: DeferredInterface,
}

impl workflow::scan::Executor for CliScanExecutor {
    fn execute(
        &mut self,
        batch: &workflow::scan::Batch,
    ) -> Result<workflow::scan::Execution, workflow::scan::ExecutionError> {
        self.interface
            .resolve_into(&mut self.exchange.send.plan)
            .map_err(|error| {
                workflow::scan::ExecutionError::new(
                    error.message,
                    error.classification,
                    error.causes,
                )
            })?;
        let client = system_client(Arc::clone(&self.registry), self.policy.clone());
        workflow::scan::ClientExecutor::new(&client, self.exchange.clone()).execute(batch)
    }
}

pub(super) fn scan_cli_error(error: workflow::scan::Error) -> CliError {
    let sequence = error.sequence();
    let mut error = CliError::classified(error);
    if let Some(sequence) = sequence {
        error = error.at_sequence(sequence);
    }
    error
}

fn render_scan_text(
    result: output::scan::Result,
    diagnostics: Vec<packet::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "target={} resolved={}",
        result.target,
        result
            .resolved_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    ))?;
    for port in &result.ports {
        let destination = port
            .evidence
            .first()
            .map(|evidence| evidence.destination)
            .ok_or_else(|| CliError::new(70, "scan endpoint has no attempt evidence"))?;
        let endpoint = if port.transport == "icmp" {
            "icmp".to_owned()
        } else {
            format!("{}/{}", port.transport, port.port)
        };
        write_stdout_line(format_args!(
            "{} {} classification={}",
            destination,
            endpoint,
            scan_classification_name(port.classification)
        ))?;
        for evidence in &port.evidence {
            write_stdout_line(format_args!(
                "  attempt={} status={} classification={} sent={} received={} responder={} latency={} reason={}",
                evidence.attempt,
                scan_probe_status_name(evidence.status),
                scan_classification_name(evidence.classification),
                output_timestamp_text(evidence.sent_at),
                evidence
                    .received_at
                    .map(output_timestamp_text)
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .responder
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                evidence
                    .latency
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|| "none".to_owned()),
                evidence.reason,
            ))?;
            if let Some(frame) = &evidence.frame {
                write_stdout_line(format_args!(
                    "    frame dlt={} caplen={} wirelen={} {}",
                    frame.link_type,
                    frame.captured_length,
                    frame.original_length,
                    spaced_hex(frame.bytes())
                ))?;
            }
        }
    }
    for frame in &result.undecoded {
        write_stdout_line(format_args!(
            "undecoded dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        ))?;
    }
    write_stdout_line(format_args!(
        "scanned {} endpoint(s) with {} completed probe(s), {} byte(s)",
        result.ports.len(),
        stats.packets_completed,
        stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn scan_classification_name(value: output::scan::Classification) -> &'static str {
    match value {
        output::scan::Classification::Open => "open",
        output::scan::Classification::Closed => "closed",
        output::scan::Classification::Filtered => "filtered",
        output::scan::Classification::Unreachable => "unreachable",
        output::scan::Classification::Unknown => "unknown",
        output::scan::Classification::Timeout => "timeout",
    }
}

fn scan_probe_status_name(value: output::scan::ProbeStatus) -> &'static str {
    match value {
        output::scan::ProbeStatus::Response => "response",
        output::scan::ProbeStatus::Timeout => "timeout",
    }
}
