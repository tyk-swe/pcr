// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Scan CLI command logic.

pub(super) mod arguments;
mod connect;
mod payload;
mod profiles;
mod rendering;

use crate::output::contract::ToolFormat;

use crate::output;

use self::arguments::Args;
use super::execution;
use crate::errors::CliError;
use crate::rendering::StreamEncoder;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_in_flight: Count @ Operation,
            max_targets: Count @ Operation,
            max_ports: Count @ Operation,
            max_probes: Count @ Operation,
            max_undecoded: Count @ ResultRetention,
            max_prepared_bytes: Bytes @ Preparation,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if arguments.connect && !matches!(arguments.transport, arguments::Transport::Tcp) {
        return Err(CliError::new(
            packetcraftr_core::error::Kind::Usage,
            "--connect requires TCP transport",
        ));
    }
    if arguments.connect && !arguments.route.supports_kernel_tcp() {
        return Err(CliError::from_classification(
            packetcraftr_core::error::Classification::new(
                "capability.scan_tcp_route",
                packetcraftr_core::error::Kind::Capability,
                Some("omit packet interface/source/link overrides for ordinary TCP"),
            ),
            "TCP connect uses kernel route and source selection",
            Vec::new(),
        ));
    }
    let Args {
        connect,
        max_in_flight,
        max_prepared_bytes,
        targets,
        exclusions,
        max_targets,
        transport,
        udp_payload_hex,
        udp_payload_file,
        udp_profiles,
        family,
        ports,
        attempts,
        timeout,
        rate,
        max_ports,
        max_probes,
        duration,
        max_undecoded,
        route,
        limits,
        policy,
    } = arguments;
    let udp_payload = payload::read(
        transport,
        udp_payload_hex.as_deref(),
        udp_payload_file.as_deref(),
    )?;
    let udp_profiles = profiles::load(udp_profiles.as_deref(), transport)?;
    let targets = packetcraftr::target::Selection {
        include: targets
            .iter()
            .map(|target| target.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(CliError::classified)?,
        exclude: exclusions,
    };
    targets.validate().map_err(CliError::classified)?;
    let queue_limits = limits.into_limits();
    let scan_limits = packetcraftr::scan::Limits {
        max_prepared_bytes,
        max_targets,
        max_ports,
        max_probes,
        max_duration: duration.max_duration(),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded,
    };
    scan_limits.validate().map_err(CliError::classified)?;
    let ports = packetcraftr::scan::select_ports(ports.into_iter().map(|spec| spec.0), max_ports)
        .map_err(CliError::classified)?;
    let request = packetcraftr::scan::Request {
        max_in_flight,
        targets,
        transport: transport.into(),
        udp_payload,
        udp_profiles,
        address_family: family.into(),
        ports,
        attempts,
        timeout: timeout.timeout(),
        probes_per_second: rate,
        limits: scan_limits,
        route: packetcraftr::route::Options::default(),
        collection: packetcraftr::exchange::Collection::default(),
    };
    if connect {
        return connect::run(&request, policy, format, stream);
    }
    let execution::Providers {
        executor, runtime, ..
    } = execution::prepare(
        route,
        policy,
        request.timeout,
        MAX_TEMPLATE_PACKETS,
        queue_limits,
    )?;
    let request = packetcraftr::scan::Request {
        route: executor.send.plan,
        collection: executor.collection,
        ..request
    };
    // Events publish on the workflow runtime, as they did before scan ran
    // on the client, so the `resources` report keeps its rows.
    let client = executor.client.with_runtime(runtime);
    execution::run_workflow(
        &mut (),
        format,
        stream,
        crate::cancellation::signal(),
        execution::Hooks {
            command: output::contract::Command::Scan,
            run: Box::new(|_| {
                let collector = packetcraftr::scan::Collector::default();
                let report = client
                    .scan(request.clone(), collector.clone())
                    .map_err(rendering::scan_error)?;
                collector.finish(report).map_err(rendering::scan_error)
            }),
            run_with_events: Box::new(|_, emit| {
                client
                    .scan(request.clone(), emit)
                    .map_err(rendering::scan_error)
            }),
            on_event: rendering::emit_event,
            into_result: Box::new(|report| {
                output::envelope::Published::<output::scan::Report>::try_from(report)
                    .map_err(CliError::classified)
            }),
            render_text: Box::new(|report, _| {
                rendering::render_text(
                    output::envelope::Published::try_from(report).map_err(CliError::classified)?,
                )
            }),
            complete: rendering::emit_complete,
        },
    )
}

/// Every scan exchange carries exactly one correlated probe.
const MAX_TEMPLATE_PACKETS: usize = 1;
