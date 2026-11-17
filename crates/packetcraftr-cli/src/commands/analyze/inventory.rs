// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod output;

use packetcraftr_core::analysis;

use self::arguments::Args;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::output::contract::{Format, PublishedType};
use crate::output::envelope::Published;
use crate::publication::emit_published;
use crate::terminal::write_stdout_line;

impl crate::commands::Spec for Args {
    const PUBLISHED: &'static [PublishedType] = &[PublishedType {
        definition: "inventorySuccess",
        command: "inventory",
        rust_types: &["crate::commands::analyze::inventory::output::Report"],
        events: &[],
        example: "examples/documents/output-inventory-success.json",
    }];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(false),
        );
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let prepared = prepare(
        arguments.limits,
        arguments.filter.as_deref(),
        &arguments.decode,
    )?;
    let mut collector = analysis::inventory::Collector::new();
    let mut reader = prepared.open(invocation, &arguments.path)?;
    let options = prepared.options(invocation);
    let summary = analysis::run(&mut reader, prepared.registry.clone(), &options, |record| {
        collector.observe(&record);
        Ok(())
    })
    .map_err(CliError::classified)?;
    let report = output::Report::from(collector.finish(&summary));
    match invocation.format {
        Format::Text => render_text(invocation, &report),
        Format::Json => emit_published(
            invocation,
            crate::output::contract::Command::Inventory,
            Published::new(report, Vec::new()),
        ),
        other => other.unreachable(),
    }
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    report: &output::Report,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "hosts={} protocols={} frames_read={}",
            report.hosts.len(),
            report.protocols.len(),
            report.frames_read
        ),
    )?;
    for host in &report.hosts {
        let ports = host
            .observed_ports
            .iter()
            .map(|port| format!("{:?}/{}", port.transport, port.port).to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        write_stdout_line(
            invocation,
            format_args!(
                "host={} mac={} sent={} received={} protocols={} ports={}",
                host.address,
                if host.mac_addresses.is_empty() {
                    "-".to_owned()
                } else {
                    host.mac_addresses.join(",")
                },
                host.frames_sent,
                host.frames_received,
                host.protocols.join(","),
                if ports.is_empty() {
                    "-".to_owned()
                } else {
                    ports
                },
            ),
        )?;
    }
    for protocol in &report.protocols {
        write_stdout_line(
            invocation,
            format_args!("protocol={} frames={}", protocol.protocol, protocol.frames),
        )?;
    }
    Ok(())
}
