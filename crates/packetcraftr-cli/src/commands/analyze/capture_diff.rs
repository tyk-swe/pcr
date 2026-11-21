// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use clap::Args;
use packetcraftr_core::analysis;
use packetcraftr_core::error::Kind;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};
use crate::commands::Generate;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Compare passive inventories from a baseline capture and a later capture. Hosts, observed transport ports, protocols, and ARP-established MAC addresses are compared by identity. New in this output means observed in the later capture and not observed in the baseline. It does not prove the host or service first existed then. No packets are sent and no names are resolved.

Example:
  packetcraftr analyze capture-diff baseline.pcapng current.pcapng";

#[derive(Debug, Args)]
pub(crate) struct CaptureDiff {
    /// Baseline PCAP or PCAPNG capture.
    before: PathBuf,
    /// Later PCAP or PCAPNG capture.
    after: PathBuf,
    #[command(flatten)]
    decode: DecodeArgs,
    #[command(flatten)]
    limits: OfflineLimitsArgs,
}

impl Generate for CaptureDiff {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("capture-diff prints text only, not --output {format}"),
            ));
        }
        if self.before == Path::new("-") && self.after == Path::new("-") {
            return Err(CliError::new(
                Kind::Usage,
                "baseline and later captures cannot both read stdin",
            ));
        }
        let prepared = prepare(self.limits, None, &self.decode)?;
        let inventory = |path: &Path| -> Result<analysis::inventory::Report, CliError> {
            let mut reader = prepared.open(invocation, path)?;
            let options = prepared.options(invocation);
            analysis::inventory::run(&mut reader, prepared.registry.clone(), &options)
                .map_err(CliError::classified)
        };
        let before = inventory(&self.before)?;
        let after = inventory(&self.after)?;
        let diff = analysis::inventory::diff(&before, &after);
        let mut text = format!(
            "before_frames={} after_frames={} new_hosts={} gone_hosts={} new_ports={} gone_ports={} new_protocols={} gone_protocols={} mac_changes={}\n",
            before.frames_read,
            after.frames_read,
            diff.new_hosts.len(),
            diff.gone_hosts.len(),
            diff.new_ports.len(),
            diff.gone_ports.len(),
            diff.new_protocols.len(),
            diff.gone_protocols.len(),
            diff.mac_changes.len(),
        );
        for host in &diff.new_hosts {
            text.push_str(&format!("new_host {host}\n"));
        }
        for host in &diff.gone_hosts {
            text.push_str(&format!("gone_host {host}\n"));
        }
        for port in &diff.new_ports {
            text.push_str(&format!(
                "new_port {} {:?}/{}\n",
                port.address, port.observed_port.transport, port.observed_port.port
            ));
        }
        for port in &diff.gone_ports {
            text.push_str(&format!(
                "gone_port {} {:?}/{}\n",
                port.address, port.observed_port.transport, port.observed_port.port
            ));
        }
        for protocol in &diff.new_protocols {
            text.push_str(&format!("new_protocol {protocol}\n"));
        }
        for protocol in &diff.gone_protocols {
            text.push_str(&format!("gone_protocol {protocol}\n"));
        }
        for change in &diff.mac_changes {
            let render = |macs: &[packetcraftr_core::packet::MacAddress]| {
                if macs.is_empty() {
                    "-".to_owned()
                } else {
                    macs.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            };
            text.push_str(&format!(
                "mac_change {} before={} after={}\n",
                change.address,
                render(&change.before),
                render(&change.after),
            ));
        }
        emit_stdout_document(invocation, &text)
    }
}
