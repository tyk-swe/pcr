// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::Args;
use packetcraftr_core::analysis;
use packetcraftr_core::error::Kind;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};
use crate::commands::offline_analysis::prepare;
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Report first-hop identity conflicts observed in one capture: IPv4 addresses claimed by more than one ARP sender MAC, DHCPv4 Offer/ACK server identities, DHCPv6 Advertise/Reply server identities, and IPv6 Router Advertisement sources. Multiple legitimate servers or routers can exist, so counts are observations to reconcile with the authorized design, not proof that a server is rogue. No packets are sent and no names are resolved.

Example:
  packetcraftr analyze first-hop capture.pcapng";

#[derive(Debug, Args)]
pub(crate) struct FirstHop {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    path: PathBuf,
    #[command(flatten)]
    decode: DecodeArgs,
    #[command(flatten)]
    limits: OfflineLimitsArgs,
}

impl Generate for FirstHop {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("first-hop prints text only, not --output {format}"),
            ));
        }
        let prepared = prepare(self.limits, None, &self.decode)?;
        let mut reader = prepared.open(invocation, &self.path)?;
        let options = prepared.options(invocation);
        let report = analysis::first_hop::run(&mut reader, prepared.registry.clone(), &options)
            .map_err(CliError::classified)?;
        let mut text = format!(
            "frames_read={} arp_conflicts={} dhcp_servers={} dhcpv6_servers={} router_advertisers={} multiple_dhcp={} multiple_dhcpv6={} multiple_routers={}\n",
            report.frames_read,
            report.arp_conflicts.len(),
            report.dhcp_servers.len(),
            report.dhcpv6_servers.len(),
            report.router_advertisers.len(),
            report.has_multiple_dhcp_servers(),
            report.has_multiple_dhcpv6_servers(),
            report.has_multiple_router_advertisers(),
        );
        for conflict in &report.arp_conflicts {
            text.push_str(&format!(
                "arp_conflict address={} mac={}\n",
                conflict.address,
                conflict
                    .mac_addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        for server in &report.dhcp_servers {
            text.push_str(&format!("dhcp_server {server}\n"));
        }
        for server in &report.dhcpv6_servers {
            text.push_str(&format!("dhcpv6_server {server}\n"));
        }
        for router in &report.router_advertisers {
            text.push_str(&format!("router_advertiser {router}\n"));
        }
        emit_stdout_document(invocation, &text)?;
        Ok(CommandExit::SUCCESS)
    }
}
