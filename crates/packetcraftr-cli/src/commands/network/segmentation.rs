// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use packetcraftr::scan::segmentation::{Matrix, Verdict, evaluate};
use packetcraftr_core::clock::{Clock as _, SystemClock};
use packetcraftr_core::error::Kind;

use crate::command_options::{
    Bounded as _, CaptureLimitsArgs, IdentificationPolicyArgs, MaxDurationArgs,
};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Run a TCP segmentation matrix from this host. The packetcraftr.segmentation/v1 document lists numeric destination TCP cells as reachable, refused, or silent. Connect scans grouped by destination cover only the listed destination-port pairs, then each cell is reported as pass, mismatch, or inconclusive. Silence is a connect timeout, a deadline expiry is inconclusive, and an unreachable result is never dressed up as a firewall proving the cell blocked. A mismatch returns an error after the matrix is printed.

Example:
  packetcraftr network segmentation segmentation.json";

#[derive(Debug, Args)]
pub(crate) struct Segmentation {
    /// Segmentation matrix JSON document.
    matrix: PathBuf,
    #[arg(long, default_value_t = 1)]
    attempts: u32,
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 128)]
    max_in_flight: usize,
    #[command(flatten)]
    duration: MaxDurationArgs,
    #[command(flatten)]
    limits: CaptureLimitsArgs,
    #[command(flatten)]
    policy: IdentificationPolicyArgs,
}

impl Generate for Segmentation {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("segmentation prints text only, not --output {format}"),
            ));
        }
        let bytes = crate::input::read_document(
            &invocation.control,
            &self.matrix,
            packetcraftr::scan::segmentation::MAX_MATRIX_DOCUMENT_BYTES,
            crate::input::InputKind::Recipe,
        )?;
        let matrix = Matrix::parse(&bytes).map_err(CliError::classified)?;
        let groups = matrix.probe_groups();
        let pairs = groups.iter().map(|(_, ports)| ports.len()).sum::<usize>();
        let probes = pairs
            .checked_mul(self.attempts as usize)
            .ok_or_else(|| CliError::new(Kind::Usage, "segmentation probe count overflowed"))?;
        if probes > packetcraftr::scan::MAX_PROBES {
            return Err(CliError::new(
                Kind::Usage,
                format!(
                    "segmentation matrix expands to {probes} probes, above {}",
                    packetcraftr::scan::MAX_PROBES
                ),
            ));
        }
        let timeout = Duration::from_millis(self.timeout_ms);
        let queue_limits = self.limits.clone().into_limits();
        let max_duration = self.duration.max_duration();
        let policy = self.policy.into_policy();
        authorize_matrix(&policy, &groups, probes)?;
        let client = crate::system::client(
            invocation,
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            crate::system::Runtime::ScanConnect,
        );
        let started = SystemClock.now();
        let mut endpoints = Vec::new();
        for (destination, ports) in &groups {
            let Some(remaining) = max_duration.checked_sub(started.elapsed()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let group_probes = ports.len() * self.attempts as usize;
            let limits = packetcraftr::scan::Limits {
                max_targets: 1,
                max_ports: ports.len(),
                max_probes: group_probes,
                max_duration: remaining,
                ..packetcraftr::scan::Limits::default()
            };
            let request = packetcraftr::scan::Request {
                max_in_flight: self.max_in_flight,
                targets: packetcraftr::target::Selection {
                    include: vec![packetcraftr::target::Specification::Target(
                        packetcraftr::target::Target::Address(*destination),
                    )],
                    exclude: Vec::new(),
                },
                target_sources: Vec::new(),
                endpoints: ports
                    .iter()
                    .map(|port| packetcraftr::probe::Endpoint::Tcp { port: *port })
                    .collect(),
                tcp_scan: packetcraftr::scan::TcpScan::Syn,
                sctp_scan: packetcraftr::scan::SctpScan::default(),
                discovery: packetcraftr::scan::discovery::Options::default(),
                udp_payload: bytes::Bytes::new(),
                udp_profiles: BTreeMap::new(),
                address_family: packetcraftr::target::Family::Any,
                attempts: self.attempts,
                adaptive: None,
                timeout,
                probes_per_second: None,
                limits,
                route: packetcraftr::route::Options::default(),
                collection: crate::system::collection(timeout, queue_limits)?,
            };
            request.validate().map_err(CliError::classified)?;
            let collector = packetcraftr::scan::connect::Collector::default();
            let report = client
                .scan_connect(request, collector.clone())
                .map_err(CliError::classified)?;
            let aggregate = collector.finish(report).map_err(CliError::classified)?;
            endpoints.extend(aggregate.endpoints);
        }
        let results = evaluate(&matrix, &endpoints);
        let counts = |verdict: Verdict| {
            results
                .iter()
                .filter(|result| result.verdict == verdict)
                .count()
        };
        let mut text = format!(
            "segmentation label={} cells={} pass={} mismatch={} inconclusive={}\n",
            matrix.label,
            results.len(),
            counts(Verdict::Pass),
            counts(Verdict::Mismatch),
            counts(Verdict::Inconclusive),
        );
        for result in &results {
            text.push_str(&format!(
                "cell from={} destination={} port={} expect={} observed={} verdict={}\n",
                result.cell.from,
                result.cell.destination,
                result.cell.port,
                result.cell.expect.as_str(),
                result
                    .observed
                    .map_or("-", |classification| classification.as_str()),
                result.verdict.as_str(),
            ));
        }
        emit_stdout_document(invocation, &text)?;
        if counts(Verdict::Mismatch) > 0 {
            return Err(CliError::new(
                Kind::Policy,
                "segmentation matrix has mismatched cells",
            ));
        }
        Ok(CommandExit::SUCCESS)
    }
}

fn authorize_matrix(
    policy: &packetcraftr::policy::Policy,
    groups: &[(std::net::IpAddr, Vec<u16>)],
    probes: usize,
) -> Result<(), CliError> {
    let endpoints: Vec<SocketAddr> = groups
        .iter()
        .flat_map(|(destination, ports)| {
            ports
                .iter()
                .map(move |port| SocketAddr::new(*destination, *port))
        })
        .collect();
    let operation = packetcraftr::policy::SocketOperation::new(
        &endpoints,
        packetcraftr::policy::SocketLimits::new(u64::try_from(probes).unwrap_or(u64::MAX), 0, 0),
    )
    .map_err(CliError::classified)?;
    policy
        .authorize(packetcraftr::policy::Operation::Socket(operation))
        .map_err(CliError::classified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn matrix_authorization_counts_every_group() {
        let groups: Vec<(IpAddr, Vec<u16>)> = vec![
            ("10.0.0.1".parse().unwrap(), vec![443, 22]),
            ("10.0.0.2".parse().unwrap(), vec![25]),
        ];
        let mut policy = packetcraftr::policy::Policy {
            max_packets_per_operation: 2,
            ..packetcraftr::policy::Policy::default()
        };
        assert!(authorize_matrix(&policy, &groups, 3).is_err());
        policy.max_packets_per_operation = 3;
        assert!(authorize_matrix(&policy, &groups, 3).is_ok());
    }
}
