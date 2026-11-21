// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use packetcraftr::scan::segmentation::{Matrix, Verdict, evaluate};
use packetcraftr_core::error::Kind;

use crate::command_options::{
    Bounded as _, CaptureLimitsArgs, IdentificationPolicyArgs, MaxDurationArgs,
};
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Run a TCP segmentation matrix from this host. The packetcraftr.segmentation/v1 document lists numeric destination TCP cells as reachable, refused, or silent. One connect scan covers every distinct destination and port, then each cell is reported as pass, mismatch, or inconclusive. Silence is a connect timeout, a deadline expiry is inconclusive, and an unreachable result is never dressed up as a firewall proving the cell blocked. A mismatch returns an error after the matrix is printed.

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
        let destinations = matrix.destinations();
        let ports = matrix.ports();
        let probes = destinations
            .len()
            .checked_mul(ports.len())
            .and_then(|count| count.checked_mul(self.attempts as usize))
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
        let limits = packetcraftr::scan::Limits {
            max_targets: destinations.len(),
            max_ports: ports.len(),
            max_probes: probes,
            max_duration: self.duration.max_duration(),
            ..packetcraftr::scan::Limits::default()
        };
        let request = packetcraftr::scan::Request {
            max_in_flight: self.max_in_flight,
            targets: packetcraftr::target::Selection {
                include: destinations
                    .iter()
                    .map(|address| {
                        packetcraftr::target::Specification::Target(
                            packetcraftr::target::Target::Address(*address),
                        )
                    })
                    .collect(),
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
        let client = crate::system::client(
            invocation,
            packetcraftr_core::protocol::builtin::registry(),
            self.policy.into_policy(),
            crate::system::Runtime::ScanConnect,
        );
        let collector = packetcraftr::scan::connect::Collector::default();
        let report = client
            .scan_connect(request, collector.clone())
            .map_err(CliError::classified)?;
        let aggregate = collector.finish(report).map_err(CliError::classified)?;
        let results = evaluate(&matrix, &aggregate.endpoints);
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
