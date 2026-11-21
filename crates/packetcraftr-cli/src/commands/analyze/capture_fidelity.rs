// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use clap::Args;
use packetcraftr_core::analysis::fidelity;
use packetcraftr_core::error::Kind;

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Measures how much of the operator capture a sensor capture can see. Frames pair first by exact bytes, then by strict prefix of at least 20 captured bytes so snap-length truncation is counted separately from loss without treating degenerate prefixes as visibility. Timestamp skew is reported only for paired frames and assumes the two capture clocks are comparable. This measures capture visibility, not forwarding or detection.

Example:
  packetcraftr analyze capture-fidelity operator.pcapng sensor.pcapng";

#[derive(Debug, Args)]
pub(crate) struct CaptureFidelity {
    /// Operator PCAP or PCAPNG capture; - reads redirected stdin.
    operator: PathBuf,
    /// Sensor PCAP or PCAPNG capture of the same traffic.
    sensor: PathBuf,
    #[command(flatten)]
    limits: OfflineCaptureLimitsArgs,
}

impl Generate for CaptureFidelity {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("capture-fidelity prints text only, not --output {format}"),
            ));
        }
        if self.operator == Path::new("-") && self.sensor == Path::new("-") {
            return Err(CliError::new(
                Kind::Usage,
                "operator and sensor captures cannot both read stdin",
            ));
        }
        let operator = super::frames::read_frames(invocation, &self.operator, self.limits)?;
        let sensor = super::frames::read_frames(invocation, &self.sensor, self.limits)?;
        let report = fidelity::compare(&operator, &sensor);
        let visibility = report
            .visibility_percent()
            .map_or_else(|| "-".to_owned(), |value| format!("{value:.1}"));
        let optional =
            |value: Option<u128>| value.map_or_else(|| "-".to_owned(), |value| value.to_string());
        emit_stdout_document(
            invocation,
            &format!(
                "operator_frames={} sensor_frames={} exact_matches={} truncated_matches={} operator_only={} sensor_only={} visibility_percent={visibility} link_type_mismatches={} max_abs_skew_ms={} median_abs_skew_ms={}\n",
                report.operator_frames,
                report.sensor_frames,
                report.exact_matches,
                report.truncated_matches,
                report.operator_only,
                report.sensor_only,
                report.link_type_mismatches,
                optional(report.max_abs_skew_ms),
                optional(report.median_abs_skew_ms),
            ),
        )?;
        Ok(CommandExit::SUCCESS)
    }
}
