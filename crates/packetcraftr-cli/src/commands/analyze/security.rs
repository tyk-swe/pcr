// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, input, publish, read, source};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
use crate::{
    command_options::{ApplicationLimitsArgs, Bounded, DecodeArgs, OfflineLimitsArgs},
    errors::CliError,
    resources::Settings,
};
use clap::Args;
use packetcraftr_core::security;
use std::path::PathBuf;

#[derive(Debug, Args)]
struct Capture {
    /// Classic PCAP or PCAPNG input; - reads redirected stdin.
    path: PathBuf,
    /// Display filter selecting evidence within the capture.
    #[arg(long)]
    filter: Option<String>,
    #[command(flatten)]
    decode: DecodeArgs,
    #[command(flatten)]
    limits: OfflineLimitsArgs,
    #[command(flatten)]
    application: ApplicationLimitsArgs,
    #[command(flatten)]
    bounds: Bounds,
}
#[derive(Debug, Args)]
pub(crate) struct Hunt {
    #[command(flatten)]
    capture: Capture,
    /// Local packetcraftr.indicators/v1 JSON document; - reads redirected JSON stdin.
    #[arg(long)]
    indicators: PathBuf,
}
#[derive(Debug, Args)]
pub(crate) struct Dns {
    #[command(flatten)]
    capture: Capture,
    /// Epoch-aligned observation window in seconds; must be greater than zero.
    #[arg(long, default_value_t = 60)]
    window_seconds: u64,
    /// Minimum matched responses per window; must be greater than zero.
    #[arg(long, default_value_t = 20)]
    min_responses: usize,
    /// Minimum NXDOMAIN ratio, from 0 through 1.
    #[arg(long, default_value_t = 0.5)]
    nxdomain_ratio: f64,
    /// Minimum distinct high-entropy labels; must be greater than zero.
    #[arg(long, default_value_t = 20)]
    min_labels: usize,
    /// Minimum label length, from 1 through 63 bytes.
    #[arg(long, default_value_t = 32)]
    min_label_length: usize,
    /// Minimum Shannon entropy, from 0 through 8 bits per byte.
    #[arg(long, default_value_t = 4.0)]
    min_entropy: f64,
}
#[derive(Debug, Args)]
pub(crate) struct Beacons {
    #[command(flatten)]
    capture: Capture,
    /// Minimum distinct connection attempts; must be at least 3.
    #[arg(long, default_value_t = 6)]
    min_attempts: usize,
    /// Minimum mean attempt interval in seconds; must be finite and positive.
    #[arg(long, default_value_t = 1.0)]
    min_interval_seconds: f64,
    /// Maximum interval coefficient of variation, from 0 through 1.
    #[arg(long, default_value_t = 0.10)]
    max_cv: f64,
}
impl Capture {
    fn resources(&self, settings: &mut Settings<'_>) {
        self.bounds.resources(settings);
        self.application.resources(settings);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
    }
    fn run(
        self,
        mode: security::capture::Mode,
        command: Command,
        invocation: &Invocation,
        source: Option<security::Source>,
    ) -> Result<CommandExit, CliError> {
        let limits = self.bounds.core()?;
        self.application.validate_output()?;
        let collector = security::capture::Collector::new(mode, limits, self.application.core())
            .map_err(CliError::classified)?;
        let prepared = crate::commands::offline_analysis::prepare(
            self.limits,
            self.filter.as_deref(),
            &self.decode,
        )?;
        let session = packetcraftr_core::analysis::Session::new(
            prepared.registry.clone(),
            prepared.options(invocation),
            collector,
        );
        let mut reader =
            crate::input::open_capture(invocation, &self.path, self.limits.capture.reader)?;
        let mut report = session
            .run(&mut reader, |_| Ok(()), |_| Ok(()))
            .map_err(CliError::classified)?
            .summary;
        if self.filter.is_some() {
            report
                .measurements
                .insert("filter".into(), serde_json::json!(self.filter));
            report
                .completeness
                .note("analysis restricted by display filter");
        }
        if let Some(source) = source {
            report.sources.push(source);
        }
        // Capture provenance is supplied by physical frame numbers and scope definitions;
        // streamed stdin is deliberately not reread to manufacture a source hash.
        report
            .measurements
            .insert("capture".into(), serde_json::json!(self.path));
        let mut bounds = self.bounds;
        bounds.max_result_bytes = bounds
            .max_result_bytes
            .min(self.application.max_application_output_bytes);
        publish(invocation, command, report, bounds)
    }
}
macro_rules! capture_spec {
    ($ty:ty, $command:ident, $mode:expr) => {
        impl Spec for $ty {
            const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
            const CANCELLATION: bool = true;
            const OFFLINE: bool = true;
            fn run_time(&self) -> Option<&dyn Bounded> {
                Some(&self.capture.limits)
            }
            fn resources(&self, s: &mut Settings<'_>) {
                self.capture.resources(s);
            }
            fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
                let mode = ($mode)(&self);
                self.capture.run(mode, Command::$command, i, None)
            }
        }
    };
}
capture_spec!(Dns, DnsAnomalies, |s: &Dns| security::capture::Mode::Dns(
    security::capture::DnsOptions {
        window_seconds: s.window_seconds,
        min_responses: s.min_responses,
        nxdomain_ratio: s.nxdomain_ratio,
        min_labels: s.min_labels,
        min_label_length: s.min_label_length,
        min_entropy: s.min_entropy
    }
));
capture_spec!(Beacons, Beacons, |s: &Beacons| {
    security::capture::Mode::Beacons(security::capture::BeaconOptions {
        min_attempts: s.min_attempts,
        min_interval_seconds: s.min_interval_seconds,
        max_cv: s.max_cv,
    })
});
impl Spec for Hunt {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(&self.capture.limits)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.capture.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        input::validate_stdin_sources([self.capture.path.as_path(), self.indicators.as_path()])?;
        let bytes = read(&self.indicators, security::indicators::MAX_DOCUMENT_BYTES)?;
        let doc = security::indicators::Document::parse(&bytes).map_err(CliError::classified)?;
        let source = source(&self.indicators, &bytes);
        self.capture.run(
            security::capture::Mode::Hunt(doc),
            Command::Hunt,
            i,
            Some(source),
        )
    }
}
