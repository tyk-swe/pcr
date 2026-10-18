// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod report;
use super::{CommandExit, Spec};
use crate::{
    command_options::{
        ApplicationLimitsArgs, Bounded, DecodeArgs, IdentificationPolicyArgs, OfflineLimitsArgs,
    },
    errors::CliError,
    invocation::Invocation,
    output::contract::{Command, Format},
    resources::Settings,
};
use clap::{Args, ValueEnum};
use packetcraftr_core::{
    error::Kind,
    security::{self, Report, Severity},
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(super) enum SeverityArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Info => Self::Info,
            SeverityArg::Low => Self::Low,
            SeverityArg::Medium => Self::Medium,
            SeverityArg::High => Self::High,
            SeverityArg::Critical => Self::Critical,
        }
    }
}
#[derive(Clone, Copy, Debug, Args)]
pub(super) struct Bounds {
    /// Maximum retained security findings.
    #[arg(long, default_value_t = 4096)]
    max_findings: usize,
    /// Maximum distinct security groups or compared endpoints.
    #[arg(long, default_value_t = 4096)]
    max_groups: usize,
    /// Maximum retained analysis observations.
    #[arg(long, default_value_t = 100_000)]
    max_observations: usize,
    /// Maximum serialized result bytes, in every output format.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_result_bytes: usize,
    /// Exit 1 when a finding meets or exceeds this severity.
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,
}
impl Bounds {
    fn core(self) -> Result<security::Limits, CliError> {
        let limits = security::Limits {
            max_findings: self.max_findings,
            max_groups: self.max_groups,
            max_observations: self.max_observations,
        };
        limits.validate().map_err(CliError::classified)?;
        if self.max_result_bytes == 0 || self.max_result_bytes > 256 * 1024 * 1024 {
            return Err(invalid("max-result-bytes must be in 1..=268435456"));
        }
        Ok(limits)
    }
    fn resources(&self, settings: &mut Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_findings: Count @ ResultRetention preset(256, 4096),
            max_groups: Count @ ActiveState preset(256, 4096),
            max_observations: Count @ ActiveState preset(10000, 100000),
            max_result_bytes: Bytes @ ResultRetention preset(2097152, 16777216),
        ]);
    }
}
#[derive(Debug, Args)]
pub(super) struct Capture {
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
    /// Local packetcraftr.indicators/v1 JSON document.
    #[arg(long)]
    indicators: PathBuf,
}
#[derive(Debug, Args)]
pub(crate) struct Dns {
    #[command(flatten)]
    capture: Capture,
    #[arg(long, default_value_t = 60)]
    window_seconds: u64,
    #[arg(long, default_value_t = 20)]
    min_responses: usize,
    #[arg(long, default_value_t = 0.5)]
    nxdomain_ratio: f64,
    #[arg(long, default_value_t = 20)]
    min_labels: usize,
    #[arg(long, default_value_t = 32)]
    min_label_length: usize,
    #[arg(long, default_value_t = 4.0)]
    min_entropy: f64,
}
#[derive(Debug, Args)]
pub(crate) struct Beacons {
    #[command(flatten)]
    capture: Capture,
    #[arg(long, default_value_t = 6)]
    min_attempts: usize,
    #[arg(long, default_value_t = 1.0)]
    min_interval_seconds: f64,
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
        let prepared =
            super::offline_analysis::prepare(self.limits, self.filter.as_deref(), &self.decode)?;
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
        let bytes = read(&self.indicators, security::indicators::MAX_DOCUMENT_BYTES)?;
        let doc = security::indicators::Document::parse(&bytes).map_err(CliError::classified)?;
        let source = report::source(&self.indicators, &bytes);
        self.capture.run(
            security::capture::Mode::Hunt(doc),
            Command::Hunt,
            i,
            Some(source),
        )
    }
}
#[derive(Debug, Args)]
pub(crate) struct ScanDiff {
    before: PathBuf,
    after: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
}
impl Spec for ScanDiff {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        let a = read(&self.before, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let b = read(&self.after, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let mut result =
            security::scan::compare(&a, &b, self.bounds.core()?).map_err(CliError::classified)?;
        result.sources = vec![
            report::source(&self.before, &a),
            report::source(&self.after, &b),
        ];
        publish(i, Command::ScanDiff, result, self.bounds)
    }
}
#[derive(Debug, Args)]
pub(super) struct Connection {
    /// Numeric IP:PORT; use `[IPv6]:PORT` for IPv6.
    endpoint: std::net::SocketAddr,
    /// Explicit TLS identity and SNI; never resolved to another target.
    #[arg(long)]
    server_name: Option<String>,
    /// PEM trust anchors replacing the bundled WebPKI roots.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 131072)]
    max_tls_write_bytes: usize,
    #[arg(long, default_value_t = 131072)]
    max_tls_read_bytes: usize,
    #[command(flatten)]
    policy: IdentificationPolicyArgs,
    #[command(flatten)]
    bounds: Bounds,
}
impl Bounded for Connection {
    fn max_duration(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}
impl Connection {
    fn request(&self) -> Result<packetcraftr::audit::TlsRequest, CliError> {
        self.bounds.core()?;
        let mut request = packetcraftr::audit::TlsRequest::new(self.endpoint);
        request.server_name = self.server_name.clone();
        request.timeout = self.max_duration();
        request.limits.max_wire_bytes_sent = self.max_tls_write_bytes;
        request.limits.max_wire_bytes_read = self.max_tls_read_bytes;
        request.limits.handshake_timeout = self.max_duration();
        if let Some(path) = &self.ca_file {
            request.trust =
                packetcraftr_netio::tls::TrustStore::from_pem(&read(path, 1024 * 1024)?)
                    .map_err(invalid)?;
        }
        Ok(request)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
        self.policy.resources(s);
        crate::resources::declare!(s, self, [ timeout_ms: Milliseconds @ Operation, max_tls_write_bytes: Bytes @ Operation, max_tls_read_bytes: Bytes @ ActiveState ]);
    }
}
#[derive(Debug, Args)]
pub(crate) struct AuditTls {
    #[command(flatten)]
    connection: Connection,
}
#[derive(Debug, Args)]
pub(crate) struct AuditHttp {
    #[command(flatten)]
    connection: Connection,
    /// Authenticate TLS before sending HTTP.
    #[arg(long)]
    tls: bool,
    /// Explicit HTTP Host header (does not alter the numeric target).
    #[arg(long)]
    host: Option<String>,
    #[arg(long, default_value = "/")]
    path: String,
    #[arg(long, default_value_t = 65535)]
    max_response_bytes: usize,
}
impl Spec for AuditTls {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(&self.connection)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.connection.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        let request = self.connection.request()?;
        let client = crate::system::client(
            i,
            packetcraftr_core::protocol::builtin::registry(),
            self.connection.policy.into_policy(),
            crate::system::Runtime::Workflow,
        );
        publish(
            i,
            Command::AuditTls,
            client.audit_tls(&request).map_err(CliError::classified)?,
            self.connection.bounds,
        )
    }
}
impl Spec for AuditHttp {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(&self.connection)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.connection.resources(s);
        crate::resources::declare!(s, self, [max_response_bytes: Bytes @ ActiveState]);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        if !self.tls && (self.connection.server_name.is_some() || self.connection.ca_file.is_some())
        {
            return Err(invalid(
                "--server-name and --ca-file require --tls for HTTP audits",
            ));
        }
        let mut request = packetcraftr::audit::HttpRequest::new(self.connection.endpoint);
        request.connection = self.connection.request()?;
        request.tls = self.tls;
        request.host = self.host.unwrap_or_else(|| {
            self.connection
                .server_name
                .clone()
                .unwrap_or_else(|| self.connection.endpoint.to_string())
        });
        request.path = self.path;
        request.max_response_bytes = self.max_response_bytes;
        let client = crate::system::client(
            i,
            packetcraftr_core::protocol::builtin::registry(),
            self.connection.policy.into_policy(),
            crate::system::Runtime::Workflow,
        );
        publish(
            i,
            Command::AuditHttp,
            client.audit_http(&request).map_err(CliError::classified)?,
            self.connection.bounds,
        )
    }
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, CliError> {
    crate::input::read_bounded_json_document(path, limit)
}
fn invalid(message: impl Into<String>) -> CliError {
    CliError::new(Kind::Usage, message)
}
fn publish(
    i: &Invocation,
    command: Command,
    report: Report,
    bounds: Bounds,
) -> Result<CommandExit, CliError> {
    i.check()?;
    let limits = bounds.core()?;
    if report.findings.len() > limits.max_findings {
        return Err(CliError::classified(security::Error::Limit {
            field: "max_findings",
            limit: limits.max_findings,
        }));
    }
    crate::rendering::bounded_json_len(&report, bounds.max_result_bytes)
        .map_err(|e| e.into_cli_error(|| invalid("security result exceeds --max-result-bytes")))?;
    let fail = report.meets(bounds.fail_on.map(Into::into));
    match i.format {
        Format::Json => crate::rendering::emit_aggregate(i, command, report, Vec::new())?,
        Format::Ndjson => {
            for finding in &report.findings {
                i.check()?;
                i.output.emit_data(FindingRecord(finding), Vec::new())?;
            }
            i.output.complete(report, Vec::new())?;
        }
        Format::Text => {
            crate::rendering::write_stdout_line(
                i,
                format_args!(
                    "{}: {} finding(s); evidence {}",
                    report.kind,
                    report.findings.len(),
                    if report.completeness.complete {
                        "complete within the selected input"
                    } else {
                        "incomplete"
                    }
                ),
            )?;
            for key in [
                "endpoint",
                "protocol",
                "cipher",
                "certificate_sha256",
                "verification",
                "status",
                "frames_read",
                "thresholds",
                "before_endpoints",
                "after_endpoints",
                "unchanged_endpoints",
                "html",
            ] {
                if let Some(value) = report.measurements.get(key) {
                    crate::rendering::write_stdout_line(i, format_args!("  {key}: {value}"))?;
                }
            }
            for f in &report.findings {
                crate::rendering::write_stdout_line(
                    i,
                    format_args!(
                        "{:?} {} {}: {}",
                        f.severity, f.rule_id, f.subject, f.summary
                    ),
                )?;
                for key in [
                    "responses",
                    "nxdomain",
                    "ratio",
                    "distinct_labels",
                    "attempts",
                    "mean_interval_seconds",
                    "coefficient_of_variation",
                ] {
                    if let Some(value) = f.evidence.get(key) {
                        crate::rendering::write_stdout_line(i, format_args!("  {key}: {value}"))?;
                    }
                }
                if i.output.presentation().verbose {
                    crate::rendering::write_stdout_line(
                        i,
                        format_args!(
                            "  frames: {:?}\n  evidence: {}\n  remediation: {}",
                            f.frames, f.evidence, f.remediation
                        ),
                    )?;
                }
            }
            for reason in &report.completeness.reasons {
                crate::rendering::write_stdout_line(i, format_args!("  {reason}"))?;
            }
        }
        other => other.unreachable(),
    }
    Ok(CommandExit::status(u8::from(fail)))
}
#[derive(serde::Serialize)]
struct FindingRecord<'a>(&'a security::Finding);
impl crate::output::stream::StreamRecord for FindingRecord<'_> {
    fn event_name(&self) -> &'static str {
        "finding"
    }
}
pub(crate) use report::Assessment;
