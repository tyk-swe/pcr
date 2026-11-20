// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod beacons;
mod dns_anomalies;
mod hunt;

use super::{Error, Finding, Limits, Report, Severity, indicators::Document};
use crate::{
    analysis::{self, FrameRecord, application, dns},
    error::BoundaryError,
    protocol::application::dns::Dns,
    registry::Registry,
};
use serde_json::json;
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub struct DnsOptions {
    pub window_seconds: u64,
    pub min_responses: usize,
    pub nxdomain_ratio: f64,
    pub min_labels: usize,
    pub min_label_length: usize,
    pub min_entropy: f64,
}
impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            window_seconds: 60,
            min_responses: 20,
            nxdomain_ratio: 0.5,
            min_labels: 20,
            min_label_length: 32,
            min_entropy: 4.0,
        }
    }
}
impl DnsOptions {
    /// Validate DNS thresholds before opening or processing a capture.
    pub fn validate(self) -> Result<(), Error> {
        if self.window_seconds == 0 {
            return Err(Error::Invalid(
                "window_seconds must be greater than 0".into(),
            ));
        }
        if self.min_responses == 0 {
            return Err(Error::Invalid(
                "min_responses must be greater than 0".into(),
            ));
        }
        if self.min_labels == 0 {
            return Err(Error::Invalid("min_labels must be greater than 0".into()));
        }
        if !(1..=63).contains(&self.min_label_length) {
            return Err(Error::Invalid("min_label_length must be in 1..=63".into()));
        }
        if !self.nxdomain_ratio.is_finite() || !(0.0..=1.0).contains(&self.nxdomain_ratio) {
            return Err(Error::Invalid(
                "nxdomain_ratio must be finite and in 0..=1".into(),
            ));
        }
        if !self.min_entropy.is_finite() || !(0.0..=8.0).contains(&self.min_entropy) {
            return Err(Error::Invalid(
                "min_entropy must be finite and in 0..=8".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct BeaconOptions {
    pub min_attempts: usize,
    pub min_interval_seconds: f64,
    pub max_cv: f64,
}
impl Default for BeaconOptions {
    fn default() -> Self {
        Self {
            min_attempts: 6,
            min_interval_seconds: 1.0,
            max_cv: 0.10,
        }
    }
}
impl BeaconOptions {
    /// Validate beacon thresholds before opening or processing a capture.
    pub fn validate(self) -> Result<(), Error> {
        if self.min_attempts < 3 {
            return Err(Error::Invalid("min_attempts must be at least 3".into()));
        }
        if !self.min_interval_seconds.is_finite() || self.min_interval_seconds <= 0.0 {
            return Err(Error::Invalid(
                "min_interval_seconds must be finite and greater than 0".into(),
            ));
        }
        if !self.max_cv.is_finite() || !(0.0..=1.0).contains(&self.max_cv) {
            return Err(Error::Invalid("max_cv must be finite and in 0..=1".into()));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub enum Mode {
    Hunt(Document),
    Dns(DnsOptions),
    Beacons(BeaconOptions),
}

pub struct Collector {
    engine: Engine,
    output: Output,
}

/// The state one mode keeps; no mode carries another's collectors or groups.
enum Engine {
    Hunt(Box<hunt::Hunt>),
    Dns(Box<dns_anomalies::Anomalies>),
    Beacons(beacons::Beacons),
}

/// What every mode records into: its limits, its report, and the observations charged.
struct Output {
    limits: Limits,
    report: Report,
    observations: usize,
}

impl Collector {
    pub fn new(
        mode: Mode,
        limits: Limits,
        app: application::Limits,
        registry: Arc<Registry>,
    ) -> Result<Self, BoundaryError> {
        limits.validate().map_err(BoundaryError::from_error)?;
        let (kind, engine) = match mode {
            Mode::Hunt(mut document) => {
                let indicators = document.compile().map_err(BoundaryError::from_error)?;
                (
                    "hunt",
                    Engine::Hunt(Box::new(hunt::Hunt::new(indicators, app, registry)?)),
                )
            }
            Mode::Dns(options) => {
                options.validate().map_err(BoundaryError::from_error)?;
                (
                    "dns-anomalies",
                    Engine::Dns(Box::new(dns_anomalies::Anomalies::new(
                        options, app, registry,
                    )?)),
                )
            }
            Mode::Beacons(options) => {
                options.validate().map_err(BoundaryError::from_error)?;
                ("beacons", Engine::Beacons(beacons::Beacons::new(options)))
            }
        };
        Ok(Self {
            engine,
            output: Output {
                limits,
                report: Report::new(kind),
                observations: 0,
            },
        })
    }
}

impl Output {
    fn charge(&mut self) -> Result<(), BoundaryError> {
        if self.observations == self.limits.max_observations {
            return Err(BoundaryError::from_error(Error::Limit {
                field: "max_observations",
                limit: self.limits.max_observations,
            }));
        }
        self.observations += 1;
        Ok(())
    }

    /// The group at `key`, opened with `open` if it is new and `max_groups` allows another.
    fn group<'m, K: Ord, V>(
        &self,
        groups: &'m mut BTreeMap<K, V>,
        key: K,
        open: impl FnOnce() -> V,
    ) -> Result<&'m mut V, BoundaryError> {
        let open_groups = groups.len();
        match groups.entry(key) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                if open_groups >= self.limits.max_groups {
                    return Err(BoundaryError::from_error(Error::Limit {
                        field: "max_groups",
                        limit: self.limits.max_groups,
                    }));
                }
                Ok(entry.insert(open()))
            }
        }
    }

    fn add(&mut self, finding: Finding) -> Result<(), BoundaryError> {
        self.limits
            .push(&mut self.report, finding)
            .map_err(BoundaryError::from_error)
    }

    /// Charges a DNS message and notes an incomplete one. `None` means it did not parse.
    fn dns_message<'m>(
        &mut self,
        message: &'m dns::Message,
    ) -> Result<Option<(&'m Dns, Vec<u64>)>, BoundaryError> {
        self.charge()?;
        if message.status != dns::Status::Complete {
            self.report
                .completeness
                .note("incomplete or malformed DNS messages");
        }
        Ok(message
            .dns
            .as_ref()
            .map(|d| (d, message.sources.iter().map(|s| s.number).collect())))
    }

    fn dns_issue(&mut self) {
        self.report
            .completeness
            .note("DNS stream has missing or conflicting bytes");
    }

    fn note_run(&mut self, run: &analysis::Summary) {
        if run.frames_matched == 0 {
            self.report
                .completeness
                .note("no frames matched the selected capture scope");
        }
        if !run.incomplete_sources.is_empty() || run.source_outcomes_omitted > 0 {
            self.report
                .completeness
                .note("capture reassembly has incomplete source evidence");
        }
        if run.clock.regressions > 0 {
            self.report
                .completeness
                .note("capture clock regressions observed; beacon timing conclusions suppressed");
        }
    }
}
fn sample(dest: &mut Vec<u64>, source: &[u64]) {
    for f in source {
        if dest.len() < 64 && !dest.contains(f) {
            dest.push(*f);
        }
    }
}
pub fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[usize::from(*b)] += 1;
    }
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / bytes.len() as f64;
            -p * p.log2()
        })
        .sum()
}
impl analysis::Collector for Collector {
    type Event = Finding;
    type Summary = Report;
    fn needs(&self) -> analysis::CollectorNeeds {
        analysis::CollectorNeeds {
            tcp_stream: true,
            udp_stream: true,
            ip_reassembly: true,
            tcp_events: !matches!(self.engine, Engine::Beacons(_)),
            track_sources: true,
        }
    }
    fn observe(
        &mut self,
        r: &FrameRecord<'_>,
        _deadline: &crate::budget::Deadline,
    ) -> Result<Vec<Finding>, BoundaryError> {
        if r.decoded.frame.captured_length() < r.decoded.frame.original_length() {
            self.output
                .report
                .completeness
                .note("capture contains truncated frames");
        }
        match &mut self.engine {
            Engine::Hunt(hunt) => hunt.observe(r, &mut self.output)?,
            Engine::Dns(anomalies) => anomalies.observe(r, &mut self.output)?,
            Engine::Beacons(beacons) => beacons.observe(r, &mut self.output)?,
        }
        Ok(Vec::new())
    }
    fn finish(
        self,
        run: &analysis::Summary,
        deadline: &crate::budget::Deadline,
        sink: &mut dyn FnMut(Finding) -> Result<(), BoundaryError>,
    ) -> Result<Report, BoundaryError> {
        let report = self.finalize(run, deadline)?;
        for finding in &report.findings {
            deadline.enforce().map_err(BoundaryError::from_error)?;
            sink(finding.clone())?;
            deadline.enforce().map_err(BoundaryError::from_error)?;
        }
        Ok(report)
    }
}
impl Collector {
    fn finalize(
        self,
        run: &analysis::Summary,
        deadline: &crate::budget::Deadline,
    ) -> Result<Report, BoundaryError> {
        deadline.enforce().map_err(BoundaryError::from_error)?;
        let Self { engine, mut output } = self;
        match engine {
            Engine::Hunt(hunt) => hunt.finish(run, deadline, &mut output)?,
            Engine::Dns(anomalies) => anomalies.finish(run, deadline, &mut output)?,
            Engine::Beacons(beacons) => beacons.finish(run, deadline, &mut output)?,
        }
        let mut report = output.report;
        report
            .measurements
            .insert("frames_read".into(), json!(run.frames_read));
        report
            .measurements
            .insert("frames_matched".into(), json!(run.frames_matched));
        report.measurements.insert("clock".into(), json!(run.clock));
        report
            .measurements
            .insert("scopes".into(), json!(run.scopes));
        for f in &mut report.findings {
            f.complete &= report.completeness.complete;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
