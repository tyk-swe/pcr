// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod beacons;
mod dns_anomalies;
mod hunt;

use super::{Error, Finding, Limits, Report, Severity, indicators::Document};
use crate::{
    analysis::{self, FrameRecord, application, dns, http, tls},
    error::BoundaryError,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

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
#[derive(Default)]
struct DnsGroup {
    responses: usize,
    nx: usize,
    labels: BTreeSet<Vec<u8>>,
    frames: Vec<u64>,
}
#[derive(Default)]
struct BeaconGroup {
    times: Vec<f64>,
    frames: Vec<u64>,
}
type DnsKey = (u32, IpAddr, u64, Option<String>);
type BeaconKey = (u32, IpAddr, IpAddr, u16);

pub struct Collector {
    mode: Mode,
    limits: Limits,
    report: Report,
    dns: Option<dns::Collector>,
    http: Option<http::Collector>,
    tls: Option<tls::Collector>,
    dns_groups: BTreeMap<DnsKey, DnsGroup>,
    replies: BTreeMap<u64, (u16, u64)>,
    beacons: BTreeMap<BeaconKey, BeaconGroup>,
    stream_sources: BTreeMap<u64, Vec<u64>>,
    syns: BTreeMap<analysis::reassembly::tcp::ScopedFlowKey, BTreeSet<u32>>,
    observations: usize,
}
impl Collector {
    pub fn new(
        mode: Mode,
        limits: Limits,
        app: application::Limits,
    ) -> Result<Self, BoundaryError> {
        limits.validate().map_err(BoundaryError::from_error)?;
        match &mode {
            Mode::Dns(options) => options.validate().map_err(BoundaryError::from_error)?,
            Mode::Beacons(options) => options.validate().map_err(BoundaryError::from_error)?,
            Mode::Hunt(_) => {}
        }
        let hunt = matches!(mode, Mode::Hunt(_));
        let has_dns = !matches!(mode, Mode::Beacons(_));
        let report = Report::new(match mode {
            Mode::Hunt(_) => "hunt",
            Mode::Dns(_) => "dns-anomalies",
            Mode::Beacons(_) => "beacons",
        });
        Ok(Self {
            mode,
            limits,
            report,
            dns: if has_dns {
                Some(dns::Collector::new(app, [53]).map_err(BoundaryError::from_error)?)
            } else {
                None
            },
            http: if hunt {
                Some(
                    http::Collector::new(app, [80, 8080, 8000], 256 * 1024 * 1024)
                        .map_err(BoundaryError::from_error)?,
                )
            } else {
                None
            },
            tls: if hunt {
                Some(
                    tls::Collector::new(tls::Limits {
                        max_sessions: app.max_streams,
                        max_buffered_bytes: app.max_buffer_bytes,
                    })
                    .map_err(BoundaryError::from_error)?,
                )
            } else {
                None
            },
            dns_groups: BTreeMap::new(),
            replies: BTreeMap::new(),
            beacons: BTreeMap::new(),
            stream_sources: BTreeMap::new(),
            syns: BTreeMap::new(),
            observations: 0,
        })
    }
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
    fn group(&self) -> Result<(), BoundaryError> {
        if self.dns_groups.len() + self.beacons.len() + self.stream_sources.len()
            >= self.limits.max_groups
        {
            return Err(BoundaryError::from_error(Error::Limit {
                field: "max_groups",
                limit: self.limits.max_groups,
            }));
        }
        Ok(())
    }
    fn add(&mut self, finding: Finding) -> Result<(), BoundaryError> {
        self.limits
            .push(&mut self.report, finding)
            .map_err(BoundaryError::from_error)
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
            tcp_events: !matches!(self.mode, Mode::Beacons(_)),
            track_sources: true,
        }
    }
    fn observe(&mut self, r: &FrameRecord<'_>) -> Result<Vec<Finding>, BoundaryError> {
        if r.decoded.frame.captured_length() < r.decoded.frame.original_length() {
            self.report
                .completeness
                .note("capture contains truncated frames");
        }
        if matches!(self.mode, Mode::Hunt(_)) {
            self.observe_hunt(r)?;
        }
        if matches!(self.mode, Mode::Beacons(_)) {
            self.beacon(r)?;
        }
        if let Some(d) = &mut self.dns {
            let events = d.observe(r).map_err(BoundaryError::from_error)?;
            self.dns_events(events)?;
        }
        if let Some(h) = &mut self.http {
            let events = h.observe(r).map_err(BoundaryError::from_error)?;
            self.http_events(events)?;
        }
        if let Some(t) = &mut self.tls {
            let events = t.observe(r);
            self.tls_events(events)?;
        }
        Ok(Vec::new())
    }
    fn finish(self, run: &analysis::Summary) -> Result<(Vec<Finding>, Report), BoundaryError> {
        let report = self.finalize(run, &crate::budget::Deadline::new(std::time::Duration::MAX))?;
        Ok((report.findings.clone(), report))
    }
    fn finish_controlled(
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
        mut self,
        run: &analysis::Summary,
        deadline: &crate::budget::Deadline,
    ) -> Result<Report, BoundaryError> {
        deadline.enforce().map_err(BoundaryError::from_error)?;
        if let Some(d) = self.dns.take() {
            analysis::Collector::finish_controlled(d, run, deadline, &mut |e| {
                self.dns_events(vec![e])
            })?;
        }
        if let Some(h) = self.http.take() {
            analysis::Collector::finish_controlled(h, run, deadline, &mut |e| {
                self.http_events(vec![e])
            })?;
        }
        if let Some(t) = self.tls.take() {
            analysis::Collector::finish_controlled(t, run, deadline, &mut |e| {
                self.tls_events(vec![e])
            })?;
        }
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
        match self.mode {
            Mode::Dns(o) => self.finish_dns(o, deadline)?,
            Mode::Beacons(o) => self.finish_beacons(o, run, deadline)?,
            Mode::Hunt(_) => {}
        }
        self.report
            .measurements
            .insert("frames_read".into(), json!(run.frames_read));
        self.report
            .measurements
            .insert("frames_matched".into(), json!(run.frames_matched));
        self.report
            .measurements
            .insert("clock".into(), json!(run.clock));
        self.report
            .measurements
            .insert("scopes".into(), json!(run.scopes));
        for f in &mut self.report.findings {
            f.complete &= self.report.completeness.complete;
        }
        Ok(self.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::Collector as _,
        budget::{Cancellation, Deadline},
    };
    use std::time::Duration;

    #[test]
    fn threshold_validation_reports_each_invalid_field_and_accepts_boundaries() {
        for (options, field) in [
            (
                DnsOptions {
                    window_seconds: 0,
                    ..Default::default()
                },
                "window_seconds",
            ),
            (
                DnsOptions {
                    min_responses: 0,
                    ..Default::default()
                },
                "min_responses",
            ),
            (
                DnsOptions {
                    min_labels: 0,
                    ..Default::default()
                },
                "min_labels",
            ),
            (
                DnsOptions {
                    min_label_length: 64,
                    ..Default::default()
                },
                "min_label_length",
            ),
            (
                DnsOptions {
                    nxdomain_ratio: f64::NAN,
                    ..Default::default()
                },
                "nxdomain_ratio",
            ),
            (
                DnsOptions {
                    nxdomain_ratio: 1.1,
                    ..Default::default()
                },
                "nxdomain_ratio",
            ),
            (
                DnsOptions {
                    min_entropy: f64::INFINITY,
                    ..Default::default()
                },
                "min_entropy",
            ),
            (
                DnsOptions {
                    min_entropy: -0.1,
                    ..Default::default()
                },
                "min_entropy",
            ),
        ] {
            assert!(options.validate().unwrap_err().to_string().contains(field));
            assert!(
                Collector::new(
                    Mode::Dns(options),
                    Limits::default(),
                    application::Limits::default()
                )
                .is_err()
            );
        }
        for (options, field) in [
            (
                BeaconOptions {
                    min_attempts: 2,
                    ..Default::default()
                },
                "min_attempts",
            ),
            (
                BeaconOptions {
                    min_interval_seconds: 0.0,
                    ..Default::default()
                },
                "min_interval_seconds",
            ),
            (
                BeaconOptions {
                    min_interval_seconds: f64::NAN,
                    ..Default::default()
                },
                "min_interval_seconds",
            ),
            (
                BeaconOptions {
                    max_cv: f64::INFINITY,
                    ..Default::default()
                },
                "max_cv",
            ),
            (
                BeaconOptions {
                    max_cv: 1.1,
                    ..Default::default()
                },
                "max_cv",
            ),
        ] {
            assert!(options.validate().unwrap_err().to_string().contains(field));
            assert!(
                Collector::new(
                    Mode::Beacons(options),
                    Limits::default(),
                    application::Limits::default()
                )
                .is_err()
            );
        }
        for (ratio, entropy, length) in [(0.0, 0.0, 1), (1.0, 8.0, 63)] {
            assert!(
                DnsOptions {
                    nxdomain_ratio: ratio,
                    min_entropy: entropy,
                    min_label_length: length,
                    ..Default::default()
                }
                .validate()
                .is_ok()
            );
        }
        for max_cv in [0.0, 1.0] {
            assert!(
                BeaconOptions {
                    min_attempts: 3,
                    max_cv,
                    ..Default::default()
                }
                .validate()
                .is_ok()
            );
        }
    }

    fn collector() -> Collector {
        let mut collector = Collector::new(
            Mode::Beacons(BeaconOptions::default()),
            Limits::default(),
            application::Limits::default(),
        )
        .unwrap();
        for subject in ["first", "second"] {
            collector
                .add(Finding::new(
                    "test",
                    Severity::Low,
                    subject,
                    "summary",
                    json!({"observed":true}),
                    "review",
                ))
                .unwrap();
        }
        collector
    }

    #[test]
    fn controlled_finalization_preserves_events_summary_and_completeness() {
        let run = analysis::Summary::default();
        let (expected_events, expected_report) = collector().finish(&run).unwrap();
        let mut events = Vec::new();
        let report = collector()
            .finish_controlled(&run, &Deadline::new(Duration::from_secs(1)), &mut |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            serde_json::to_value(&events).unwrap(),
            serde_json::to_value(expected_events).unwrap()
        );
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::to_value(expected_report).unwrap()
        );
        assert!(events.iter().all(|event| !event.complete));
    }

    #[test]
    fn controlled_finalization_stops_on_sink_error_expiry_and_cancellation() {
        let run = analysis::Summary::default();
        let mut delivered = 0;
        let error = collector()
            .finish_controlled(&run, &Deadline::new(Duration::from_secs(1)), &mut |_| {
                delivered += 1;
                Err(BoundaryError::from_error(Error::Invalid(
                    "sink refused".into(),
                )))
            })
            .unwrap_err();
        assert_eq!(delivered, 1);
        assert!(error.to_string().contains("sink refused"));
        assert!(
            collector()
                .finish_controlled(&run, &Deadline::immediate(None), &mut |_| panic!(
                    "expired events must not be delivered"
                ))
                .is_err()
        );
        let cancellation = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
        let mut delivered = 0;
        assert!(
            collector()
                .finish_controlled(&run, &deadline, &mut |_| {
                    delivered += 1;
                    cancellation.cancel();
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(delivered, 1);
    }
}
