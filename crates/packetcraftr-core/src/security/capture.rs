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
        if let Mode::Dns(o) = mode
            && (o.window_seconds == 0
                || o.min_responses == 0
                || o.min_labels == 0
                || !(1..=63).contains(&o.min_label_length)
                || !o.nxdomain_ratio.is_finite()
                || !(0.0..=1.0).contains(&o.nxdomain_ratio)
                || !o.min_entropy.is_finite()
                || !(0.0..=8.0).contains(&o.min_entropy))
        {
            return Err(BoundaryError::from_error(Error::Invalid(
                "invalid DNS thresholds".into(),
            )));
        }
        if let Mode::Beacons(o) = mode
            && (o.min_attempts < 3
                || !o.min_interval_seconds.is_finite()
                || o.min_interval_seconds <= 0.0
                || !o.max_cv.is_finite()
                || !(0.0..=1.0).contains(&o.max_cv))
        {
            return Err(BoundaryError::from_error(Error::Invalid(
                "invalid beacon thresholds".into(),
            )));
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
        self.finalize(run, &crate::budget::Deadline::new(std::time::Duration::MAX))
    }
    fn finish_controlled(
        self,
        run: &analysis::Summary,
        deadline: &crate::budget::Deadline,
        sink: &mut dyn FnMut(Finding) -> Result<(), BoundaryError>,
    ) -> Result<Report, BoundaryError> {
        let (events, report) = self.finalize(run, deadline)?;
        for event in events {
            deadline.enforce().map_err(BoundaryError::from_error)?;
            sink(event)?;
        }
        Ok(report)
    }
}
impl Collector {
    fn finalize(
        mut self,
        run: &analysis::Summary,
        deadline: &crate::budget::Deadline,
    ) -> Result<(Vec<Finding>, Report), BoundaryError> {
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
        Ok((self.report.findings.clone(), self.report))
    }
}
