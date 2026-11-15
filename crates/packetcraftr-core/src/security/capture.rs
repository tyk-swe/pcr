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
};
use serde_json::json;
use std::collections::{BTreeMap, btree_map::Entry};

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
    ) -> Result<Self, BoundaryError> {
        limits.validate().map_err(BoundaryError::from_error)?;
        let (kind, engine) = match mode {
            Mode::Hunt(mut document) => {
                let indicators = document.compile().map_err(BoundaryError::from_error)?;
                (
                    "hunt",
                    Engine::Hunt(Box::new(hunt::Hunt::new(indicators, app)?)),
                )
            }
            Mode::Dns(options) => {
                options.validate().map_err(BoundaryError::from_error)?;
                (
                    "dns-anomalies",
                    Engine::Dns(Box::new(dns_anomalies::Anomalies::new(options, app)?)),
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
mod tests {
    use super::*;
    use crate::{
        analysis::Collector as _,
        budget::{Cancellation, Deadline},
        security::indicators::{Indicator, Kind, SCHEMA},
    };
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn threshold_validation_accepts_exact_boundaries() {
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
                .output
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
    fn controlled_finalization_preserves_evidence() {
        let run = analysis::Summary::default();
        let expected_report = collector()
            .finalize(&run, &Deadline::new(Duration::MAX))
            .unwrap();
        let mut events = Vec::new();
        let report = collector()
            .finish(&run, &Deadline::new(Duration::from_secs(1)), &mut |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            serde_json::to_value(&events).unwrap(),
            serde_json::to_value(&expected_report.findings).unwrap()
        );
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::to_value(expected_report).unwrap()
        );
        assert!(events.iter().all(|event| !event.complete));
    }

    #[test]
    fn finalization_stops_on_errors_and_interrupts() {
        let run = analysis::Summary::default();
        let mut delivered = 0;
        let error = collector()
            .finish(&run, &Deadline::new(Duration::from_secs(1)), &mut |_| {
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
                .finish(&run, &Deadline::immediate(None), &mut |_| panic!(
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
                .finish(&run, &deadline, &mut |_| {
                    delivered += 1;
                    cancellation.cancel();
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(delivered, 1);
    }

    #[test]
    fn constructed_hunts_validate_and_normalize() {
        let document = |id: &str, value: &str| Document {
            schema: SCHEMA.into(),
            indicators: vec![Indicator {
                id: id.into(),
                kind: Kind::Domain,
                value: value.into(),
            }],
        };
        for doc in [
            document("", "example.test"),
            document("dns", "."),
            Document {
                schema: "unknown".into(),
                indicators: vec![],
            },
        ] {
            assert!(
                Collector::new(
                    Mode::Hunt(doc),
                    Limits::default(),
                    application::Limits::default()
                )
                .is_err()
            );
        }
        let mut collector = Collector::new(
            Mode::Hunt(document("dns", "EXAMPLE.TEST.")),
            Limits::default(),
            application::Limits::default(),
        )
        .unwrap();
        let Engine::Hunt(hunt) = &collector.engine else {
            panic!("a hunt document builds a hunt")
        };
        hunt.matches
            .dns_events(vec![dns_event("Example.TEST.")], &mut collector.output)
            .unwrap();
        let findings = &collector.output.report.findings;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].indicator_id.as_deref(), Some("dns"));
    }

    #[test]
    fn beacon_intervals_preserve_nanosecond_precision() {
        let options = BeaconOptions {
            min_attempts: 3,
            min_interval_seconds: 1e-10,
            max_cv: 0.0,
        };
        let mut collector = Collector::new(
            Mode::Beacons(options),
            Limits::default(),
            application::Limits::default(),
        )
        .unwrap();
        let epoch = Duration::from_secs(1_800_000_000);
        let Engine::Beacons(beacons) = &mut collector.engine else {
            panic!("beacon options build a beacon collector")
        };
        beacons.groups.insert(
            (
                0,
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                443,
            ),
            beacons::BeaconGroup {
                times: vec![
                    epoch,
                    epoch + Duration::from_nanos(1),
                    epoch + Duration::from_nanos(2),
                ],
                frames: vec![1, 2, 3],
            },
        );
        let report = collector
            .finalize(
                &analysis::Summary::default(),
                &crate::budget::Deadline::new(Duration::from_secs(1)),
            )
            .unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].evidence["mean_interval_seconds"],
            json!(1e-9)
        );
    }

    fn dns_event(name: &str) -> dns::Event {
        use crate::analysis::{
            FlowKey, ScopedFlowKey, StreamTransport,
            provenance::{SourceFrame, Tracker},
            scope::Interner,
        };
        use crate::protocol::application::dns::{Dns, Question};
        let mut message = Dns::default();
        message.questions.push(Question {
            name: name.parse().unwrap(),
            query_type: 1,
            class: 1,
        });
        dns::Event::Message(Box::new(dns::Message {
            index: 1,
            transport: StreamTransport::Udp,
            stream: 1,
            generation: 0,
            flow: ScopedFlowKey {
                scope: Interner::default().intern(None, vec![]).unwrap(),
                flow: FlowKey {
                    source: "192.0.2.1".parse().unwrap(),
                    source_port: 1000,
                    destination: "192.0.2.2".parse().unwrap(),
                    destination_port: 53,
                },
            },
            status: dns::Status::Complete,
            wire: bytes::Bytes::new(),
            declared_length: None,
            framing_bytes: bytes::Bytes::new(),
            dns: Some(message),
            error: None,
            sources: Tracker::new(4096, 8)
                .unwrap()
                .single(SourceFrame {
                    number: 1,
                    timestamp: UNIX_EPOCH + Duration::from_secs(100),
                })
                .unwrap(),
        }))
    }

    fn group_dns(collector: &mut Collector, name: &str) -> Result<(), BoundaryError> {
        let Engine::Dns(anomalies) = &mut collector.engine else {
            panic!("DNS options build a DNS collector")
        };
        anomalies
            .grouping
            .events(vec![dns_event(name)], &mut collector.output)
    }

    fn dns_groups(
        collector: &Collector,
    ) -> &BTreeMap<dns_anomalies::DnsKey, dns_anomalies::DnsGroup> {
        let Engine::Dns(anomalies) = &collector.engine else {
            panic!("DNS options build a DNS collector")
        };
        &anomalies.grouping.groups
    }

    #[test]
    fn dns_groups_inner_labels_within_budget() {
        let options = DnsOptions {
            min_label_length: 4,
            min_entropy: 1.0,
            min_labels: 1,
            ..Default::default()
        };
        let mut collector = Collector::new(
            Mode::Dns(options),
            Limits::default(),
            application::Limits::default(),
        )
        .unwrap();
        group_dns(&mut collector, "a.aBcD.Example.test.").unwrap();
        let groups = dns_groups(&collector);
        assert!(
            groups
                .keys()
                .any(|key| key.3.as_deref() == Some("example.test."))
        );
        assert!(
            groups
                .values()
                .any(|group| group.labels.contains(b"abcd".as_slice()))
        );
        assert!(!groups.keys().any(|key| key.3.as_deref() == Some(".")));
        group_dns(&mut collector, "aBcD.").unwrap();
        assert!(
            !dns_groups(&collector)
                .keys()
                .any(|key| key.3.as_deref() == Some("."))
        );
        let mut bounded = Collector::new(
            Mode::Dns(options),
            Limits {
                max_groups: 1,
                ..Default::default()
            },
            application::Limits::default(),
        )
        .unwrap();
        assert!(group_dns(&mut bounded, "aBcD.eFgH.test.").is_err());
    }
}
