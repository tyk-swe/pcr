// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Error, Finding, Limits, Report, Severity,
    indicators::{Document, Kind},
};
use crate::{
    analysis::{self, FrameRecord, application, dns, http, tls},
    error::BoundaryError,
    protocol::{
        application::dns::RecordValue,
        network::{Ipv4, Ipv6},
        transport::Tcp,
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::UNIX_EPOCH,
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
    fn indicator_matches(
        &mut self,
        value: &str,
        ip: Option<IpAddr>,
        fingerprint: Option<Kind>,
        frames: Vec<u64>,
        context: serde_json::Value,
    ) -> Result<(), BoundaryError> {
        let Mode::Hunt(doc) = &self.mode else {
            return Ok(());
        };
        let matched: Vec<_> = doc
            .indicators
            .iter()
            .filter(|i| {
                if let Some(ip) = ip {
                    i.matches_ip(ip)
                } else if let Some(kind) = fingerprint {
                    i.kind == kind && i.value == value
                } else {
                    i.matches_domain(value)
                }
            })
            .map(|i| i.id.clone())
            .collect();
        for id in matched {
            let mut finding = Finding::new(
                "ioc.match",
                Severity::High,
                value,
                "Observed value matches a local indicator",
                json!({"value": value, "context": context}),
                "Validate the indicator and investigate the contributing frames and endpoint.",
            );
            finding.indicator_id = Some(id);
            finding.frames = frames.clone();
            self.add(finding)?;
        }
        Ok(())
    }
    fn dns_events(&mut self, events: Vec<dns::Event>) -> Result<(), BoundaryError> {
        for event in events {
            match event {
                dns::Event::Message(m) => {
                    self.charge()?;
                    if m.status != dns::Status::Complete {
                        self.report
                            .completeness
                            .note("incomplete or malformed DNS messages");
                    }
                    let Some(d) = &m.dns else { continue };
                    let frames: Vec<_> = m.sources.iter().map(|s| s.number).collect();
                    let time = m
                        .sources
                        .first()
                        .and_then(|s| s.timestamp.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs());
                    if matches!(self.mode, Mode::Hunt(_)) {
                        for q in &d.questions {
                            self.indicator_matches(
                                &q.name.to_string(),
                                None,
                                None,
                                frames.clone(),
                                json!({"protocol":"dns", "scope":m.flow.scope, "message":m.index}),
                            )?;
                        }
                        for rr in d.answers.iter().chain(&d.authorities).chain(&d.additionals) {
                            self.indicator_matches(
                                &rr.owner.to_string(),
                                None,
                                None,
                                frames.clone(),
                                json!({"protocol":"dns", "scope":m.flow.scope, "message":m.index}),
                            )?;
                            match &rr.value {
                                RecordValue::A(ip) => self.indicator_matches(
                                    &ip.to_string(),
                                    Some((*ip).into()),
                                    None,
                                    frames.clone(),
                                    json!({"protocol":"dns_answer"}),
                                )?,
                                RecordValue::Aaaa(ip) => self.indicator_matches(
                                    &ip.to_string(),
                                    Some((*ip).into()),
                                    None,
                                    frames.clone(),
                                    json!({"protocol":"dns_answer"}),
                                )?,
                                RecordValue::Cname(n)
                                | RecordValue::Ns(n)
                                | RecordValue::Ptr(n)
                                | RecordValue::Mx { exchange: n, .. }
                                | RecordValue::Srv { target: n, .. } => self.indicator_matches(
                                    &n.to_string(),
                                    None,
                                    None,
                                    frames.clone(),
                                    json!({"protocol":"dns_rdata"}),
                                )?,
                                RecordValue::Soa {
                                    primary_name_server,
                                    responsible_mailbox,
                                    ..
                                } => {
                                    for n in [primary_name_server, responsible_mailbox] {
                                        self.indicator_matches(
                                            &n.to_string(),
                                            None,
                                            None,
                                            frames.clone(),
                                            json!({"protocol":"dns_rdata"}),
                                        )?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else if let Mode::Dns(o) = self.mode {
                        let Some(time) = time else {
                            self.report.completeness.note("DNS timestamp unavailable");
                            continue;
                        };
                        if d.truncated {
                            self.report
                                .completeness
                                .note("truncated DNS responses observed");
                        }
                        if d.response {
                            let extended = d
                                .additionals
                                .iter()
                                .find_map(|r| match &r.value {
                                    RecordValue::Opt(edns) => Some(edns.extended_response_code),
                                    _ => None,
                                })
                                .unwrap_or(0);
                            self.replies.insert(
                                m.index,
                                (
                                    (u16::from(extended) << 4) | u16::from(d.rcode),
                                    time / o.window_seconds,
                                ),
                            );
                        } else {
                            for q in &d.questions {
                                let labels = q.name.labels();
                                let Some(first) = labels.first() else {
                                    continue;
                                };
                                if first.len() >= o.min_label_length
                                    && entropy(first) >= o.min_entropy
                                {
                                    let suffix =
                                        crate::protocol::application::dns::Name::from_labels(
                                            labels.iter().skip(1).cloned(),
                                        )
                                        .expect("decoded DNS labels are valid")
                                        .to_string()
                                        .to_ascii_lowercase();
                                    let key = (
                                        m.flow.scope.get(),
                                        m.flow.flow.source,
                                        time / o.window_seconds,
                                        Some(suffix),
                                    );
                                    if !self.dns_groups.contains_key(&key) {
                                        self.group()?;
                                    }
                                    let group = self.dns_groups.entry(key).or_default();
                                    group
                                        .labels
                                        .insert(first.iter().map(u8::to_ascii_lowercase).collect());
                                    sample(&mut group.frames, &frames);
                                }
                            }
                        }
                    }
                }
                dns::Event::Transaction(t) => {
                    if matches!(self.mode, Mode::Dns(_)) {
                        if t.status == dns::TransactionStatus::Matched {
                            if let Some((rcode, window)) =
                                t.response.and_then(|i| self.replies.remove(&i))
                            {
                                let key = (t.flow.scope.get(), t.flow.flow.source, window, None);
                                if !self.dns_groups.contains_key(&key) {
                                    self.group()?;
                                }
                                let g = self.dns_groups.entry(key).or_default();
                                g.responses += 1;
                                g.nx += usize::from(rcode == 3);
                                sample(
                                    &mut g.frames,
                                    &t.sources.iter().map(|s| s.number).collect::<Vec<_>>(),
                                );
                            }
                        } else {
                            self.report.completeness.note("DNS transactions include unanswered, orphan, or duplicate messages");
                        }
                    }
                }
                dns::Event::Issue(_) => self
                    .report
                    .completeness
                    .note("DNS stream has missing or conflicting bytes"),
            }
        }
        Ok(())
    }
    fn http_events(&mut self, events: Vec<http::Event>) -> Result<(), BoundaryError> {
        for event in events {
            match event {
                http::Event::Message(m) => {
                    if m.status != http::Status::Complete {
                        self.report.completeness.note("incomplete HTTP messages");
                    }
                    if let Some(head) = m.head {
                        for host in head.values("host") {
                            let host = String::from_utf8_lossy(host);
                            let host = host.trim();
                            let socket = host.parse::<std::net::SocketAddr>().ok();
                            let domain = host
                                .rsplit_once(':')
                                .filter(|(_, port)| port.parse::<u16>().is_ok())
                                .map_or(host, |(name, _)| name);
                            let literal = socket.map(|s| s.ip()).or_else(|| {
                                host.trim_start_matches('[')
                                    .trim_end_matches(']')
                                    .parse::<IpAddr>()
                                    .ok()
                            });
                            let observed = literal
                                .map(|ip| ip.to_string())
                                .unwrap_or_else(|| domain.to_owned());
                            self.indicator_matches(
                                &observed,
                                literal,
                                None,
                                m.sources.iter().map(|s| s.number).collect(),
                                json!({"protocol":"http_host", "scope":m.flow.scope}),
                            )?;
                        }
                    }
                }
                http::Event::Issue(_) => self
                    .report
                    .completeness
                    .note("HTTP stream has missing or conflicting bytes"),
            }
        }
        Ok(())
    }
    fn tls_events(&mut self, events: Vec<tls::SessionEvent>) -> Result<(), BoundaryError> {
        for e in events {
            let s = e.session;
            if s.status != tls::Status::Complete {
                self.report.completeness.note("incomplete TLS sessions");
            }
            if let Some(c) = s.client {
                let mut frames: Vec<_> = self
                    .stream_sources
                    .get(&s.tcp_stream)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|number| *number >= s.first_frame && *number <= s.last_frame)
                    .collect();
                if frames.is_empty() {
                    frames.push(s.first_frame);
                }

                let context = json!({"protocol":"tls", "scope":s.scope, "stream":s.tcp_stream, "frames_sampled":true});
                if let Some(name) = c.sni {
                    self.indicator_matches(&name, None, None, frames.clone(), context.clone())?;
                }
                self.indicator_matches(
                    &c.ja3,
                    None,
                    Some(Kind::Ja3),
                    frames.clone(),
                    context.clone(),
                )?;
                self.indicator_matches(&c.ja4, None, Some(Kind::Ja4), frames, context)?;
            }
        }
        Ok(())
    }
    fn beacon(&mut self, r: &FrameRecord<'_>) -> Result<(), BoundaryError> {
        let Some(tcp) = r.tcp else { return Ok(()) };
        let Some(c) = tcp.conversation else {
            return Ok(());
        };
        if tcp.header.flags & (Tcp::RST | Tcp::FIN) != 0 {
            self.syns.remove(c.flow);
            self.syns.remove(&c.flow.reverse());
        }
        if tcp.header.flags & (Tcp::SYN | Tcp::ACK) != Tcp::SYN {
            return Ok(());
        }
        if self
            .syns
            .get(c.flow)
            .is_some_and(|seen| seen.contains(&tcp.header.sequence))
        {
            return Ok(());
        }
        self.charge()?;
        self.syns
            .entry(c.flow.clone())
            .or_default()
            .insert(tcp.header.sequence);
        let Ok(time) = r.timestamp.duration_since(UNIX_EPOCH) else {
            self.report
                .completeness
                .note("beacon timestamp unavailable");
            return Ok(());
        };
        let key = (
            c.flow.scope.get(),
            c.flow.flow.source,
            c.flow.flow.destination,
            c.flow.flow.destination_port,
        );
        if !self.beacons.contains_key(&key) {
            self.group()?;
        }
        let g = self.beacons.entry(key).or_default();
        g.times.push(time.as_secs_f64());
        sample(
            &mut g.frames,
            &r.tcp_sources()
                .map_or_else(|| vec![r.number], |s| s.iter().map(|f| f.number).collect()),
        );
        Ok(())
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
            if let Some(tcp) = r.tcp
                && let Some(c) = tcp.conversation
            {
                if !self.stream_sources.contains_key(&c.index) {
                    self.group()?;
                }
                let sources = r
                    .tcp_sources()
                    .map_or_else(|| vec![r.number], |s| s.iter().map(|f| f.number).collect());
                sample(self.stream_sources.entry(c.index).or_default(), &sources);
            }
            for (packet, sources) in std::iter::once((&r.decoded.packet, r.physical_sources()))
                .chain(
                    r.derived_datagrams()
                        .iter()
                        .map(|d| (&d.decoded.packet, d.sources.as_ref())),
                )
            {
                for layer in packet.iter() {
                    let ips: Option<[IpAddr; 2]> = if let Some(ip) = layer.downcast_ref::<Ipv4>() {
                        Some([ip.source.into(), ip.destination.into()])
                    } else {
                        layer
                            .downcast_ref::<Ipv6>()
                            .map(|ip| [ip.source.into(), ip.destination.into()])
                    };
                    if let Some(ips) = ips {
                        for ip in ips {
                            self.indicator_matches(
                                &ip.to_string(),
                                Some(ip),
                                None,
                                sources.map_or_else(
                                    || vec![r.number],
                                    |s| s.iter().map(|f| f.number).collect(),
                                ),
                                json!({"protocol":"ip", "interface":r.decoded.frame.interface}),
                            )?;
                        }
                    }
                }
            }
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
            Mode::Dns(o) => {
                self.report.measurements.insert("thresholds".into(), json!({"window_seconds":o.window_seconds,"min_responses":o.min_responses,"nxdomain_ratio":o.nxdomain_ratio,"min_labels":o.min_labels,"min_label_length":o.min_label_length,"min_entropy":o.min_entropy}));
                for ((scope, client, window, suffix), g) in std::mem::take(&mut self.dns_groups) {
                    deadline.enforce().map_err(BoundaryError::from_error)?;
                    let ratio = g.nx as f64 / g.responses.max(1) as f64;
                    let rule = if suffix.is_none()
                        && g.responses >= o.min_responses
                        && ratio >= o.nxdomain_ratio
                    {
                        Some((
                            "dns.nxdomain_ratio",
                            "High ratio of matched NXDOMAIN responses",
                        ))
                    } else if suffix.is_some() && g.labels.len() >= o.min_labels {
                        Some((
                            "dns.high_entropy_labels",
                            "Repeated distinct high-entropy DNS query labels",
                        ))
                    } else {
                        None
                    };
                    if let Some((rule, summary)) = rule {
                        let mut f = Finding::new(
                            rule,
                            Severity::Medium,
                            client.to_string(),
                            summary,
                            json!({"scope":scope,"window_start_seconds":window * o.window_seconds,"window_seconds":o.window_seconds,"responses":g.responses,"nxdomain":g.nx,"ratio":ratio,"distinct_labels":g.labels.len(),"suffix":suffix,"frames_sampled":true}),
                            "Inspect the queried domains, resolver behavior, and originating process; these patterns also occur in benign traffic.",
                        );
                        f.frames = g.frames;
                        self.add(f)?;
                    }
                }
            }
            Mode::Beacons(o) => {
                self.report.measurements.insert("thresholds".into(), json!({"min_attempts":o.min_attempts,"min_interval_seconds":o.min_interval_seconds,"max_cv":o.max_cv}));
                for ((scope, src, dst, port), g) in std::mem::take(&mut self.beacons) {
                    deadline.enforce().map_err(BoundaryError::from_error)?;
                    if run.clock.regressions > 0 || g.times.len() < o.min_attempts {
                        continue;
                    }
                    let intervals: Vec<_> = g.times.windows(2).map(|w| w[1] - w[0]).collect();
                    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
                    if mean < o.min_interval_seconds || intervals.iter().any(|x| *x <= 0.0) {
                        continue;
                    }
                    let sd = (intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
                        / intervals.len() as f64)
                        .sqrt();
                    let cv = sd / mean;
                    if cv <= o.max_cv {
                        let mut f = Finding::new(
                            "traffic.periodic_connections",
                            Severity::Medium,
                            format!("{src} → {dst}:{port}"),
                            "Regularly spaced TCP connection attempts",
                            json!({"scope":scope,"source":src,"destination":dst,"destination_port":port,"attempts":g.times.len(),"mean_interval_seconds":mean,"standard_deviation_seconds":sd,"coefficient_of_variation":cv,"min_interval_seconds":intervals.iter().copied().fold(f64::INFINITY, f64::min),"max_interval_seconds":intervals.iter().copied().fold(0.0, f64::max),"frames_sampled":true}),
                            "Correlate periodic traffic with the originating process and expected scheduled activity.",
                        );
                        f.frames = g.frames;
                        self.add(f)?;
                    }
                }
            }
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
