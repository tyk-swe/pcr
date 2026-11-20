// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS transaction grouping and threshold evaluation.

use super::{DnsOptions, Finding, Output, Severity, entropy, sample};
use crate::{
    analysis::{self, FrameRecord, application, dns},
    budget::Deadline,
    error::BoundaryError,
    protocol::application::dns::RecordValue,
    registry::Registry,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
    time::UNIX_EPOCH,
};

#[derive(Default)]
pub(super) struct DnsGroup {
    responses: usize,
    nx: usize,
    pub(super) labels: BTreeSet<Vec<u8>>,
    frames: Vec<u64>,
}
/// Without a suffix the group counts matched responses; with one, the labels queried below it.
pub(super) type DnsKey = (u32, IpAddr, u64, Option<String>);

pub(super) struct Anomalies {
    dns: dns::Collector,
    pub(super) grouping: Grouping,
}

pub(super) struct Grouping {
    options: DnsOptions,
    pub(super) groups: BTreeMap<DnsKey, DnsGroup>,
    replies: BTreeMap<u64, (u16, u64)>,
}

impl Anomalies {
    pub(super) fn new(
        options: DnsOptions,
        app: application::Limits,
        registry: Arc<Registry>,
    ) -> Result<Self, BoundaryError> {
        Ok(Self {
            dns: dns::Collector::new(app, [53], registry).map_err(BoundaryError::from_error)?,
            grouping: Grouping {
                options,
                groups: BTreeMap::new(),
                replies: BTreeMap::new(),
            },
        })
    }

    pub(super) fn observe(
        &mut self,
        r: &FrameRecord<'_>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        let events = self.dns.observe(r).map_err(BoundaryError::from_error)?;
        self.grouping.events(events, output)
    }

    pub(super) fn finish(
        self,
        run: &analysis::Summary,
        deadline: &Deadline,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        let Self { dns, mut grouping } = self;
        analysis::Collector::finish(dns, run, deadline, &mut |e| {
            grouping.events(vec![e], output)
        })?;
        output.note_run(run);
        grouping.finish(deadline, output)
    }
}

impl Grouping {
    pub(super) fn events(
        &mut self,
        events: Vec<dns::Event>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        let o = self.options;
        for event in events {
            match event {
                dns::Event::Message(m) => {
                    let Some((d, frames)) = output.dns_message(&m)? else {
                        continue;
                    };
                    let Some(time) = m
                        .sources
                        .first()
                        .and_then(|s| s.timestamp.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                    else {
                        output.report.completeness.note("DNS timestamp unavailable");
                        continue;
                    };
                    if d.truncated {
                        output
                            .report
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
                        continue;
                    }
                    for q in &d.questions {
                        let labels = q.name.labels();
                        // A qualifying label is grouped by the domain following it.
                        // The final label has no following domain and cannot qualify.
                        for (position, label) in labels
                            .iter()
                            .enumerate()
                            .take(labels.len().saturating_sub(1))
                        {
                            if label.len() < o.min_label_length || entropy(label) < o.min_entropy {
                                continue;
                            }
                            let suffix = crate::protocol::application::dns::Name::from_labels(
                                labels.iter().skip(position + 1).cloned(),
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
                            let group = output.group(&mut self.groups, key, DnsGroup::default)?;
                            group
                                .labels
                                .insert(label.iter().map(u8::to_ascii_lowercase).collect());
                            sample(&mut group.frames, &frames);
                        }
                    }
                }
                dns::Event::Transaction(t) => {
                    if t.status != dns::TransactionStatus::Matched {
                        output.report.completeness.note(
                            "DNS transactions include unanswered, orphan, or duplicate messages",
                        );
                        continue;
                    }
                    let Some((rcode, window)) = t.response.and_then(|i| self.replies.remove(&i))
                    else {
                        continue;
                    };
                    let key = (t.flow.scope.get(), t.flow.flow.source, window, None);
                    let g = output.group(&mut self.groups, key, DnsGroup::default)?;
                    g.responses += 1;
                    g.nx += usize::from(rcode == 3);
                    sample(
                        &mut g.frames,
                        &t.sources.iter().map(|s| s.number).collect::<Vec<_>>(),
                    );
                }
                dns::Event::Issue(_) => output.dns_issue(),
            }
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        deadline: &Deadline,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        let o = self.options;
        output.report.measurements.insert("thresholds".into(), json!({"window_seconds":o.window_seconds,"min_responses":o.min_responses,"nxdomain_ratio":o.nxdomain_ratio,"min_labels":o.min_labels,"min_label_length":o.min_label_length,"min_entropy":o.min_entropy}));
        for ((scope, client, window, suffix), g) in self.groups {
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
                output.add(f)?;
            }
        }
        Ok(())
    }
}
