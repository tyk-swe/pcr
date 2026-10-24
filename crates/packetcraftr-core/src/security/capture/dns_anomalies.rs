// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS transaction grouping and threshold evaluation.

use super::{Collector, DnsOptions, Finding, Mode, Severity, entropy, sample};
use crate::{
    analysis::dns, budget::Deadline, error::BoundaryError, protocol::application::dns::RecordValue,
};
use serde_json::json;
use std::time::UNIX_EPOCH;

impl Collector {
    pub(super) fn dns_events(&mut self, events: Vec<dns::Event>) -> Result<(), BoundaryError> {
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
                                // A qualifying label is grouped by the domain following it.
                                // The final label has no following domain and cannot qualify.
                                for (position, label) in labels
                                    .iter()
                                    .enumerate()
                                    .take(labels.len().saturating_sub(1))
                                {
                                    if label.len() < o.min_label_length
                                        || entropy(label) < o.min_entropy
                                    {
                                        continue;
                                    }
                                    let suffix =
                                        crate::protocol::application::dns::Name::from_labels(
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
                                    if !self.dns_groups.contains_key(&key) {
                                        self.group()?;
                                    }
                                    let group = self.dns_groups.entry(key).or_default();
                                    group
                                        .labels
                                        .insert(label.iter().map(u8::to_ascii_lowercase).collect());
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
    pub(super) fn finish_dns(
        &mut self,
        o: DnsOptions,
        deadline: &Deadline,
    ) -> Result<(), BoundaryError> {
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
        Ok(())
    }
}
