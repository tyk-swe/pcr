// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Indicator matching across packet, DNS, HTTP, and TLS observations.

use super::{Finding, Output, Severity, sample};
use crate::protocol::{application::dns::RecordValue, identity};
use crate::security::indicators::{Kind, Matcher};
use crate::{
    analysis::{self, FrameRecord, application, dns, http, tls},
    budget::Deadline,
    error::BoundaryError,
    registry::Registry,
};
use serde_json::json;
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

const HTTP_PORTS: [u16; 3] = [80, 8080, 8000];

pub(super) struct Hunt {
    dns: dns::Collector,
    http: http::Collector,
    tls: tls::Collector,
    pub(super) matches: Matches,
}

pub(super) struct Matches {
    indicators: Matcher,
    stream_sources: BTreeMap<u64, Vec<u64>>,
}

impl Hunt {
    pub(super) fn new(
        indicators: Matcher,
        app: application::Limits,
        registry: Arc<Registry>,
    ) -> Result<Self, BoundaryError> {
        Ok(Self {
            dns: dns::Collector::new(app, [53], registry).map_err(BoundaryError::from_error)?,
            http: http::Collector::new(app, HTTP_PORTS, application::MAX_BODY_BYTES)
                .map_err(BoundaryError::from_error)?,
            tls: tls::Collector::new(tls::Limits {
                max_sessions: app.max_streams,
                max_buffered_bytes: app.max_buffer_bytes,
            })
            .map_err(BoundaryError::from_error)?,
            matches: Matches {
                indicators,
                stream_sources: BTreeMap::new(),
            },
        })
    }

    pub(super) fn observe(
        &mut self,
        r: &FrameRecord<'_>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        self.matches.frame(r, output)?;
        let events = self.dns.observe(r).map_err(BoundaryError::from_error)?;
        self.matches.dns_events(events, output)?;
        let events = self.http.observe(r).map_err(BoundaryError::from_error)?;
        self.matches.http_events(events, output)?;
        let events = self.tls.observe(r);
        self.matches.tls_events(events, output)
    }

    pub(super) fn finish(
        self,
        run: &analysis::Summary,
        deadline: &Deadline,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        let Self {
            dns,
            http,
            tls,
            matches,
        } = self;
        analysis::Collector::finish(dns, run, deadline, &mut |e| {
            matches.dns_events(vec![e], output)
        })?;
        analysis::Collector::finish(http, run, deadline, &mut |e| {
            matches.http_events(vec![e], output)
        })?;
        analysis::Collector::finish(tls, run, deadline, &mut |e| {
            matches.tls_events(vec![e], output)
        })?;
        output.note_run(run);
        Ok(())
    }
}

impl Matches {
    fn indicator_matches(
        &self,
        output: &mut Output,
        value: &str,
        ip: Option<IpAddr>,
        fingerprint: Option<Kind>,
        frames: Vec<u64>,
        context: serde_json::Value,
    ) -> Result<(), BoundaryError> {
        let indicators = &self.indicators;
        let matched = if let Some(ip) = ip {
            indicators.ip(ip)
        } else if let Some(kind) = fingerprint {
            indicators.fingerprint(kind, value)
        } else {
            indicators.domain(value)
        };
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
            output.add(finding)?;
        }
        Ok(())
    }
    pub(super) fn dns_events(
        &self,
        events: Vec<dns::Event>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        for event in events {
            let message = match event {
                dns::Event::Message(message) => message,
                dns::Event::Transaction(_) => continue,
                dns::Event::Issue(_) => {
                    output.dns_issue();
                    continue;
                }
            };
            let Some((d, frames)) = output.dns_message(&message)? else {
                continue;
            };
            let context =
                json!({"protocol":"dns", "scope":message.flow.scope, "message":message.index});
            for q in &d.questions {
                self.indicator_matches(
                    output,
                    &q.name.to_string(),
                    None,
                    None,
                    frames.clone(),
                    context.clone(),
                )?;
            }
            for rr in d.answers.iter().chain(&d.authorities).chain(&d.additionals) {
                self.indicator_matches(
                    output,
                    &rr.owner.to_string(),
                    None,
                    None,
                    frames.clone(),
                    context.clone(),
                )?;
                let answer = |ip: IpAddr| (ip.to_string(), Some(ip), "dns_answer");
                let rdata = |name: String| (name, None, "dns_rdata");
                let values = match &rr.value {
                    RecordValue::A(ip) => vec![answer((*ip).into())],
                    RecordValue::Aaaa(ip) => vec![answer((*ip).into())],
                    RecordValue::Cname(n)
                    | RecordValue::Ns(n)
                    | RecordValue::Ptr(n)
                    | RecordValue::Mx { exchange: n, .. }
                    | RecordValue::Srv { target: n, .. } => vec![rdata(n.to_string())],
                    RecordValue::Soa {
                        primary_name_server,
                        responsible_mailbox,
                        ..
                    } => vec![
                        rdata(primary_name_server.to_string()),
                        rdata(responsible_mailbox.to_string()),
                    ],
                    _ => Vec::new(),
                };
                for (value, ip, protocol) in values {
                    self.indicator_matches(
                        output,
                        &value,
                        ip,
                        None,
                        frames.clone(),
                        json!({ "protocol": protocol }),
                    )?;
                }
            }
        }
        Ok(())
    }
    fn http_events(
        &self,
        events: Vec<http::Event>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        for event in events {
            match event {
                http::Event::Message(m) => {
                    if m.status != http::Status::Complete {
                        output.report.completeness.note("incomplete HTTP messages");
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
                                output,
                                &observed,
                                literal,
                                None,
                                m.sources.iter().map(|s| s.number).collect(),
                                json!({"protocol":"http_host", "scope":m.flow.scope}),
                            )?;
                        }
                    }
                }
                http::Event::Issue(_) => output
                    .report
                    .completeness
                    .note("HTTP stream has missing or conflicting bytes"),
            }
        }
        Ok(())
    }
    fn tls_events(
        &self,
        events: Vec<tls::SessionEvent>,
        output: &mut Output,
    ) -> Result<(), BoundaryError> {
        for e in events {
            let s = e.session;
            if s.status != tls::Status::Complete {
                output.report.completeness.note("incomplete TLS sessions");
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
                    self.indicator_matches(
                        output,
                        &name,
                        None,
                        None,
                        frames.clone(),
                        context.clone(),
                    )?;
                }
                self.indicator_matches(
                    output,
                    &c.ja3,
                    None,
                    Some(Kind::Ja3),
                    frames.clone(),
                    context.clone(),
                )?;
                self.indicator_matches(output, &c.ja4, None, Some(Kind::Ja4), frames, context)?;
            }
        }
        Ok(())
    }
    fn frame(&mut self, r: &FrameRecord<'_>, output: &mut Output) -> Result<(), BoundaryError> {
        if let Some(tcp) = r.tcp
            && let Some(c) = tcp.conversation
        {
            let sampled = output.group(&mut self.stream_sources, c.index, Vec::new)?;
            let sources = r
                .tcp_sources()
                .map_or_else(|| vec![r.number], |s| s.iter().map(|f| f.number).collect());
            sample(sampled, &sources);
        }
        for (packet, sources) in std::iter::once((&r.decoded.packet, r.physical_sources())).chain(
            r.derived_datagrams()
                .iter()
                .map(|d| (&d.decoded.packet, d.sources.as_ref())),
        ) {
            for layer in packet.iter() {
                let ips: Option<[IpAddr; 2]> = identity::network_endpoints(layer)
                    .map(|(source, destination)| [source, destination]);
                if let Some(ips) = ips {
                    for ip in ips {
                        self.indicator_matches(
                            output,
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
        Ok(())
    }
}
