// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Indicator matching across packet, DNS, HTTP, and TLS observations.

use super::{Collector, Finding, Mode, Severity, sample};
use crate::security::indicators::Kind;
use crate::{
    analysis::{FrameRecord, http, tls},
    error::BoundaryError,
    protocol::network::{Ipv4, Ipv6},
};
use serde_json::json;
use std::net::IpAddr;

impl Collector {
    pub(super) fn indicator_matches(
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
    pub(super) fn http_events(&mut self, events: Vec<http::Event>) -> Result<(), BoundaryError> {
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
    pub(super) fn tls_events(
        &mut self,
        events: Vec<tls::SessionEvent>,
    ) -> Result<(), BoundaryError> {
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
    pub(super) fn observe_hunt(&mut self, r: &FrameRecord<'_>) -> Result<(), BoundaryError> {
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
        for (packet, sources) in std::iter::once((&r.decoded.packet, r.physical_sources())).chain(
            r.derived_datagrams()
                .iter()
                .map(|d| (&d.decoded.packet, d.sources.as_ref())),
        ) {
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
        Ok(())
    }
}
