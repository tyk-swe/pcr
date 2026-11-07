// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::published_enum;
use serde::Serialize;

use crate::output::contract::Error;

use crate::output::envelope::Published;

use crate::output::frame::{Captured, Timestamp};

use crate::output::hex::compact_hex;
use packetcraftr::os as library;

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub target: String,
    pub probe_set: &'static str,
    pub corpus: String,
    pub corpus_version: String,
    pub identification: Match,
    pub observations: Vec<Observation>,
    pub retained_evidence_bytes: usize,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: Summary,
    pub evidence: Vec<Event>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Preparation {
        interface: Option<String>,
        target: Option<std::net::IpAddr>,
        request_hex: Option<String>,
        packets_attempted: u64,
        bytes: u64,
        captured: Vec<Captured>,
    },
    Probe {
        sequence: u64,
        probe: Option<Probe>,
        attempt: u32,
        sent: Captured,
        response: Option<Captured>,
        observation: Option<Observation>,
        received_at: Option<Timestamp>,
        latency: Option<std::time::Duration>,
        reason: String,
    },
    Additional {
        sequence: u64,
        observation: Option<Observation>,
        frame: Captured,
        reason: String,
    },
    Undecoded {
        frame: Captured,
    },
    Diagnostic {},
    Complete {
        #[serde(flatten)]
        summary: Summary,
    },
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Preparation { .. } => "os_preparation",
            Self::Probe { .. } => "os_probe",
            Self::Additional { .. } => "os_additional",
            Self::Undecoded { .. } => "os_undecoded",
            Self::Diagnostic { .. } => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}

fn summary(report: library::Report) -> Summary {
    Summary {
        target: report.target.to_string(),
        probe_set: report.probe_set,
        corpus: report.corpus,
        corpus_version: report.corpus_version,
        identification: report.identification.into(),
        observations: report.observations.into_iter().map(Into::into).collect(),
        retained_evidence_bytes: report.retained_evidence_bytes,
        complete: report.complete,
    }
}

impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;
    fn try_from(event: library::Event) -> Result<Self, Error> {
        let value = match event {
            library::Event::Preparation(preparation) => Event::Preparation {
                interface: preparation.interface.map(|interface| interface.name),
                target: preparation.target,
                request_hex: preparation.request_bytes.map(|bytes| compact_hex(&bytes)),
                packets_attempted: preparation.stats.packets_attempted,
                bytes: preparation.stats.bytes,
                captured: preparation
                    .captured
                    .into_iter()
                    .map(Captured::try_from)
                    .collect::<Result<_, _>>()?,
            },
            library::Event::Probe(probe) => Event::Probe {
                sequence: probe.sequence,
                probe: probe.probe.map(Into::into),
                attempt: probe.attempt,
                sent: probe.sent.try_into()?,
                response: probe.response.map(Captured::try_from).transpose()?,
                observation: probe.observation.map(Into::into),
                received_at: probe.received_at.map(Timestamp::try_from).transpose()?,
                latency: probe.latency,
                reason: probe.reason,
            },
            library::Event::Additional {
                sequence,
                observation,
                frame,
                reason,
            } => Event::Additional {
                sequence,
                observation: observation.map(Into::into),
                frame: frame.try_into()?,
                reason,
            },
            library::Event::Undecoded(frame) => Event::Undecoded {
                frame: frame.try_into()?,
            },
            library::Event::Diagnostic(diagnostic) => {
                return Ok(Self::new(Event::Diagnostic {}, vec![diagnostic]));
            }
        };
        Ok(Self::new(value, Vec::new()))
    }
}

impl From<library::Report> for Published<Event> {
    fn from(report: library::Report) -> Self {
        let stats = report.stats.clone();
        Self::new(
            Event::Complete {
                summary: summary(report),
            },
            Vec::new(),
        )
        .with_stats(stats)
    }
}

impl TryFrom<library::Aggregate> for Published<Report> {
    type Error = Error;
    fn try_from(aggregate: library::Aggregate) -> Result<Self, Error> {
        let stats = aggregate.report.stats.clone();
        let mut diagnostics = Vec::new();
        let mut evidence = Vec::new();
        for event in aggregate.events {
            let event = Published::<Event>::try_from(event)?;
            diagnostics.extend(event.diagnostics);
            if !matches!(event.result, Event::Diagnostic {}) {
                evidence.push(event.result);
            }
        }
        Ok(Self::new(
            Report {
                summary: summary(aggregate.report),
                evidence,
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}

published_enum! {
    pub enum Probe from packetcraftr_core::document::os_fingerprints::Probe {
        OpenSyn => "open_syn",
        ClosedSyn => "closed_syn",
        TimestampSyn => "timestamp_syn",
        Echo => "echo",
    }
}

published_enum! {
    pub enum Family from packetcraftr_core::document::os_fingerprints::Family {
        Linux => "linux",
        Windows => "windows",
        Macos => "macos",
    }
}

published_enum! {
    pub enum AddressFamily from packetcraftr_core::document::os_fingerprints::AddressFamily {
        Ipv4 => "ipv4",
        Ipv6 => "ipv6",
    }
}

published_enum! {
    pub enum Outcome from packetcraftr_core::document::os_fingerprints::Outcome {
        Matched => "matched",
        Ambiguous => "ambiguous",
        Unknown => "unknown",
        Inconclusive => "inconclusive",
    }
}

published_enum! {
    pub enum Confidence from packetcraftr_core::document::os_fingerprints::Confidence {
        Qualified => "qualified",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TcpFingerprint {
    pub flags: u16,
    pub window: u16,
    pub option_kinds: Vec<u8>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: bool,
}

impl From<packetcraftr_core::document::os_fingerprints::TcpFingerprint> for TcpFingerprint {
    fn from(value: packetcraftr_core::document::os_fingerprints::TcpFingerprint) -> Self {
        Self {
            flags: value.flags,
            window: value.window,
            option_kinds: value.option_kinds,
            mss: value.mss,
            window_scale: value.window_scale,
            sack_permitted: value.sack_permitted,
            timestamps: value.timestamps,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub probe: Probe,
    pub address_family: AddressFamily,
    pub tcp: Option<TcpFingerprint>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub observed_hop_limit: u8,
    pub ipv4_identification: Option<u16>,
    pub ipv4_dont_fragment: Option<bool>,
    pub sequence: Option<u32>,
    pub acknowledgment: Option<u32>,
    pub timestamp_value: Option<u32>,
    pub timestamp_echo: Option<u32>,
    pub suitable: bool,
}

impl From<packetcraftr_core::document::os_fingerprints::Observation> for Observation {
    fn from(value: packetcraftr_core::document::os_fingerprints::Observation) -> Self {
        Self {
            probe: value.probe.into(),
            address_family: value.address_family.into(),
            tcp: value.tcp.map(Into::into),
            icmp_type: value.icmp_type,
            icmp_code: value.icmp_code,
            observed_hop_limit: value.observed_hop_limit,
            ipv4_identification: value.ipv4_identification,
            ipv4_dont_fragment: value.ipv4_dont_fragment,
            sequence: value.sequence,
            acknowledgment: value.acknowledgment,
            timestamp_value: value.timestamp_value,
            timestamp_echo: value.timestamp_echo,
            suitable: value.suitable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub family: Family,
    pub signature: String,
    pub corpus: String,
    pub corpus_version: String,
    pub reference: String,
    pub matched_predicates: usize,
    pub confidence: Confidence,
    pub observation_indices: Vec<usize>,
}

impl From<packetcraftr_core::document::os_fingerprints::Candidate> for Candidate {
    fn from(value: packetcraftr_core::document::os_fingerprints::Candidate) -> Self {
        Self {
            family: value.family.into(),
            signature: value.signature,
            corpus: value.corpus,
            corpus_version: value.corpus_version,
            reference: value.reference,
            matched_predicates: value.matched_predicates,
            confidence: value.confidence.into(),
            observation_indices: value.observation_indices,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Match {
    pub outcome: Outcome,
    pub reason: String,
    pub candidates: Vec<Candidate>,
}

impl From<packetcraftr_core::document::os_fingerprints::Match> for Match {
    fn from(value: packetcraftr_core::document::os_fingerprints::Match) -> Self {
        Self {
            outcome: value.outcome.into(),
            reason: value.reason,
            candidates: value.candidates.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::document::os_fingerprints as fingerprint;
    use serde_json::json;

    #[test]
    fn fingerprint_results_preserve_nested_wire_values_and_nulls() {
        let observation = fingerprint::Observation {
            probe: fingerprint::Probe::OpenSyn,
            address_family: fingerprint::AddressFamily::Ipv4,
            tcp: Some(fingerprint::TcpFingerprint {
                flags: 18,
                window: 4096,
                option_kinds: vec![2, 3, 4],
                mss: Some(1460),
                window_scale: Some(2),
                sack_permitted: true,
                timestamps: false,
            }),
            icmp_type: None,
            icmp_code: None,
            observed_hop_limit: 64,
            ipv4_identification: Some(42),
            ipv4_dont_fragment: Some(true),
            sequence: Some(7),
            acknowledgment: Some(8),
            timestamp_value: None,
            timestamp_echo: None,
            suitable: true,
        };
        assert_eq!(
            serde_json::to_value(Observation::from(observation)).unwrap(),
            json!({
                "probe": "open_syn", "address_family": "ipv4",
                "tcp": { "flags": 18, "window": 4096, "option_kinds": [2, 3, 4], "mss": 1460, "window_scale": 2, "sack_permitted": true, "timestamps": false },
                "icmp_type": null, "icmp_code": null, "observed_hop_limit": 64,
                "ipv4_identification": 42, "ipv4_dont_fragment": true,
                "sequence": 7, "acknowledgment": 8, "timestamp_value": null,
                "timestamp_echo": null, "suitable": true,
            })
        );
        let identification = fingerprint::Match {
            outcome: fingerprint::Outcome::Matched,
            reason: "matched predicates".into(),
            candidates: vec![fingerprint::Candidate {
                family: fingerprint::Family::Linux,
                signature: "syn".into(),
                corpus: "reference".into(),
                corpus_version: "1".into(),
                reference: "signature".into(),
                matched_predicates: 3,
                confidence: fingerprint::Confidence::Qualified,
                observation_indices: vec![0],
            }],
        };
        assert_eq!(
            serde_json::to_value(Match::from(identification)).unwrap(),
            json!({
                "outcome": "matched", "reason": "matched predicates", "candidates": [{
                    "family": "linux", "signature": "syn", "corpus": "reference",
                    "corpus_version": "1", "reference": "signature", "matched_predicates": 3,
                    "confidence": "qualified", "observation_indices": [0],
                }],
            })
        );
    }
}
