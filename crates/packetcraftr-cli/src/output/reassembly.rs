// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured IP fragment-reassembly lifecycle and terminal accounting.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use packetcraftr_core::analysis::reassembly::ip;
use packetcraftr_core::analysis::{
    IpDatagramOutcome as AnalysisOutcome, IpEvent as AnalysisEvent,
    IpEventRecord as AnalysisEventRecord, IpFamilyCounters as AnalysisFamilyCounters,
    IpReassemblyReport as AnalysisReport,
};

published_enum! {
    /// The IP version a fragment or datagram belongs to.
    pub enum Family from ip::Family {
        Ipv4 => "ipv4",
        Ipv6 => "ipv6",
    }
}

published_enum! {
    /// How conflicting fragment bytes were resolved.
    pub enum OverlapPolicy from ip::OverlapPolicy {
        Reject => "reject",
        First => "first",
        Last => "last",
    }
}

published_enum! {
    /// Why a partial datagram was retired.
    pub enum IncompleteReason from ip::IncompleteReason {
        IdleExpired => "idle_expired",
        EndOfCapture => "end_of_capture",
    }
}

/// Exact IPv4 fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ipv4DatagramKey {
    pub scope: u32,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub identification: u16,
    pub protocol: u8,
}

/// Exact IPv6 fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ipv6DatagramKey {
    pub scope: u32,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub identification: u32,
}

/// Exact, capture-scoped fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "family")]
pub enum DatagramKey {
    #[serde(rename = "ipv4")]
    Ipv4(Ipv4DatagramKey),
    #[serde(rename = "ipv6")]
    Ipv6(Ipv6DatagramKey),
}

impl From<ip::DatagramKey> for DatagramKey {
    fn from(value: ip::DatagramKey) -> Self {
        match value {
            ip::DatagramKey::Ipv4(key) => Self::Ipv4(Ipv4DatagramKey {
                scope: key.scope.get(),
                source: key.source,
                destination: key.destination,
                identification: key.identification,
                protocol: key.protocol,
            }),
            ip::DatagramKey::Ipv6(key) => Self::Ipv6(Ipv6DatagramKey {
                scope: key.scope.get(),
                source: key.source,
                destination: key.destination,
                identification: key.identification,
            }),
        }
    }
}

/// Bounded evidence for a datagram that retired with gaps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncompleteDatagram {
    pub key: DatagramKey,
    pub reason: IncompleteReason,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_final_length: Option<usize>,
    pub duplicate_fragments: usize,
    pub overlap_bytes: usize,
}

impl From<ip::IncompleteDatagram> for IncompleteDatagram {
    fn from(value: ip::IncompleteDatagram) -> Self {
        Self {
            key: value.key.into(),
            reason: value.reason.into(),
            fragment_count: value.fragment_count,
            unique_bytes: value.unique_bytes,
            known_final_length: value.known_final_length,
            duplicate_fragments: value.duplicate_fragments,
            overlap_bytes: value.overlap_bytes,
        }
    }
}

/// How one datagram's reassembly ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status")]
pub enum DatagramOutcome {
    #[serde(rename = "completed")]
    Completed {
        key: DatagramKey,
        fragment_count: usize,
        unique_bytes: usize,
        final_payload_length: usize,
        datagram_bytes: usize,
        duplicate_fragments: usize,
        overlap_bytes: usize,
    },
    #[serde(rename = "incomplete")]
    Incomplete(IncompleteDatagram),
}

impl From<AnalysisOutcome> for DatagramOutcome {
    fn from(value: AnalysisOutcome) -> Self {
        match value {
            AnalysisOutcome::Completed {
                key,
                fragment_count,
                unique_bytes,
                final_payload_length,
                datagram_bytes,
                duplicate_fragments,
                overlap_bytes,
            } => Self::Completed {
                key: key.into(),
                fragment_count,
                unique_bytes,
                final_payload_length,
                datagram_bytes,
                duplicate_fragments,
                overlap_bytes,
            },
            AnalysisOutcome::Incomplete(datagram) => Self::Incomplete(datagram.into()),
        }
    }
}

/// One family's capture-global fragment and datagram counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub physical_fragments: u64,
    pub atomic_fragments: u64,
    pub admitted_fragments: u64,
    pub duplicate_fragments: u64,
    pub overlap_resolved_fragments: u64,
    pub completing_fragments: u64,
    pub completed_datagrams: u64,
    pub incomplete_datagrams: u64,
    pub idle_expired_datagrams: u64,
    pub end_of_capture_datagrams: u64,
    pub overlap_bytes: u64,
    pub derived_datagram_bytes: u64,
    pub derived_payload_bytes: u64,
}

impl From<&AnalysisFamilyCounters> for Counters {
    fn from(value: &AnalysisFamilyCounters) -> Self {
        Self {
            physical_fragments: value.physical_fragments,
            atomic_fragments: value.atomic_fragments,
            admitted_fragments: value.admitted_fragments,
            duplicate_fragments: value.duplicate_fragments,
            overlap_resolved_fragments: value.overlap_resolved_fragments,
            completing_fragments: value.completing_fragments,
            completed_datagrams: value.completed_datagrams,
            incomplete_datagrams: value.incomplete_datagrams,
            idle_expired_datagrams: value.idle_expired_datagrams,
            end_of_capture_datagrams: value.end_of_capture_datagrams,
            overlap_bytes: value.overlap_bytes,
            derived_datagram_bytes: value.derived_datagram_bytes,
            derived_payload_bytes: value.derived_payload_bytes,
        }
    }
}

/// Family label attached to the domain's counters for tabular output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FamilyCounters {
    pub family: Family,
    #[serde(flatten)]
    pub counters: Counters,
}

/// Capture-global counters and bounded terminal outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub families: Vec<FamilyCounters>,
    pub outcomes: Vec<DatagramOutcome>,
    pub outcomes_omitted: u64,
}

impl Default for Report {
    fn default() -> Self {
        Self::from(&AnalysisReport::default())
    }
}

impl From<&AnalysisReport> for Report {
    fn from(value: &AnalysisReport) -> Self {
        Self {
            families: vec![
                FamilyCounters {
                    family: Family::Ipv4,
                    counters: (&value.counters.ipv4).into(),
                },
                FamilyCounters {
                    family: Family::Ipv6,
                    counters: (&value.counters.ipv6).into(),
                },
            ],
            outcomes: value.outcomes.iter().cloned().map(Into::into).collect(),
            outcomes_omitted: value.outcomes_omitted,
        }
    }
}

/// Progressive lifecycle record emitted before downstream data enabled by the
/// same completing fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    IpOverlapResolved {
        frame: u64,
        key: DatagramKey,
        policy: OverlapPolicy,
        affected_bytes: usize,
        fragment_count: usize,
        unique_bytes: usize,
    },
    IpDatagramCompleted {
        frame: u64,
        outcome: DatagramOutcome,
    },
    IpDatagramIncomplete {
        frame: u64,
        outcome: DatagramOutcome,
    },
}

impl From<AnalysisEventRecord> for Event {
    fn from(value: AnalysisEventRecord) -> Self {
        match value.event {
            AnalysisEvent::OverlapResolved {
                key,
                policy,
                affected_bytes,
                fragment_count,
                unique_bytes,
            } => Self::IpOverlapResolved {
                frame: value.number,
                key: key.into(),
                policy: policy.into(),
                affected_bytes,
                fragment_count,
                unique_bytes,
            },
            AnalysisEvent::Outcome(outcome) => match outcome {
                outcome @ AnalysisOutcome::Completed { .. } => Self::IpDatagramCompleted {
                    frame: value.number,
                    outcome: outcome.into(),
                },
                outcome @ AnalysisOutcome::Incomplete(_) => Self::IpDatagramIncomplete {
                    frame: value.number,
                    outcome: outcome.into(),
                },
            },
        }
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::IpOverlapResolved { .. } => "ip_overlap_resolved",
            Self::IpDatagramCompleted { .. } => "ip_datagram_completed",
            Self::IpDatagramIncomplete { .. } => "ip_datagram_incomplete",
        }
    }
}
