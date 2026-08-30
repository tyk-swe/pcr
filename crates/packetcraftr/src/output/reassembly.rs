// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured IP fragment-reassembly lifecycle and terminal accounting.

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_core::analysis::reassembly::ip::{
    DatagramKey as AnalysisKey, Family as AnalysisFamily,
    IncompleteReason as AnalysisIncompleteReason, OverlapPolicy as AnalysisOverlapPolicy,
};
use packetcraftr_core::analysis::{
    IpDatagramOutcome as AnalysisOutcome, IpEventRecord as AnalysisEventRecord,
    IpFamilyCounters as AnalysisFamilyCounters, IpReassemblyReport as AnalysisReport,
};

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum Family from AnalysisFamily {
        Ipv4 = Ipv4,
        Ipv6 = Ipv6,
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum OverlapPolicy from AnalysisOverlapPolicy {
        Reject = Reject,
        First = First,
        Last = Last,
    }
}

mirror_enum! {
    #[serde(rename_all = "snake_case")]
    pub enum IncompleteReason from AnalysisIncompleteReason {
        IdleExpired = IdleExpired,
        EndOfCapture = EndOfCapture,
    }
}

/// Stable, capture-scoped identity of one fragmented datagram.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatagramKey {
    pub family: Family,
    pub scope: u32,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identification: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
}

impl From<&AnalysisKey> for DatagramKey {
    fn from(value: &AnalysisKey) -> Self {
        match value {
            AnalysisKey::Ipv4(key) => Self {
                family: Family::Ipv4,
                scope: key.scope.get(),
                source: IpAddr::V4(key.source),
                destination: IpAddr::V4(key.destination),
                identification: u32::from(key.identification),
                protocol: Some(key.protocol),
            },
            AnalysisKey::Ipv6(key) => Self {
                family: Family::Ipv6,
                scope: key.scope.get(),
                source: IpAddr::V6(key.source),
                destination: IpAddr::V6(key.destination),
                identification: key.identification,
                protocol: None,
            },
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        })
    }
}

impl std::fmt::Display for IncompleteReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::IdleExpired => "idle-expired",
            Self::EndOfCapture => "end-of-capture",
        })
    }
}

impl std::fmt::Display for DatagramKey {
    /// Renders the same fields the JSON form carries, so the text and
    /// structured views of one datagram cannot drift apart.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} scope {} {} -> {} identification {}",
            self.family, self.scope, self.source, self.destination, self.identification
        )?;
        match self.protocol {
            Some(protocol) => write!(formatter, " protocol {protocol}"),
            None => Ok(()),
        }
    }
}

/// Terminal evidence for a single datagram, retained under `--max-ip-outcomes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DatagramOutcome {
    Completed {
        key: DatagramKey,
        fragment_count: usize,
        unique_bytes: usize,
        final_payload_length: usize,
        datagram_bytes: usize,
        duplicate_fragments: usize,
        overlap_bytes: usize,
    },
    Incomplete {
        key: DatagramKey,
        reason: IncompleteReason,
        fragment_count: usize,
        unique_bytes: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        known_final_length: Option<usize>,
        duplicate_fragments: usize,
        overlap_bytes: usize,
    },
}

impl From<&AnalysisOutcome> for DatagramOutcome {
    fn from(value: &AnalysisOutcome) -> Self {
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
                fragment_count: *fragment_count,
                unique_bytes: *unique_bytes,
                final_payload_length: *final_payload_length,
                datagram_bytes: *datagram_bytes,
                duplicate_fragments: *duplicate_fragments,
                overlap_bytes: *overlap_bytes,
            },
            AnalysisOutcome::Incomplete {
                key,
                reason,
                fragment_count,
                unique_bytes,
                known_final_length,
                duplicate_fragments,
                overlap_bytes,
            } => Self::Incomplete {
                key: key.into(),
                reason: (*reason).into(),
                fragment_count: *fragment_count,
                unique_bytes: *unique_bytes,
                known_final_length: *known_final_length,
                duplicate_fragments: *duplicate_fragments,
                overlap_bytes: *overlap_bytes,
            },
        }
    }
}

/// Fragment and derived-datagram counters for one address family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FamilyCounters {
    pub family: Family,
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

impl FamilyCounters {
    fn from_analysis(family: Family, value: &AnalysisFamilyCounters) -> Self {
        Self {
            family,
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

/// Capture-global counters and bounded terminal outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub families: Vec<FamilyCounters>,
    pub outcomes: Vec<DatagramOutcome>,
    pub outcomes_omitted: u64,
}

impl Default for Report {
    fn default() -> Self {
        Self::from_analysis(&AnalysisReport::default())
    }
}

impl Report {
    #[must_use]
    pub fn from_analysis(value: &AnalysisReport) -> Self {
        Self {
            families: vec![
                FamilyCounters::from_analysis(Family::Ipv4, &value.counters.ipv4),
                FamilyCounters::from_analysis(Family::Ipv6, &value.counters.ipv6),
            ],
            outcomes: value.outcomes.iter().map(Into::into).collect(),
            outcomes_omitted: value.outcomes_omitted,
        }
    }
}

/// Progressive lifecycle record emitted before downstream data enabled by the
/// same completing fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
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
            packetcraftr_core::analysis::IpEvent::OverlapResolved {
                key,
                policy,
                affected_bytes,
                fragment_count,
                unique_bytes,
            } => Self::IpOverlapResolved {
                frame: value.number,
                key: (&key).into(),
                policy: policy.into(),
                affected_bytes,
                fragment_count,
                unique_bytes,
            },
            packetcraftr_core::analysis::IpEvent::Outcome(outcome) => match &outcome {
                AnalysisOutcome::Completed { .. } => Self::IpDatagramCompleted {
                    frame: value.number,
                    outcome: (&outcome).into(),
                },
                AnalysisOutcome::Incomplete { .. } => Self::IpDatagramIncomplete {
                    frame: value.number,
                    outcome: (&outcome).into(),
                },
            },
        }
    }
}
