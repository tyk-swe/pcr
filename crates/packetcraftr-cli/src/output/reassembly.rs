// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured IP fragment-reassembly lifecycle and terminal accounting.

use packetcraftr_core::analysis::IpDatagramOutcome as DatagramOutcome;

use packetcraftr_core::analysis::reassembly::ip::DatagramKey;

use packetcraftr_core::analysis::reassembly::ip::OverlapPolicy;

use packetcraftr_core::analysis::reassembly::ip::Family;

use serde::Serialize;

use packetcraftr_core::analysis::{
    IpDatagramOutcome as AnalysisOutcome, IpEventRecord as AnalysisEventRecord,
    IpFamilyCounters as AnalysisFamilyCounters, IpReassemblyReport as AnalysisReport,
};

/// Family label attached to the domain's counters for tabular output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FamilyCounters {
    pub family: Family,
    #[serde(flatten)]
    pub counters: AnalysisFamilyCounters,
}
impl FamilyCounters {
    fn from_analysis(family: Family, value: &AnalysisFamilyCounters) -> Self {
        Self {
            family,
            counters: value.clone(),
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
            outcomes: value.outcomes.clone(),
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
            packetcraftr_core::analysis::IpEvent::OverlapResolved {
                key,
                policy,
                affected_bytes,
                fragment_count,
                unique_bytes,
            } => Self::IpOverlapResolved {
                frame: value.number,
                key,
                policy,
                affected_bytes,
                fragment_count,
                unique_bytes,
            },
            packetcraftr_core::analysis::IpEvent::Outcome(outcome) => match &outcome {
                AnalysisOutcome::Completed { .. } => Self::IpDatagramCompleted {
                    frame: value.number,
                    outcome,
                },
                AnalysisOutcome::Incomplete(_) => Self::IpDatagramIncomplete {
                    frame: value.number,
                    outcome,
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
