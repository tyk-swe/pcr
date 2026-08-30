// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-pipeline accounting around the standalone IP reassembler.

use std::time::Instant;

use crate::analysis::adapter::IpFragments;
use crate::analysis::reassembly::Limits as ReassemblyLimits;
use crate::analysis::reassembly::ip::{
    self, CompletedDatagram, DatagramKey, Family, FragmentDisposition, IncompleteReason,
    OverlapPolicy, PushOutcome,
};

/// Counters for one IP family. Sub-counters describe admitted fragments and
/// are intentionally independent: a completing fragment may also resolve an
/// overlap.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpFamilyCounters {
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

/// Capture-global IPv4 and IPv6 fragment counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpCounters {
    pub ipv4: IpFamilyCounters,
    pub ipv6: IpFamilyCounters,
}

impl IpCounters {
    fn family_mut(&mut self, family: Family) -> &mut IpFamilyCounters {
        match family {
            Family::Ipv4 => &mut self.ipv4,
            Family::Ipv6 => &mut self.ipv6,
        }
    }
}

/// Bounded terminal evidence for one completed or incomplete datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpDatagramOutcome {
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
        known_final_length: Option<usize>,
        duplicate_fragments: usize,
        overlap_bytes: usize,
    },
}

/// Progressive IP lifecycle evidence. The pipeline attributes each value to
/// the physical frame whose arrival revealed it (or the final frame for EOF
/// outcomes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpEvent {
    OverlapResolved {
        key: DatagramKey,
        policy: OverlapPolicy,
        affected_bytes: usize,
        fragment_count: usize,
        unique_bytes: usize,
    },
    /// One datagram reached its terminal completed or incomplete outcome.
    Outcome(IpDatagramOutcome),
}

/// One event together with its physical capture attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpEventRecord {
    pub number: u64,
    pub event: IpEvent,
}

/// Terminal capture-global IP reassembly accounting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpReassemblyReport {
    pub counters: IpCounters,
    pub outcomes: Vec<IpDatagramOutcome>,
    pub outcomes_omitted: u64,
}

pub(super) struct IpDispatch {
    reassembler: ip::Reassembler,
    max_outcomes: usize,
    report: IpReassemblyReport,
}

impl IpDispatch {
    pub(super) fn new(
        limits: ReassemblyLimits,
        overlap_policy: OverlapPolicy,
        max_outcomes: usize,
    ) -> Self {
        Self {
            reassembler: ip::Reassembler::new(limits, overlap_policy),
            max_outcomes,
            report: IpReassemblyReport::default(),
        }
    }

    pub(super) fn dispatch(
        &mut self,
        fragments: IpFragments,
        now: Instant,
        external_memory_charge: usize,
    ) -> Result<(Option<CompletedDatagram>, Vec<IpEvent>), ip::Error> {
        let mut events = Vec::new();

        for family in fragments.atomic {
            let counters = self.report.counters.family_mut(family);
            counters.physical_fragments = counters.physical_fragments.saturating_add(1);
            counters.atomic_fragments = counters.atomic_fragments.saturating_add(1);
        }

        let Some(fragment) = fragments.non_atomic else {
            return Ok((None, events));
        };
        let family = fragment.family();
        let counters = self.report.counters.family_mut(family);
        counters.physical_fragments = counters.physical_fragments.saturating_add(1);
        let outcome =
            self.reassembler
                .push_with_external_charge(fragment, now, external_memory_charge)?;
        let (fragment, completed) = match outcome {
            PushOutcome::Accepted(fragment) => (fragment, None),
            PushOutcome::Completed { fragment, datagram } => (fragment, Some(datagram)),
        };
        let counters = self.report.counters.family_mut(family);
        counters.admitted_fragments = counters.admitted_fragments.saturating_add(1);
        match fragment.disposition {
            FragmentDisposition::Accepted { .. } => {}
            FragmentDisposition::Duplicate { .. } => {
                counters.duplicate_fragments = counters.duplicate_fragments.saturating_add(1);
            }
            FragmentDisposition::OverlapResolved {
                policy,
                affected_bytes,
                ..
            } => {
                counters.overlap_resolved_fragments =
                    counters.overlap_resolved_fragments.saturating_add(1);
                counters.overlap_bytes = counters
                    .overlap_bytes
                    .saturating_add(u64::try_from(affected_bytes).unwrap_or(u64::MAX));
                events.push(IpEvent::OverlapResolved {
                    key: fragment.key.clone(),
                    policy,
                    affected_bytes,
                    fragment_count: fragment.fragment_count,
                    unique_bytes: fragment.unique_bytes,
                });
            }
        }

        let Some(datagram) = completed else {
            return Ok((None, events));
        };
        let counters = self.report.counters.family_mut(family);
        counters.completing_fragments = counters.completing_fragments.saturating_add(1);
        counters.completed_datagrams = counters.completed_datagrams.saturating_add(1);
        counters.derived_datagram_bytes = counters
            .derived_datagram_bytes
            .saturating_add(u64::try_from(datagram.bytes.len()).unwrap_or(u64::MAX));
        counters.derived_payload_bytes = counters
            .derived_payload_bytes
            .saturating_add(u64::try_from(datagram.final_payload_length).unwrap_or(u64::MAX));
        let terminal = IpDatagramOutcome::Completed {
            key: datagram.key.clone(),
            fragment_count: datagram.fragment_count,
            unique_bytes: datagram.unique_bytes,
            final_payload_length: datagram.final_payload_length,
            datagram_bytes: datagram.bytes.len(),
            duplicate_fragments: datagram.duplicate_fragments,
            overlap_bytes: datagram.overlap_bytes,
        };
        self.retain(terminal.clone());
        events.push(IpEvent::Outcome(terminal));
        Ok((Some(datagram), events))
    }

    pub(super) fn expire(&mut self, now: Instant) -> Vec<IpEvent> {
        let retired = self.reassembler.expire(now);
        self.drain(retired, IncompleteReason::IdleExpired)
    }

    pub(super) fn flush(&mut self) -> Vec<IpEvent> {
        let retired = self.reassembler.flush();
        self.drain(retired, IncompleteReason::EndOfCapture)
    }

    /// Accounts one batch of retired datagrams: the outcomes the engine could
    /// still name become events, the rest only move counters.
    fn drain(&mut self, retired: ip::RetiredDatagrams, reason: IncompleteReason) -> Vec<IpEvent> {
        for (count, family) in [
            (retired.omitted_ipv4, Family::Ipv4),
            (retired.omitted_ipv6, Family::Ipv6),
        ] {
            self.record_omitted(count, family, reason);
        }
        retired
            .outcomes
            .into_iter()
            .map(|outcome| self.record_incomplete(outcome))
            .collect()
    }

    pub(super) fn report(&self) -> &IpReassemblyReport {
        &self.report
    }

    pub(super) fn retained_memory_charge(&self) -> usize {
        self.reassembler.aggregate_memory_charge()
    }

    fn record_incomplete(&mut self, outcome: ip::IncompleteDatagram) -> IpEvent {
        self.count_incomplete(outcome.family(), outcome.reason, 1);
        let terminal = IpDatagramOutcome::Incomplete {
            key: outcome.key,
            reason: outcome.reason,
            fragment_count: outcome.fragment_count,
            unique_bytes: outcome.unique_bytes,
            known_final_length: outcome.known_final_length,
            duplicate_fragments: outcome.duplicate_fragments,
            overlap_bytes: outcome.overlap_bytes,
        };
        self.retain(terminal.clone());
        IpEvent::Outcome(terminal)
    }

    fn retain(&mut self, outcome: IpDatagramOutcome) {
        if self.report.outcomes.len() < self.max_outcomes {
            self.report.outcomes.push(outcome);
        } else {
            self.report.outcomes_omitted = self.report.outcomes_omitted.saturating_add(1);
        }
    }

    fn record_omitted(&mut self, count: u64, family: Family, reason: IncompleteReason) {
        self.count_incomplete(family, reason, count);
        self.report.outcomes_omitted = self.report.outcomes_omitted.saturating_add(count);
    }

    fn count_incomplete(&mut self, family: Family, reason: IncompleteReason, count: u64) {
        let counters = self.report.counters.family_mut(family);
        counters.incomplete_datagrams = counters.incomplete_datagrams.saturating_add(count);
        match reason {
            IncompleteReason::IdleExpired => {
                counters.idle_expired_datagrams =
                    counters.idle_expired_datagrams.saturating_add(count);
            }
            IncompleteReason::EndOfCapture => {
                counters.end_of_capture_datagrams =
                    counters.end_of_capture_datagrams.saturating_add(count);
            }
        }
    }
}
