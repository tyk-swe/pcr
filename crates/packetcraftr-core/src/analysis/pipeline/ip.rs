// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::mem::size_of;
use std::time::{Duration, Instant, SystemTime};

use crate::analysis::Error;
use crate::analysis::adapter::IpFragments;
use crate::analysis::pipeline::DerivedDatagram;
use crate::analysis::pipeline::clock::CaptureClock;
use crate::analysis::reassembly::ip::{
    self, CompletedDatagram, DatagramKey, Family, FragmentDisposition, IncompleteReason,
    Limits as IpReassemblyLimits, OverlapPolicy, PushOutcome,
};
use crate::decode::DecodedPacket;

/// Sub-counters are intentionally independent: a completing fragment may also resolve an overlap.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
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
    Incomplete(ip::IncompleteDatagram),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpEvent {
    OverlapResolved {
        key: DatagramKey,
        policy: OverlapPolicy,
        affected_bytes: usize,
        fragment_count: usize,
        unique_bytes: usize,
    },
    Outcome(IpDatagramOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpEventRecord {
    pub number: u64,
    pub event: IpEvent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpReassemblyReport {
    pub counters: IpCounters,
    pub outcomes: Vec<IpDatagramOutcome>,
    pub outcomes_omitted: u64,
}

pub(super) struct DerivedDecodeBudget {
    pub(super) charge: usize,
    pub(super) max_layers: usize,
    pub(super) budget_reduced: bool,
}

pub(super) struct IpDispatch {
    reassembler: ip::Reassembler,
    clock: CaptureClock,
    max_aggregate_bytes: usize,
    max_outcomes: usize,
    report: IpReassemblyReport,
}

impl IpDispatch {
    pub(super) fn contains_datagram(&self, key: &DatagramKey) -> bool {
        self.reassembler.contains_datagram(key)
    }
    pub(super) fn new(
        limits: IpReassemblyLimits,
        overlap_policy: OverlapPolicy,
    ) -> Result<Self, crate::analysis::Error> {
        Ok(Self {
            max_aggregate_bytes: limits.max_aggregate_bytes,
            max_outcomes: limits.max_retained_outcomes,
            reassembler: ip::Reassembler::new(limits, overlap_policy)?,
            clock: CaptureClock::new(),
            report: IpReassemblyReport::default(),
        })
    }

    /// Every physical frame advances IP expiry, matched or not.
    pub(super) fn at(
        &mut self,
        timestamp: SystemTime,
        number: u64,
    ) -> Result<(Instant, Option<Duration>), Error> {
        self.clock.at(timestamp, number)
    }

    pub(super) fn clock_report(&self) -> &super::clock::ClockReport {
        self.clock.report()
    }

    /// Capping the decoder to the layers reserved here makes the pre-allocation charge enforceable.
    pub(super) fn plan_derived_decode(
        &self,
        current: usize,
        datagram_bytes: usize,
    ) -> Result<DerivedDecodeBudget, ip::Error> {
        const LAYER_METADATA_RESERVATION: usize = 4_096;

        let limit = self.max_aggregate_bytes;
        let occupied = current
            .checked_add(self.retained_memory_charge())
            .ok_or_else(|| self.aggregate_memory_error())?;
        let available = limit
            .checked_sub(occupied)
            .ok_or_else(|| self.aggregate_memory_error())?;
        let base_charge = datagram_bytes
            .checked_add(size_of::<DecodedPacket>())
            .and_then(|charge| {
                size_of::<DerivedDatagram>()
                    .checked_mul(2)
                    .and_then(|metadata| charge.checked_add(metadata))
            })
            .ok_or_else(|| self.aggregate_memory_error())?;
        let per_layer_charge = datagram_bytes
            .checked_mul(2)
            .and_then(|charge| charge.checked_add(size_of::<Box<dyn crate::layer::Layer>>()))
            .and_then(|charge| charge.checked_add(size_of::<Option<usize>>()))
            .and_then(|charge| charge.checked_add(LAYER_METADATA_RESERVATION))
            .ok_or_else(|| self.aggregate_memory_error())?;
        let structural_layers = crate::packet::Limits::default()
            .max_layers
            .min(datagram_bytes.saturating_add(1));
        let affordable_layers = available
            .checked_sub(base_charge)
            .and_then(|remaining| remaining.checked_div(per_layer_charge))
            .unwrap_or(0);
        let max_layers = structural_layers.min(affordable_layers);
        if max_layers == 0 {
            return Err(self.aggregate_memory_error());
        }
        let charge = per_layer_charge
            .checked_mul(max_layers)
            .and_then(|metadata| base_charge.checked_add(metadata))
            .ok_or_else(|| self.aggregate_memory_error())?;
        Ok(DerivedDecodeBudget {
            charge,
            max_layers,
            budget_reduced: max_layers < structural_layers,
        })
    }

    pub(super) fn charge_derived_memory(
        &self,
        current: usize,
        charge: usize,
    ) -> Result<usize, ip::Error> {
        let derived = current
            .checked_add(charge)
            .ok_or_else(|| self.aggregate_memory_error())?;
        self.retained_memory_charge()
            .checked_add(derived)
            .filter(|total| *total <= self.max_aggregate_bytes)
            .ok_or_else(|| self.aggregate_memory_error())?;
        Ok(derived)
    }

    pub(super) fn aggregate_memory_error(&self) -> ip::Error {
        ip::Resource::AggregateMemoryLimit {
            limit: self.max_aggregate_bytes,
        }
        .into()
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

    /// The flag reports whether any datagram was removed, even one omitted from the events.
    pub(super) fn expire(&mut self, now: Instant) -> (Vec<IpEvent>, bool) {
        let retired = self.reassembler.expire(now);
        let removed =
            !retired.outcomes.is_empty() || retired.omitted_ipv4 > 0 || retired.omitted_ipv6 > 0;
        (self.drain(retired, IncompleteReason::IdleExpired), removed)
    }

    pub(super) fn flush(&mut self) -> Vec<IpEvent> {
        let retired = self.reassembler.flush();
        self.drain(retired, IncompleteReason::EndOfCapture)
    }

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

    fn retained_memory_charge(&self) -> usize {
        self.reassembler.aggregate_memory_charge()
    }

    fn record_incomplete(&mut self, outcome: ip::IncompleteDatagram) -> IpEvent {
        self.count_incomplete(outcome.family(), outcome.reason, 1);
        let terminal = IpDatagramOutcome::Incomplete(outcome);
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
