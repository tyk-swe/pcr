// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-pipeline accounting around the standalone IP reassembler.

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

/// Counters for one IP family. Sub-counters describe admitted fragments and
/// are intentionally independent: a completing fragment may also resolve an
/// overlap.
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

/// Bounded terminal evidence for one completed or incomplete datagram.
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
    /// The engine's own retirement evidence, carried through unchanged.
    Incomplete(ip::IncompleteDatagram),
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

/// How much of the aggregate IP memory budget one derived decode may spend,
/// and how many layers that buys.
pub(super) struct DerivedDecodeBudget {
    pub(super) charge: usize,
    pub(super) max_layers: usize,
    /// Whether the layer cap came from the budget rather than from the
    /// datagram's own structure, so a layer-limit refusal can be reported as
    /// the resource failure it is.
    pub(super) budget_reduced: bool,
}

/// Owns the whole aggregate IP memory ledger: the reassembler's retained
/// state and the derived-decode charges the pipeline holds while it feeds a
/// completion cascade back in.
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
    pub(super) fn new(limits: IpReassemblyLimits, overlap_policy: OverlapPolicy) -> Self {
        Self {
            max_aggregate_bytes: limits.max_aggregate_bytes,
            max_outcomes: limits.max_retained_outcomes,
            reassembler: ip::Reassembler::new(limits, overlap_policy),
            clock: CaptureClock::new(),
            report: IpReassemblyReport::default(),
        }
    }

    /// The monotonic instant this frame's capture timestamp maps to, plus the
    /// rollback the timestamp showed when it regressed. Every physical frame
    /// advances IP expiry, matched or not.
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

    /// Plans one derived decode against whatever the ledger already holds.
    ///
    /// Each committed layer consumes at least one input byte; only the final
    /// stop layer may consume zero. Capping the decoder to the number of
    /// layers reserved here makes the pre-allocation charge enforceable.
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
        let structural_layers = crate::decode::Options::default()
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

    /// Adds one planned derived decode to the caller-held charge, refusing
    /// the total the reassembler's retained state could not also afford.
    pub(super) fn charge_derived_memory(
        &self,
        current: usize,
        datagram_bytes: usize,
    ) -> Result<usize, ip::Error> {
        let derived = current
            .checked_add(datagram_bytes)
            .ok_or_else(|| self.aggregate_memory_error())?;
        self.retained_memory_charge()
            .checked_add(derived)
            .filter(|total| *total <= self.max_aggregate_bytes)
            .ok_or_else(|| self.aggregate_memory_error())?;
        Ok(derived)
    }

    fn aggregate_memory_error(&self) -> ip::Error {
        ip::ResourceError::AggregateMemoryLimit {
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

    /// Idle-expiry sweep. Besides the bounded events, it reports whether the
    /// reassembler removed any datagram at all — including retirements whose
    /// outcome records were bounded away into the omitted counters — so the
    /// caller can skip provenance reconciliation when nothing left.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::reassembly::ip::{
        Fragment, Ipv4DatagramKey, Ipv4Fragment, Limits as ReassemblyLimits,
    };
    use crate::analysis::scope::Interner;
    use bytes::Bytes;
    use std::net::Ipv4Addr;

    fn fragment(identification: u16) -> Fragment {
        let payload = Bytes::from_static(&[7_u8; 8]);
        let mut header = [0_u8; 20];
        let total_length = u16::try_from(header.len() + payload.len())
            .expect("fixture length fits")
            .to_be_bytes();
        header[0] = 0x45;
        header[2..4].copy_from_slice(&total_length);
        header[4..6].copy_from_slice(&identification.to_be_bytes());
        header[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        header[8] = 64;
        header[9] = 17;
        header[12..16].copy_from_slice(&[192, 0, 2, 1]);
        header[16..20].copy_from_slice(&[198, 51, 100, 2]);
        Fragment::Ipv4(Ipv4Fragment {
            key: Ipv4DatagramKey {
                scope: Interner::new()
                    .intern(None, Vec::new())
                    .expect("scope interns"),
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                identification,
                protocol: 17,
            },
            fragment_offset: 0,
            more_fragments: true,
            header: Bytes::copy_from_slice(&header),
            payload,
        })
    }

    #[test]
    fn expire_reports_removal_only_when_datagrams_leave() {
        let mut dispatch = IpDispatch::new(
            ReassemblyLimits {
                idle_expiry: Duration::from_secs(30),
                ..ReassemblyLimits::default()
            },
            OverlapPolicy::Reject,
        );
        let start = Instant::now();
        dispatch
            .reassembler
            .push(fragment(1), start)
            .expect("fragment admitted");

        let (events, removed) = dispatch.expire(start + Duration::from_secs(10));
        assert!(events.is_empty());
        assert!(!removed, "a quiet sweep removed nothing");

        let (events, removed) = dispatch.expire(start + Duration::from_secs(31));
        assert!(removed, "the expired datagram must signal a removal");
        assert_eq!(events.len(), 1);
        assert_eq!(dispatch.report().counters.ipv4.idle_expired_datagrams, 1);
    }

    #[test]
    fn expire_reports_removal_when_every_outcome_is_omitted() {
        let mut dispatch = IpDispatch::new(
            ReassemblyLimits {
                idle_expiry: Duration::from_secs(30),
                max_retained_outcomes: 0,
                ..ReassemblyLimits::default()
            },
            OverlapPolicy::Reject,
        );
        let start = Instant::now();
        for identification in 1..=2 {
            dispatch
                .reassembler
                .push(fragment(identification), start)
                .expect("fragment admitted");
        }

        let (events, removed) = dispatch.expire(start + Duration::from_secs(31));
        assert!(
            removed,
            "retirements bounded into omitted counters still prove removal"
        );
        assert!(events.is_empty(), "no outcomes fit the zero cap");
        assert_eq!(dispatch.report().outcomes_omitted, 2);
        assert_eq!(dispatch.report().counters.ipv4.idle_expired_datagrams, 2);
    }
}
