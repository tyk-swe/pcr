// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded response/result state for one armed exchange.

use std::{collections::HashSet, sync::Arc, time::Instant};

use packetcraftr_core::{
    Packet,
    decode::{DecodedPacket, Dissector},
    registry::Registry,
};
use packetcraftr_netio::capture::RecordIdentity;

use super::preparation::PreparedPacket;
use crate::evidence::Budget;

#[derive(Clone, Copy)]
pub(super) struct UnsolicitedFreshness {
    pub(super) received_at: Instant,
    pub(super) eligible_requests: usize,
}

pub(super) struct UnsolicitedEvidence {
    pub(super) decoded: DecodedPacket,
    pub(super) freshness: Option<UnsolicitedFreshness>,
}

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct Accumulator {
    pub(super) unsolicited: Vec<UnsolicitedEvidence>,
    pub(super) pending_events: Vec<super::contract::Event>,
    pub(crate) diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    pub(super) evidence_budget: Budget,
    pub(crate) response_counts: Vec<usize>,
    pub(super) response_count: usize,
    pub(super) retained_unmatched: usize,
    pub(super) correlation_deadline_expired: bool,
    pub(super) retained_record_identities: HashSet<RecordIdentity>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProcessContext<'a> {
    pub(crate) registry: &'a Registry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) prepared: &'a [PreparedPacket],
    pub(crate) sent: &'a [Arc<crate::SentPacket>],
    pub(crate) deadline: Instant,
    pub(crate) options: &'a super::contract::Options,
}

#[derive(Clone, Copy)]
pub(crate) struct WorkflowPromotionContext<'a> {
    pub(crate) prepared: &'a [PreparedPacket],
    pub(crate) sent: &'a [Arc<crate::SentPacket>],
    pub(crate) deadline: Instant,
    pub(crate) max_responses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessOutcome {
    Continue,
    CorrelationDeadlineExpired,
    DuplicateRecordIdentity,
}

impl Accumulator {
    pub(crate) fn new(requests: usize) -> Self {
        Self {
            unsolicited: Vec::new(),
            pending_events: Vec::new(),
            diagnostics: Vec::new(),
            evidence_budget: Budget::default(),
            response_counts: vec![0; requests],
            response_count: 0,
            retained_unmatched: 0,
            correlation_deadline_expired: false,
            retained_record_identities: HashSet::new(),
        }
    }

    pub(super) fn can_retain_record(&self, identity: RecordIdentity) -> bool {
        !self.retained_record_identities.contains(&identity)
    }

    pub(super) fn mark_record_retained(&mut self, identity: RecordIdentity) {
        self.retained_record_identities.insert(identity);
    }

    pub(super) fn drain_events(&mut self) -> std::vec::Drain<'_, super::contract::Event> {
        self.pending_events.drain(..)
    }
}
