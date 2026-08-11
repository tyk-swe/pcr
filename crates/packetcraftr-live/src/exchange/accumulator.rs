// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded response/result state for one armed exchange.

use std::{collections::HashSet, time::Instant};

use packetcraftr_network::capture::RecordIdentity;
use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{
    Packet,
    decode::{Decoder as Dissector, Result as DecodedPacket},
    registry::Registry,
};

use super::contract::{ExchangeOptions, ExchangeResult, MatchedResponse};
use super::preparation::PreparedExchangePacket;
use crate::Stats;

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

pub(crate) struct ExchangeAccumulator {
    pub(crate) responses: Vec<MatchedResponse>,
    pub(super) unsolicited: Vec<UnsolicitedEvidence>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<packetcraftr_packet::diagnostic::Diagnostic>,
    pub(super) retained_frames: usize,
    pub(super) retained_bytes: usize,
    pub(crate) response_counts: Vec<usize>,
    pub(super) correlation_deadline_expired: bool,
    pub(super) workflow_examined_unsolicited: usize,
    pub(super) retained_record_identities: HashSet<RecordIdentity>,
}

#[derive(Clone, Copy)]
pub(crate) struct ExchangeProcessContext<'a> {
    pub(crate) registry: &'a Registry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent: &'a [crate::SentPacket],
    pub(crate) deadline: Instant,
    pub(crate) options: &'a ExchangeOptions,
}

#[derive(Clone, Copy)]
pub(crate) struct WorkflowPromotionContext<'a> {
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent: &'a [crate::SentPacket],
    pub(crate) deadline: Instant,
    pub(crate) max_responses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeProcessOutcome {
    Continue,
    CorrelationDeadlineExpired,
    DuplicateRecordIdentity,
}

impl ExchangeAccumulator {
    pub(crate) fn new(requests: usize) -> Self {
        Self {
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            retained_frames: 0,
            retained_bytes: 0,
            response_counts: vec![0; requests],
            correlation_deadline_expired: false,
            workflow_examined_unsolicited: 0,
            retained_record_identities: HashSet::new(),
        }
    }

    pub(super) fn can_retain_record(&self, identity: RecordIdentity) -> bool {
        !self.retained_record_identities.contains(&identity)
    }

    pub(super) fn mark_record_retained(&mut self, identity: RecordIdentity) {
        self.retained_record_identities.insert(identity);
    }

    pub(crate) fn finish(
        self,
        sent: Vec<crate::SentPacket>,
        unanswered: Vec<usize>,
        stats: Stats,
    ) -> ExchangeResult {
        ExchangeResult {
            sent,
            responses: self.responses,
            unanswered,
            unsolicited: self
                .unsolicited
                .into_iter()
                .map(|evidence| evidence.decoded)
                .collect(),
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats,
        }
    }
}
