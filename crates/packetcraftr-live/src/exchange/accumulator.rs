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

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct ExchangeAccumulator {
    pub(crate) responses: Vec<MatchedResponse>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<packetcraftr_packet::diagnostic::Diagnostic>,
    pub(super) unsolicited_freshness: Vec<Option<UnsolicitedFreshness>>,
    pub(super) retained_frames: usize,
    pub(super) retained_bytes: usize,
    pub(crate) response_counts: Vec<usize>,
    pub(super) correlation_deadline_expired: bool,
    pub(super) workflow_examined_unsolicited: usize,
    pub(super) seen_records: HashSet<RecordIdentity>,
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
            unsolicited_freshness: Vec::new(),
            retained_frames: 0,
            retained_bytes: 0,
            response_counts: vec![0; requests],
            correlation_deadline_expired: false,
            workflow_examined_unsolicited: 0,
            seen_records: HashSet::new(),
        }
    }

    pub(super) fn accept_record(&mut self, identity: RecordIdentity) -> bool {
        self.seen_records.insert(identity)
    }

    pub(crate) fn finish(
        self,
        sent: Vec<crate::SentPacket>,
        unanswered: Vec<usize>,
        stats: Stats,
    ) -> ExchangeResult {
        debug_assert_eq!(self.unsolicited.len(), self.unsolicited_freshness.len());
        ExchangeResult {
            sent,
            responses: self.responses,
            unanswered,
            unsolicited: self.unsolicited,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats,
        }
    }
}
