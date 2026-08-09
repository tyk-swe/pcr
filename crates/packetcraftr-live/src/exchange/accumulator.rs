// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded response/result state for one armed exchange.

use std::time::Instant;

use packetcraftr_packet::{
    Packet,
    decode::{Decoder as Dissector, Result as DecodedPacket},
    registry::Registry,
};

use super::contract::{
    ExchangeOptions, ExchangeResult, MatchedResponse, UndecodedCapture, UnsolicitedResponse,
};
use super::preparation::PreparedExchangePacket;
use crate::Stats;
use crate::send::SentPacket;

pub(crate) type WorkflowResponseMatcher<'a> =
    dyn FnMut(usize, &Packet, &DecodedPacket) -> bool + 'a;

pub(crate) struct ExchangeAccumulator {
    pub(crate) responses: Vec<MatchedResponse>,
    pub(crate) unsolicited: Vec<UnsolicitedResponse>,
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<packetcraftr_packet::diagnostic::Diagnostic>,
    pub(super) retained_frames: usize,
    pub(super) retained_bytes: usize,
    pub(crate) response_counts: Vec<usize>,
    pub(super) correlation_deadline_expired: bool,
    pub(super) workflow_examined_unsolicited: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ExchangeProcessContext<'a> {
    pub(crate) registry: &'a Registry,
    pub(crate) dissector: &'a Dissector,
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent: &'a [SentPacket],
    pub(crate) deadline: Instant,
    pub(crate) options: &'a ExchangeOptions,
}

#[derive(Clone, Copy)]
pub(crate) struct WorkflowPromotionContext<'a> {
    pub(crate) prepared: &'a [PreparedExchangePacket],
    pub(crate) sent: &'a [SentPacket],
    pub(crate) deadline: Instant,
    pub(crate) max_responses: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeProcessOutcome {
    Continue,
    CorrelationDeadlineExpired,
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
        }
    }

    pub(crate) fn finish(
        self,
        sent: Vec<SentPacket>,
        unanswered: Vec<usize>,
        stats: Stats,
    ) -> ExchangeResult {
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
