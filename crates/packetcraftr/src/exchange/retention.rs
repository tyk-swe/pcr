// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Unsolicited and undecodable frame retention under aggregate bounds.

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::RecordIdentity;

use super::accumulator::{Accumulator, UnsolicitedEvidence};
use super::contract::Options;

use crate::evidence::BudgetError;

impl Accumulator {
    pub(super) fn reserve_decoded_evidence(
        &mut self,
        additional: usize,
        options: &Options,
    ) -> bool {
        let error = match self.evidence_budget.reserve(
            additional,
            options.capture.max_frames,
            options.capture.max_bytes,
        ) {
            Ok(()) => return true,
            Err(error) => error,
        };
        let (code, message) = match error {
            BudgetError::FrameCountOverflow => (
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained".to_owned(),
            ),
            BudgetError::FrameLimit => (
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {} reached; later frames were not retained",
                    options.capture.max_frames
                ),
            ),
            BudgetError::ByteCountOverflow => (
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained".to_owned(),
            ),
            BudgetError::ByteLimit => (
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {} reached; later frames were not retained",
                    options.capture.max_bytes
                ),
            ),
        };
        self.diagnostics
            .push_once(Diagnostic::warning(code, message));
        false
    }

    /// The one retention gate every unattributed capture record passes: the
    /// unsolicited/undecoded frame ceiling, then the aggregate evidence budget.
    ///
    /// Both retention paths reach the ceiling under the same condition, so both
    /// report it with the same words. They previously published the same
    /// `exchange.unsolicited_limit` code with two different messages, and
    /// `push_once` deduplicates by code, so whichever path hit the limit first
    /// decided what the operator saw.
    fn reserve_unattributed(
        &mut self,
        identity: RecordIdentity,
        frame_bytes: usize,
        options: &Options,
    ) -> bool {
        if self.retained_unmatched >= options.max_unmatched_frames {
            self.diagnostics.push_once(Diagnostic::warning(
                "exchange.unsolicited_limit",
                format!(
                    "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                    options.max_unmatched_frames
                ),
            ));
            return false;
        }
        if !self.reserve_decoded_evidence(frame_bytes, options) {
            return false;
        }
        self.mark_record_retained(identity);
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the early return above keeps `retained_unmatched` below \
                      `max_unmatched_frames`, so the increment cannot overflow"
        )]
        {
            self.retained_unmatched += 1;
        }
        true
    }

    pub(super) fn retain_unsolicited(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &Options,
        freshness: Option<super::accumulator::UnsolicitedFreshness>,
    ) {
        if self.reserve_unattributed(identity, decoded.original.len(), options) {
            self.unsolicited
                .push(UnsolicitedEvidence { decoded, freshness });
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        options: &Options,
    ) {
        if self.reserve_unattributed(identity, frame.bytes().len(), options) {
            self.pending_events
                .push(super::contract::Event::Undecoded { frame });
        }
    }
}
