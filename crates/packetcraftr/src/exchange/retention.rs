// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Unsolicited and undecodable frame retention under aggregate bounds.

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::RecordIdentity;

use super::accumulator::{Accumulator, UnsolicitedEvidence};

use crate::evidence::BudgetError;

impl Accumulator {
    pub(super) fn reserve_decoded_evidence(
        &mut self,
        additional: usize,
        options: &super::model::Options,
    ) -> bool {
        let error = match self.evidence_budget.reserve(
            additional,
            options.max_capture_queue_frames,
            options.max_captured_bytes,
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
                    options.max_capture_queue_frames
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
                    options.max_captured_bytes
                ),
            ),
        };
        packetcraftr_core::diagnostic::push_once(
            &mut self.diagnostics,
            packetcraftr_core::diagnostic::Diagnostic::warning(code, message),
        );
        false
    }

    pub(super) fn retain_unsolicited(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &super::model::Options,
        freshness: Option<super::accumulator::UnsolicitedFreshness>,
    ) {
        if self.retained_unmatched >= options.max_unmatched_frames {
            packetcraftr_core::diagnostic::push_once(
                &mut self.diagnostics,
                packetcraftr_core::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited frame limit {} reached; later frames were not retained",
                        options.max_unmatched_frames
                    ),
                ),
            );
            return;
        }
        if self.reserve_decoded_evidence(decoded.original.len(), options) {
            self.mark_record_retained(identity);
            self.retained_unmatched += 1;
            self.unsolicited
                .push(UnsolicitedEvidence { decoded, freshness });
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        options: &super::model::Options,
    ) {
        if self.retained_unmatched >= options.max_unmatched_frames {
            packetcraftr_core::diagnostic::push_once(
                &mut self.diagnostics,
                packetcraftr_core::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                        options.max_unmatched_frames
                    ),
                ),
            );
            return;
        }
        if self.reserve_decoded_evidence(frame.bytes().len(), options) {
            self.mark_record_retained(identity);
            self.retained_unmatched += 1;
            self.pending_events
                .push(super::model::Event::Undecoded { frame });
        }
    }
}
