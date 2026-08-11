// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Unsolicited and undecodable frame retention under aggregate bounds.

use packetcraftr_network::capture::RecordIdentity;
use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{decode::Result as DecodedPacket, diagnostic::push_diagnostic_once};

use super::accumulator::{ExchangeAccumulator, UnsolicitedEvidence};
use super::contract::ExchangeOptions;
use crate::evidence::reserve_capture_evidence;

impl ExchangeAccumulator {
    pub(super) fn reserve_decoded_evidence(
        &mut self,
        additional: usize,
        options: &ExchangeOptions,
    ) -> bool {
        reserve_capture_evidence(
            &mut self.retained_frames,
            &mut self.retained_bytes,
            additional,
            options.max_capture_queue_frames,
            options.max_captured_bytes,
            &mut self.diagnostics,
        )
    }

    pub(super) fn retain_unsolicited(
        &mut self,
        identity: RecordIdentity,
        decoded: DecodedPacket,
        options: &ExchangeOptions,
        freshness: Option<super::accumulator::UnsolicitedFreshness>,
    ) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if self.reserve_decoded_evidence(decoded.original.len(), options) {
            self.mark_record_retained(identity);
            self.unsolicited
                .push(UnsolicitedEvidence { decoded, freshness });
        }
    }

    pub(super) fn retain_undecoded(
        &mut self,
        identity: RecordIdentity,
        frame: Frame,
        options: &ExchangeOptions,
    ) {
        if self.unsolicited.len() + self.undecoded.len() >= options.max_unsolicited {
            push_diagnostic_once(
                &mut self.diagnostics,
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "exchange.unsolicited_limit",
                    format!(
                        "unsolicited/undecoded frame limit {} reached; later frames were not retained",
                        options.max_unsolicited
                    ),
                ),
            );
            return;
        }
        if self.reserve_decoded_evidence(frame.bytes().len(), options) {
            self.mark_record_retained(identity);
            self.undecoded.push(frame);
        }
    }
}
