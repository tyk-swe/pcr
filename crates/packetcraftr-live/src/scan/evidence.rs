// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact scan executor-evidence validation and accounting errors.

use std::time::Duration;

use packetcraftr_packet::decode::Result as DecodedPacket;

use crate::probe::evidence::{
    ExchangeEvidence, ExchangeEvidenceError, MatchedResponseEvidence, ResponseEvidence,
    format_exchange_evidence_error,
    validate_exchange_evidence as validate_shared_exchange_evidence,
};

use super::error::ScanError;
use super::model::{ScanBatch, ScanBatchExecution, ScanLimits, ScanMatchedResponse};
use super::probe::sent_scan_probe_matches;

pub(super) fn validate_exchange_evidence(
    batch: &ScanBatch,
    exchange: &ScanBatchExecution,
    limits: ScanLimits,
) -> Result<(), ScanError> {
    validate_shared_exchange_evidence(
        ExchangeEvidence {
            request_count: batch.probes.len(),
            sent_packets: &exchange.sent,
            sent_frames: &exchange.sent_evidence,
            matched_responses: &exchange.responses,
            unsolicited: &exchange.unsolicited,
            undecoded: &exchange.undecoded,
            timeout: batch.timeout,
            stats: &exchange.stats,
        },
        limits.max_evidence_frames,
        limits.max_evidence_bytes,
        |request_index, sent| sent_scan_probe_matches(&batch.probes[request_index], sent),
    )
    .map_err(|error| map_scan_evidence_error(batch, error))
}

impl ResponseEvidence for ScanMatchedResponse {
    fn response(&self) -> &DecodedPacket {
        &self.response
    }

    fn latency(&self) -> Duration {
        self.latency
    }
}

impl MatchedResponseEvidence for ScanMatchedResponse {
    fn request_index(&self) -> usize {
        self.request_index
    }
}

fn map_scan_evidence_error(batch: &ScanBatch, error: ExchangeEvidenceError) -> ScanError {
    let batch_sequence = batch.probes[0].sequence;
    let sequence = match &error {
        ExchangeEvidenceError::SentPacketMismatch { request_index } => {
            batch.probes[*request_index].sequence
        }
        _ => batch_sequence,
    };
    let message = format_exchange_evidence_error(error, "batch", "scan");
    ScanError::InvalidEvidence { sequence, message }
}
