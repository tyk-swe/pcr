// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange options and results.

use std::time::Duration;

use packetcraftr_network::capture::{
    CaptureRecordId, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, OverflowPolicy,
};
use packetcraftr_packet::frame::Frame;
use packetcraftr_packet::{
    decode::{Options as DecodeOptions, Result as DecodedPacket},
    template::DEFAULT_MAX_TEMPLATE_PACKETS,
};

use super::super::Stats;
use super::super::send::{SendOptions, SentPacket};

pub const DEFAULT_MAX_UNSOLICITED_FRAMES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;
pub const MAX_EXCHANGE_TIMEOUT: Duration = packetcraftr_network::capture::MAX_TIMEOUT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeOptions {
    pub send: SendOptions,
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub max_unsolicited: usize,
    pub max_responses: usize,
    /// One aggregate backend queue bound shared by matched, unsolicited, and
    /// undecodable capture traffic.
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub capture_overflow_policy: OverflowPolicy,
    pub decode: DecodeOptions,
}

impl Default for ExchangeOptions {
    fn default() -> Self {
        Self {
            send: SendOptions::default(),
            timeout: Duration::from_secs(3),
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_unsolicited: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_responses: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_capture_queue_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_captured_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            capture_overflow_policy: OverflowPolicy::Fail,
            decode: DecodeOptions::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MatchedResponse {
    pub(crate) record_id: CaptureRecordId,
    pub(crate) request_index: usize,
    pub(crate) response: DecodedPacket,
    pub(crate) received_at: std::time::Instant,
    pub(crate) latency: Duration,
}

impl MatchedResponse {
    pub(crate) fn new(
        record_id: CaptureRecordId,
        request_index: usize,
        response: DecodedPacket,
        received_at: std::time::Instant,
        latency: Duration,
    ) -> Self {
        Self {
            record_id,
            request_index,
            response,
            received_at,
            latency,
        }
    }

    pub fn record_id(&self) -> CaptureRecordId {
        self.record_id
    }

    pub fn request_index(&self) -> usize {
        self.request_index
    }

    pub fn response(&self) -> &DecodedPacket {
        &self.response
    }

    pub fn latency(&self) -> Duration {
        self.latency
    }

    pub(crate) fn received_at(&self) -> std::time::Instant {
        self.received_at
    }
}

/// A decoded capture record that was retained without unique request
/// attribution. The capture identity and monotonic ingress marker remain
/// attached to the record; no wall-clock subtraction is performed.
#[derive(Clone, Debug)]
pub struct UnsolicitedResponse {
    pub(crate) record_id: CaptureRecordId,
    pub(crate) response: DecodedPacket,
    pub(crate) received_at: Option<std::time::Instant>,
    pub(crate) workflow_eligible: bool,
}

impl UnsolicitedResponse {
    pub fn record_id(&self) -> CaptureRecordId {
        self.record_id
    }

    pub fn response(&self) -> &DecodedPacket {
        &self.response
    }

    pub fn received_at(&self) -> Option<std::time::Instant> {
        self.received_at
    }

    pub(crate) fn workflow_eligible(&self) -> bool {
        self.workflow_eligible
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        record_id: CaptureRecordId,
        response: DecodedPacket,
        received_at: Option<std::time::Instant>,
        workflow_eligible: bool,
    ) -> Self {
        Self {
            record_id,
            response,
            received_at,
            workflow_eligible,
        }
    }
}

/// A capture record that could not be decoded under the configured limits.
#[derive(Clone, Debug)]
pub struct UndecodedCapture {
    pub(crate) record_id: CaptureRecordId,
    pub(crate) frame: Frame,
    pub(crate) received_at: Option<std::time::Instant>,
}

impl UndecodedCapture {
    pub fn record_id(&self) -> CaptureRecordId {
        self.record_id
    }

    pub fn frame(&self) -> &Frame {
        &self.frame
    }

    pub fn received_at(&self) -> Option<std::time::Instant> {
        self.received_at
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        record_id: CaptureRecordId,
        frame: Frame,
        received_at: Option<std::time::Instant>,
    ) -> Self {
        Self {
            record_id,
            frame,
            received_at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExchangeResult {
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<MatchedResponse>,
    pub(crate) unanswered: Vec<usize>,
    pub(crate) unsolicited: Vec<UnsolicitedResponse>,
    /// Captured records whose bytes could not be decoded under the configured
    /// limits. The complete raw frame is retained for evidence.
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<packetcraftr_packet::diagnostic::Diagnostic>,
    pub(crate) stats: Stats,
}

impl ExchangeResult {
    pub fn sent(&self) -> &[SentPacket] {
        &self.sent
    }

    pub fn responses(&self) -> &[MatchedResponse] {
        &self.responses
    }

    pub fn unanswered(&self) -> &[usize] {
        &self.unanswered
    }

    pub fn unsolicited(&self) -> &[UnsolicitedResponse] {
        &self.unsolicited
    }

    pub fn undecoded(&self) -> &[UndecodedCapture] {
        &self.undecoded
    }

    pub fn diagnostics(&self) -> &[packetcraftr_packet::diagnostic::Diagnostic] {
        &self.diagnostics
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}
