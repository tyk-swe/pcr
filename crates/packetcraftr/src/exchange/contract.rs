// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public exchange options and results.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::frame::Frame;
use packetcraftr_core::{decode::DecodedPacket, template::DEFAULT_MAX_TEMPLATE_PACKETS};
use packetcraftr_netio::capture::{
    DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, OverflowPolicy,
};

use super::super::Stats;

pub const DEFAULT_MAX_UNMATCHED_FRAMES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;
pub const DEFAULT_MAX_RESPONSES: usize = DEFAULT_CAPTURE_QUEUE_FRAMES;
pub const MAX_EXCHANGE_TIMEOUT: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub send: super::super::send::Options,
    pub timeout: Duration,
    pub max_template_packets: usize,
    pub max_unmatched_frames: usize,
    pub max_responses: usize,
    /// One aggregate backend queue bound shared by matched, unsolicited, and
    /// undecodable capture traffic.
    pub max_capture_queue_frames: usize,
    pub max_captured_bytes: usize,
    pub capture_overflow_policy: OverflowPolicy,
    pub decode: packetcraftr_core::decode::Options,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            send: super::super::send::Options::default(),
            timeout: Duration::from_secs(3),
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            max_unmatched_frames: DEFAULT_MAX_UNMATCHED_FRAMES,
            max_responses: DEFAULT_MAX_RESPONSES,
            max_capture_queue_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_captured_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            capture_overflow_policy: OverflowPolicy::Fail,
            decode: packetcraftr_core::decode::Options::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct Result {
    /// Trusted receipts for exact provider-accepted transmissions.
    pub sent: Vec<Arc<crate::SentPacket>>,
    pub responses: Vec<Response>,
    pub unanswered: Vec<usize>,
    pub unsolicited: Vec<DecodedPacket>,
    /// Captured records whose bytes could not be decoded under the configured
    /// limits. The complete raw frame is retained for evidence.
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    pub stats: Stats,
}

/// One exchange outcome published when its classification becomes final.
#[derive(Clone, Debug)]
pub enum Event {
    Sent {
        request_index: usize,
        sent: Arc<crate::SentPacket>,
    },
    Response(Response),
    Unanswered {
        request_index: usize,
    },
    Unsolicited {
        frame: DecodedPacket,
    },
    Undecoded {
        frame: Frame,
    },
    Diagnostic(packetcraftr_core::diagnostic::Diagnostic),
}

/// Final exchange metadata published after capture shutdown and validation.
#[derive(Clone, Debug)]
pub struct Summary {
    pub unanswered: Vec<usize>,
    pub diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
    pub stats: Stats,
}

/// Reconstructs the aggregate exchange result from progressive domain events.
#[derive(Default)]
pub struct Collector {
    sent: Vec<(usize, Arc<crate::SentPacket>)>,
    responses: Vec<Response>,
    unanswered: Vec<usize>,
    unsolicited: Vec<DecodedPacket>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
}

impl Collector {
    /// Adds one progressive event to the aggregate result under construction.
    pub fn observe(&mut self, event: Event) {
        match event {
            Event::Sent {
                request_index,
                sent,
            } => self.sent.push((request_index, sent)),
            Event::Response(response) => self.responses.push(response),
            Event::Unanswered { request_index } => self.unanswered.push(request_index),
            Event::Unsolicited { frame } => self.unsolicited.push(frame),
            Event::Undecoded { frame } => self.undecoded.push(frame),
            Event::Diagnostic(diagnostic) => self.diagnostics.push(diagnostic),
        }
    }

    /// Combines collected events with final diagnostics and statistics.
    pub fn finish(mut self, summary: Summary) -> std::result::Result<Result, crate::Error> {
        self.validate(&summary)?;
        self.diagnostics.extend(summary.diagnostics);
        Ok(Result {
            sent: self.sent.into_iter().map(|(_, sent)| sent).collect(),
            responses: self.responses,
            unanswered: self.unanswered,
            unsolicited: self.unsolicited,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats: summary.stats,
        })
    }

    fn validate(&self, summary: &Summary) -> std::result::Result<(), crate::Error> {
        if self.unanswered != summary.unanswered {
            return Err(incoherent("unanswered events disagree with the summary"));
        }
        if self
            .sent
            .iter()
            .enumerate()
            .any(|(expected, (actual, _))| expected != *actual)
        {
            return Err(incoherent(
                "sent events are missing, duplicated, or reordered",
            ));
        }
        let sent_count = self.sent.len();
        if self
            .responses
            .iter()
            .any(|response| response.request_index >= sent_count)
            || self.unanswered.iter().any(|index| *index >= sent_count)
        {
            return Err(incoherent(
                "response or unanswered identity has no sent request",
            ));
        }
        if u64::try_from(sent_count).unwrap_or(u64::MAX) != summary.stats.packets_completed {
            return Err(incoherent(
                "sent events disagree with completion statistics",
            ));
        }
        Ok(())
    }
}

fn incoherent(message: &str) -> crate::Error {
    crate::Error::InvalidExchangeEvents {
        message: message.to_owned(),
    }
}

pub(crate) fn into_sent_packet(sent: Arc<crate::SentPacket>) -> crate::SentPacket {
    Arc::unwrap_or_clone(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_rejects_summary_without_matching_sent_events() {
        let summary = Summary {
            unanswered: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_completed: 1,
                ..Stats::default()
            },
        };
        assert!(matches!(
            Collector::default().finish(summary),
            Err(crate::Error::InvalidExchangeEvents { .. })
        ));
    }
}
