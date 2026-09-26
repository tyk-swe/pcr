// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exchange events and validation of their request identities and totals.

use super::{Aggregate, Error, Report};
use crate::evidence::SentPacket;
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, frame::Frame};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Response {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

/// One exchange outcome, published when its classification becomes final.
#[derive(Clone, Debug)]
pub enum Event {
    Sent {
        request_index: usize,
        sent: Arc<SentPacket>,
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
    Diagnostic(Diagnostic),
}

/// The events of one exchange, in publication order.
#[derive(Default)]
pub(crate) struct Observed {
    sent: Vec<(usize, Arc<SentPacket>)>,
    responses: Vec<Response>,
    unanswered: Vec<usize>,
    unsolicited: Vec<DecodedPacket>,
    undecoded: Vec<Frame>,
    diagnostics: Vec<Diagnostic>,
}

impl Observed {
    pub(crate) fn observe(&mut self, event: Event) {
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

    pub(crate) fn finish(mut self, report: Report) -> Result<Aggregate, Error> {
        self.validate(&report)?;
        self.diagnostics.extend(report.diagnostics);
        Ok(Aggregate {
            sent: self.sent.into_iter().map(|(_, sent)| sent).collect(),
            responses: self.responses,
            unanswered: self.unanswered,
            unsolicited: self.unsolicited,
            undecoded: self.undecoded,
            diagnostics: self.diagnostics,
            stats: report.stats,
        })
    }

    fn validate(&self, report: &Report) -> Result<(), Error> {
        if self.unanswered != report.unanswered {
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
        if u64::try_from(sent_count).unwrap_or(u64::MAX) != report.stats.packets_completed {
            return Err(incoherent(
                "sent events disagree with completion statistics",
            ));
        }
        Ok(())
    }
}

fn incoherent(message: &str) -> Error {
    Error::IncoherentEvents {
        message: message.to_owned(),
    }
}

pub(crate) fn into_sent_packet(sent: Arc<SentPacket>) -> SentPacket {
    Arc::unwrap_or_clone(sent)
}
