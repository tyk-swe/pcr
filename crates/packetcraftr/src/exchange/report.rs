// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::execution::Shared;
use crate::{Sink, Stats, evidence::SentPacket};
use packetcraftr_core::error::BoundaryError;

use super::Error;

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

/// The terminal result of one exchange, returned after capture shutdown and
/// validation.
#[derive(Clone, Debug)]
pub struct Report {
    pub unanswered: Vec<usize>,
    /// Diagnostics not already published as [`Event::Diagnostic`]. The
    /// exchange publishes every diagnostic as an event before it returns, so
    /// a report it produces leaves this empty; [`Collector::finish`] appends
    /// any entries after the observed ones.
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

/// Every event of one exchange, joined with its terminal report.
#[derive(Clone, Debug)]
pub struct Aggregate {
    /// Trusted receipts for exact provider-accepted transmissions.
    pub sent: Vec<Arc<SentPacket>>,
    pub responses: Vec<Response>,
    pub unanswered: Vec<usize>,
    pub unsolicited: Vec<DecodedPacket>,
    /// Captured records whose bytes could not be decoded under the configured
    /// limits. The complete raw frame is retained for evidence.
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

/// A sink that rebuilds the [`Aggregate`] from published events. Pass a
/// clone to [`Client::exchange`](crate::Client::exchange) and
/// [`finish`](Self::finish) the one kept with the report it returns.
#[derive(Clone, Default)]
pub struct Collector(Shared<Observed>);

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|observed| observed.observe(event));
        Ok(())
    }
}

impl Collector {
    /// Joins the collected events with the exchange's terminal `report`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncoherentEvents`] when the events are missing,
    /// duplicated, or reordered relative to the report.
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        self.0.take().finish(report)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_rejects_a_report_without_matching_sent_events() {
        let report = Report {
            unanswered: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_completed: 1,
                ..Stats::default()
            },
        };
        assert!(matches!(
            Collector::default().finish(report),
            Err(Error::IncoherentEvents { .. })
        ));
    }
}
