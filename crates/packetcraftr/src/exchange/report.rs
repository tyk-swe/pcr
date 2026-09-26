// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;

use crate::execution::Shared;
use crate::{Sink, Stats, evidence::SentPacket};
use packetcraftr_core::error::BoundaryError;

use super::{Error, Event, Observed, Response};

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
