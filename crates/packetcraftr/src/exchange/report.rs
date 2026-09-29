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

/// Diagnostics are not repeated here: each one already reached the caller as
/// [`Event::Diagnostic`].
#[derive(Clone, Debug)]
pub struct Report {
    pub unanswered: Vec<usize>,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub sent: Vec<Arc<SentPacket>>,
    pub responses: Vec<Response>,
    pub unanswered: Vec<usize>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}

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
