// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::execution::Shared;
use crate::{Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::{Error, Event, SentFrame};

#[derive(Clone, Debug)]
pub struct Report {
    pub passes_completed: u32,
    pub stats: Stats,
}

#[derive(Clone, Debug)]
pub struct Aggregate {
    pub sent: Vec<SentFrame>,
    pub passes_completed: u32,
    pub stats: Stats,
}

#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<SentFrame>>);

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|sent| match event {
            Event::Sent(frame) => sent.push(frame),
        });
        Ok(())
    }
}

impl Collector {
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let sent = self.0.take();
        super::evidence::validate(&sent, &report)?;
        Ok(Aggregate {
            sent,
            passes_completed: report.passes_completed,
            stats: report.stats,
        })
    }
}
