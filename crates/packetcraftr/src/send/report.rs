// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::execution::Shared;
use crate::{SentPacket, Sink, Stats};
use packetcraftr_core::error::BoundaryError;

use super::Error;

/// One confirmed transmission inside a send.
#[derive(Clone, Debug)]
pub struct SentFrame {
    /// One-based pass over the packet set.
    pub pass: u32,
    /// Zero-based index of the packet within one expansion pass.
    pub index: u64,
    pub packet: SentPacket,
}

/// What a send publishes while it runs. Each event is answered before the
/// next frame is transmitted.
#[derive(Clone, Debug)]
pub enum Event {
    /// The provider confirmed this frame.
    Sent(SentFrame),
}

/// The terminal result of one send.
#[derive(Clone, Debug)]
pub struct Report {
    pub passes_completed: u32,
    pub stats: Stats,
}

/// Every confirmed transmission of one send, in send order, with its
/// terminal report.
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub sent: Vec<SentFrame>,
    pub passes_completed: u32,
    pub stats: Stats,
}

/// A sink that keeps every published frame. Pass a clone to
/// [`Client::send`](crate::Client::send) and [`finish`](Self::finish) the one
/// kept with the report the send returns.
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
    /// Joins the collected frames with the send's terminal `report`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncoherentEvents`] when the collected frames are not
    /// the ones the report counts.
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let sent = self.0.take();
        if u64::try_from(sent.len()).unwrap_or(u64::MAX) != report.stats.packets_completed {
            return Err(Error::IncoherentEvents {
                message: "sent events disagree with completion statistics".to_owned(),
            });
        }
        Ok(Aggregate {
            sent,
            passes_completed: report.passes_completed,
            stats: report.stats,
        })
    }
}
