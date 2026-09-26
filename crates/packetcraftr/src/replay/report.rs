// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::capture_file::Format;
use packetcraftr_netio::interface::Id as InterfaceId;
use serde::Serialize;

use crate::execution::Shared;
use crate::{BoundaryError, Sink};

use super::error::Error;
use super::evidence::FrameEvidence;
use super::request::Timing;

/// What a replay publishes while it runs. Each event is answered before the
/// next frame is read.
#[derive(Clone, Debug)]
pub enum Event {
    /// The provider confirmed this frame's exact bytes.
    Frame(FrameEvidence),
}

/// The terminal counters of one replay.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub passes_completed: u32,
    pub interfaces_used: Vec<InterfaceId>,
    pub source_format: Format,
    pub timing: Timing,
    #[serde(rename = "frames_attempted")]
    pub frames_read: u64,
    #[serde(rename = "frames_completed")]
    pub frames_transmitted: u64,
    #[serde(rename = "bytes_completed")]
    pub bytes_transmitted: u64,
    pub scheduled_duration: Duration,
}

/// Every confirmed frame of one replay, in transmission order, with its
/// terminal report.
#[derive(Clone, Debug)]
pub struct Aggregate {
    pub frames: Vec<FrameEvidence>,
    pub report: Report,
}

/// A sink that keeps every published frame. Pass a clone to
/// [`Client::replay`](crate::Client::replay) and [`finish`](Self::finish) the
/// one kept with the report the replay returns.
#[derive(Clone, Default)]
pub struct Collector(Shared<Vec<FrameEvidence>>);

impl Sink<Event> for Collector {
    type Ack = ();

    fn publish(&mut self, event: Event) -> Result<(), BoundaryError> {
        self.0.update(|frames| match event {
            Event::Frame(frame) => frames.push(frame),
        });
        Ok(())
    }
}

impl Collector {
    /// Joins the collected frames with the replay's terminal `report`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IncoherentEvents`] when the collected frames are not
    /// the ones the report counts.
    pub fn finish(self, report: Report) -> Result<Aggregate, Error> {
        let frames = self.0.take();
        if u64::try_from(frames.len()).unwrap_or(u64::MAX) != report.frames_transmitted {
            return Err(Error::IncoherentEvents {
                message: "frame events disagree with the transmitted frame count".to_owned(),
            });
        }
        Ok(Aggregate { frames, report })
    }
}
