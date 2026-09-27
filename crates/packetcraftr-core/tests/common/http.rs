// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared HTTP collection: folding capture fixtures through one
//! [`Collector`] under the analysis pipeline.

use packetcraftr_core::analysis::http::{Collector, Event, Message, Summary};
use packetcraftr_core::analysis::{self, Options};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;

use super::tls_capture::{Capture, Stream};
use super::{reader, registry};

/// One TCP port-80 conversation opened inside a fresh capture.
pub(crate) fn setup() -> (Capture, Stream) {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    (capture, stream)
}

/// Runs `frames` through `collector` under provenance-tracking TCP event
/// delivery and returns the events plus the closed-run summary.
pub(crate) fn collect_events(frames: &[Frame], mut collector: Collector) -> (Vec<Event>, Summary) {
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(frames),
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            events.extend(
                collector
                    .observe(&record)
                    .map_err(BoundaryError::from_error)?,
            );
            Ok(())
        },
    )
    .unwrap();
    let (trailing, summary) = collector.finish(&run).unwrap();
    events.extend(trailing);
    (events, summary)
}

/// [`collect_events`], keeping only the completed messages.
pub(crate) fn collect(frames: &[Frame], collector: Collector) -> (Vec<Message>, Summary) {
    let (events, summary) = collect_events(frames, collector);
    (
        events
            .into_iter()
            .filter_map(|event| {
                if let Event::Message(message) = event {
                    Some(*message)
                } else {
                    None
                }
            })
            .collect(),
        summary,
    )
}
