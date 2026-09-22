// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;
use std::time::Duration;

use crate::output::contract::Error;
use crate::output::frame::{Captured, Decoded, Wire};
use packetcraftr::Stats;

/// One response correlated with a sent request, with its measured latency.
#[derive(Clone, Debug, Serialize)]
pub struct Response {
    pub request_index: u64,
    pub response: Decoded,
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub sent: Vec<Wire>,
    pub responses: Vec<Response>,
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<Decoded>,
    pub undecoded: Vec<Captured>,
    /// Original captured frames for PCAP/PCAPNG, not part of the v6 JSON result.
    #[serde(skip)]
    capture_frames: Vec<packetcraftr_core::frame::Frame>,
}

impl Report {
    pub fn capture_frames(&self) -> &[packetcraftr_core::frame::Frame] {
        &self.capture_frames
    }

    pub fn try_from_exchange(
        result: packetcraftr::exchange::Report,
    ) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        // Capture output needs original link types, timestamps and wire bytes,
        // not the JSON projection. Preserve them during this one conversion.
        let mut capture_frames = result
            .sent
            .iter()
            .map(|sent| sent.frame())
            .chain(
                result
                    .responses
                    .iter()
                    .map(|response| &response.response.frame),
            )
            .chain(result.unsolicited.iter().map(|packet| &packet.frame))
            .chain(result.undecoded.iter())
            .cloned()
            .collect::<Vec<_>>();
        capture_frames.sort_by_key(|frame| frame.timestamp);
        let packetcraftr::exchange::Report {
            sent,
            responses,
            unanswered,
            unsolicited,
            undecoded,
            mut diagnostics,
            stats,
        } = result;
        let sent_frames = sent
            .into_iter()
            .map(|sent| {
                let (frame, sent_diagnostics) = sent_output(sent);
                diagnostics.extend(sent_diagnostics);
                frame
            })
            .collect();
        let response_outputs = responses
            .into_iter()
            .map(response_output)
            .collect::<Result<Vec<_>, Error>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(Decoded::try_from_decoded)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered.into_iter().map(request_index).collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded
                    .into_iter()
                    .map(Captured::try_from_frame)
                    .collect::<Result<Vec<_>, _>>()?,
                capture_frames,
            },
            diagnostics,
            stats,
        ))
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Event {
    Sent {
        request_index: u64,
        frame: Wire,
    },
    Response {
        request_index: u64,
        response: Decoded,
        latency: Duration,
    },
    Unanswered {
        request_index: u64,
    },
    Unsolicited {
        frame: Decoded,
    },
    Undecoded {
        frame: Captured,
    },
    Diagnostic {},
    Complete {
        unanswered: Vec<u64>,
    },
}

impl Event {
    pub fn try_from_exchange(
        event: packetcraftr::exchange::Event,
    ) -> Result<(Self, Vec<Diagnostic>), Error> {
        let (event, diagnostics) = match event {
            packetcraftr::exchange::Event::Sent {
                request_index: index,
                sent,
            } => {
                let (frame, diagnostics) = sent_output(sent);
                (
                    Self::Sent {
                        request_index: request_index(index),
                        frame,
                    },
                    diagnostics,
                )
            }
            packetcraftr::exchange::Event::Response(response) => {
                let response = response_output(response)?;
                (
                    Self::Response {
                        request_index: response.request_index,
                        response: response.response,
                        latency: response.latency,
                    },
                    Vec::new(),
                )
            }
            packetcraftr::exchange::Event::Unanswered {
                request_index: index,
            } => (
                Self::Unanswered {
                    request_index: request_index(index),
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Unsolicited { frame } => (
                Self::Unsolicited {
                    frame: Decoded::try_from_decoded(frame)?,
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Undecoded { frame } => (
                Self::Undecoded {
                    frame: Captured::try_from_frame(frame)?,
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Diagnostic(diagnostic) => {
                (Self::Diagnostic {}, vec![diagnostic])
            }
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_exchange(
        summary: packetcraftr::exchange::Summary,
    ) -> (Self, Vec<Diagnostic>, Stats) {
        let packetcraftr::exchange::Summary {
            unanswered,
            diagnostics,
            stats,
        } = summary;
        (
            Self::Complete {
                unanswered: unanswered.into_iter().map(request_index).collect(),
            },
            diagnostics,
            stats,
        )
    }
}

pub struct Conversion;

impl super::workflow::Conversion for Conversion {
    type EngineEvent = packetcraftr::exchange::Event;
    type EngineSummary = packetcraftr::exchange::Summary;
    type EngineReport = packetcraftr::exchange::Report;
    type Event = Event;
    type Terminal = Event;
    type Result = Report;

    fn event(event: Self::EngineEvent) -> Result<(Event, Vec<Diagnostic>), Error> {
        Event::try_from_exchange(event)
    }

    fn summary(
        summary: Self::EngineSummary,
    ) -> Result<(Event, Vec<Diagnostic>, Option<Stats>), Error> {
        let (event, diagnostics, stats) = Event::complete_from_exchange(summary);
        Ok((event, diagnostics, Some(stats)))
    }

    fn report(report: Self::EngineReport) -> Result<super::workflow::Converted<Report>, Error> {
        Report::try_from_exchange(report).map(super::workflow::Converted::with_stats)
    }
}

fn sent_output(sent: std::sync::Arc<packetcraftr::SentPacket>) -> (Wire, Vec<Diagnostic>) {
    (
        Wire::new(sent.wire_bytes().clone()),
        sent.built().diagnostics.clone(),
    )
}

fn response_output(response: packetcraftr::exchange::Response) -> Result<Response, Error> {
    Ok(Response {
        request_index: request_index(response.request_index),
        response: Decoded::try_from_decoded(response.response)?,
        latency: response.latency,
    })
}

fn request_index(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Sent { .. } => "sent",
            Self::Response { .. } => "response",
            Self::Unanswered { .. } => "unanswered",
            Self::Unsolicited { .. } => "unsolicited",
            Self::Undecoded { .. } => "undecoded",
            Self::Diagnostic {} => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}
