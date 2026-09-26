// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;
use std::time::Duration;

use crate::output::contract::Error;
use crate::output::envelope::Published;
use crate::output::frame::{Captured, Decoded, Wire};

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
}

/// An exchange, with the request builder's diagnostics and the totals.
impl TryFrom<packetcraftr::exchange::Report> for Published<Report> {
    type Error = Error;

    fn try_from(result: packetcraftr::exchange::Report) -> Result<Self, Error> {
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
            .map(Response::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(Decoded::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(
            Report {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered.into_iter().map(request_index).collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded
                    .into_iter()
                    .map(Captured::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            },
            diagnostics,
        )
        .with_stats(stats))
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

/// One exchange event, with any diagnostic it carried for the envelope.
impl TryFrom<packetcraftr::exchange::Event> for Published<Event> {
    type Error = Error;

    fn try_from(event: packetcraftr::exchange::Event) -> Result<Self, Error> {
        let (event, diagnostics) = match event {
            packetcraftr::exchange::Event::Sent {
                request_index: index,
                sent,
            } => {
                let (frame, diagnostics) = sent_output(sent);
                (
                    Event::Sent {
                        request_index: request_index(index),
                        frame,
                    },
                    diagnostics,
                )
            }
            packetcraftr::exchange::Event::Response(response) => {
                let response = Response::try_from(response)?;
                (
                    Event::Response {
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
                Event::Unanswered {
                    request_index: request_index(index),
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Unsolicited { frame } => (
                Event::Unsolicited {
                    frame: frame.try_into()?,
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Undecoded { frame } => (
                Event::Undecoded {
                    frame: frame.try_into()?,
                },
                Vec::new(),
            ),
            packetcraftr::exchange::Event::Diagnostic(diagnostic) => {
                (Event::Diagnostic {}, vec![diagnostic])
            }
        };
        Ok(Self::new(event, diagnostics))
    }
}

/// The terminal record, with the exchange's diagnostics and totals.
impl From<packetcraftr::exchange::Summary> for Published<Event> {
    fn from(summary: packetcraftr::exchange::Summary) -> Self {
        let packetcraftr::exchange::Summary {
            unanswered,
            diagnostics,
            stats,
        } = summary;
        Self::new(
            Event::Complete {
                unanswered: unanswered.into_iter().map(request_index).collect(),
            },
            diagnostics,
        )
        .with_stats(stats)
    }
}

fn sent_output(sent: std::sync::Arc<packetcraftr::SentPacket>) -> (Wire, Vec<Diagnostic>) {
    (
        sent.wire_bytes().clone().into(),
        sent.built().diagnostics.clone(),
    )
}

impl TryFrom<packetcraftr::exchange::Response> for Response {
    type Error = Error;

    fn try_from(response: packetcraftr::exchange::Response) -> Result<Self, Error> {
        Ok(Self {
            request_index: request_index(response.request_index),
            response: response.response.try_into()?,
            latency: response.latency,
        })
    }
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
