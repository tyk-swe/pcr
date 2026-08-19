// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contracts for the `exchange` command.

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;
use std::time::Duration;

use crate::output::contract::Error;
use crate::output::envelope::Stats;
use crate::output::frame::{Captured, Decoded, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct Response {
    pub request_index: u64,
    pub response: Decoded,
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct Result {
    pub sent: Vec<Wire>,
    pub responses: Vec<Response>,
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<Decoded>,
    pub undecoded: Vec<Captured>,
}

impl Result {
    pub fn try_from_exchange(
        result: crate::exchange::Result,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let crate::exchange::Result {
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
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(decoded_output)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered.into_iter().map(request_index).collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded
                    .into_iter()
                    .map(captured_output)
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

/// One NDJSON event produced by `exchange`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
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
    Diagnostic,
    Complete {
        unanswered: Vec<u64>,
    },
}

impl Event {
    pub fn try_from_exchange(
        event: crate::exchange::Event,
    ) -> std::result::Result<(Self, Vec<Diagnostic>), Error> {
        let (event, diagnostics) = match event {
            crate::exchange::Event::Sent {
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
            crate::exchange::Event::Response(response) => {
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
            crate::exchange::Event::Unanswered {
                request_index: index,
            } => (
                Self::Unanswered {
                    request_index: request_index(index),
                },
                Vec::new(),
            ),
            crate::exchange::Event::Unsolicited { frame } => (
                Self::Unsolicited {
                    frame: decoded_output(frame)?,
                },
                Vec::new(),
            ),
            crate::exchange::Event::Undecoded { frame } => (
                Self::Undecoded {
                    frame: captured_output(frame)?,
                },
                Vec::new(),
            ),
            crate::exchange::Event::Diagnostic(diagnostic) => (Self::Diagnostic, vec![diagnostic]),
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_exchange(
        summary: crate::exchange::Summary,
    ) -> (Self, Vec<Diagnostic>, Stats) {
        let crate::exchange::Summary {
            unanswered,
            diagnostics,
            stats,
        } = summary;
        (
            Self::Complete {
                unanswered: unanswered.into_iter().map(request_index).collect(),
            },
            diagnostics,
            stats.into(),
        )
    }
}

fn sent_output(sent: std::sync::Arc<crate::SentPacket>) -> (Wire, Vec<Diagnostic>) {
    (
        Wire::new(sent.wire_bytes().clone()),
        sent.built().diagnostics.clone(),
    )
}

fn response_output(response: crate::exchange::Response) -> std::result::Result<Response, Error> {
    Ok(Response {
        request_index: request_index(response.request_index),
        response: decoded_output(response.response)?,
        latency: response.latency,
    })
}

fn decoded_output(
    frame: packetcraftr_core::decode::DecodedPacket,
) -> std::result::Result<Decoded, Error> {
    Decoded::try_from_decoded(frame)
}

fn captured_output(frame: packetcraftr_core::frame::Frame) -> std::result::Result<Captured, Error> {
    Captured::try_from_frame(frame)
}

fn request_index(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}
