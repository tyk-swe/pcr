// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contracts for the `exchange` command.

use packetcraftr_live::exchange::Result as ExchangeResult;
use packetcraftr_packet::diagnostic::Diagnostic;
use serde::Serialize;
use std::time::Duration;

use crate::output::contract::Error;
use crate::output::envelope::Stats;
use crate::output::frame::{Captured, Decoded};

pub use crate::output::frame::{Captured as Frame, Decoded as DecodedFrame, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeResponseOutput {
    pub request_index: u64,
    pub response: Decoded,
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct ExchangeCommandResult {
    pub sent: Vec<Wire>,
    pub responses: Vec<ExchangeResponseOutput>,
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<Decoded>,
    pub undecoded: Vec<Captured>,
}

impl ExchangeCommandResult {
    pub fn try_from_exchange(
        result: ExchangeResult,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let sent_frames = result
            .sent()
            .iter()
            .map(|sent| Wire::new(sent.wire_bytes().clone()))
            .collect();
        let response_outputs = result
            .responses()
            .iter()
            .map(|response| {
                Ok(ExchangeResponseOutput {
                    request_index: response.request_index() as u64,
                    response: Decoded::try_from_decoded(response.response().clone())?,
                    latency: response.latency(),
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let unsolicited_outputs = result
            .unsolicited()
            .iter()
            .map(|response| Decoded::try_from_decoded(response.response().clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let undecoded_frames = result
            .undecoded()
            .iter()
            .map(|capture| Captured::try_from_frame(capture.frame().clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let diagnostics = result
            .diagnostics()
            .iter()
            .cloned()
            .chain(
                result
                    .sent()
                    .iter()
                    .flat_map(|sent| sent.built().diagnostics.iter().cloned()),
            )
            .collect();
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: result
                    .unanswered()
                    .iter()
                    .map(|index| *index as u64)
                    .collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded_frames,
            },
            diagnostics,
            result.stats().clone().into(),
        ))
    }
}

/// One NDJSON event produced by `exchange`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExchangeStreamCommandResult {
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
    Complete {
        unanswered: Vec<u64>,
    },
}

pub use ExchangeCommandResult as Result;
pub use ExchangeResponseOutput as Response;
pub use ExchangeStreamCommandResult as Event;
