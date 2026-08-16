// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contracts for the `exchange` command.

use crate::exchange::Result as ExchangeResult;
use packetcraftr_core::diagnostic::Diagnostic;
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
        let ExchangeResult {
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
                diagnostics.extend(sent.built().diagnostics.clone());
                Wire::new(sent.wire_bytes().clone())
            })
            .collect();
        let response_outputs = responses
            .into_iter()
            .map(|response| {
                Ok(ExchangeResponseOutput {
                    request_index: u64::try_from(response.request_index).unwrap_or(u64::MAX),
                    response: Decoded::try_from_decoded(response.response)?,
                    latency: response.latency,
                })
            })
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(Decoded::try_from_decoded)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered
                    .into_iter()
                    .map(|index| u64::try_from(index).unwrap_or(u64::MAX))
                    .collect(),
                unsolicited: unsolicited_outputs,
                undecoded: Captured::try_from_frames(undecoded)?,
            },
            diagnostics,
            stats.into(),
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
