// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contracts for the `exchange` command.

use packetcraftr_client::exchange::Result as ExchangeResult;
use packetcraftr_packet::diagnostic::Diagnostic;
use serde::Serialize;
use std::time::Duration;

use crate::output::contract::OutputContractError;
use crate::output::envelope::OperationStats;
use crate::output::frame::{DecodedFrameOutput, FrameOutput, WireFrameOutput};

pub use crate::output::frame::{Captured as Frame, Decoded as DecodedFrame, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeResponseOutput {
    pub request_index: u64,
    pub response: DecodedFrameOutput,
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct ExchangeCommandResult {
    pub sent: Vec<WireFrameOutput>,
    pub responses: Vec<ExchangeResponseOutput>,
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<DecodedFrameOutput>,
    pub undecoded: Vec<FrameOutput>,
}

impl ExchangeCommandResult {
    pub fn try_from_exchange(
        result: ExchangeResult,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let ExchangeResult {
            sent,
            sent_evidence: _,
            responses,
            unanswered,
            unsolicited,
            undecoded,
            mut diagnostics,
            stats,
        } = result;
        let sent_frames = sent
            .into_iter()
            .map(|built| {
                diagnostics.extend(built.diagnostics);
                WireFrameOutput::new(built.bytes)
            })
            .collect();
        let response_outputs = responses
            .into_iter()
            .map(|response| {
                Ok(ExchangeResponseOutput {
                    request_index: response.request_index as u64,
                    response: DecodedFrameOutput::try_from_decoded(response.response)?,
                    latency: response.latency,
                })
            })
            .collect::<std::result::Result<Vec<_>, OutputContractError>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(DecodedFrameOutput::try_from_decoded)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let undecoded_frames = undecoded
            .into_iter()
            .map(FrameOutput::try_from_frame)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered.into_iter().map(|index| index as u64).collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded_frames,
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
        frame: WireFrameOutput,
    },
    Response {
        request_index: u64,
        response: DecodedFrameOutput,
        latency: Duration,
    },
    Unanswered {
        request_index: u64,
    },
    Unsolicited {
        frame: DecodedFrameOutput,
    },
    Undecoded {
        frame: FrameOutput,
    },
    Complete {
        unanswered: Vec<u64>,
    },
}

pub use ExchangeCommandResult as Result;
pub use ExchangeResponseOutput as Response;
pub use ExchangeStreamCommandResult as Event;
