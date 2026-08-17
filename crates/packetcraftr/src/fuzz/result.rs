// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::{Deref, DerefMut};
use std::time::Duration;

use packetcraftr_core::{diagnostic::Diagnostic, frame::Frame, fuzz as packet_fuzz};
use packetcraftr_netio::capture::Statistics as CaptureStatistics;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    Built,
    Rejected,
    Response,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct Case {
    pub prepared: packet_fuzz::Case,
    pub outcome: CaseOutcome,
    pub sent: Option<Frame>,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
}

impl From<packet_fuzz::Case> for Case {
    fn from(prepared: packet_fuzz::Case) -> Self {
        let outcome = match prepared.outcome {
            packet_fuzz::CaseOutcome::Built => CaseOutcome::Built,
            packet_fuzz::CaseOutcome::Rejected => CaseOutcome::Rejected,
        };
        Self {
            prepared,
            outcome,
            sent: None,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
        }
    }
}

impl Deref for Case {
    type Target = packet_fuzz::Case;

    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}

impl DerefMut for Case {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.prepared
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct Result {
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<Case>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Stats,
}
