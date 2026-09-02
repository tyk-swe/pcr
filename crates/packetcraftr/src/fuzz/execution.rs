// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The live fuzz executor boundary: one permit-bound case in, one bounded
//! evidence receipt out.

use std::time::Duration;

use packetcraftr_core::frame::Frame;
use packetcraftr_core::{Packet, diagnostic::Diagnostic};

#[derive(Clone, Debug)]
pub struct ExecutionCase {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) packet: Packet,
    /// How long the executor may wait for responses to this one case.
    pub(crate) timeout: Duration,
}

impl crate::probe::Request for ExecutionCase {
    type Execution = Execution;
}

#[derive(Clone, Debug)]
pub struct Execution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) sent: crate::SentPacket,
    pub(crate) responses: Vec<Frame>,
    pub(crate) unmatched: Vec<Frame>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: crate::Stats,
}
