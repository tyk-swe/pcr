// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::frame::Frame;
use packetcraftr_core::{Packet, diagnostic::Diagnostic};

#[derive(Clone, Debug)]
pub struct ExecutionCase {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) packet: Packet,
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

pub trait Authorizer {
    /// Authorize the complete packet set, optional route destination, and
    /// conservative maximum wire-byte budget before route or capture effects.
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> std::result::Result<(), crate::BoundaryError>;
}

pub trait Executor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        timeout: Duration,
    ) -> std::result::Result<Execution, crate::BoundaryError>;
}
