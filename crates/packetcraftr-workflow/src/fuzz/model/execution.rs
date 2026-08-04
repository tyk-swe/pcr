// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_capture::Frame;
use packetcraftr_packet::{Packet, build::BuiltPacket, diagnostic::Diagnostic};

#[derive(Clone, Debug)]
pub struct FuzzExecutionCase {
    pub index: u64,
    pub seed: u64,
    pub packet: Packet,
}

#[derive(Clone, Debug)]
pub struct FuzzCaseExecution {
    pub built: BuiltPacket,
    pub sent: Frame,
    pub responses: Vec<Frame>,
    pub unmatched: Vec<Frame>,
    pub undecoded: Vec<Frame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: crate::Stats,
}

pub trait FuzzAuthorizer {
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

pub trait FuzzExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> std::result::Result<FuzzCaseExecution, crate::BoundaryError>;
}
