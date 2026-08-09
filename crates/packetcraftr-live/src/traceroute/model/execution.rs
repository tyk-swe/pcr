// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic};

use crate::exchange::{ExchangeResult, MatchedResponse, UndecodedCapture, UnsolicitedResponse};
use crate::send::SentPacket;
use crate::{BoundaryError, Stats};

use super::request::TracerouteStrategy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl TracerouteProbe {
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteBatch {
    pub probes: Vec<TracerouteProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteMatchedResponse {
    pub(crate) inner: MatchedResponse,
}

impl TracerouteMatchedResponse {
    pub fn request_index(&self) -> usize {
        self.inner.request_index()
    }
    pub fn response(&self) -> &DecodedPacket {
        self.inner.response()
    }
    pub fn latency(&self) -> Duration {
        self.inner.latency()
    }
    pub fn record_id(&self) -> packetcraftr_network::capture::CaptureRecordId {
        self.inner.record_id()
    }
}

#[derive(Clone, Debug)]
pub struct TracerouteBatchExecution {
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<TracerouteMatchedResponse>,
    pub(crate) unsolicited: Vec<UnsolicitedResponse>,
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl TracerouteBatchExecution {
    pub fn from_exchange(
        batch: &TracerouteBatch,
        exchange: &ExchangeResult,
    ) -> Result<Self, BoundaryError> {
        let sent = exchange.sent().to_vec();
        if sent.len() != batch.probes.len()
            || sent.iter().enumerate().any(|(index, receipt)| {
                !super::super::probe::sent_traceroute_probe_matches(
                    &batch.probes[index],
                    receipt.packet(),
                )
            })
        {
            return Err(BoundaryError::internal_execution(
                "exchange sent receipts do not match the authorized traceroute probes",
                "internal.traceroute_execution",
                "discard mismatched trusted exchange evidence",
            ));
        }
        Ok(Self {
            sent,
            responses: exchange
                .responses()
                .iter()
                .cloned()
                .map(|inner| TracerouteMatchedResponse { inner })
                .collect(),
            unsolicited: exchange.unsolicited().to_vec(),
            undecoded: exchange.undecoded().to_vec(),
            diagnostics: exchange.diagnostics().to_vec(),
            stats: exchange.stats().clone(),
        })
    }

    pub fn sent(&self) -> &[SentPacket] {
        &self.sent
    }
    pub fn responses(&self) -> &[TracerouteMatchedResponse] {
        &self.responses
    }
    pub fn unsolicited(&self) -> &[UnsolicitedResponse] {
        &self.unsolicited
    }
    pub fn undecoded(&self) -> &[UndecodedCapture] {
        &self.undecoded
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

pub trait TracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> std::result::Result<TracerouteBatchExecution, crate::BoundaryError>;
}
