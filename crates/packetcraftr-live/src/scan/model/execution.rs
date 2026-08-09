// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic};

use crate::exchange::{ExchangeResult, MatchedResponse, UndecodedCapture, UnsolicitedResponse};
use crate::send::SentPacket;
use crate::{BoundaryError, Stats};

use super::request::ScanTransport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub attempt: u32,
}

impl ScanProbe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        super::super::probe::probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanBatch {
    pub probes: Vec<ScanProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanMatchedResponse {
    pub(crate) inner: MatchedResponse,
}

impl ScanMatchedResponse {
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
pub struct ScanBatchExecution {
    pub(crate) sent: Vec<SentPacket>,
    pub(crate) responses: Vec<ScanMatchedResponse>,
    pub(crate) unsolicited: Vec<UnsolicitedResponse>,
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl ScanBatchExecution {
    /// Converts only an opaque, client-produced exchange result into scan
    /// evidence. Callers cannot provide semantic packets, sent frames, or
    /// latencies independently.
    pub fn from_exchange(
        batch: &ScanBatch,
        exchange: &ExchangeResult,
    ) -> Result<Self, BoundaryError> {
        let sent = exchange.sent().to_vec();
        if sent.len() != batch.probes.len()
            || sent.iter().enumerate().any(|(index, receipt)| {
                !super::super::probe::sent_scan_probe_matches(
                    &batch.probes[index],
                    receipt.packet(),
                )
            })
        {
            return Err(BoundaryError::internal_execution(
                "exchange sent receipts do not match the authorized scan probes",
                "internal.scan_execution",
                "discard mismatched trusted exchange evidence",
            ));
        }
        Ok(Self {
            sent,
            responses: exchange
                .responses()
                .iter()
                .cloned()
                .map(|inner| ScanMatchedResponse { inner })
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
    pub fn responses(&self) -> &[ScanMatchedResponse] {
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

pub trait ScanExecutor {
    fn execute(
        &mut self,
        batch: &ScanBatch,
    ) -> std::result::Result<ScanBatchExecution, crate::BoundaryError>;
}
