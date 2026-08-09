// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_packet::protocol::{
    application::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_packet::{
    Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic, layer::Raw,
};

use crate::exchange::{ExchangeResult, MatchedResponse, UndecodedCapture, UnsolicitedResponse};
use crate::probe::nonzero_ipv4_identification;
use crate::send::SentPacket;
use crate::{BoundaryError, Stats};

use super::super::DEFAULT_DNS_SERVER_PORT;
use super::request::DnsQueryType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsProbe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub query: Bytes,
}

impl DnsProbe {
    pub fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.server_address {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    destination,
                    identification: nonzero_ipv4_identification(u64::from(self.attempt)),
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    destination,
                    flow_label: u32::from(self.transaction_id),
                    ..Ipv6::default()
                });
            }
        }
        packet.push(Udp {
            source_port: self.source_port,
            destination_port: self.server_port,
            ..Udp::default()
        });
        if self.server_port == DEFAULT_DNS_SERVER_PORT
            || self.source_port == DEFAULT_DNS_SERVER_PORT
        {
            if let Ok(dns) = Dns::from_wire(self.query.clone()) {
                packet.push(dns);
            } else {
                packet.push(Raw::new(self.query.clone()));
            }
        } else {
            packet.push(Raw::new(self.query.clone()));
        }
        packet
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsExchange {
    pub probe: DnsProbe,
    pub timeout: Duration,
    pub max_responses: usize,
}

#[derive(Clone, Debug)]
pub struct DnsMatchedResponse {
    pub(crate) inner: MatchedResponse,
}

impl DnsMatchedResponse {
    pub fn response(&self) -> &DecodedPacket {
        self.inner.response()
    }
    pub fn latency(&self) -> Duration {
        self.inner.latency()
    }

    pub(crate) fn received_at(&self) -> std::time::Instant {
        self.inner.received_at()
    }
}

#[derive(Clone, Debug)]
pub struct DnsExchangeExecution {
    pub(crate) sent: SentPacket,
    pub(crate) responses: Vec<DnsMatchedResponse>,
    pub(crate) unsolicited: Vec<UnsolicitedResponse>,
    pub(crate) undecoded: Vec<UndecodedCapture>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

impl DnsExchangeExecution {
    pub fn from_exchange(exchange: &ExchangeResult) -> Result<Self, BoundaryError> {
        let Some(sent) = exchange.sent().first().cloned() else {
            return Err(BoundaryError::internal_execution(
                "DNS exchange did not produce a sent receipt",
                "internal.dns_execution",
                "discard incomplete trusted exchange evidence",
            ));
        };
        if exchange.sent().len() != 1
            || exchange
                .responses()
                .iter()
                .any(|response| response.request_index() != 0)
        {
            return Err(BoundaryError::internal_execution(
                "single-query DNS exchange returned an invalid request identity",
                "internal.dns_execution",
                "discard mismatched trusted exchange evidence",
            ));
        }
        Ok(Self {
            sent,
            responses: exchange
                .responses()
                .iter()
                .cloned()
                .map(|inner| DnsMatchedResponse { inner })
                .collect(),
            unsolicited: exchange.unsolicited().to_vec(),
            undecoded: exchange.undecoded().to_vec(),
            diagnostics: exchange.diagnostics().to_vec(),
            stats: exchange.stats().clone(),
        })
    }

    pub fn sent(&self) -> &SentPacket {
        &self.sent
    }
    pub fn responses(&self) -> &[DnsMatchedResponse] {
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

pub trait DnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> std::result::Result<DnsExchangeExecution, crate::BoundaryError>;
}
