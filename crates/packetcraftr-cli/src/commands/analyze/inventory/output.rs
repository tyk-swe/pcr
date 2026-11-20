// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_core::analysis::inventory as library;

use crate::commands::offline_analysis::output::StreamTransport as Transport;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ObservedPort {
    pub transport: Transport,
    pub port: u16,
}

impl From<library::ObservedPort> for ObservedPort {
    fn from(value: library::ObservedPort) -> Self {
        Self {
            transport: value.transport.into(),
            port: value.port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Host {
    pub address: IpAddr,
    pub mac_addresses: Vec<String>,
    pub protocols: Vec<String>,
    pub observed_ports: Vec<ObservedPort>,
    pub frames_sent: u64,
    pub frames_received: u64,
}

impl From<library::Host> for Host {
    fn from(value: library::Host) -> Self {
        Self {
            address: value.address,
            mac_addresses: value
                .mac_addresses
                .into_iter()
                .map(|mac| mac.to_string())
                .collect(),
            protocols: value.protocols,
            observed_ports: value
                .observed_ports
                .into_iter()
                .map(ObservedPort::from)
                .collect(),
            frames_sent: value.frames_sent,
            frames_received: value.frames_received,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Protocol {
    pub protocol: String,
    pub frames: u64,
}

impl From<library::ProtocolCount> for Protocol {
    fn from(value: library::ProtocolCount) -> Self {
        Self {
            protocol: value.protocol,
            frames: value.frames,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Report {
    pub frames_read: u64,
    pub hosts: Vec<Host>,
    pub protocols: Vec<Protocol>,
}

impl From<library::Report> for Report {
    fn from(value: library::Report) -> Self {
        Self {
            frames_read: value.frames_read,
            hosts: value.hosts.into_iter().map(Host::from).collect(),
            protocols: value.protocols.into_iter().map(Protocol::from).collect(),
        }
    }
}
