// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::document::{service_exclusions, service_probes};
use serde::Serialize;

use super::{
    Error, MAX_ATTEMPTS, MAX_ENDPOINTS, MAX_OPERATION_BYTES, MAX_RESPONSE_BYTES, Transport,
};
use crate::policy::{Operation, Policy, SocketLimits, SocketOperation};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub transport: Transport,
}

impl Endpoint {
    /// Select only scan endpoints inferred open, plus UDP's open-or-filtered
    /// endpoints. Selection itself sends nothing; the caller must invoke identify.
    pub fn from_scan(endpoint: &crate::scan::Endpoint) -> Option<Self> {
        use crate::scan::State;
        let state = endpoint.inference.as_ref()?.state?;
        let transport = match endpoint.transport {
            crate::probe::Transport::Tcp if state == State::Open => Transport::Tcp,
            crate::probe::Transport::Udp
                if matches!(state, State::Open | State::OpenOrFiltered) =>
            {
                Transport::Udp
            }
            _ => return None,
        };
        let port = endpoint.port?;
        let address = match endpoint.address {
            std::net::IpAddr::V4(address) => SocketAddr::new(address.into(), port),
            std::net::IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                address,
                port,
                0,
                endpoint
                    .scope
                    .as_ref()
                    .map_or(0, |scope| scope.interface.index),
            )),
        };
        Some(Self { address, transport })
    }
}

/// Attempts and application bytes available within one budget scope.
/// A TCP connection is used for exactly one probe attempt; retransmissions
/// are fresh connections and consume the enclosing host and probe budgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub attempts: u64,
    pub write_bytes: u64,
    pub read_bytes: u64,
    pub timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub operation: Limit,
    pub host: Limit,
    pub connection: Limit,
    pub probe: Limit,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            operation: Limit {
                attempts: 128,
                write_bytes: 128 * 1024,
                read_bytes: 1024 * 1024,
                timeout: Duration::from_secs(30),
            },
            host: Limit {
                attempts: 16,
                write_bytes: 16 * 1024,
                read_bytes: 128 * 1024,
                timeout: Duration::from_secs(10),
            },
            connection: Limit {
                attempts: 1,
                write_bytes: 1024,
                read_bytes: 16 * 1024,
                timeout: Duration::from_secs(2),
            },
            probe: Limit {
                attempts: 1,
                write_bytes: 1024,
                read_bytes: 16 * 1024,
                timeout: Duration::from_secs(2),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub endpoints: Vec<Endpoint>,
    pub corpus: Arc<service_probes::Corpus>,
    pub exclusions: Arc<service_exclusions::Exclusions>,
    /// Probe intensity threshold, independent of conventional port numbers.
    pub intensity: u8,
    pub limits: Limits,
    pub parent_deadline: Option<Arc<Deadline>>,
}

impl Request {
    pub fn new(
        endpoints: Vec<Endpoint>,
        corpus: Arc<service_probes::Corpus>,
        exclusions: Arc<service_exclusions::Exclusions>,
    ) -> Self {
        Self {
            endpoints,
            corpus,
            exclusions,
            intensity: 2,
            limits: Limits::default(),
            parent_deadline: None,
        }
    }

    /// Validate the documents, hard bounds, and declared socket traffic before
    /// any provider is called. Exclusions are applied before probe planning.
    pub fn validate(&self, policy: &Policy) -> Result<(), Error> {
        self.corpus.validate()?;
        self.exclusions.validate()?;
        if self.endpoints.is_empty() || self.endpoints.len() > MAX_ENDPOINTS {
            return Err(Error::request(format!(
                "endpoint count must be 1..={MAX_ENDPOINTS}"
            )));
        }
        if !(1..=9).contains(&self.intensity) {
            return Err(Error::request("intensity must be 1..=9"));
        }
        let mut unique = BTreeSet::new();
        for endpoint in &self.endpoints {
            let address = endpoint.address.ip().to_canonical();
            if endpoint.address.port() == 0
                || address.is_unspecified()
                || address.is_multicast()
                || address == std::net::IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
                || !unique.insert(*endpoint)
            {
                return Err(Error::request(
                    "endpoints must be distinct, unicast, nonzero numeric socket addresses",
                ));
            }
            if let SocketAddr::V6(address) = endpoint.address
                && address.ip().is_unicast_link_local()
                && address.scope_id() == 0
            {
                return Err(Error::request(
                    "link-local IPv6 endpoints require a numeric scope ID",
                ));
            }
        }
        for (name, limit) in [
            ("operation", self.limits.operation),
            ("host", self.limits.host),
            ("connection", self.limits.connection),
            ("probe", self.limits.probe),
        ] {
            if limit.attempts == 0
                || limit.attempts > MAX_ATTEMPTS
                || limit.timeout.is_zero()
                || limit.timeout > Duration::from_secs(3600)
                || limit.write_bytes > MAX_OPERATION_BYTES
                || limit.read_bytes == 0
                || limit.read_bytes > MAX_OPERATION_BYTES
            {
                return Err(Error::request(format!(
                    "{name} limits exceed finite identification bounds"
                )));
            }
        }
        if self.limits.connection.read_bytes > MAX_RESPONSE_BYTES
            || self.limits.probe.read_bytes > MAX_RESPONSE_BYTES
        {
            return Err(Error::request(format!(
                "connection and probe response limits must not exceed {MAX_RESPONSE_BYTES}"
            )));
        }
        let endpoints = self
            .endpoints
            .iter()
            .filter(|endpoint| {
                !self
                    .exclusions
                    .excludes(endpoint.transport, endpoint.address.port())
            })
            .map(|endpoint| endpoint.address)
            .collect::<Vec<_>>();
        let attempts = if endpoints.is_empty() {
            0
        } else {
            self.limits.operation.attempts
        };
        let declaration = SocketOperation::new(
            &endpoints,
            SocketLimits::new(
                attempts,
                attempts,
                if attempts == 0 {
                    0
                } else {
                    self.limits.operation.write_bytes
                },
            ),
        )
        .map_err(|source| Error::request(source.to_string()))?;
        policy.authorize(Operation::Socket(declaration))?;
        Ok(())
    }
}

pub fn builtin_corpus() -> Result<Arc<service_probes::Corpus>, Error> {
    Ok(Arc::new(service_probes::parse(include_bytes!(
        "../../data/service-probes.json"
    ))?))
}

pub fn builtin_exclusions() -> Result<Arc<service_exclusions::Exclusions>, Error> {
    Ok(Arc::new(service_exclusions::parse(include_bytes!(
        "../../data/service-exclusions.json"
    ))?))
}
