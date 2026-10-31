// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use packetcraftr_netio::deadline::MAX_WAIT;

use super::canary::{MIN_PAYLOAD_LEN, TOKEN_LEN};
use super::catalog::catalog;
use super::error::Error;
use crate::engine::execution::limits::duration_violation;
use crate::{exchange, route, send};

pub const DEFAULT_SOURCE_PORT: u16 = 53210;
pub const DEFAULT_PAYLOAD_LEN: usize = 1024;
pub const MAX_PAYLOAD_LEN: usize = 1472;
pub const DEFAULT_REPEATS: u32 = 3;
pub const MAX_REPEATS: u32 = 10;

#[derive(Clone, Debug)]
pub struct Request {
    pub target: Ipv4Addr,
    pub responder_port: u16,
    pub source_port: u16,
    pub spoof_source: Option<Ipv4Addr>,
    pub token: [u8; TOKEN_LEN],
    pub repeats: u32,
    pub payload_len: usize,
    pub timeout: Duration,
    pub max_duration: Duration,
    pub route: route::Options,
    pub collection: exchange::Collection,
    pub plan_digest: Option<String>,
}

impl Request {
    #[must_use]
    pub fn new(target: Ipv4Addr, responder_port: u16, token: [u8; TOKEN_LEN]) -> Self {
        Self {
            target,
            responder_port,
            source_port: DEFAULT_SOURCE_PORT,
            spoof_source: None,
            token,
            repeats: DEFAULT_REPEATS,
            payload_len: DEFAULT_PAYLOAD_LEN,
            timeout: Duration::from_secs(2),
            max_duration: Duration::from_secs(600),
            route: route::Options::default(),
            collection: exchange::Collection::default(),
            plan_digest: None,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.responder_port == 0 || self.source_port == 0 {
            return Err(Error::InvalidRequest {
                field: "port",
                message: "source and responder ports must be non-zero".to_owned(),
            });
        }
        if self.repeats == 0 || self.repeats > MAX_REPEATS {
            return Err(Error::InvalidRequest {
                field: "repeats",
                message: format!("must be within 1..={MAX_REPEATS}"),
            });
        }
        if self.payload_len < MIN_PAYLOAD_LEN || self.payload_len > MAX_PAYLOAD_LEN {
            return Err(Error::InvalidRequest {
                field: "payload_len",
                message: format!("must be within {MIN_PAYLOAD_LEN}..={MAX_PAYLOAD_LEN}"),
            });
        }
        if duration_violation(self.timeout, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_WAIT,
            });
        }
        if duration_violation(self.max_duration, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.max_duration,
                maximum: MAX_WAIT,
            });
        }
        let attempts = catalog().len() as u32 * self.repeats;
        let worst = self
            .timeout
            .checked_mul(attempts)
            .ok_or(Error::DurationLimit {
                actual: Duration::MAX,
                limit: self.max_duration,
            })?;
        if worst > self.max_duration {
            return Err(Error::DurationLimit {
                actual: worst,
                limit: self.max_duration,
            });
        }
        self.collection
            .validate()
            .map_err(|source| Error::Execution {
                attempt: 0,
                source: packetcraftr_core::error::BoundaryError::from_error(source),
            })?;
        Ok(())
    }

    pub(super) fn send(&self) -> send::Options {
        send::Options {
            destination: Some(std::net::IpAddr::V4(self.target)),
            plan: self.route.clone(),
            build: Default::default(),
            allow_permissive_live: false,
        }
    }

    #[must_use]
    pub fn responder_endpoint(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.target, self.responder_port)
    }
}

pub fn generate_token() -> Result<[u8; TOKEN_LEN], Error> {
    let mut token = [0_u8; TOKEN_LEN];
    getrandom::fill(&mut token).map_err(|source| Error::TokenGeneration {
        message: source.to_string(),
    })?;
    Ok(token)
}

#[derive(Clone, Debug)]
pub struct ResponderRequest {
    pub bind: Ipv4Addr,
    pub port: u16,
    pub token: [u8; TOKEN_LEN],
    pub max_duration: Duration,
    pub idle_after_first: Option<Duration>,
    pub max_datagrams: usize,
    pub cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl ResponderRequest {
    #[must_use]
    pub fn new(bind: Ipv4Addr, port: u16, token: [u8; TOKEN_LEN]) -> Self {
        Self {
            bind,
            port,
            token,
            max_duration: Duration::from_secs(300),
            idle_after_first: Some(Duration::from_secs(30)),
            max_datagrams: 4096,
            cancellation: None,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.port == 0 {
            return Err(Error::InvalidRequest {
                field: "port",
                message: "responder port must be non-zero".to_owned(),
            });
        }
        if self.max_datagrams == 0 {
            return Err(Error::InvalidRequest {
                field: "max_datagrams",
                message: "must be non-zero".to_owned(),
            });
        }
        if duration_violation(self.max_duration, MAX_WAIT) {
            return Err(Error::InvalidTimeout {
                value: self.max_duration,
                maximum: MAX_WAIT,
            });
        }
        if self
            .idle_after_first
            .is_some_and(|idle| duration_violation(idle, MAX_WAIT))
        {
            return Err(Error::InvalidTimeout {
                value: self.idle_after_first.unwrap_or_default(),
                maximum: MAX_WAIT,
            });
        }
        Ok(())
    }
}
