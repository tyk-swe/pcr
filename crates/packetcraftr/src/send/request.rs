// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::packet::Packet;
use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};

use super::Error;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<IpAddr>,
    pub plan: crate::route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    pub send: Options,
    /// Must be at least one: repetition can never mean unbounded sending.
    pub repeat: u32,
    /// Transmission-start ceiling in packets per second; `None` is unpaced.
    pub rate: Option<u32>,
    pub max_template_packets: usize,
}

impl Request {
    #[must_use]
    pub fn new(template: Template, send: Options) -> Self {
        Self {
            template,
            send,
            repeat: 1,
            rate: None,
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
        }
    }

    #[must_use]
    pub fn packet(packet: Packet, send: Options) -> Self {
        Self::new(Template::new(packet), send)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.repeat == 0 {
            return Err(invalid("repeat", "must be at least one"));
        }
        if self.rate == Some(0) {
            return Err(invalid(
                "rate",
                "must be a positive packets-per-second ceiling",
            ));
        }
        if self.max_template_packets == 0 {
            return Err(invalid("max_template_packets", "must be greater than zero"));
        }
        Ok(())
    }

    pub fn packet_count(&self) -> Result<u64, Error> {
        super::plan::Plan::try_from(self).map(|plan| plan.packet_count)
    }
}

pub(super) fn invalid(field: &'static str, message: &str) -> Error {
    Error::InvalidRequest {
        field,
        message: message.to_owned(),
    }
}
