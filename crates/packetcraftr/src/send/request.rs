// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::packet::Packet;
use packetcraftr_core::template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template};
use packetcraftr_netio::capture::MAX_TIMEOUT;

use super::Error;

/// How each packet of a send or an exchange is prepared.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<IpAddr>,
    pub plan: crate::route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

/// One send: every packet `template` expands to, `repeat` passes in
/// expansion order, under one packet and byte budget, optionally paced by a
/// rate ceiling.
#[derive(Clone, Debug)]
pub struct Request {
    pub template: Template,
    /// Per-packet options shared by every expanded frame.
    pub send: Options,
    /// Complete passes over the expansion, in expansion order. Must be at
    /// least one: repetition can never mean unbounded sending.
    pub repeat: u32,
    /// Transmission-start ceiling in packets per second; `None` is unpaced.
    pub rate: Option<u32>,
    /// Template-expansion ceiling checked before packets materialize.
    pub max_template_packets: usize,
}

impl Request {
    /// Sends every packet `template` expands to once, unpaced.
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

    /// Sends one packet once.
    #[must_use]
    pub fn packet(packet: Packet, send: Options) -> Self {
        Self::new(Template::new(packet), send)
    }

    /// Validates the finite repetition, pacing, and expansion bounds without
    /// expanding the template or consulting providers.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound.
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

    /// Validates the request and returns the complete packet count, checking
    /// the pacing schedule against the workflow ceiling. Nothing is expanded
    /// and no provider is consulted, so callers may run this before resolving
    /// hostnames or interfaces; the send repeats it.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound, or the template's refusal to count
    /// its expansion.
    pub fn packet_count(&self) -> Result<u64, Error> {
        self.validate()?;
        let count = self
            .template
            .expansion_len()
            .map_err(|source| crate::Error::Template {
                message: source.to_string(),
                source: Some(source),
            })?;
        if count == 0 || count > self.max_template_packets {
            return Err(invalid(
                "max_template_packets",
                "expansion must be non-empty and within the packet ceiling",
            ));
        }
        let total = u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(u64::from(self.repeat)))
            .ok_or_else(|| invalid("repeat", "expansion times repetition overflows u64"))?;
        let delay = self.delay()?;
        let scheduled_nanos = u128::from(total - 1) * delay.as_nanos();
        if scheduled_nanos > MAX_TIMEOUT.as_nanos() {
            return Err(Error::InvalidRequest {
                field: "rate",
                message: format!(
                    "scheduled pacing {scheduled_nanos} ns exceeds the {MAX_TIMEOUT:?} ceiling"
                ),
            });
        }
        Ok(total)
    }

    /// The pause between transmission starts.
    pub(super) fn delay(&self) -> Result<std::time::Duration, Error> {
        crate::clock::rate_delay(1, self.rate)
            .ok_or_else(|| invalid("rate", "rate-delay arithmetic overflowed"))
    }
}

fn invalid(field: &'static str, message: &str) -> Error {
    Error::InvalidRequest {
        field,
        message: message.to_owned(),
    }
}
