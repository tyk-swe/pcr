// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use crate::Stats;

/// Maximum cumulative pacing delay accepted by one set send, matching the
/// capture/replay ceiling for intentional operation time.
pub const MAX_SEND_DURATION: Duration = packetcraftr_netio::capture::MAX_TIMEOUT;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub destination: Option<IpAddr>,
    pub plan: packetcraftr_netio::route::Options,
    pub build: packetcraftr_core::build::Options,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub sent: crate::SentPacket,
    pub stats: Stats,
}

/// Options for a set send: a template expansion repeated a finite number of
/// times under one operation budget, optionally paced by a rate ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetOptions {
    /// Per-packet options shared by every expanded frame.
    pub send: Options,
    /// Complete passes over the expansion, in expansion order. Must be at
    /// least one — repetition can never mean unbounded sending.
    pub repeat: u32,
    /// Transmission-start ceiling in packets per second; `None` is unpaced.
    pub rate: Option<u32>,
    /// Template-expansion ceiling checked before packets materialize.
    pub max_template_packets: usize,
}

impl Default for SetOptions {
    fn default() -> Self {
        Self {
            send: Options::default(),
            repeat: 1,
            rate: None,
            max_template_packets: packetcraftr_core::template::DEFAULT_MAX_TEMPLATE_PACKETS,
        }
    }
}

impl SetOptions {
    /// Validates finite repetition, pacing, and expansion bounds before any
    /// packet is expanded or a provider is invoked.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.repeat == 0 {
            return Err(crate::Error::InvalidSendOption {
                field: "repeat",
                message: "must be at least one".to_owned(),
            });
        }
        if self.rate == Some(0) {
            return Err(crate::Error::InvalidSendOption {
                field: "rate",
                message: "must be a positive packets-per-second ceiling".to_owned(),
            });
        }
        if self.max_template_packets == 0 {
            return Err(crate::Error::InvalidSendOption {
                field: "max_template_packets",
                message: "must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }

    /// Checks the complete packet count and pacing schedule without expanding
    /// packets or consulting providers. CLI callers use this before resolving
    /// hostnames or interfaces; execution repeats the same validation.
    pub fn validate_for(
        &self,
        template: &packetcraftr_core::template::Template,
    ) -> Result<u64, crate::Error> {
        self.validate()?;
        let count = template
            .expansion_len()
            .map_err(|source| crate::Error::Template {
                message: source.to_string(),
                source: Some(source),
            })?;
        if count == 0 || count > self.max_template_packets {
            return Err(crate::Error::InvalidSendOption {
                field: "max_template_packets",
                message: "expansion must be non-empty and within the packet ceiling".to_owned(),
            });
        }
        let total = u64::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(u64::from(self.repeat)))
            .ok_or_else(|| crate::Error::InvalidSendOption {
                field: "repeat",
                message: "expansion times repetition overflows u64".to_owned(),
            })?;
        let delay = crate::clock::rate_delay(1, self.rate).ok_or_else(|| {
            crate::Error::InvalidSendOption {
                field: "rate",
                message: "rate-delay arithmetic overflowed".to_owned(),
            }
        })?;
        let scheduled_nanos = u128::from(total - 1) * delay.as_nanos();
        if scheduled_nanos > MAX_SEND_DURATION.as_nanos() {
            return Err(crate::Error::InvalidSendOption {
                field: "rate",
                message: format!(
                    "scheduled pacing {scheduled_nanos} ns exceeds the {MAX_SEND_DURATION:?} ceiling"
                ),
            });
        }
        Ok(total)
    }
}

/// One confirmed transmission inside a set send.
#[derive(Clone, Debug)]
pub struct SentFrame {
    /// One-based pass over the packet set.
    pub pass: u32,
    /// Zero-based index of the packet within one expansion pass.
    pub index: u64,
    /// The provider-confirmed transmission.
    pub packet: crate::SentPacket,
}

/// Aggregate result of a set send.
#[derive(Clone, Debug)]
pub struct SetReport {
    /// Every confirmed transmission, in send order.
    pub sent: Vec<SentFrame>,
    /// Passes over the set completed in full.
    pub passes_completed: u32,
    pub stats: Stats,
}
