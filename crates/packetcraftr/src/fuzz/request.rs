// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES};
use packetcraftr_netio::deadline::MAX_WAIT;

use crate::execution::limits::EvidenceLimits;
use crate::{exchange, route, send};

use super::MAX_RATE;
use super::error::Error;

#[derive(Clone, Debug)]
pub struct Request {
    pub campaign: packet_fuzz::Request,
    pub packet: Packet,
    pub timeout: Duration,
    /// Case-start ceiling; `None` is unpaced.
    pub cases_per_second: Option<u32>,
    /// The destination every case is authorized for and routed to; `None`
    /// uses each case's own.
    pub destination: Option<IpAddr>,
    pub route: route::Options,
    pub collection: exchange::Collection,
    pub allow_permissive_live: bool,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
}

impl Request {
    #[must_use]
    pub fn new(campaign: packet_fuzz::Request, packet: Packet) -> Self {
        Self {
            campaign,
            packet,
            timeout: Duration::from_secs(1),
            cases_per_second: None,
            destination: None,
            route: route::Options::default(),
            collection: exchange::Collection::default(),
            allow_permissive_live: false,
            max_evidence_frames: MAX_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: MAX_CAPTURE_QUEUE_BYTES,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.evidence()
            .validate(|field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            })?;
        if self.timeout.is_zero() || self.timeout > MAX_WAIT {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_WAIT,
            });
        }
        if let Some(rate) = self.cases_per_second
            && (rate == 0 || rate > MAX_RATE)
        {
            return Err(Error::InvalidLimit {
                field: "cases_per_second",
                value: u64::from(rate),
                reason: format!("must be within 1..={MAX_RATE}"),
            });
        }
        self.campaign.validate()?;
        Ok(())
    }

    pub(super) fn send(&self) -> send::Options {
        send::Options {
            destination: self.destination,
            plan: self.route.clone(),
            build: self.campaign.build.clone(),
            allow_permissive_live: self.allow_permissive_live,
        }
    }

    pub(super) const fn evidence(&self) -> EvidenceLimits {
        EvidenceLimits {
            max_frames: self.max_evidence_frames,
            max_bytes: self.max_evidence_bytes,
            max_undecoded: self.max_evidence_frames,
        }
    }
}
