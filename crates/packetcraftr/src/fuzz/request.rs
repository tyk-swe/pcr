// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::capture::{MAX_CAPTURE_QUEUE_BYTES, MAX_CAPTURE_QUEUE_FRAMES, MAX_TIMEOUT};

use crate::execution::limits::EvidenceLimits;
use crate::{exchange, route, send};

use super::MAX_RATE;
use super::error::Error;

/// One live fuzz campaign: the offline campaign core prepares, and how each
/// of its built cases is sent, paced, and collected.
#[derive(Clone, Debug)]
pub struct Request {
    /// The deterministic campaign every case comes from. Its limits bound the
    /// whole live run, including its duration.
    pub campaign: packet_fuzz::Request,
    /// The template packet every case mutates.
    pub packet: Packet,
    /// How long each case's exchange collects responses.
    pub timeout: Duration,
    /// Case-start ceiling; `None` is unpaced.
    pub cases_per_second: Option<u32>,
    /// The destination every case is authorized for and routed to; `None`
    /// uses each case's own.
    pub destination: Option<IpAddr>,
    pub route: route::Options,
    /// How each case's capture is armed and what it retains.
    pub collection: exchange::Collection,
    /// Second explicit opt-in, required in addition to policy approval when
    /// a case is a permissive packet.
    pub allow_permissive_live: bool,
    /// Exact frames the whole campaign retains as case evidence.
    pub max_evidence_frames: usize,
    /// Bytes the whole campaign retains as case evidence.
    pub max_evidence_bytes: usize,
}

impl Request {
    /// A live run of `campaign` over `packet`, unpaced, with a one-second
    /// collection window and the largest evidence retention.
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

    /// Rejects every bound this workflow cannot run under: an out-of-range
    /// evidence retention, timeout, or rate, then an invalid campaign.
    ///
    /// # Errors
    ///
    /// Returns the first invalid bound.
    pub fn validate(&self) -> Result<(), Error> {
        self.evidence()
            .validate(|field, value, reason| Error::InvalidLimit {
                field,
                value,
                reason,
            })?;
        if self.timeout.is_zero() || self.timeout > MAX_TIMEOUT {
            return Err(Error::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_TIMEOUT,
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

    /// How every case is prepared: built as the campaign builds it, towards
    /// the requested destination and route.
    pub(super) fn send(&self) -> send::Options {
        send::Options {
            destination: self.destination,
            plan: self.route.clone(),
            build: self.campaign.build.clone(),
            allow_permissive_live: self.allow_permissive_live,
        }
    }

    /// Fuzz bounds undecodable frames by the frame budget alone.
    pub(super) const fn evidence(&self) -> EvidenceLimits {
        EvidenceLimits {
            max_frames: self.max_evidence_frames,
            max_bytes: self.max_evidence_bytes,
            max_undecoded: self.max_evidence_frames,
        }
    }
}
