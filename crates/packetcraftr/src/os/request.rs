// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::document::os_fingerprints::Corpus;

use super::{
    Error, MAX_ATTEMPTS, MAX_DURATION, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_FRAMES, MAX_FRAME_BYTES,
    MAX_PROBES,
};

#[derive(Clone, Debug)]
pub struct Limits {
    /// All workflow transmissions, including cleanup and neighbor preparation.
    pub max_probes: usize,
    pub max_duration: Duration,
    pub evidence: crate::evidence::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_probes: MAX_PROBES,
            max_duration: MAX_DURATION,
            evidence: crate::evidence::Limits {
                max_frames: MAX_EVIDENCE_FRAMES,
                max_bytes: MAX_EVIDENCE_BYTES,
                max_undecoded: MAX_EVIDENCE_FRAMES,
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub target: crate::target::Target,
    pub open_port: u16,
    pub closed_port: u16,
    pub attempts: u32,
    pub timeout: Duration,
    pub probes_per_second: u32,
    pub limits: Limits,
    pub corpus: Arc<Corpus>,
    pub route: crate::route::Options,
    pub collection: crate::exchange::Collection,
}

impl Request {
    pub fn new(
        target: crate::target::Target,
        open_port: u16,
        closed_port: u16,
        corpus: Arc<Corpus>,
    ) -> Self {
        let mut collection = crate::exchange::Collection::default();
        collection.capture.max_frames = MAX_EVIDENCE_FRAMES;
        collection.capture.max_bytes = MAX_EVIDENCE_BYTES;
        collection.capture.snap_length = MAX_FRAME_BYTES;
        collection.max_responses = MAX_EVIDENCE_FRAMES;
        collection.max_unmatched_frames = MAX_EVIDENCE_FRAMES;
        Self {
            target,
            open_port,
            closed_port,
            corpus,
            attempts: 2,
            timeout: Duration::from_secs(1),
            probes_per_second: 10,
            limits: Limits::default(),
            route: crate::route::Options::default(),
            collection,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let address = match &self.target {
            crate::target::Target::Address(address) => *address,
            crate::target::Target::ScopedAddress(address) => address.address().into(),
            crate::target::Target::Hostname(_) => {
                return Err(Error::Invalid("a numeric target is required".into()));
            }
        };
        if address.is_unspecified()
            || address.is_multicast()
            || address == std::net::Ipv4Addr::BROADCAST
        {
            return Err(Error::Invalid("a unicast target is required".into()));
        }
        if self.open_port == 0 || self.closed_port == 0 || self.open_port == self.closed_port {
            return Err(Error::Invalid(
                "distinct nonzero open and closed TCP ports are required".into(),
            ));
        }
        if !(1..=MAX_ATTEMPTS).contains(&self.attempts)
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(1)
            || self.probes_per_second == 0
            || self.probes_per_second > 10
            || self.limits.max_duration.is_zero()
            || self.limits.max_duration > MAX_DURATION
            || self.limits.max_probes > MAX_PROBES
            || self.limits.max_probes < 6 * self.attempts as usize + 1
        {
            return Err(Error::Invalid(
                "invalid finite attempts, timeout, rate, duration, or transmission limit".into(),
            ));
        }
        self.limits.evidence.validate(|field, value, reason| {
            Error::Invalid(format!("{field}={value}: {reason}"))
        })?;
        if self.limits.evidence.max_frames > MAX_EVIDENCE_FRAMES
            || self.limits.evidence.max_bytes > MAX_EVIDENCE_BYTES
            || self.collection.capture.snap_length > MAX_FRAME_BYTES
            || self.collection.capture.max_frames > self.limits.evidence.max_frames
            || self.collection.capture.max_bytes > self.limits.evidence.max_bytes
            || self.collection.max_responses == 0
            || self.collection.capture.overflow_policy
                != packetcraftr_netio::capture::OverflowPolicy::Fail
        {
            return Err(Error::Invalid(
                "capture must fit the OS evidence ceilings and fail on loss".into(),
            ));
        }
        self.collection
            .validate()
            .map_err(|source| Error::Invalid(source.to_string()))?;
        self.corpus.validate()?;
        Ok(())
    }
}
