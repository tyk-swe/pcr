// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::error::{SpecError, SpecResult};

use crate::domain::request::TransmissionRequest;

use super::layer2::Layer2Spec;

#[derive(Debug, Clone, Default)]
pub struct TransmissionSpec {
    pub count: Option<u64>,
    pub interval: Option<Duration>,
    pub flood: bool,
    pub loop_send: bool,
    pub force_layer3: bool,
    pub ipv6_nd: bool,
    pub auto_layer3: bool,
}

impl TransmissionSpec {
    pub(crate) fn from_request(request: &TransmissionRequest) -> SpecResult<Self> {
        if request.flood.unwrap_or(false) && request.interval.is_some() {
            return Err(SpecError::IntervalConflictsWithFlood);
        }
        if request.loop_forever.unwrap_or(false) && request.count.is_some() {
            return Err(SpecError::LoopConflictsWithCount);
        }
        if matches!(request.count, Some(0)) {
            return Err(SpecError::CountMustBePositive);
        }

        Ok(Self {
            count: request.count,
            interval: parse_interval_option(request.interval.as_deref())?,
            flood: request.flood.unwrap_or(false),
            loop_send: request.loop_forever.unwrap_or(false),
            force_layer3: request.force_layer3.unwrap_or(false),
            ipv6_nd: request.ipv6_nd.unwrap_or(false),
            auto_layer3: false,
        })
    }

    /// Returns true if either forced or auto-selected layer-3 is active.
    pub fn is_layer3(&self) -> bool {
        self.force_layer3 || self.auto_layer3
    }

    pub(crate) fn apply_ipv6_defaults(&mut self, layer2: &Layer2Spec, ipv6_target: bool) {
        if !ipv6_target {
            return;
        }

        if self.is_layer3() || self.ipv6_nd {
            return;
        }

        if layer2.destination.is_some()
            || layer2.source.is_some()
            || layer2.ethertype.is_some()
            || layer2.vlan.is_some()
        {
            return;
        }

        self.auto_layer3 = true;
    }
}

pub(crate) fn parse_interval_option(value: Option<&str>) -> SpecResult<Option<Duration>> {
    match value {
        Some(raw) => Ok(Some(parse_interval(raw)?)),
        None => Ok(None),
    }
}

pub(crate) fn parse_interval(raw: &str) -> SpecResult<Duration> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SpecError::EmptyIntervalValue);
    }

    if let Ok(value) = trimmed.parse::<u64>() {
        return Ok(Duration::from_millis(value));
    }

    if let Ok(duration) = humantime::parse_duration(trimmed) {
        return Ok(duration);
    }

    let lowered = trimmed.to_ascii_lowercase();
    if let Ok(duration) = humantime::parse_duration(&lowered) {
        return Ok(duration);
    }

    Err(SpecError::IntervalParse {
        value: raw.to_string(),
    })
}
