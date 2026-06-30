// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use super::error::{SpecError, SpecResult};

use crate::domain::request::TransmissionRequest;

use super::layer2::Layer2Spec;

#[derive(Debug, Clone, Default)]
pub(crate) struct TransmissionSpec {
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
    pub(crate) fn is_layer3(&self) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(request: TransmissionRequest) -> Result<TransmissionSpec, SpecError> {
        TransmissionSpec::from_request(&request)
    }

    #[test]
    fn rejects_conflicting_transmission_options() {
        assert!(matches!(
            spec_from(TransmissionRequest {
                flood: Some(true),
                interval: Some("10ms".to_string()),
                ..Default::default()
            }),
            Err(SpecError::IntervalConflictsWithFlood)
        ));

        assert!(matches!(
            spec_from(TransmissionRequest {
                loop_forever: Some(true),
                count: Some(1),
                ..Default::default()
            }),
            Err(SpecError::LoopConflictsWithCount)
        ));

        assert!(matches!(
            spec_from(TransmissionRequest {
                count: Some(0),
                ..Default::default()
            }),
            Err(SpecError::CountMustBePositive)
        ));
    }

    #[test]
    fn parses_numeric_and_human_intervals() {
        assert_eq!(parse_interval("250").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_interval("1.5s").unwrap(), Duration::from_millis(1500));
        assert!(matches!(
            parse_interval(""),
            Err(SpecError::EmptyIntervalValue)
        ));
        assert!(matches!(
            parse_interval("soon"),
            Err(SpecError::IntervalParse { .. })
        ));
    }
}
