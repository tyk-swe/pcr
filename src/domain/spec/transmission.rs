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
    use crate::domain::net::MacAddress;

    #[test]
    fn parse_interval_treats_bare_number_as_milliseconds() {
        assert_eq!(parse_interval("250").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn parse_interval_accepts_humantime_units_case_insensitively() {
        assert_eq!(parse_interval("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_interval("2S").unwrap(), Duration::from_secs(2));
    }

    #[test]
    fn parse_interval_rejects_empty_and_invalid_values() {
        assert!(matches!(
            parse_interval(" ").unwrap_err(),
            SpecError::EmptyIntervalValue
        ));
        assert!(matches!(
            parse_interval("later").unwrap_err(),
            SpecError::IntervalParse { .. }
        ));
    }

    #[test]
    fn transmission_spec_rejects_conflicting_modes() {
        let flood_err = TransmissionSpec::from_request(&TransmissionRequest {
            flood: Some(true),
            interval: Some("1s".to_string()),
            ..Default::default()
        })
        .unwrap_err();
        let loop_err = TransmissionSpec::from_request(&TransmissionRequest {
            count: Some(2),
            loop_forever: Some(true),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(flood_err, SpecError::IntervalConflictsWithFlood));
        assert!(matches!(loop_err, SpecError::LoopConflictsWithCount));
    }

    #[test]
    fn transmission_spec_rejects_zero_count() {
        let err = TransmissionSpec::from_request(&TransmissionRequest {
            count: Some(0),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::CountMustBePositive));
    }

    #[test]
    fn transmission_spec_from_request_parses_all_fields() {
        let spec = TransmissionSpec::from_request(&TransmissionRequest {
            count: Some(3),
            interval: Some("10ms".to_string()),
            force_layer3: Some(true),
            ipv6_nd: Some(true),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(spec.count, Some(3));
        assert_eq!(spec.interval, Some(Duration::from_millis(10)));
        assert!(spec.force_layer3);
        assert!(spec.ipv6_nd);
        assert!(spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_selects_layer3_when_no_layer2_options() {
        let mut spec = TransmissionSpec::default();

        spec.apply_ipv6_defaults(&Layer2Spec::default(), true);

        assert!(spec.auto_layer3);
        assert!(spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_preserves_layer2_explicit_path() {
        let mut spec = TransmissionSpec::default();
        let layer2 = Layer2Spec {
            destination: Some(MacAddress::new([0, 1, 2, 3, 4, 5])),
            ..Default::default()
        };

        spec.apply_ipv6_defaults(&layer2, true);

        assert!(!spec.auto_layer3);
    }
}
