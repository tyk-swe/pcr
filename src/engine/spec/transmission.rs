use std::time::Duration;

use super::error::{SpecError, SpecResult};

use crate::engine::request::TransmissionRequest;

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pnet::util::MacAddr;

    use crate::engine::request::TransmissionRequest;
    use crate::engine::spec::Layer2Spec;

    use super::{parse_interval, parse_interval_option, SpecError, TransmissionSpec};

    #[test]
    fn transmission_rejects_interval_with_flood() {
        let options = TransmissionRequest {
            flood: Some(true),
            interval: Some("10ms".to_string()),
            ..Default::default()
        };

        let result = TransmissionSpec::from_request(&options);
        assert!(matches!(result, Err(SpecError::IntervalConflictsWithFlood)));
    }

    #[test]
    fn transmission_rejects_loop_with_count() {
        let options = TransmissionRequest {
            loop_forever: Some(true),
            count: Some(5),
            ..Default::default()
        };

        let result = TransmissionSpec::from_request(&options);
        assert!(matches!(result, Err(SpecError::LoopConflictsWithCount)));
    }

    #[test]
    fn transmission_rejects_zero_count() {
        let options = TransmissionRequest {
            count: Some(0),
            ..Default::default()
        };

        let result = TransmissionSpec::from_request(&options);
        assert!(matches!(result, Err(SpecError::CountMustBePositive)));
    }

    #[test]
    fn parse_interval_option_none() {
        let result = parse_interval_option(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_interval_numeric_millis() {
        let duration = parse_interval("150").unwrap();
        assert_eq!(duration, Duration::from_millis(150));
    }

    #[test]
    fn parse_interval_humantime() {
        let duration = parse_interval("250ms").unwrap();
        assert_eq!(duration, Duration::from_millis(250));
    }

    #[test]
    fn parse_interval_uppercase_units() {
        let duration = parse_interval("1S").unwrap();
        assert_eq!(duration, Duration::from_secs(1));
    }

    #[test]
    fn parse_interval_trims_whitespace() {
        let duration = parse_interval("  500ms ").unwrap();
        assert_eq!(duration, Duration::from_millis(500));
    }

    #[test]
    fn parse_interval_rejects_empty() {
        let result = parse_interval("");
        assert!(matches!(result, Err(SpecError::EmptyIntervalValue)));
    }

    #[test]
    fn parse_interval_rejects_invalid() {
        let result = parse_interval("nonsense");
        assert!(matches!(result, Err(SpecError::IntervalParse { .. })));
    }

    #[test]
    fn apply_ipv6_defaults_sets_auto_layer3() {
        let mut spec = TransmissionSpec::default();
        let layer2 = Layer2Spec::default();

        spec.apply_ipv6_defaults(&layer2, true);

        assert!(spec.auto_layer3);
        assert!(spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_skips_with_layer2_hints() {
        let mut spec = TransmissionSpec::default();
        let layer2 = Layer2Spec {
            source: Some(MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)),
            ..Default::default()
        };

        spec.apply_ipv6_defaults(&layer2, true);

        assert!(!spec.auto_layer3);
        assert!(!spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_skips_when_force_layer3() {
        let mut spec = TransmissionSpec {
            force_layer3: true,
            ..Default::default()
        };
        let layer2 = Layer2Spec::default();

        spec.apply_ipv6_defaults(&layer2, true);

        assert!(!spec.auto_layer3);
        assert!(spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_skips_when_ipv6_nd_enabled() {
        let mut spec = TransmissionSpec {
            ipv6_nd: true,
            ..Default::default()
        };
        let layer2 = Layer2Spec::default();

        spec.apply_ipv6_defaults(&layer2, true);

        assert!(!spec.auto_layer3);
        assert!(!spec.is_layer3());
    }

    #[test]
    fn apply_ipv6_defaults_skips_when_ipv6_target_false() {
        let mut spec = TransmissionSpec::default();
        let layer2 = Layer2Spec::default();

        spec.apply_ipv6_defaults(&layer2, false);

        assert!(!spec.auto_layer3);
        assert!(!spec.is_layer3());
    }

    #[test]
    fn is_layer3_true_for_auto_layer3() {
        let spec = TransmissionSpec {
            auto_layer3: true,
            ..TransmissionSpec::default()
        };
        assert!(spec.is_layer3());
    }
}
