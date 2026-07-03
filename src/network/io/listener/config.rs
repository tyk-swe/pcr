// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "pcap")]
use std::path::PathBuf;
#[cfg(feature = "pcap")]
use std::time::Duration;

#[cfg(not(feature = "pcap"))]
use crate::domain::listener_config::ListenerPcapRequirement;
#[cfg(feature = "pcap")]
use crate::domain::listener_config::NormalizedListenerRequest;
use crate::domain::listener_config::{normalize_queue_capacity, QueueCapacityError};
use crate::domain::request::ListenerRequest;
#[cfg(feature = "pcap")]
use crate::domain::spec::ListenerSpec;

use super::error::ListenerError;

#[cfg(feature = "pcap")]
mod availability {
    use super::*;

    pub(super) fn validate_request(_options: &ListenerRequest) -> Result<(), ListenerError> {
        Ok(())
    }
}

#[cfg(not(feature = "pcap"))]
mod availability {
    use super::*;

    pub(super) fn validate_request(options: &ListenerRequest) -> Result<(), ListenerError> {
        if let Some(requirement) =
            crate::domain::listener_config::runtime_request_pcap_requirement(options)
        {
            return Err(match requirement {
                ListenerPcapRequirement::Filter => ListenerError::FilterRequiresPcap,
                ListenerPcapRequirement::Capture => ListenerError::CaptureRequiresPcap,
                ListenerPcapRequirement::Listen | ListenerPcapRequirement::ShowReply => {
                    ListenerError::ListenerRequiresPcap
                }
            });
        }

        Ok(())
    }
}

#[cfg(feature = "pcap")]
#[derive(Clone, Debug)]
pub(crate) struct ListenerRuntimeConfig {
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub timeout: Option<Duration>,
    pub show_reply: bool,
    pub capture_file: Option<PathBuf>,
    pub queue_capacity: usize,
}

#[cfg(not(feature = "pcap"))]
pub(crate) fn validate_request_options(options: &ListenerRequest) -> Result<(), ListenerError> {
    availability::validate_request(options)?;
    normalize_queue_capacity(options.queue_capacity).map_err(queue_capacity_request_error)?;
    Ok(())
}

#[cfg(feature = "pcap")]
impl ListenerRuntimeConfig {
    pub(crate) fn from_request(options: &ListenerRequest) -> Result<Self, ListenerError> {
        availability::validate_request(options)?;
        let normalized = NormalizedListenerRequest::from_request(options);
        let queue_capacity = normalize_queue_capacity(normalized.queue_capacity)
            .map_err(queue_capacity_request_error)?;

        Ok(Self {
            filter: normalized.filter,
            promiscuous: normalized.promiscuous,
            timeout: normalized.timeout,
            show_reply: normalized.show_reply,
            capture_file: normalized.capture_file,
            queue_capacity,
        })
    }

    #[cfg(feature = "pcap")]
    pub(crate) fn from_spec(spec: &ListenerSpec) -> Result<Self, ListenerError> {
        let queue_capacity =
            normalize_queue_capacity(spec.queue_capacity).map_err(queue_capacity_spec_error)?;

        Ok(Self {
            filter: spec.filter.clone(),
            promiscuous: spec.promiscuous,
            timeout: spec.timeout,
            show_reply: spec.show_reply,
            capture_file: spec.capture_file.clone(),
            queue_capacity,
        })
    }
}

fn queue_capacity_request_error(error: QueueCapacityError) -> ListenerError {
    match error {
        QueueCapacityError::Zero => ListenerError::QueueCapacityZero,
        QueueCapacityError::TooLarge { max } => ListenerError::QueueCapacityTooLarge { max },
    }
}

#[cfg(feature = "pcap")]
fn queue_capacity_spec_error(error: QueueCapacityError) -> ListenerError {
    match error {
        QueueCapacityError::Zero => ListenerError::SpecQueueCapacityZero,
        QueueCapacityError::TooLarge { max } => ListenerError::SpecQueueCapacityTooLarge { max },
    }
}

#[cfg(all(test, feature = "daemon", not(feature = "pcap")))]
mod tests {
    use super::*;

    #[test]
    fn daemon_listener_validation_without_pcap_rejects_filter_and_capture() {
        let filter = validate_request_options(&ListenerRequest {
            filter: Some("icmp".to_string()),
            ..Default::default()
        })
        .unwrap_err();
        let capture = validate_request_options(&ListenerRequest {
            capture_file: Some("capture.pcap".to_string()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(filter, ListenerError::FilterRequiresPcap));
        assert!(matches!(capture, ListenerError::CaptureRequiresPcap));
    }

    #[test]
    fn daemon_listener_validation_without_pcap_still_checks_queue_capacity() {
        let err = validate_request_options(&ListenerRequest {
            queue_capacity: Some(0),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, ListenerError::QueueCapacityZero));
    }
}

#[cfg(all(test, feature = "pcap"))]
mod pcap_tests {
    use super::*;
    use crate::domain::listener_config::{DEFAULT_QUEUE_CAPACITY, MAX_QUEUE_CAPACITY};

    #[test]
    fn listener_runtime_config_from_request_maps_supported_fields() {
        let config = ListenerRuntimeConfig::from_request(&ListenerRequest {
            filter: Some("tcp port 443".to_string()),
            promiscuous: Some(true),
            show_reply: Some(true),
            timeout: Some(7),
            capture_file: Some("capture/reply.pcap".to_string()),
            queue_capacity: Some(512),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(config.filter.as_deref(), Some("tcp port 443"));
        assert!(config.promiscuous);
        assert!(config.show_reply);
        assert_eq!(config.timeout, Some(Duration::from_secs(7)));
        assert_eq!(
            config
                .capture_file
                .as_ref()
                .map(|path| path.display().to_string()),
            Some("capture/reply.pcap".to_string())
        );
        assert_eq!(config.queue_capacity, 512);
    }

    #[test]
    fn listener_runtime_config_from_request_applies_default_queue_capacity() {
        let config = ListenerRuntimeConfig::from_request(&ListenerRequest::default()).unwrap();

        assert_eq!(config.queue_capacity, DEFAULT_QUEUE_CAPACITY);
    }

    #[test]
    fn listener_runtime_config_from_request_rejects_queue_capacity_bounds() {
        let zero = ListenerRuntimeConfig::from_request(&ListenerRequest {
            queue_capacity: Some(0),
            ..Default::default()
        })
        .unwrap_err();
        let too_large = ListenerRuntimeConfig::from_request(&ListenerRequest {
            queue_capacity: Some(MAX_QUEUE_CAPACITY + 1),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(zero, ListenerError::QueueCapacityZero));
        assert!(matches!(
            too_large,
            ListenerError::QueueCapacityTooLarge {
                max: MAX_QUEUE_CAPACITY
            }
        ));
    }

    #[test]
    fn listener_runtime_config_from_spec_maps_supported_fields() {
        let spec = ListenerSpec {
            enabled: true,
            filter: Some("icmp".to_string()),
            promiscuous: true,
            show_reply: true,
            timeout: Some(Duration::from_secs(3)),
            capture_file: Some(PathBuf::from("spec.pcap")),
            implicit: false,
            queue_capacity: Some(64),
        };

        let config = ListenerRuntimeConfig::from_spec(&spec).unwrap();

        assert_eq!(config.filter.as_deref(), Some("icmp"));
        assert!(config.promiscuous);
        assert!(config.show_reply);
        assert_eq!(config.timeout, Some(Duration::from_secs(3)));
        assert_eq!(
            config
                .capture_file
                .as_ref()
                .map(|path| path.display().to_string()),
            Some("spec.pcap".to_string())
        );
        assert_eq!(config.queue_capacity, 64);
    }

    #[test]
    fn listener_runtime_config_from_spec_uses_spec_specific_queue_errors() {
        let zero = ListenerRuntimeConfig::from_spec(&ListenerSpec {
            queue_capacity: Some(0),
            ..Default::default()
        })
        .unwrap_err();
        let too_large = ListenerRuntimeConfig::from_spec(&ListenerSpec {
            queue_capacity: Some(MAX_QUEUE_CAPACITY + 1),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(zero, ListenerError::SpecQueueCapacityZero));
        assert!(matches!(
            too_large,
            ListenerError::SpecQueueCapacityTooLarge {
                max: MAX_QUEUE_CAPACITY
            }
        ));
    }
}
