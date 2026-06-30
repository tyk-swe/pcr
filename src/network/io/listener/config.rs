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
