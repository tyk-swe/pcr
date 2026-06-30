// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::time::Duration;

use crate::domain::listener_config::{
    normalize_queue_capacity, NormalizedListenerRequest, QueueCapacityError,
};
use crate::domain::request::ListenerRequest;
#[cfg(feature = "pcap")]
use crate::domain::spec::ListenerSpec;

use super::error::ListenerError;

#[derive(Clone, Debug)]
pub struct ListenerRuntimeConfig {
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub timeout: Option<Duration>,
    pub show_reply: bool,
    pub capture_file: Option<PathBuf>,
    pub queue_capacity: usize,
}

impl ListenerRuntimeConfig {
    pub fn from_request(options: &ListenerRequest) -> Result<Self, ListenerError> {
        #[cfg(not(feature = "pcap"))]
        if let Some(requirement) =
            crate::domain::listener_config::runtime_request_pcap_requirement(options)
        {
            return Err(match requirement {
                crate::domain::listener_config::ListenerPcapRequirement::Filter => {
                    ListenerError::FilterRequiresPcap
                }
                crate::domain::listener_config::ListenerPcapRequirement::Capture => {
                    ListenerError::CaptureRequiresPcap
                }
                crate::domain::listener_config::ListenerPcapRequirement::Listen
                | crate::domain::listener_config::ListenerPcapRequirement::ShowReply => {
                    ListenerError::ListenerRequiresPcap
                }
            });
        }

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
    pub fn from_spec(spec: &ListenerSpec) -> Result<Self, ListenerError> {
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
