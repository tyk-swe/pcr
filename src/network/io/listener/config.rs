use std::path::PathBuf;
use std::time::Duration;

use crate::engine::listener_config::{
    normalize_queue_capacity, NormalizedListenerRequest, QueueCapacityError,
};
use crate::engine::request::ListenerRequest;
use crate::engine::spec::ListenerSpec;

use super::error::ListenerError;

pub use crate::engine::listener_config::{DEFAULT_QUEUE_CAPACITY, MAX_QUEUE_CAPACITY};

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
            crate::engine::listener_config::runtime_request_pcap_requirement(options)
        {
            return Err(match requirement {
                crate::engine::listener_config::ListenerPcapRequirement::Filter => {
                    ListenerError::FilterRequiresPcap
                }
                crate::engine::listener_config::ListenerPcapRequirement::Capture => {
                    ListenerError::CaptureRequiresPcap
                }
                crate::engine::listener_config::ListenerPcapRequirement::Listen
                | crate::engine::listener_config::ListenerPcapRequirement::ShowReply => {
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

    pub fn from_spec(spec: &ListenerSpec) -> Result<Self, ListenerError> {
        #[cfg(not(feature = "pcap"))]
        if spec.filter.is_some() {
            return Err(ListenerError::FilterRequiresPcap);
        }

        #[cfg(not(feature = "pcap"))]
        if spec.capture_file.is_some() {
            return Err(ListenerError::CaptureRequiresPcap);
        }

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

fn queue_capacity_spec_error(error: QueueCapacityError) -> ListenerError {
    match error {
        QueueCapacityError::Zero => ListenerError::SpecQueueCapacityZero,
        QueueCapacityError::TooLarge { max } => ListenerError::SpecQueueCapacityTooLarge { max },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn filter_option_requires_pcap() {
        let options = ListenerRequest {
            filter: Some("icmp".to_string()),
            ..Default::default()
        };

        let err = ListenerRuntimeConfig::from_request(&options)
            .expect_err("filter should be rejected without pcap support");
        assert!(matches!(err, ListenerError::FilterRequiresPcap));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn capture_option_requires_pcap() {
        let options = ListenerRequest {
            capture_file: Some("out.pcap".to_string()),
            ..Default::default()
        };

        let err = ListenerRuntimeConfig::from_request(&options)
            .expect_err("pcap-save should be rejected without pcap support");
        assert!(matches!(err, ListenerError::CaptureRequiresPcap));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn capture_spec_requires_pcap() {
        let spec = ListenerSpec {
            capture_file: Some(PathBuf::from("out.pcap")),
            ..Default::default()
        };

        let err = ListenerRuntimeConfig::from_spec(&spec)
            .expect_err("pcap-save in spec should be rejected without pcap support");
        assert!(matches!(err, ListenerError::CaptureRequiresPcap));
    }

    #[test]
    fn queue_capacity_zero_is_rejected() {
        let options = ListenerRequest {
            queue_capacity: Some(0),
            ..Default::default()
        };

        let err = ListenerRuntimeConfig::from_request(&options)
            .expect_err("zero queue capacity should be invalid");
        assert!(matches!(err, ListenerError::QueueCapacityZero));
    }

    #[test]
    fn queue_capacity_exceeding_max_is_rejected() {
        let options = ListenerRequest {
            queue_capacity: Some(MAX_QUEUE_CAPACITY + 1),
            ..Default::default()
        };

        let err = ListenerRuntimeConfig::from_request(&options)
            .expect_err("excessive queue capacity should be invalid");
        assert!(matches!(err, ListenerError::QueueCapacityTooLarge { .. }));
    }

    #[test]
    fn queue_capacity_limits_enforced_for_spec_inputs() {
        let mut spec = ListenerSpec {
            queue_capacity: Some(0),
            ..Default::default()
        };

        let zero_err = ListenerRuntimeConfig::from_spec(&spec)
            .expect_err("zero queue capacity in spec should be invalid");
        assert!(matches!(zero_err, ListenerError::SpecQueueCapacityZero));

        spec.queue_capacity = Some(MAX_QUEUE_CAPACITY + 1);
        let max_err = ListenerRuntimeConfig::from_spec(&spec)
            .expect_err("excessive queue capacity in spec should be invalid");
        assert!(matches!(
            max_err,
            ListenerError::SpecQueueCapacityTooLarge { .. }
        ));
    }
}
