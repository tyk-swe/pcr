// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::time::Duration;

use super::error::SpecResult;

use crate::domain::listener_config::NormalizedListenerRequest;
use crate::domain::request::ListenerRequest;

#[cfg(feature = "pcap")]
mod availability {
    use super::*;

    pub(super) fn validate(_request: &ListenerRequest) -> SpecResult<()> {
        Ok(())
    }
}

#[cfg(not(feature = "pcap"))]
mod availability {
    use super::super::error::SpecError;
    use super::*;
    use crate::domain::listener_config::ListenerPcapRequirement;

    pub(super) fn validate(request: &ListenerRequest) -> SpecResult<()> {
        if let Some(requirement) = crate::domain::listener_config::spec_pcap_requirement(request) {
            return Err(match requirement {
                ListenerPcapRequirement::Listen => SpecError::ListenReplyRequiresPcap,
                ListenerPcapRequirement::ShowReply => SpecError::ShowReplyRequiresPcap,
                ListenerPcapRequirement::Filter => SpecError::FilterRequiresPcap,
                ListenerPcapRequirement::Capture => SpecError::PcapSaveRequiresFeature,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ListenerSpec {
    pub enabled: bool,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub show_reply: bool,
    pub timeout: Option<Duration>,
    pub capture_file: Option<PathBuf>,
    pub implicit: bool,
    pub queue_capacity: Option<usize>,
}

impl ListenerSpec {
    pub(crate) fn from_request(request: &ListenerRequest) -> SpecResult<Self> {
        availability::validate(request)?;
        let normalized = NormalizedListenerRequest::from_request(request);

        Ok(Self {
            enabled: normalized.enabled,
            filter: normalized.filter,
            promiscuous: normalized.promiscuous,
            show_reply: normalized.show_reply,
            timeout: normalized.timeout,
            capture_file: normalized.capture_file,
            implicit: normalized.implicit,
            queue_capacity: normalized.queue_capacity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "pcap"))]
    use crate::domain::spec::error::SpecError;

    #[cfg(not(feature = "pcap"))]
    fn spec_error(request: ListenerRequest) -> SpecError {
        ListenerSpec::from_request(&request).unwrap_err()
    }

    #[test]
    fn listener_spec_accepts_fully_disabled_request() {
        let spec = ListenerSpec::from_request(&ListenerRequest::default()).unwrap();

        assert!(!spec.enabled);
        assert_eq!(spec.queue_capacity, None);
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_spec_without_pcap_rejects_explicit_listen() {
        let err = spec_error(ListenerRequest {
            listen: Some(true),
            ..Default::default()
        });

        assert!(matches!(err, SpecError::ListenReplyRequiresPcap));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn listener_spec_without_pcap_rejects_show_reply_filter_and_capture() {
        assert!(matches!(
            spec_error(ListenerRequest {
                show_reply: Some(true),
                ..Default::default()
            }),
            SpecError::ShowReplyRequiresPcap
        ));
        assert!(matches!(
            spec_error(ListenerRequest {
                filter: Some("icmp".to_string()),
                ..Default::default()
            }),
            SpecError::FilterRequiresPcap
        ));
        assert!(matches!(
            spec_error(ListenerRequest {
                capture_file: Some("reply.pcap".to_string()),
                ..Default::default()
            }),
            SpecError::PcapSaveRequiresFeature
        ));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn listener_spec_with_pcap_accepts_valid_listener_requests() {
        for request in [
            ListenerRequest {
                listen: Some(true),
                timeout: Some(1),
                ..Default::default()
            },
            ListenerRequest {
                show_reply: Some(true),
                ..Default::default()
            },
            ListenerRequest {
                filter: Some("tcp port 443".to_string()),
                ..Default::default()
            },
            ListenerRequest {
                capture_file: Some("reply.pcap".to_string()),
                ..Default::default()
            },
        ] {
            assert!(ListenerSpec::from_request(&request).unwrap().enabled);
        }
    }
}
