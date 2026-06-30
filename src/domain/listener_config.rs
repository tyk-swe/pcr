// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::time::Duration;

use crate::domain::request::ListenerRequest;

pub(crate) const DEFAULT_QUEUE_CAPACITY: usize = 256;
pub(crate) const MAX_QUEUE_CAPACITY: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct NormalizedListenerRequest {
    pub(crate) enabled: bool,
    pub(crate) filter: Option<String>,
    pub(crate) promiscuous: bool,
    pub(crate) show_reply: bool,
    pub(crate) timeout: Option<Duration>,
    pub(crate) capture_file: Option<PathBuf>,
    pub(crate) implicit: bool,
    pub(crate) queue_capacity: Option<usize>,
}

impl NormalizedListenerRequest {
    pub(crate) fn from_request(request: &ListenerRequest) -> Self {
        let capture_file = request.capture_file.as_ref().map(PathBuf::from);
        let listen = request.listen.unwrap_or(false);
        let show_reply = request.show_reply.unwrap_or(false);
        let filter_present = request.filter.is_some();
        let implicit = !listen && (show_reply || capture_file.is_some() || filter_present);
        let enabled = listen || show_reply || capture_file.is_some() || filter_present;

        Self {
            enabled,
            filter: request.filter.clone(),
            promiscuous: request.promiscuous.unwrap_or(false),
            show_reply,
            timeout: request.timeout.map(Duration::from_secs),
            capture_file,
            implicit,
            queue_capacity: request.queue_capacity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerPcapRequirement {
    Listen,
    ShowReply,
    Filter,
    Capture,
}

pub(crate) fn spec_pcap_requirement(request: &ListenerRequest) -> Option<ListenerPcapRequirement> {
    if request.listen.unwrap_or(false) {
        Some(ListenerPcapRequirement::Listen)
    } else if request.show_reply.unwrap_or(false) {
        Some(ListenerPcapRequirement::ShowReply)
    } else if request.filter.is_some() {
        Some(ListenerPcapRequirement::Filter)
    } else if request.capture_file.is_some() {
        Some(ListenerPcapRequirement::Capture)
    } else {
        None
    }
}

pub(crate) fn runtime_request_pcap_requirement(
    request: &ListenerRequest,
) -> Option<ListenerPcapRequirement> {
    if request.filter.is_some() {
        Some(ListenerPcapRequirement::Filter)
    } else if request.capture_file.is_some() {
        Some(ListenerPcapRequirement::Capture)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueCapacityError {
    Zero,
    TooLarge { max: usize },
}

pub(crate) fn normalize_queue_capacity(
    queue_capacity: Option<usize>,
) -> Result<usize, QueueCapacityError> {
    let queue_capacity = queue_capacity.unwrap_or(DEFAULT_QUEUE_CAPACITY);
    if queue_capacity == 0 {
        return Err(QueueCapacityError::Zero);
    }
    if queue_capacity > MAX_QUEUE_CAPACITY {
        return Err(QueueCapacityError::TooLarge {
            max: MAX_QUEUE_CAPACITY,
        });
    }
    Ok(queue_capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_listener_request_stays_disabled_for_empty_request() {
        let normalized = NormalizedListenerRequest::from_request(&ListenerRequest::default());

        assert!(!normalized.enabled);
        assert!(!normalized.implicit);
        assert_eq!(normalized.filter, None);
        assert_eq!(normalized.timeout, None);
        assert_eq!(normalized.capture_file, None);
        assert_eq!(normalized.queue_capacity, None);
    }

    #[test]
    fn normalized_listener_request_uses_explicit_listen_without_implicit_flag() {
        let normalized = NormalizedListenerRequest::from_request(&ListenerRequest {
            listen: Some(true),
            promiscuous: Some(true),
            timeout: Some(7),
            queue_capacity: Some(128),
            ..Default::default()
        });

        assert!(normalized.enabled);
        assert!(!normalized.implicit);
        assert!(normalized.promiscuous);
        assert_eq!(normalized.timeout, Some(Duration::from_secs(7)));
        assert_eq!(normalized.queue_capacity, Some(128));
    }

    #[test]
    fn normalized_listener_request_auto_enables_for_reply_filter_or_capture() {
        for request in [
            ListenerRequest {
                show_reply: Some(true),
                ..Default::default()
            },
            ListenerRequest {
                filter: Some("icmp".to_string()),
                ..Default::default()
            },
            ListenerRequest {
                capture_file: Some("capture.pcap".to_string()),
                ..Default::default()
            },
        ] {
            let normalized = NormalizedListenerRequest::from_request(&request);

            assert!(normalized.enabled);
            assert!(normalized.implicit);
        }
    }

    #[test]
    fn normalized_listener_request_preserves_capture_and_filter_values() {
        let normalized = NormalizedListenerRequest::from_request(&ListenerRequest {
            filter: Some("tcp port 443".to_string()),
            capture_file: Some("reply.pcap".to_string()),
            show_reply: Some(true),
            ..Default::default()
        });

        assert_eq!(normalized.filter.as_deref(), Some("tcp port 443"));
        assert_eq!(
            normalized
                .capture_file
                .as_ref()
                .map(|path| path.display().to_string()),
            Some("reply.pcap".to_string())
        );
        assert!(normalized.show_reply);
    }

    #[test]
    fn spec_pcap_requirement_reports_highest_priority_requirement() {
        let requirement = spec_pcap_requirement(&ListenerRequest {
            listen: Some(true),
            show_reply: Some(true),
            filter: Some("icmp".to_string()),
            capture_file: Some("out.pcap".to_string()),
            ..Default::default()
        });

        assert_eq!(requirement, Some(ListenerPcapRequirement::Listen));
    }

    #[test]
    fn spec_pcap_requirement_reports_each_implicit_pcap_use() {
        assert_eq!(
            spec_pcap_requirement(&ListenerRequest {
                show_reply: Some(true),
                ..Default::default()
            }),
            Some(ListenerPcapRequirement::ShowReply)
        );
        assert_eq!(
            spec_pcap_requirement(&ListenerRequest {
                filter: Some("udp".to_string()),
                ..Default::default()
            }),
            Some(ListenerPcapRequirement::Filter)
        );
        assert_eq!(
            spec_pcap_requirement(&ListenerRequest {
                capture_file: Some("out.pcap".to_string()),
                ..Default::default()
            }),
            Some(ListenerPcapRequirement::Capture)
        );
        assert_eq!(spec_pcap_requirement(&ListenerRequest::default()), None);
    }

    #[test]
    fn normalize_queue_capacity_applies_default_and_accepts_bounds() {
        assert_eq!(
            normalize_queue_capacity(None).unwrap(),
            DEFAULT_QUEUE_CAPACITY
        );
        assert_eq!(normalize_queue_capacity(Some(1)).unwrap(), 1);
        assert_eq!(
            normalize_queue_capacity(Some(MAX_QUEUE_CAPACITY)).unwrap(),
            MAX_QUEUE_CAPACITY
        );
    }

    #[test]
    fn normalize_queue_capacity_rejects_zero_and_too_large_values() {
        assert_eq!(
            normalize_queue_capacity(Some(0)).unwrap_err(),
            QueueCapacityError::Zero
        );
        assert_eq!(
            normalize_queue_capacity(Some(MAX_QUEUE_CAPACITY + 1)).unwrap_err(),
            QueueCapacityError::TooLarge {
                max: MAX_QUEUE_CAPACITY
            }
        );
    }
}
