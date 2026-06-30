// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::time::Duration;

use crate::domain::request::ListenerRequest;

#[cfg(any(feature = "daemon", feature = "pcap"))]
pub(crate) const DEFAULT_QUEUE_CAPACITY: usize = 256;
#[cfg(any(feature = "daemon", feature = "pcap"))]
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

#[cfg(not(feature = "pcap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerPcapRequirement {
    Listen,
    ShowReply,
    Filter,
    Capture,
}

#[cfg(not(feature = "pcap"))]
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

#[cfg(all(not(feature = "pcap"), feature = "daemon"))]
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

#[cfg(any(feature = "daemon", feature = "pcap"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueCapacityError {
    Zero,
    TooLarge { max: usize },
}

#[cfg(any(feature = "daemon", feature = "pcap"))]
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
