// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(feature = "pcap"))]
use super::error::SpecError;
use super::error::SpecResult;

#[cfg(not(feature = "pcap"))]
use crate::domain::listener_config::ListenerPcapRequirement;
use crate::domain::listener_config::NormalizedListenerRequest;
use crate::domain::request::ListenerRequest;

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
        #[cfg(not(feature = "pcap"))]
        if let Some(requirement) = crate::domain::listener_config::spec_pcap_requirement(request) {
            return Err(match requirement {
                ListenerPcapRequirement::Listen => SpecError::ListenReplyRequiresPcap,
                ListenerPcapRequirement::ShowReply => SpecError::ShowReplyRequiresPcap,
                ListenerPcapRequirement::Filter => SpecError::FilterRequiresPcap,
                ListenerPcapRequirement::Capture => SpecError::PcapSaveRequiresFeature,
            });
        }

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
