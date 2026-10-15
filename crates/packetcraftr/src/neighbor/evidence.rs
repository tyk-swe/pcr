// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;

use bytes::Bytes;

use super::error::{invalid_request, map_io_error, resolution_error};
use super::options::Options;
use super::wire::is_unicast_mac;
use super::{MAX_VLAN_TAGS, Request as NeighborRequest};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::transmit;

pub(super) fn validate_request(request: &NeighborRequest) -> Result<(), crate::neighbor::Error> {
    if request.interface_source.is_ipv4() != request.target.is_ipv4() {
        return Err(invalid_request(format!(
            "source {} and target {} use different address families",
            request.interface_source, request.target
        )));
    }
    if request.interface_source.is_unspecified() || request.interface_source.is_multicast() {
        return Err(invalid_request(format!(
            "interface source {} is not a usable unicast address",
            request.interface_source
        )));
    }
    if request.target.is_unspecified() || request.target.is_multicast() {
        return Err(invalid_request(format!(
            "target {} is not a unicast neighbor",
            request.target
        )));
    }
    if request.link_type != LinkType::ETHERNET {
        return Err(invalid_request(format!(
            "link type {} does not support Ethernet ARP/NDP",
            request.link_type.0
        )));
    }
    if !is_unicast_mac(request.interface_mac) {
        return Err(invalid_request(format!(
            "interface MAC {} is not an individual unicast address",
            request.interface_mac
        )));
    }
    if request.mtu == 0 {
        return Err(invalid_request("interface MTU is zero"));
    }
    if request.vlan_tags.len() > MAX_VLAN_TAGS {
        return Err(invalid_request(format!(
            "VLAN stack exceeds {MAX_VLAN_TAGS} discovery tags"
        )));
    }
    for tag in &request.vlan_tags {
        if tag.priority > 7 || tag.vlan_id > 4095 {
            return Err(invalid_request(
                "VLAN priority or identifier is outside its wire range",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_captured_frame(
    request: &NeighborRequest,
    frame: &Frame,
    snap_length: usize,
) -> Result<(), crate::neighbor::Error> {
    if frame.bytes().len() > snap_length {
        return Err(resolution_error(
            &request.interface,
            request.target,
            format!(
                "capture returned {} bytes beyond the configured {snap_length}-byte snap length",
                frame.bytes().len()
            ),
        ));
    }
    Ok(())
}

pub(super) fn validate_neighbor_send(
    request: &NeighborRequest,
    expected: &Bytes,
    report: &transmit::Report,
) -> Result<(), crate::neighbor::Error> {
    report
        .validate_exact(expected)
        .map_err(|source| map_io_error(request, "validating discovery send evidence", source))
}

pub(super) struct EvidenceBuffer {
    max_frames: usize,
    max_bytes: usize,
    frames: VecDeque<Frame>,
    bytes: usize,
    truncated: bool,
}

impl EvidenceBuffer {
    pub(super) fn new(options: &Options) -> Self {
        Self {
            max_frames: options.max_capture_queue_frames,
            max_bytes: options.max_captured_bytes,
            frames: VecDeque::new(),
            bytes: 0,
            truncated: false,
        }
    }

    pub(super) fn retain(&mut self, frame: Frame) {
        if self.over_budget(frame.bytes().len()) {
            self.truncated = true;
            return;
        }
        self.push(frame);
    }

    /// Keeps `frame` even at the cost of evicting the oldest frames, so a
    /// matching response is always part of the evidence unless it alone
    /// exceeds the budget.
    pub(super) fn retain_matching(&mut self, frame: Frame) {
        let frame_length = frame.bytes().len();
        while self.over_budget(frame_length) {
            let Some(discarded) = self.frames.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(discarded.bytes().len());
            self.truncated = true;
        }
        if self.over_budget(frame_length) {
            self.truncated = true;
            return;
        }
        self.push(frame);
    }

    pub(super) fn into_evidence(self) -> (Vec<Frame>, bool) {
        (Vec::from(self.frames), self.truncated)
    }

    fn over_budget(&self, frame_length: usize) -> bool {
        self.frames.len() >= self.max_frames
            || self
                .bytes
                .checked_add(frame_length)
                .is_none_or(|total| total > self.max_bytes)
    }

    fn push(&mut self, frame: Frame) {
        self.bytes = self.bytes.saturating_add(frame.bytes().len());
        self.frames.push_back(frame);
    }
}
