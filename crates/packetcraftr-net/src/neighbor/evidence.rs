// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Captured-evidence validation and retention bounds for active neighbor resolution.

#![forbid(unsafe_code)]

use bytes::Bytes;

use super::error::{map_io_error, resolution_error};
use super::options::NeighborResolutionOptions;
use super::wire::is_unicast_mac;
use crate::{
    Error as LiveIoError,
    route::{MAX_NEIGHBOR_VLAN_TAGS, NeighborError, NeighborRequest},
    transmit::IoSendReport,
};
use packetcraftr_core::frame::{Frame, LinkType};

pub(super) fn validate_request(request: &NeighborRequest) -> Result<(), NeighborError> {
    if request.interface_source.is_ipv4() != request.target.is_ipv4() {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "source {} and target {} use different address families",
                request.interface_source, request.target
            ),
        });
    }
    if request.interface_source.is_unspecified() || request.interface_source.is_multicast() {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "interface source {} is not a usable unicast address",
                request.interface_source
            ),
        });
    }
    if request.target.is_unspecified() || request.target.is_multicast() {
        return Err(NeighborError::InvalidRequest {
            message: format!("target {} is not a unicast neighbor", request.target),
        });
    }
    if request.link_type != LinkType::ETHERNET {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "link type {} does not support Ethernet ARP/NDP",
                request.link_type.0
            ),
        });
    }
    if !is_unicast_mac(request.interface_mac) {
        return Err(NeighborError::InvalidRequest {
            message: format!(
                "interface MAC {} is not an individual unicast address",
                request.interface_mac
            ),
        });
    }
    if request.mtu == 0 {
        return Err(NeighborError::InvalidRequest {
            message: "interface MTU is zero".to_owned(),
        });
    }
    if request.vlan_tags.len() > MAX_NEIGHBOR_VLAN_TAGS {
        return Err(NeighborError::InvalidRequest {
            message: format!("VLAN stack exceeds {MAX_NEIGHBOR_VLAN_TAGS} discovery tags"),
        });
    }
    for tag in &request.vlan_tags {
        if tag.priority > 7 || tag.vlan_id > 4095 {
            return Err(NeighborError::InvalidRequest {
                message: "VLAN priority or identifier is outside its wire range".to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_captured_frame(
    request: &NeighborRequest,
    frame: &Frame,
    snap_length: usize,
) -> Result<(), NeighborError> {
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

pub(super) fn validate_send_report(
    request: &NeighborRequest,
    expected: &Bytes,
    report: IoSendReport,
) -> Result<(), NeighborError> {
    if report.bytes_sent != expected.len() {
        return Err(map_io_error(
            request,
            "sending discovery request",
            LiveIoError::PartialSend {
                expected: expected.len(),
                actual: report.bytes_sent,
            },
        ));
    }
    if report.wire_bytes != *expected {
        return Err(map_io_error(
            request,
            "validating discovery send evidence",
            LiveIoError::InvalidSendEvidence {
                message: "discovery wire bytes differ from the exact submitted frame".to_owned(),
            },
        ));
    }
    Ok(())
}

pub(super) fn retain_evidence(
    frame: Frame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<Frame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) {
    if captured.len() >= options.max_capture_queue_frames
        || *captured_bytes + frame.bytes().len() > options.max_captured_bytes
    {
        *truncated = true;
        return;
    }
    *captured_bytes += frame.bytes().len();
    captured.push(frame);
}

pub(super) fn retain_matching_evidence(
    frame: Frame,
    options: &NeighborResolutionOptions,
    captured: &mut Vec<Frame>,
    captured_bytes: &mut usize,
    truncated: &mut bool,
) {
    let frame_length = frame.bytes().len();
    while captured.len() >= options.max_capture_queue_frames
        || *captured_bytes + frame_length > options.max_captured_bytes
    {
        let discarded = captured.remove(0);
        *captured_bytes -= discarded.bytes().len();
        *truncated = true;
    }
    *captured_bytes += frame_length;
    captured.push(frame);
}
