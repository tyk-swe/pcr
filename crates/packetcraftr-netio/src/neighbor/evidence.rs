// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Captured-evidence validation and retention bounds for active neighbor resolution.

use std::collections::VecDeque;

use bytes::Bytes;

use super::Request as NeighborRequest;
use super::error::{map_io_error, resolution_error};
use super::options::Options;
use super::wire::is_unicast_mac;
use crate::link::MAX_VLAN_TAGS;
use crate::transmit;
use packetcraftr_core::frame::{Frame, LinkType};

#[cfg(test)]
use crate::Error;

pub(super) fn validate_request(request: &NeighborRequest) -> Result<(), crate::neighbor::Error> {
    if request.interface_source.is_ipv4() != request.target.is_ipv4() {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!(
                "source {} and target {} use different address families",
                request.interface_source, request.target
            ),
        });
    }
    if request.interface_source.is_unspecified() || request.interface_source.is_multicast() {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!(
                "interface source {} is not a usable unicast address",
                request.interface_source
            ),
        });
    }
    if request.target.is_unspecified() || request.target.is_multicast() {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!("target {} is not a unicast neighbor", request.target),
        });
    }
    if request.link_type != LinkType::ETHERNET {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!(
                "link type {} does not support Ethernet ARP/NDP",
                request.link_type.0
            ),
        });
    }
    if !is_unicast_mac(request.interface_mac) {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!(
                "interface MAC {} is not an individual unicast address",
                request.interface_mac
            ),
        });
    }
    if request.mtu == 0 {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: "interface MTU is zero".to_owned(),
        });
    }
    if request.vlan_tags.len() > MAX_VLAN_TAGS {
        return Err(crate::neighbor::Error::InvalidRequest {
            message: format!("VLAN stack exceeds {MAX_VLAN_TAGS} discovery tags"),
        });
    }
    for tag in &request.vlan_tags {
        if tag.priority > 7 || tag.vlan_id > 4095 {
            return Err(crate::neighbor::Error::InvalidRequest {
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

/// Captured frames retained as resolution evidence within the configured
/// frame and byte budget. `truncated` records that at least one frame was
/// dropped or evicted to stay within it.
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

    /// Keeps `frame` if it fits; otherwise drops it and marks the evidence
    /// truncated.
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
            // The frame alone exceeds the budget: dropping it is the only
            // bounded outcome, and the caller learns about it through
            // `truncated`.
            self.truncated = true;
            return;
        }
        self.push(frame);
    }

    /// The retained frames, oldest first, and whether any were dropped.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::{
        interface::Id as InterfaceId,
        link::{MacAddress, VlanKind, VlanTag},
    };

    fn request() -> NeighborRequest {
        NeighborRequest {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 3,
            },
            interface_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            interface_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            target: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            vlan_tags: Vec::new(),
            mtu: 1_500,
            link_type: LinkType::ETHERNET,
            deadline: None,
        }
    }

    fn frame(bytes: &[u8]) -> Frame {
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes.to_vec())
            .expect("fixture frame")
    }

    #[test]
    fn valid_neighbor_request_passes_all_invariants() {
        assert!(validate_request(&request()).is_ok());
    }

    #[test]
    fn neighbor_request_rejects_each_invalid_identity_and_wire_bound() {
        let cases = [
            NeighborRequest {
                target: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ..request()
            },
            NeighborRequest {
                interface_source: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ..request()
            },
            NeighborRequest {
                interface_source: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                ..request()
            },
            NeighborRequest {
                target: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                ..request()
            },
            NeighborRequest {
                target: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                ..request()
            },
            NeighborRequest {
                link_type: LinkType::RAW,
                ..request()
            },
            NeighborRequest {
                interface_mac: MacAddress([0xff; 6]),
                ..request()
            },
            NeighborRequest {
                mtu: 0,
                ..request()
            },
            NeighborRequest {
                vlan_tags: vec![
                    VlanTag {
                        kind: VlanKind::Ieee8021Q,
                        priority: 0,
                        drop_eligible: false,
                        vlan_id: 1,
                    };
                    MAX_VLAN_TAGS + 1
                ],
                ..request()
            },
            NeighborRequest {
                vlan_tags: vec![VlanTag {
                    kind: VlanKind::Ieee8021Q,
                    priority: 8,
                    drop_eligible: false,
                    vlan_id: 1,
                }],
                ..request()
            },
            NeighborRequest {
                vlan_tags: vec![VlanTag {
                    kind: VlanKind::Ieee8021Q,
                    priority: 0,
                    drop_eligible: false,
                    vlan_id: 4_096,
                }],
                ..request()
            },
        ];

        for invalid in cases {
            assert!(matches!(
                validate_request(&invalid),
                Err(crate::neighbor::Error::InvalidRequest { .. })
            ));
        }
    }

    #[test]
    fn capture_and_send_evidence_must_match_configured_and_submitted_bytes() {
        let request = request();
        assert!(validate_captured_frame(&request, &frame(&[1, 2]), 2).is_ok());
        assert!(matches!(
            validate_captured_frame(&request, &frame(&[1, 2, 3]), 2),
            Err(crate::neighbor::Error::Resolution { .. })
        ));

        let expected = Bytes::from_static(&[1, 2, 3]);
        assert!(
            validate_neighbor_send(
                &request,
                &expected,
                &transmit::Report::committed(3, expected.clone())
            )
            .is_ok()
        );
        assert!(matches!(
            validate_neighbor_send(
                &request,
                &expected,
                &transmit::Report::committed(2, expected.clone())
            ),
            Err(crate::neighbor::Error::Io {
                source: Error::PartialSend { .. },
                ..
            })
        ));
        assert!(matches!(
            validate_neighbor_send(
                &request,
                &expected,
                &transmit::Report::committed(3, Bytes::from_static(&[3, 2, 1]))
            ),
            Err(crate::neighbor::Error::Io {
                source: Error::InvalidSendEvidence { .. },
                ..
            })
        ));
    }

    #[test]
    fn evidence_retention_drops_late_frames_but_matching_retention_evicts_oldest() {
        let options = Options {
            max_attempts: 1,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(1),
            max_cache_entries: 1,
            max_capture_queue_frames: 2,
            max_captured_bytes: 4,
            snap_length: 128,
        };
        let mut evidence = EvidenceBuffer::new(&options);
        evidence.retain(frame(&[1, 2]));
        evidence.retain(frame(&[3, 4]));
        evidence.retain(frame(&[5]));
        assert_eq!(evidence.frames.len(), 2);
        assert_eq!(evidence.bytes, 4);
        assert!(evidence.truncated);

        evidence.truncated = false;
        evidence.retain_matching(frame(&[9, 9, 9]));
        assert_eq!(evidence.frames.len(), 1);
        assert_eq!(evidence.frames[0].bytes().as_ref(), [9, 9, 9]);
        assert_eq!(evidence.bytes, 3);
        assert!(evidence.truncated);
    }

    #[test]
    fn matching_retention_drops_a_frame_that_alone_exceeds_the_byte_budget() {
        let options = Options {
            max_attempts: 1,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(1),
            max_cache_entries: 1,
            max_capture_queue_frames: 2,
            max_captured_bytes: 4,
            snap_length: 128,
        };
        let mut evidence = EvidenceBuffer::new(&options);
        evidence.retain(frame(&[1, 2]));
        evidence.retain_matching(frame(&[7, 7, 7, 7, 7]));
        assert!(evidence.frames.is_empty());
        assert_eq!(evidence.bytes, 0);
        assert!(evidence.truncated);

        // The same oversized frame on an empty queue must not panic either.
        evidence.truncated = false;
        evidence.retain_matching(frame(&[7, 7, 7, 7, 7]));
        assert!(evidence.frames.is_empty());
        assert!(evidence.truncated);
    }
}
