// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Captured-evidence validation and retention bounds for active neighbor resolution.

#![forbid(unsafe_code)]

use bytes::Bytes;

use super::error::{map_io_error, resolution_error};
use super::options::NeighborResolutionOptions;
use super::wire::is_unicast_mac;
use crate::{
    route::{MAX_NEIGHBOR_VLAN_TAGS, NeighborError, NeighborRequest},
    transmit::{IoSendReport, TimingEvidence},
};
use packetcraftr_packet::frame::{Frame, LinkType};

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
) -> Result<TimingEvidence, NeighborError> {
    report
        .validate_against(expected)
        .map_err(|error| map_io_error(request, "validating discovery send evidence", error))
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::Error as LiveIoError;
    use crate::link::MacAddress;
    use crate::route::{InterfaceId, NeighborVlanKind, NeighborVlanTag};

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
                    NeighborVlanTag {
                        kind: NeighborVlanKind::Ieee8021Q,
                        priority: 0,
                        drop_eligible: false,
                        vlan_id: 1,
                    };
                    MAX_NEIGHBOR_VLAN_TAGS + 1
                ],
                ..request()
            },
            NeighborRequest {
                vlan_tags: vec![NeighborVlanTag {
                    kind: NeighborVlanKind::Ieee8021Q,
                    priority: 8,
                    drop_eligible: false,
                    vlan_id: 1,
                }],
                ..request()
            },
            NeighborRequest {
                vlan_tags: vec![NeighborVlanTag {
                    kind: NeighborVlanKind::Ieee8021Q,
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
                Err(NeighborError::InvalidRequest { .. })
            ));
        }
    }

    #[test]
    fn capture_and_send_evidence_must_match_configured_and_submitted_bytes() {
        let request = request();
        assert!(validate_captured_frame(&request, &frame(&[1, 2]), 2).is_ok());
        assert!(matches!(
            validate_captured_frame(&request, &frame(&[1, 2, 3]), 2),
            Err(NeighborError::Resolution { .. })
        ));

        let expected = Bytes::from_static(&[1, 2, 3]);
        let valid = IoSendReport::from_provider(
            3,
            expected.clone(),
            TimingEvidence::commit(
                std::time::Instant::now(),
                Some(std::time::SystemTime::now()),
            ),
        );
        assert!(validate_send_report(&request, &expected, valid).is_ok());
        assert!(matches!(
            validate_send_report(
                &request,
                &expected,
                IoSendReport::from_provider(
                    2,
                    expected.clone(),
                    TimingEvidence::commit(std::time::Instant::now(), None),
                )
            ),
            Err(NeighborError::Io {
                source: LiveIoError::PartialSend { .. },
                ..
            })
        ));
        assert!(matches!(
            validate_send_report(
                &request,
                &expected,
                IoSendReport::from_provider(
                    3,
                    Bytes::from_static(&[3, 2, 1]),
                    TimingEvidence::commit(std::time::Instant::now(), None),
                )
            ),
            Err(NeighborError::Io {
                source: LiveIoError::InvalidSendEvidence { .. },
                ..
            })
        ));
    }

    #[test]
    fn evidence_retention_drops_late_frames_but_matching_retention_evicts_oldest() {
        let options = NeighborResolutionOptions {
            max_attempts: 1,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(1),
            max_cache_entries: 1,
            max_capture_queue_frames: 2,
            max_captured_bytes: 4,
            snap_length: 128,
        };
        let mut captured = Vec::new();
        let mut bytes = 0;
        let mut truncated = false;
        retain_evidence(
            frame(&[1, 2]),
            &options,
            &mut captured,
            &mut bytes,
            &mut truncated,
        );
        retain_evidence(
            frame(&[3, 4]),
            &options,
            &mut captured,
            &mut bytes,
            &mut truncated,
        );
        retain_evidence(
            frame(&[5]),
            &options,
            &mut captured,
            &mut bytes,
            &mut truncated,
        );
        assert_eq!(captured.len(), 2);
        assert_eq!(bytes, 4);
        assert!(truncated);

        truncated = false;
        retain_matching_evidence(
            frame(&[9, 9, 9]),
            &options,
            &mut captured,
            &mut bytes,
            &mut truncated,
        );
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].bytes().as_ref(), [9, 9, 9]);
        assert_eq!(bytes, 3);
        assert!(truncated);
    }
}
