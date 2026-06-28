// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use super::error::{SpecError, SpecResult};
use pnet::packet::ethernet::EtherTypes;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};

use crate::engine::request::{Layer2Request, VlanRequest};

#[derive(Debug, Clone, Default)]
pub struct Layer2Spec {
    pub source: Option<MacAddr>,
    pub destination: Option<MacAddr>,
    pub ethertype: Option<u16>,
    pub vlan: Option<VlanTag>,
}

impl Layer2Spec {
    pub(crate) fn from_request(request: &Layer2Request) -> SpecResult<Self> {
        let vlan = parse_vlan_tag(&request.vlan)?;
        Ok(Self {
            source: parse_mac_option(request.source_mac.as_deref())?,
            destination: parse_mac_option(request.destination_mac.as_deref())?,
            ethertype: parse_ethertype_option(request.ethertype.as_deref())?,
            vlan,
        })
    }
}

/// IEEE 802.1Q VLAN tag parameters extracted from user input.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VlanTag {
    /// VLAN identifier (VID). Values 0 and 4095 are reserved per 802.1Q.
    pub identifier: u16,
    /// Priority Code Point (PCP) used for quality-of-service classification.
    pub priority: u8,
    /// Drop Eligible Indicator (DEI) bit signalled for congestion handling.
    pub drop_eligible_indicator: bool,
}

pub(crate) fn parse_vlan_tag(request: &VlanRequest) -> SpecResult<Option<VlanTag>> {
    let id = match request.id {
        Some(value) => value,
        None => {
            if request.priority.is_some() {
                return Err(SpecError::VlanPriorityRequiresId);
            }
            if request.drop_eligible_indicator.unwrap_or(false) {
                return Err(SpecError::VlanDeiRequiresId);
            }
            return Ok(None);
        }
    };

    if !(1..=4094).contains(&id) {
        return Err(SpecError::VlanIdInvalid { value: id });
    }

    let priority = request.priority.unwrap_or(0);
    if priority > 7 {
        return Err(SpecError::VlanPriorityInvalid { value: priority });
    }

    Ok(Some(VlanTag {
        identifier: id,
        priority,
        drop_eligible_indicator: request.drop_eligible_indicator.unwrap_or(false),
    }))
}

pub(crate) fn parse_mac_option(value: Option<&str>) -> SpecResult<Option<MacAddr>> {
    match value {
        Some(raw) => {
            let trimmed = raw.trim();
            Ok(Some(MacAddr::from_str(trimmed).map_err(|source| {
                SpecError::MacAddressParse {
                    value: raw.to_string(),
                    source,
                }
            })?))
        }
        None => Ok(None),
    }
}

pub(crate) fn parse_ethertype_option(value: Option<&str>) -> SpecResult<Option<u16>> {
    value.map(parse_ethertype).transpose()
}

pub(crate) fn parse_ethertype(value: &str) -> SpecResult<u16> {
    let lower = value.trim().to_ascii_lowercase();
    let ethertype = match lower.as_str() {
        "ipv4" => EtherTypes::Ipv4.0,
        "ipv6" => EtherTypes::Ipv6.0,
        "arp" => EtherTypes::Arp.0,
        "vlan" => EtherTypes::Vlan.0,
        "pppoe" => EtherTypes::PppoeDiscovery.0,
        "pppoe-session" => EtherTypes::PppoeSession.0,
        other => {
            if let Some(hex) = other.strip_prefix("0x") {
                u16::from_str_radix(hex, 16).map_err(|source| SpecError::EtherTypeParse {
                    value: value.to_string(),
                    source,
                })?
            } else {
                other
                    .parse::<u16>()
                    .map_err(|source| SpecError::EtherTypeParse {
                        value: value.to_string(),
                        source,
                    })?
            }
        }
    };
    Ok(ethertype)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_option_handles_none_valid_and_invalid_values() {
        assert!(parse_mac_option(None).unwrap().is_none());

        for input in ["aa:bb:cc:dd:ee:ff", "  aa:bb:cc:dd:ee:ff  "] {
            assert_eq!(
                parse_mac_option(Some(input)).unwrap().unwrap().to_string(),
                "aa:bb:cc:dd:ee:ff"
            );
        }

        assert!(matches!(
            parse_mac_option(Some("invalid_mac")),
            Err(SpecError::MacAddressParse { .. })
        ));
    }

    #[test]
    fn parse_ethertype_handles_named_numeric_and_invalid_values() {
        let cases = [
            ("ipv4", 0x0800),
            ("ipv6", 0x86DD),
            ("arp", 0x0806),
            ("vlan", 0x8100),
            ("0x0800", 0x0800),
            ("2048", 2048),
            ("IPv4", 0x0800),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_ethertype(input).unwrap(), expected, "{input}");
        }

        assert!(matches!(
            parse_ethertype("invalid"),
            Err(SpecError::EtherTypeParse { .. })
        ));
    }

    #[test]
    fn parse_vlan_tag_accepts_absent_and_valid_tag_fields() {
        assert!(parse_vlan_tag(&VlanRequest::default()).unwrap().is_none());

        let tag = parse_vlan_tag(&VlanRequest {
            id: Some(100),
            priority: Some(7),
            drop_eligible_indicator: Some(true),
        })
        .unwrap()
        .unwrap();
        assert_eq!(tag.identifier, 100);
        assert_eq!(tag.priority, 7);
        assert!(tag.drop_eligible_indicator);

        for id in [1, 2000, 4094] {
            let tag = parse_vlan_tag(&VlanRequest {
                id: Some(id),
                ..Default::default()
            })
            .unwrap()
            .unwrap();
            assert_eq!(tag.identifier, id);
            assert_eq!(tag.priority, 0);
            assert!(!tag.drop_eligible_indicator);
        }
    }

    #[test]
    fn parse_vlan_tag_rejects_invalid_combinations_and_reserved_values() {
        let missing_id_priority = VlanRequest {
            priority: Some(3),
            ..Default::default()
        };
        assert!(matches!(
            parse_vlan_tag(&missing_id_priority),
            Err(SpecError::VlanPriorityRequiresId)
        ));

        let missing_id_dei = VlanRequest {
            drop_eligible_indicator: Some(true),
            ..Default::default()
        };
        assert!(matches!(
            parse_vlan_tag(&missing_id_dei),
            Err(SpecError::VlanDeiRequiresId)
        ));

        for id in [0, 4095, 4096, u16::MAX] {
            assert!(matches!(
                parse_vlan_tag(&VlanRequest {
                    id: Some(id),
                    ..Default::default()
                }),
                Err(SpecError::VlanIdInvalid { value }) if value == id
            ));
        }

        for priority in [8, 255] {
            assert!(matches!(
                parse_vlan_tag(&VlanRequest {
                    id: Some(100),
                    priority: Some(priority),
                    ..Default::default()
                }),
                Err(SpecError::VlanPriorityInvalid { value }) if value == priority
            ));
        }
    }
}
