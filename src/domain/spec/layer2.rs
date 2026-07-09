// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use super::error::{SpecError, SpecResult};
use serde::{Deserialize, Serialize};

use crate::domain::net::{EtherType, MacAddress};
use crate::domain::request::{Layer2Request, VlanRequest};

#[derive(Debug, Clone, Default)]
pub(crate) struct Layer2Spec {
    pub source: Option<MacAddress>,
    pub destination: Option<MacAddress>,
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
pub(crate) struct VlanTag {
    /// VLAN identifier (VID). Values 0 and 4095 are reserved per 802.1Q.
    pub identifier: u16,
    /// Priority Code Point (PCP) used for quality-of-service classification.
    pub priority: u8,
    /// Drop Eligible Indicator (DEI) bit signalled for congestion handling.
    pub drop_eligible_indicator: bool,
}

pub(crate) fn parse_vlan_tag(request: &VlanRequest) -> SpecResult<Option<VlanTag>> {
    let Some(id) = request.id else {
        if request.priority.is_some() {
            return Err(SpecError::VlanPriorityRequiresId);
        }
        if request.drop_eligible_indicator.unwrap_or(false) {
            return Err(SpecError::VlanDeiRequiresId);
        }
        return Ok(None);
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

pub(crate) fn parse_mac_option(value: Option<&str>) -> SpecResult<Option<MacAddress>> {
    match value {
        Some(raw) => {
            let trimmed = raw.trim();
            Ok(Some(MacAddress::from_str(trimmed).map_err(|source| {
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
        "ipv4" => EtherType::IPV4.0,
        "ipv6" => EtherType::IPV6.0,
        "arp" => EtherType::ARP.0,
        "vlan" => EtherType::VLAN.0,
        "pppoe" => EtherType::PPPOE_DISCOVERY.0,
        "pppoe-session" => EtherType::PPPOE_SESSION.0,
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
    use crate::domain::request::{Layer2Request, VlanRequest};

    #[test]
    fn parse_vlan_tag_returns_none_for_empty_request() {
        assert!(parse_vlan_tag(&VlanRequest::default()).unwrap().is_none());
    }

    #[test]
    fn parse_vlan_tag_applies_defaults() {
        let tag = parse_vlan_tag(&VlanRequest {
            id: Some(100),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(tag.identifier, 100);
        assert_eq!(tag.priority, 0);
        assert!(!tag.drop_eligible_indicator);
    }

    #[test]
    fn parse_vlan_tag_preserves_priority_and_dei() {
        let tag = parse_vlan_tag(&VlanRequest {
            id: Some(4094),
            priority: Some(7),
            drop_eligible_indicator: Some(true),
        })
        .unwrap()
        .unwrap();

        assert_eq!(tag.identifier, 4094);
        assert_eq!(tag.priority, 7);
        assert!(tag.drop_eligible_indicator);
    }

    #[test]
    fn parse_vlan_tag_rejects_priority_without_id() {
        let err = parse_vlan_tag(&VlanRequest {
            priority: Some(1),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::VlanPriorityRequiresId));
    }

    #[test]
    fn parse_vlan_tag_rejects_dei_without_id() {
        let err = parse_vlan_tag(&VlanRequest {
            drop_eligible_indicator: Some(true),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::VlanDeiRequiresId));
    }

    #[test]
    fn parse_vlan_tag_rejects_reserved_id_and_bad_priority() {
        let id_err = parse_vlan_tag(&VlanRequest {
            id: Some(0),
            ..Default::default()
        })
        .unwrap_err();
        let reserved_err = parse_vlan_tag(&VlanRequest {
            id: Some(4095),
            ..Default::default()
        })
        .unwrap_err();
        let prio_err = parse_vlan_tag(&VlanRequest {
            id: Some(10),
            priority: Some(8),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(id_err, SpecError::VlanIdInvalid { value: 0 }));
        assert!(matches!(
            reserved_err,
            SpecError::VlanIdInvalid { value: 4095 }
        ));
        assert!(matches!(
            prio_err,
            SpecError::VlanPriorityInvalid { value: 8 }
        ));
    }

    #[test]
    fn parse_mac_option_trims_input() {
        let mac = parse_mac_option(Some(" aa:bb:cc:dd:ee:ff ")).unwrap();

        assert_eq!(mac.unwrap().to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parse_mac_option_rejects_empty_trimmed_input() {
        let err = parse_mac_option(Some("   ")).unwrap_err();

        assert!(matches!(
            err,
            SpecError::MacAddressParse { ref value, .. } if value == "   "
        ));
    }

    #[test]
    fn parse_ethertype_accepts_names_decimal_and_hex() {
        assert_eq!(parse_ethertype("ipv4").unwrap(), EtherType::IPV4.0);
        assert_eq!(parse_ethertype(" IPV6 ").unwrap(), EtherType::IPV6.0);
        assert_eq!(parse_ethertype("34525").unwrap(), EtherType::IPV6.0);
        assert_eq!(parse_ethertype("0x0806").unwrap(), EtherType::ARP.0);
        assert_eq!(parse_ethertype("0Xffff").unwrap(), u16::MAX);
    }

    #[test]
    fn parse_ethertype_rejects_invalid_value() {
        let err = parse_ethertype("not-an-ethertype").unwrap_err();

        assert!(matches!(err, SpecError::EtherTypeParse { .. }));
    }

    #[test]
    fn layer2_spec_from_request_parses_all_fields() {
        let spec = Layer2Spec::from_request(&Layer2Request {
            source_mac: Some("00:11:22:33:44:55".to_string()),
            destination_mac: Some("66-77-88-99-aa-bb".to_string()),
            ethertype: Some("vlan".to_string()),
            vlan: VlanRequest {
                id: Some(20),
                priority: Some(3),
                drop_eligible_indicator: Some(true),
            },
        })
        .unwrap();

        assert_eq!(spec.source.unwrap().to_string(), "00:11:22:33:44:55");
        assert_eq!(spec.destination.unwrap().to_string(), "66:77:88:99:aa:bb");
        assert_eq!(spec.ethertype, Some(EtherType::VLAN.0));
        assert_eq!(spec.vlan.unwrap().identifier, 20);
    }
}
