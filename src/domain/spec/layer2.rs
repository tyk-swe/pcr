// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::str::FromStr;

use super::error::{SpecError, SpecResult};
use pnet::packet::ethernet::EtherTypes;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};

use crate::domain::request::{Layer2Request, VlanRequest};

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
