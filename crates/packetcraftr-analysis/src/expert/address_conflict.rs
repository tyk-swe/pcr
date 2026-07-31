// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use packetcraftr_capture::LinkType;
use packetcraftr_packet::diagnostic::DiagnosticSeverity;
use packetcraftr_protocol::link::{Arp, Ethernet, Vlan, Vlan8021ad};
use packetcraftr_protocol::network::Ipv4;

use super::{Finding, FrameRecord, new_finding};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Tag {
    Ieee8021Q(u16),
    Ieee8021Ad(u16),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Scope {
    interface: Option<u32>,
    tags: Vec<Tag>,
    address: Ipv4Addr,
}

#[derive(Clone, Copy, Debug)]
struct Claim {
    mac: [u8; 6],
    first_frame: u64,
}

#[derive(Debug)]
struct Claims {
    first: Claim,
    macs: HashSet<[u8; 6]>,
}

#[derive(Debug, Default)]
pub(super) struct State {
    claims: HashMap<Scope, Claims>,
    claim_count: usize,
}

impl State {
    pub(super) fn observe(&mut self, record: &FrameRecord<'_>, findings: &mut Vec<Finding>) {
        if record.decoded.frame.link_type != LinkType::ETHERNET {
            return;
        }
        let max_claims = record.max_flows();
        let packet = &record.decoded.packet;
        let Some(ethernet) = packet
            .layer(0)
            .and_then(|layer| layer.as_any().downcast_ref::<Ethernet>())
        else {
            return;
        };
        let mut tags = Vec::new();
        let mut index = 1;
        while let Some(layer) = packet.layer(index) {
            if let Some(vlan) = layer.as_any().downcast_ref::<Vlan>() {
                tags.push(Tag::Ieee8021Q(vlan.vlan_id));
            } else if let Some(vlan) = layer.as_any().downcast_ref::<Vlan8021ad>() {
                tags.push(Tag::Ieee8021Ad(vlan.vlan_id));
            } else {
                break;
            }
            index += 1;
        }
        let Some(layer) = packet.layer(index) else {
            return;
        };
        let observation = if let Some(arp) = layer.as_any().downcast_ref::<Arp>() {
            if unusable_ipv4(arp.sender_protocol) || unusable_mac(arp.sender_hardware) {
                return;
            }
            Some((
                arp.sender_protocol,
                arp.sender_hardware,
                "arp.address_conflict",
            ))
        } else if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            if unusable_ipv4(ipv4.source) || unusable_mac(ethernet.source) {
                return;
            }
            Some((ipv4.source, ethernet.source, "ipv4.address_conflict"))
        } else {
            None
        };
        let Some((address, mac, code)) = observation else {
            return;
        };
        let scope = Scope {
            interface: record.decoded.frame.interface,
            tags,
            address,
        };
        let previous = if let Some(claims) = self.claims.get_mut(&scope) {
            if claims.macs.contains(&mac) || self.claim_count >= max_claims {
                return;
            }
            let previous = claims.first;
            let _ = claims.macs.insert(mac);
            self.claim_count += 1;
            Some(previous)
        } else {
            if self.claim_count >= max_claims {
                return;
            }
            let first = Claim {
                mac,
                first_frame: record.number,
            };
            self.claims.insert(
                scope.clone(),
                Claims {
                    first,
                    macs: HashSet::from([mac]),
                },
            );
            self.claim_count += 1;
            None
        };
        if let Some(previous) = previous {
            findings.push(new_finding(
                DiagnosticSeverity::Warning,
                code,
                record.number,
                None,
                format!(
                    "observed conflicting ownership evidence for {} in {}: {} (first seen frame \
                     {}) and newly observed {}",
                    address,
                    display_scope(&scope),
                    display_mac(previous.mac),
                    previous.first_frame,
                    display_mac(mac),
                ),
            ));
        }
    }
}

fn unusable_mac(mac: [u8; 6]) -> bool {
    mac == [0; 6] || mac == [0xff; 6] || mac[0] & 1 != 0
}

fn unusable_ipv4(address: Ipv4Addr) -> bool {
    matches!(address.octets()[0], 0 | 127 | 224..=255)
}

fn display_scope(scope: &Scope) -> String {
    let interface = scope
        .interface
        .map_or_else(|| "implicit".to_owned(), |id| id.to_string());
    let tags = if scope.tags.is_empty() {
        "untagged".to_owned()
    } else {
        scope
            .tags
            .iter()
            .map(|tag| match tag {
                Tag::Ieee8021Q(id) => format!("802.1Q:{id}"),
                Tag::Ieee8021Ad(id) => format!("802.1ad:{id}"),
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    format!("interface {interface}, Ethernet VLAN scope {tags}")
}

fn display_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
