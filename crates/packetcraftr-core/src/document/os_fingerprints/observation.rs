// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use crate::packet::Packet;
use crate::protocol::{
    network::{Fragment, Icmpv4, Icmpv6, Ipv4, Ipv6},
    transport::{Tcp, TcpOption},
};

use super::{AddressFamily, Probe};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpFingerprint {
    pub flags: u16,
    pub window: u16,
    pub option_kinds: Vec<u8>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub probe: Probe,
    pub address_family: AddressFamily,
    pub tcp: Option<TcpFingerprint>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub observed_hop_limit: u8,
    pub ipv4_identification: Option<u16>,
    pub ipv4_dont_fragment: Option<bool>,
    pub sequence: Option<u32>,
    pub acknowledgment: Option<u32>,
    pub timestamp_value: Option<u32>,
    pub timestamp_echo: Option<u32>,
    /// Unknown/malformed options and duplicate singleton options prevent matching.
    pub suitable: bool,
}

impl Observation {
    pub(super) fn stable_eq(&self, other: &Self) -> bool {
        self.address_family == other.address_family
            && self.tcp == other.tcp
            && self.icmp_type == other.icmp_type
            && self.icmp_code == other.icmp_code
            && self.suitable == other.suitable
    }
}

/// Extracts a direct, non-tunneled response. Correlation, checksums and ingress
/// freshness must be established by the caller before this can qualify identity.
pub fn extract(probe: Probe, packet: &Packet) -> Option<Observation> {
    if packet.iter_of::<Ipv4>().count() + packet.iter_of::<Ipv6>().count() != 1 {
        return None;
    }
    if probe != Probe::Echo
        && (packet.get::<Icmpv4>().is_some() || packet.get::<Icmpv6>().is_some())
    {
        return None;
    }
    let (address_family, observed_hop_limit, ipv4_identification, ipv4_dont_fragment) =
        if let Some(ip) = packet.get::<Ipv4>() {
            (
                AddressFamily::Ipv4,
                ip.ttl,
                Some(ip.identification),
                Some(ip.dont_fragment),
            )
        } else {
            let ip = packet.get::<Ipv6>()?;
            (AddressFamily::Ipv6, ip.hop_limit, None, None)
        };
    let mut observation = Observation {
        probe,
        address_family,
        tcp: None,
        icmp_type: None,
        icmp_code: None,
        observed_hop_limit,
        ipv4_identification,
        ipv4_dont_fragment,
        sequence: None,
        acknowledgment: None,
        timestamp_value: None,
        timestamp_echo: None,
        suitable: packet
            .get::<Ipv4>()
            .is_none_or(|ip| !ip.more_fragments && ip.fragment_offset == 0)
            && packet.get::<Fragment>().is_none(),
    };
    if probe == Probe::Echo {
        if let Some(icmp) = packet.get::<Icmpv4>() {
            observation.icmp_type = Some(icmp.icmp_type);
            observation.icmp_code = Some(icmp.code);
        } else {
            let icmp = packet.get::<Icmpv6>()?;
            observation.icmp_type = Some(icmp.icmp_type);
            observation.icmp_code = Some(icmp.code);
        }
        return Some(observation);
    }
    let tcp = packet.get::<Tcp>()?;
    let mut fingerprint = TcpFingerprint {
        flags: tcp.flags,
        window: tcp.window,
        option_kinds: Vec::new(),
        mss: None,
        window_scale: None,
        sack_permitted: false,
        timestamps: false,
    };
    observation.sequence = Some(tcp.sequence);
    observation.acknowledgment = Some(tcp.acknowledgment);
    for option in &tcp.options {
        if let Some(kind) = option.kind() {
            fingerprint.option_kinds.push(kind);
        }
        match option {
            TcpOption::Mss(value) => {
                observation.suitable &= fingerprint.mss.replace(*value).is_none();
            }
            TcpOption::WindowScale(value) => {
                observation.suitable &=
                    *value <= 14 && fingerprint.window_scale.replace(*value).is_none();
            }
            TcpOption::SackPermitted => {
                observation.suitable &= !fingerprint.sack_permitted;
                fingerprint.sack_permitted = true;
            }
            TcpOption::Timestamps { value, echo_reply } => {
                observation.suitable &= !fingerprint.timestamps;
                fingerprint.timestamps = true;
                observation.timestamp_value = Some(*value);
                observation.timestamp_echo = Some(*echo_reply);
            }
            TcpOption::Raw { .. } | TcpOption::Sack(_) => observation.suitable = false,
            TcpOption::Trailing(bytes) => {
                observation.suitable &= bytes.iter().all(|byte| *byte == 0);
            }
            TcpOption::End | TcpOption::Nop => {}
        }
    }
    observation.tcp = Some(fingerprint);
    Some(observation)
}
