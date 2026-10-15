// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::probe;
use crate::scan::plan::Probe;
use packetcraftr_core::protocol::network::ip_protocol;

/// Header-only IP replies have no echoed attempt identity. IPv6 extension
/// replies may also match a probe for a protocol carried after that header.
pub(in crate::scan) fn replies_overlap(a: &Probe, b: &Probe) -> bool {
    if a.address != b.address
        || (a.endpoint.ip_protocol().is_none() && b.endpoint.ip_protocol().is_none())
    {
        return false;
    }
    response_protocol(a.endpoint, a.address.is_ipv6())
        == response_protocol(b.endpoint, b.address.is_ipv6())
        || (a.address.is_ipv6() && (extension_probe(a.endpoint) || extension_probe(b.endpoint)))
}

pub(in crate::scan) fn response_protocol(endpoint: probe::Endpoint, ipv6: bool) -> u8 {
    match endpoint {
        probe::Endpoint::Ip { protocol } => protocol,
        probe::Endpoint::Tcp { .. } | probe::Endpoint::TcpAck { .. } => ip_protocol::TCP,
        probe::Endpoint::Udp { .. } => ip_protocol::UDP,
        probe::Endpoint::Sctp { .. } => ip_protocol::SCTP,
        probe::Endpoint::Icmp | probe::Endpoint::IcmpTimestamp | probe::Endpoint::IcmpNetmask => {
            if ipv6 {
                ip_protocol::ICMPV6
            } else {
                ip_protocol::ICMPV4
            }
        }
    }
}

fn extension_probe(endpoint: probe::Endpoint) -> bool {
    endpoint.ip_protocol().is_some_and(|protocol| {
        matches!(
            protocol,
            ip_protocol::HOP_BY_HOP
                | ip_protocol::ROUTING
                | ip_protocol::FRAGMENT
                | ip_protocol::AH
                | ip_protocol::DESTINATION_OPTIONS
        )
    })
}

/// Every overlap-induced pause lasts at most one probe timeout. Count the
/// sends after the first member of each potentially conflicting identity.
/// IPv6 extension probes can conflict with every other endpoint at an address.
pub(super) fn overlap_waits(
    targets: &[crate::target::SelectedAddress],
    endpoints: &[probe::Endpoint],
    attempts: u32,
) -> Option<usize> {
    if !endpoints
        .iter()
        .any(|endpoint| endpoint.ip_protocol().is_some())
    {
        return Some(0);
    }
    let mut members = [[0usize; 256]; 2];
    let mut opaque = [false; 256];
    let mut extensions = false;
    for &endpoint in endpoints {
        for (family, counts) in members.iter_mut().enumerate() {
            let protocol = usize::from(response_protocol(endpoint, family == 1));
            counts[protocol] = counts[protocol].checked_add(1)?;
        }
        if let Some(protocol) = endpoint.ip_protocol() {
            opaque[usize::from(protocol)] = true;
        }
        extensions |= extension_probe(endpoint);
    }
    // The executor compares numeric addresses, including targets selected on
    // multiple scoped interfaces, so admission groups them the same way.
    let mut addresses = std::collections::BTreeMap::<std::net::IpAddr, usize>::new();
    for target in targets {
        let count = addresses.entry(target.address).or_default();
        *count = count.checked_add(1)?;
    }
    let mut waits = 0usize;
    for (address, count) in addresses {
        let repetitions = count.checked_mul(usize::try_from(attempts).ok()?)?;
        if address.is_ipv6() && extensions {
            waits =
                waits.checked_add(endpoints.len().checked_mul(repetitions)?.saturating_sub(1))?;
        } else {
            for (protocol, &count) in members[usize::from(address.is_ipv6())].iter().enumerate() {
                if opaque[protocol] {
                    waits = waits.checked_add(count.checked_mul(repetitions)?.saturating_sub(1))?;
                }
            }
        }
    }
    Some(waits)
}
