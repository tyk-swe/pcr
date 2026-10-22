// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;

use packetcraftr_core::{packet::Packet, protocol::semantics};
use packetcraftr_netio::interface;

use crate::scan::{Probe, plan::response_protocol};

/// Compact operation-scoped identities, without retained packets or frames.
/// Each new group requires a successfully sent, admitted probe, so both groups
/// and interfaces are bounded by the operation's finite max_probes budget.
pub(super) struct ReplyHistory {
    enabled: bool,
    interfaces: HashMap<interface::Id, HashMap<(IpAddr, IpAddr), [u8; 256]>>,
}

impl ReplyHistory {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            interfaces: HashMap::new(),
        }
    }

    pub(super) fn sent(&mut self, probe: &Probe, packet: &Packet, interface: &interface::Id) {
        if !self.enabled {
            return;
        }
        let Some(path) = semantics::outer_ip_path(packet).ok().flatten() else {
            return;
        };
        let counts = self
            .interfaces
            .entry(interface.clone())
            .or_default()
            .entry((path.source, path.final_destination))
            .or_insert([0; 256]);
        let protocol = usize::from(response_protocol(probe.endpoint, path.source.is_ipv6()));
        // Only zero, one, or more than one transmission matters.
        counts[protocol] = counts[protocol].saturating_add(1).min(2);
    }

    pub(super) fn ambiguous(
        &self,
        probe: &Probe,
        response: &Packet,
        interface: &interface::Id,
    ) -> bool {
        let Some(path) = semantics::outer_ip_path(response).ok().flatten() else {
            return false;
        };
        let Some(counts) = self
            .interfaces
            .get(interface)
            .and_then(|groups| groups.get(&(path.final_destination, path.source)))
        else {
            return false;
        };
        let current = response_protocol(probe.endpoint, path.source.is_ipv6());
        counts.iter().enumerate().any(|(protocol, &count)| {
            count > u8::from(protocol == usize::from(current))
                && crate::engine::correlation::outer_has_protocol(response, protocol as u8)
        })
    }
}
