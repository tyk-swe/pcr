// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Network-envelope and link-padding scope for decode traversal.

use crate::{codec::NetworkEnvelope, protocol::BuiltinProtocol};

pub(super) struct TraversalScope {
    allow_trailing_padding: bool,
    network: Option<NetworkEnvelope>,
}

impl TraversalScope {
    pub(super) fn new(root: &crate::layer::Id) -> Self {
        Self {
            allow_trailing_padding: link_scope_allows_padding(BuiltinProtocol::from_id(*root)),
            network: None,
        }
    }

    pub(super) fn network(&self) -> Option<NetworkEnvelope> {
        self.network
    }

    pub(super) fn allows_current_link_padding(&self) -> bool {
        self.allow_trailing_padding && self.network.is_none()
    }

    pub(super) fn accept_network(&mut self, network: Option<NetworkEnvelope>) {
        if let Some(network) = network {
            self.network = Some(network);
        }
    }

    pub(super) fn enter_child(
        &mut self,
        parent: &crate::layer::Id,
        child: Option<&crate::layer::Id>,
    ) {
        if BuiltinProtocol::from_id(*parent).is_some_and(BuiltinProtocol::is_encapsulation_boundary)
        {
            self.network = None;
            self.allow_trailing_padding =
                link_scope_allows_padding(child.copied().and_then(BuiltinProtocol::from_id));
        }
    }
}

fn link_scope_allows_padding(root: Option<BuiltinProtocol>) -> bool {
    matches!(
        root,
        Some(
            BuiltinProtocol::Ethernet
                | BuiltinProtocol::Vlan
                | BuiltinProtocol::Vlan8021ad
                | BuiltinProtocol::BsdNull
                | BuiltinProtocol::BsdLoop
                | BuiltinProtocol::LinuxSll
                | BuiltinProtocol::LinuxSll2
        )
    )
}
