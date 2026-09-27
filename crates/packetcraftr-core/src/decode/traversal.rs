// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{codec::NetworkEnvelope, protocol::BuiltinProtocol, registry::Registry};

pub(super) struct TraversalScope {
    allow_trailing_padding: bool,
    network: Option<NetworkEnvelope>,
}

impl TraversalScope {
    pub(super) fn new(registry: &Registry, root: &crate::layer::Id) -> Self {
        Self {
            allow_trailing_padding: registry.allows_trailing_padding(root.as_str()),
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
        registry: &Registry,
        parent: &crate::layer::Id,
        child: Option<&crate::layer::Id>,
    ) {
        if BuiltinProtocol::from_id(*parent).is_some_and(BuiltinProtocol::is_encapsulation_boundary)
        {
            self.network = None;
            self.allow_trailing_padding =
                child.is_some_and(|child| registry.allows_trailing_padding(child.as_str()));
        }
    }
}
