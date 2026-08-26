// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact capture-domain identities shared by indexing and reassembly.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frame::GlobalInterfaceId;

/// One semantic identifier in the ordered encapsulation path enclosing a flow.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncapsulationIdentifier {
    Vlan {
        vlan_id: u16,
    },
    Vlan8021ad {
        vlan_id: u16,
    },
    /// Direction-neutral endpoints of an outer IP header.
    Network {
        first: IpAddr,
        second: IpAddr,
    },
    Vxlan {
        vni: u32,
    },
    Geneve {
        vni: u32,
    },
    Gre {
        key: Option<u32>,
    },
    Mpls {
        label: u32,
    },
    Pppoe {
        session_id: u16,
    },
    L2tpv3 {
        session_id: u32,
    },
    Erspan {
        vlan: u16,
        session_id: u16,
    },
    Ah {
        spi: u32,
    },
}

/// Run-local compact identity of one exact capture domain: an interface and
/// the ordered encapsulation path enclosing a flow.
///
/// All keys offered to one index or reassembler must use IDs issued by the
/// same [`Interner`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeId(u32);

impl ScopeId {
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Failure to allocate another compact scope identity.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("capture scope table exhausted its 32-bit identity space")]
    Capacity,
}

/// Exact interner for semantic encapsulation paths and capture scopes.
#[derive(Debug, Default)]
pub struct Interner {
    scopes: HashMap<(Option<GlobalInterfaceId>, Vec<EncapsulationIdentifier>), ScopeId>,
    next: u32,
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the compact ID for an exact interface and encapsulation path.
    pub fn intern(
        &mut self,
        interface: Option<GlobalInterfaceId>,
        encapsulation: Vec<EncapsulationIdentifier>,
    ) -> Result<ScopeId, Error> {
        let scope = (interface, encapsulation);
        if let Some(id) = self.scopes.get(&scope) {
            return Ok(*id);
        }
        let next = self.next.checked_add(1).ok_or(Error::Capacity)?;
        let id = ScopeId(self.next);
        self.next = next;
        self.scopes.insert(scope, id);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn tunnel_path(vni: u32) -> Vec<EncapsulationIdentifier> {
        vec![
            EncapsulationIdentifier::Network {
                first: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                second: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            },
            EncapsulationIdentifier::Vxlan { vni },
        ]
    }

    #[test]
    fn exact_scope_reuses_its_identity() {
        let mut interner = Interner::new();

        let first = interner
            .intern(Some(7), tunnel_path(42))
            .expect("first scope fits");
        let repeated = interner
            .intern(Some(7), tunnel_path(42))
            .expect("same scope reuses its identity");

        assert_eq!(first, repeated);
        assert_eq!(first.get(), 0);
    }

    #[test]
    fn interface_and_encapsulation_are_independent_scope_dimensions() {
        let mut interner = Interner::new();
        let base = interner
            .intern(Some(1), tunnel_path(10))
            .expect("base scope fits");
        let other_interface = interner
            .intern(Some(2), tunnel_path(10))
            .expect("interface-specific scope fits");
        let other_tunnel = interner
            .intern(Some(1), tunnel_path(11))
            .expect("encapsulation-specific scope fits");

        assert_eq!(
            [base.get(), other_interface.get(), other_tunnel.get()],
            [0, 1, 2]
        );
        assert_eq!(
            interner
                .intern(Some(1), tunnel_path(10))
                .expect("base scope is still interned"),
            base
        );
    }
}
