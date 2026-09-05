// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact capture-domain identities shared by indexing and reassembly.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frame::GlobalInterfaceId;

/// One semantic identifier in the ordered encapsulation path enclosing a flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
        /// Sorted endpoints of the enclosing Ethernet header, when present.
        endpoints: Option<([u8; 6], [u8; 6])>,
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
    #[error("capture scope {scope} was not issued by this interner")]
    Unknown { scope: u32 },
    #[error("capture scope {scope} does not end with the expected replayed encapsulation")]
    ReplayMismatch { scope: u32 },
    #[error("capture scope table reached configured limit {limit}")]
    Limit { limit: usize },
}

/// Exact interner for semantic encapsulation paths and capture scopes.
#[derive(Debug)]
pub struct Interner {
    scopes: HashMap<(Option<GlobalInterfaceId>, Vec<EncapsulationIdentifier>), ScopeId>,
    definitions: Vec<(Option<GlobalInterfaceId>, Vec<EncapsulationIdentifier>)>,
    next: u32,
    limit: usize,
}

impl Default for Interner {
    fn default() -> Self {
        Self {
            scopes: HashMap::new(),
            definitions: Vec::new(),
            next: 0,
            limit: usize::MAX,
        }
    }
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
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
        if self.scopes.len() >= self.limit {
            return Err(Error::Limit { limit: self.limit });
        }
        let next = self.next.checked_add(1).ok_or(Error::Capacity)?;
        let id = ScopeId(self.next);
        self.next = next;
        self.scopes.insert(scope.clone(), id);
        self.definitions.push(scope);
        Ok(id)
    }

    /// Replaces identifiers replayed while decoding a reconstructed datagram
    /// before appending the complete derived encapsulation path.
    pub(crate) fn replace_suffix(
        &mut self,
        base: ScopeId,
        replayed: &[EncapsulationIdentifier],
        replacement: &[EncapsulationIdentifier],
    ) -> Result<ScopeId, Error> {
        let index = usize::try_from(base.0).map_err(|_| Error::Unknown { scope: base.0 })?;
        let (interface, mut path) = self
            .definitions
            .get(index)
            .cloned()
            .ok_or(Error::Unknown { scope: base.0 })?;
        if !path.ends_with(replayed) {
            return Err(Error::ReplayMismatch { scope: base.0 });
        }
        path.truncate(path.len().saturating_sub(replayed.len()));
        path.try_reserve(replacement.len())
            .map_err(|_| Error::Capacity)?;
        path.extend_from_slice(replacement);
        self.intern(interface, path)
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

    #[test]
    fn derived_encapsulation_extends_the_exact_physical_scope() {
        let mut interner = Interner::new();
        let base_path = tunnel_path(10);
        let base = interner
            .intern(Some(7), base_path.clone())
            .expect("base scope fits");
        let suffix = [EncapsulationIdentifier::Gre { key: Some(42) }];
        let extended = interner
            .replace_suffix(base, &[], &suffix)
            .expect("derived scope extension fits");
        let mut expected_path = base_path;
        expected_path.extend_from_slice(&suffix);
        let expected = interner
            .intern(Some(7), expected_path)
            .expect("composed scope is interned");

        assert_eq!(extended, expected);
        assert_ne!(extended, base);
        assert_eq!(
            interner
                .replace_suffix(base, &[], &[])
                .expect("empty suffix reuses base"),
            base
        );
    }

    #[test]
    fn derived_encapsulation_replaces_replayed_scope_suffix_in_order() {
        let mut interner = Interner::new();
        let ah = EncapsulationIdentifier::Ah { spi: 42 };
        let base = interner
            .intern(Some(7), vec![ah])
            .expect("fragment scope fits");
        let mut replacement = tunnel_path(10);
        replacement.insert(1, ah);
        let composed = interner
            .replace_suffix(base, std::slice::from_ref(&ah), &replacement)
            .expect("replayed suffix composes");
        let expected = interner
            .intern(Some(7), replacement)
            .expect("unfragmented scope is interned");

        assert_eq!(composed, expected);
    }

    #[test]
    fn configured_scope_limit_bounds_persistent_path_metadata() {
        let mut interner = Interner::with_limit(1);
        let first = interner
            .intern(Some(1), tunnel_path(10))
            .expect("first scope fits");
        assert_eq!(
            interner
                .intern(Some(1), tunnel_path(10))
                .expect("existing scope remains reusable"),
            first
        );
        assert_eq!(
            interner.intern(Some(1), tunnel_path(11)),
            Err(Error::Limit { limit: 1 })
        );
    }
}
