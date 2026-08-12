// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact capture-domain identities shared by indexing and reassembly.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

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

/// An exact, shared encapsulation descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InternedEncapsulationPath(Arc<[EncapsulationIdentifier]>);

impl InternedEncapsulationPath {
    #[must_use]
    pub fn as_slice(&self) -> &[EncapsulationIdentifier] {
        &self.0
    }
}

/// Exact capture domain before it is reduced to a compact [`ScopeId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowScope {
    pub interface: Option<GlobalInterfaceId>,
    pub encapsulation: InternedEncapsulationPath,
}

/// Run-local compact identity of one exact [`FlowScope`].
///
/// All keys offered to one index or reassembler must use IDs issued by the
/// same [`ScopeInterner`].
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
pub enum ScopeError {
    #[error("capture scope table exhausted its 32-bit identity space")]
    Capacity,
}

/// Exact interner for semantic encapsulation paths and capture scopes.
#[derive(Debug, Default)]
pub struct ScopeInterner {
    paths: HashSet<InternedEncapsulationPath>,
    scopes: HashMap<FlowScope, ScopeId>,
    descriptors: Vec<FlowScope>,
}

impl ScopeInterner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the compact ID for an exact interface and encapsulation path.
    pub fn intern(
        &mut self,
        interface: Option<GlobalInterfaceId>,
        encapsulation: Vec<EncapsulationIdentifier>,
    ) -> Result<ScopeId, ScopeError> {
        let candidate = InternedEncapsulationPath(Arc::from(encapsulation));
        let encapsulation = match self.paths.get(&candidate) {
            Some(existing) => existing.clone(),
            None => {
                self.paths.insert(candidate.clone());
                candidate
            }
        };
        let scope = FlowScope {
            interface,
            encapsulation,
        };
        if let Some(id) = self.scopes.get(&scope) {
            return Ok(*id);
        }
        let id = ScopeId(u32::try_from(self.descriptors.len()).map_err(|_| ScopeError::Capacity)?);
        self.scopes.insert(scope.clone(), id);
        self.descriptors.push(scope);
        Ok(id)
    }

    #[must_use]
    pub fn get(&self, id: ScopeId) -> Option<&FlowScope> {
        usize::try_from(id.0)
            .ok()
            .and_then(|index| self.descriptors.get(index))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }
}
