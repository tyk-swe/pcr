// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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

/// Keys offered to one index or reassembler must use IDs issued by the same [`Interner`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeId(u32);

impl ScopeId {
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Encapsulation preserves its enclosing order; reverse traffic shares a domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Definition {
    pub id: ScopeId,
    pub interface: Option<u32>,
    pub encapsulation: Arc<[EncapsulationIdentifier]>,
}

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
    #[error("capture scope metadata needs {actual} charged bytes, exceeding {limit}")]
    Bytes { actual: usize, limit: usize },
    #[error("capture scope limit {value} exceeds the {maximum} scopes a 32-bit identity can name")]
    InvalidLimit { value: usize, maximum: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Capacity | Self::Limit { .. } | Self::Bytes { .. } => {
                super::error::resource_limit(super::error::GENERAL_RESOURCE_REMEDIATION)
            }
            Self::InvalidLimit { .. } => Classification::new(
                "cli.analysis_limit",
                Kind::Usage,
                Some("use a scope limit within the 32-bit scope identity space"),
            ),
            Self::Unknown { .. } | Self::ReplayMismatch { .. } => Classification::new(
                "internal.scope_composition",
                Kind::Internal,
                Some("report the capture and command as an internal scope-composition failure"),
            ),
        }
    }
}

pub const MAX_SCOPES: usize = u32::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_scopes: usize,
    /// Conservative retained-byte ceiling, not RSS. Zero refuses new entries.
    pub max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_scopes: MAX_SCOPES,
            max_bytes: usize::MAX,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_scopes > MAX_SCOPES {
            return Err(Error::InvalidLimit {
                value: self.max_scopes,
                maximum: MAX_SCOPES,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct Interner {
    scopes: HashMap<(Option<u32>, Vec<EncapsulationIdentifier>), ScopeId>,
    definitions: Vec<Definition>,
    retained_bytes: usize,
    limits: Limits,
    next: u32,
}

impl Interner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        Ok(Self {
            limits,
            ..Self::default()
        })
    }

    pub fn definition(&self, id: ScopeId) -> Option<&Definition> {
        self.definitions.get(id.get() as usize)
    }

    pub fn definitions(&self) -> &[Definition] {
        &self.definitions
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn intern(
        &mut self,
        interface: Option<u32>,
        encapsulation: Vec<EncapsulationIdentifier>,
    ) -> Result<ScopeId, Error> {
        let scope = (interface, encapsulation);
        if let Some(id) = self.scopes.get(&scope) {
            return Ok(*id);
        }
        if self.scopes.len() >= self.limits.max_scopes {
            return Err(Error::Limit {
                limit: self.limits.max_scopes,
            });
        }
        let charge = scope
            .1
            .capacity()
            .checked_add(scope.1.len())
            .and_then(|count| count.checked_mul(size_of::<EncapsulationIdentifier>()))
            .and_then(|bytes| bytes.checked_add(4 * size_of::<Definition>() + 128))
            .ok_or(Error::Capacity)?;
        let actual = self
            .retained_bytes
            .checked_add(charge)
            .ok_or(Error::Capacity)?;
        if actual > self.limits.max_bytes {
            return Err(Error::Bytes {
                actual,
                limit: self.limits.max_bytes,
            });
        }
        let next = self.next.checked_add(1).ok_or(Error::Capacity)?;
        let id = ScopeId(self.next);
        self.next = next;
        self.definitions.push(Definition {
            id,
            interface: scope.0,
            encapsulation: Arc::from(scope.1.as_slice()),
        });
        self.scopes.insert(scope, id);
        self.retained_bytes = actual;
        Ok(id)
    }

    pub(crate) fn replace_suffix(
        &mut self,
        base: ScopeId,
        replayed: &[EncapsulationIdentifier],
        replacement: &[EncapsulationIdentifier],
    ) -> Result<ScopeId, Error> {
        let index = usize::try_from(base.0).map_err(|_| Error::Unknown { scope: base.0 })?;
        let definition = self
            .definitions
            .get(index)
            .ok_or(Error::Unknown { scope: base.0 })?;
        let interface = definition.interface;
        let mut path = definition.encapsulation.to_vec();
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

    use super::*;

    #[test]
    fn a_scope_limit_beyond_the_identity_space_is_refused() {
        let beyond = Limits {
            max_scopes: MAX_SCOPES + 1,
            ..Limits::default()
        };
        let expected = Error::InvalidLimit {
            value: MAX_SCOPES + 1,
            maximum: MAX_SCOPES,
        };
        assert_eq!(beyond.validate(), Err(expected.clone()));
        assert_eq!(Interner::with_limits(beyond).unwrap_err(), expected);
        assert_eq!(expected.classification().code, "cli.analysis_limit");
        assert!(Limits::default().validate().is_ok());
    }

    #[test]
    fn scope_budget_rejects_before_admission_and_preserves_existing_identity() {
        let path = vec![EncapsulationIdentifier::Vxlan { vni: 7 }; 16];
        let mut measured = Interner::new();
        measured.intern(Some(1), path.clone()).unwrap();
        let charge = measured.retained_bytes();
        for limit in [charge - 1, charge, charge + 1] {
            let mut scopes = Interner::with_limits(Limits {
                max_scopes: 2,
                max_bytes: limit,
            })
            .expect("valid limits");
            let result = scopes.intern(Some(1), path.clone());
            if limit < charge {
                assert!(matches!(result, Err(Error::Bytes { .. })));
                assert_eq!(scopes.retained_bytes(), 0);
            } else {
                let id = result.unwrap();
                assert_eq!(scopes.intern(Some(1), path.clone()).unwrap(), id);
                assert!(matches!(
                    scopes.intern(Some(2), path.clone()),
                    Err(Error::Bytes { .. })
                ));
                assert_eq!(scopes.retained_bytes(), charge);
                assert_eq!(scopes.definition(id).unwrap().interface, Some(1));
            }
        }
    }
}
