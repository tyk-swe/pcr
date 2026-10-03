// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, PoisonError};

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface::{self, Id as InterfaceId};

use super::Error;

/// A name or index selector is resolved through the client's interface
/// provider only after the operation is admitted, so a refused operation
/// never enumerates interfaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Interface {
    Id(InterfaceId),
    Name(String),
    Index(NonZeroU32),
}

impl Interface {
    #[must_use]
    pub fn matches(&self, id: &InterfaceId) -> bool {
        match self {
            Self::Id(selected) => selected == id,
            Self::Name(name) => id.name == *name,
            Self::Index(index) => id.index == index.get(),
        }
    }

    pub(crate) fn id(&self) -> Option<&InterfaceId> {
        match self {
            Self::Id(id) => Some(id),
            Self::Name(_) | Self::Index(_) => None,
        }
    }
}

impl From<InterfaceId> for Interface {
    fn from(id: InterfaceId) -> Self {
        Self::Id(id)
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(InterfaceId { name, .. }) | Self::Name(name) => formatter.write_str(name),
            Self::Index(index) => write!(formatter, "{index}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ResolvedInterface(Arc<Mutex<Option<(Interface, InterfaceId)>>>);

impl ResolvedInterface {
    pub(crate) fn resolve<N: interface::Provider + ?Sized>(
        &self,
        selector: &Interface,
        provider: &N,
        deadline: &Deadline,
    ) -> Result<InterfaceId, Error> {
        if let Some(id) = selector.id() {
            return Ok(id.clone());
        }
        let cached = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((resolved, id)) = cached.as_ref()
            && resolved == selector
        {
            return Ok(id.clone());
        }
        drop(cached);
        let id = provider
            .interfaces(deadline)?
            .into_iter()
            .map(|info| info.id)
            .find(|id| selector.matches(id))
            .ok_or_else(|| Error::UnknownInterface {
                selector: selector.to_string(),
            })?;
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((selector.clone(), id.clone()));
        Ok(id)
    }

    /// Drops the memo only while it still names `stale`; another operation
    /// may already have replaced it with a fresh resolution.
    pub(crate) fn forget(&self, stale: &InterfaceId) {
        let mut cached = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if cached.as_ref().is_some_and(|(_, id)| id == stale) {
            *cached = None;
        }
    }
}
