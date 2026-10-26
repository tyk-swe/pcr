// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_netio::interface::Id as InterfaceId;

type Decision = packetcraftr_netio::route::Decision;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PreferenceKey {
    destination: IpAddr,
    interface_hint: Option<InterfaceId>,
    preferred_source: Option<IpAddr>,
}

/// Caches passive route decisions for one exchange. Interface lookups may
/// return no decision, unlike preference lookups.
pub(crate) struct CachedProvider<'a, R> {
    inner: &'a R,
    by_preference: Mutex<HashMap<PreferenceKey, Decision>>,
    by_interface: Mutex<HashMap<InterfaceId, Option<Decision>>>,
}

impl<'a, R: packetcraftr_netio::route::Provider> CachedProvider<'a, R> {
    pub(crate) fn new(inner: &'a R) -> Self {
        Self {
            inner,
            by_preference: Mutex::new(HashMap::new()),
            by_interface: Mutex::new(HashMap::new()),
        }
    }
}

fn cached<K: Clone + Eq + std::hash::Hash, V: Clone, E>(
    cache: &Mutex<HashMap<K, V>>,
    key: K,
    lookup: impl FnOnce() -> Result<V, E>,
) -> Result<V, E> {
    let hit = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned();
    if let Some(value) = hit {
        return Ok(value);
    }
    let value = lookup()?;
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, value.clone());
    Ok(value)
}

impl<R: packetcraftr_netio::route::Provider> packetcraftr_netio::route::Provider
    for CachedProvider<'_, R>
{
    type Error = super::Error;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        deadline.live_remaining()?;
        let key = PreferenceKey {
            destination,
            interface_hint: interface_hint.cloned(),
            preferred_source,
        };
        let result = cached(&self.by_preference, key, || {
            self.inner
                .lookup_with_preferences(destination, interface_hint, preferred_source, deadline)
                .map_err(|source| super::Error::RouteLookup {
                    destination,
                    failure: source.classification(),
                    source: Box::new(source),
                })
        });
        deadline.live_remaining()?;
        result
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
        deadline: &Deadline,
    ) -> Result<Option<Decision>, Self::Error> {
        deadline.live_remaining()?;
        let result = cached(&self.by_interface, interface.clone(), || {
            self.inner
                .lookup_interface(interface, deadline)
                .map_err(|source| super::Error::InterfaceLookup {
                    interface: interface.name.clone(),
                    failure: source.classification(),
                    source: Box::new(source),
                })
        });
        deadline.live_remaining()?;
        result
    }
}

#[cfg(test)]
mod tests;
