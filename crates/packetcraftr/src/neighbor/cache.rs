// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use super::Request as NeighborRequest;
use super::error::invalid_options;
use super::options::Options;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::{MacAddress, VlanTag};
use packetcraftr_netio::interface::Id as InterfaceId;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct NeighborCacheKey {
    interface: InterfaceId,
    interface_source: IpAddr,
    interface_mac: MacAddress,
    target: IpAddr,
    vlan_tags: Vec<VlanTag>,
    link_type: LinkType,
}

impl From<&NeighborRequest> for NeighborCacheKey {
    fn from(request: &NeighborRequest) -> Self {
        Self {
            interface: request.interface.clone(),
            interface_source: request.interface_source,
            interface_mac: request.interface_mac,
            target: request.target,
            vlan_tags: request.vlan_tags.clone(),
            link_type: request.link_type,
        }
    }
}

#[derive(Debug)]
pub(super) struct NeighborCacheEntry {
    pub(super) mac_address: MacAddress,
    pub(super) inserted_at: Instant,
    pub(super) expires_at: Instant,
}

#[derive(Debug, Default)]
pub(super) struct NeighborCache {
    entries: Mutex<HashMap<NeighborCacheKey, NeighborCacheEntry>>,
}

impl NeighborCache {
    pub(super) fn get(
        &self,
        key: &NeighborCacheKey,
    ) -> Result<Option<MacAddress>, crate::neighbor::Error> {
        let mut cache = self
            .entries
            .lock()
            .map_err(|_| crate::neighbor::Error::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?;
        let Some(entry) = cache.get(key) else {
            return Ok(None);
        };
        if entry.expires_at > Instant::now() {
            return Ok(Some(entry.mac_address));
        }
        cache.remove(key);
        Ok(None)
    }

    pub(super) fn insert(
        &self,
        mac_address: MacAddress,
        key: NeighborCacheKey,
        options: &Options,
    ) -> Result<(), crate::neighbor::Error> {
        let now = Instant::now();
        let expires_at = now
            .checked_add(options.cache_ttl)
            .ok_or_else(|| invalid_options("cache deadline overflowed".to_owned()))?;
        let mut cache = self
            .entries
            .lock()
            .map_err(|_| crate::neighbor::Error::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?;
        cache.retain(|_, entry| entry.expires_at > now);
        if !cache.contains_key(&key)
            && cache.len() >= options.max_cache_entries
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert(
            key,
            NeighborCacheEntry {
                mac_address,
                inserted_at: now,
                expires_at,
            },
        );
        Ok(())
    }
}
