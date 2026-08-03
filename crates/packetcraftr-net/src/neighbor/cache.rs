// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution cache key, entry, and state management.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use super::error::invalid_configuration;
use super::options::NeighborResolutionOptions;
use crate::{
    link::MacAddress,
    route::{InterfaceId, NeighborError, NeighborRequest, NeighborVlanTag},
};
use packetcraftr_core::frame::{Frame, LinkType};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct NeighborCacheKey {
    interface: InterfaceId,
    interface_source: IpAddr,
    interface_mac: MacAddress,
    target: IpAddr,
    vlan_tags: Vec<NeighborVlanTag>,
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

pub(super) struct NeighborExchangeOutcome {
    pub(super) mac_address: Option<MacAddress>,
    pub(super) attempts: u32,
    pub(super) captured: Vec<Frame>,
    pub(super) evidence_truncated: bool,
}

#[derive(Debug)]
pub(super) struct NeighborCache {
    entries: Mutex<HashMap<NeighborCacheKey, NeighborCacheEntry>>,
}

impl NeighborCache {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn get(&self, key: &NeighborCacheKey) -> Result<Option<MacAddress>, NeighborError> {
        let now = Instant::now();
        let mut cache = self.entries.lock().map_err(|_| NeighborError::State {
            message: "neighbor cache mutex was poisoned".to_owned(),
        })?;
        cache.retain(|_, entry| entry.expires_at > now);
        Ok(cache.get(key).map(|entry| entry.mac_address))
    }

    pub(super) fn insert(
        &self,
        mac_address: MacAddress,
        key: NeighborCacheKey,
        options: &NeighborResolutionOptions,
    ) -> Result<(), NeighborError> {
        let now = Instant::now();
        let expires_at = now
            .checked_add(options.cache_ttl)
            .ok_or_else(|| invalid_configuration("cache deadline overflowed".to_owned()))?;
        let mut cache = self.entries.lock().map_err(|_| NeighborError::State {
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
