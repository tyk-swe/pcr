// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::clock::{Clock, SystemClock};
use std::collections::{BTreeMap, HashMap};
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
struct NeighborCacheEntry {
    mac_address: MacAddress,
    inserted_at: Instant,
    expires_at: Instant,
    sequence: u128,
}

#[derive(Debug, Default)]
struct CacheEntries {
    entries: HashMap<NeighborCacheKey, NeighborCacheEntry>,
    expiry: BTreeMap<(Instant, u128), NeighborCacheKey>,
    insertion: BTreeMap<(Instant, u128), NeighborCacheKey>,
    sequence: u128,
    #[cfg(test)]
    expiry_visits: usize,
}

impl CacheEntries {
    fn remove(&mut self, key: &NeighborCacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.expiry.remove(&(entry.expires_at, entry.sequence));
            self.insertion.remove(&(entry.inserted_at, entry.sequence));
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(key) = {
            #[cfg(test)]
            {
                self.expiry_visits += 1;
            }
            self.expiry
                .first_key_value()
                .filter(|((expiry, _), _)| *expiry <= now)
                .map(|(_, key)| key.clone())
        } {
            self.remove(&key);
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct NeighborCache {
    entries: Mutex<CacheEntries>,
}

impl NeighborCache {
    pub(super) fn get(
        &self,
        key: &NeighborCacheKey,
    ) -> Result<Option<MacAddress>, crate::neighbor::Error> {
        self.get_with_clock(key, || SystemClock.now())
    }

    #[cfg(test)]
    pub(super) fn get_at(
        &self,
        key: &NeighborCacheKey,
        now: Instant,
    ) -> Result<Option<MacAddress>, crate::neighbor::Error> {
        self.get_with_clock(key, || now)
    }

    pub(super) fn get_with_clock(
        &self,
        key: &NeighborCacheKey,
        now: impl FnOnce() -> Instant,
    ) -> Result<Option<MacAddress>, crate::neighbor::Error> {
        let mut cache = self
            .entries
            .lock()
            .map_err(|_| crate::neighbor::Error::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?;
        let Some(entry) = cache.entries.get(key) else {
            return Ok(None);
        };
        if entry.expires_at > now() {
            return Ok(Some(entry.mac_address));
        }
        cache.remove(key);
        Ok(None)
    }

    #[cfg(test)]
    pub(super) fn metrics(&self) -> (usize, usize, usize, usize) {
        let cache = self.entries.lock().unwrap();
        (
            cache.entries.len(),
            cache.expiry.len(),
            cache.insertion.len(),
            cache.expiry_visits,
        )
    }

    pub(super) fn insert(
        &self,
        mac_address: MacAddress,
        key: NeighborCacheKey,
        options: &Options,
    ) -> Result<(), crate::neighbor::Error> {
        self.insert_with_clock(mac_address, key, options, || SystemClock.now())
    }

    #[cfg(test)]
    pub(super) fn insert_at(
        &self,
        mac_address: MacAddress,
        key: NeighborCacheKey,
        options: &Options,
        now: Instant,
    ) -> Result<(), crate::neighbor::Error> {
        self.insert_with_clock(mac_address, key, options, || now)
    }

    fn insert_with_clock(
        &self,
        mac_address: MacAddress,
        key: NeighborCacheKey,
        options: &Options,
        now: impl FnOnce() -> Instant,
    ) -> Result<(), crate::neighbor::Error> {
        let mut cache = self
            .entries
            .lock()
            .map_err(|_| crate::neighbor::Error::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?;
        let now = now();
        let expires_at = now
            .checked_add(options.cache_ttl)
            .ok_or_else(|| invalid_options("cache deadline overflowed".to_owned()))?;
        cache.expire(now);
        if !cache.entries.contains_key(&key)
            && cache.entries.len() >= options.max_cache_entries
            && let Some((_, oldest)) = cache.insertion.first_key_value()
        {
            let oldest = oldest.clone();
            cache.remove(&oldest);
        }
        cache.remove(&key);
        let sequence = cache.sequence;
        cache.sequence += 1;
        cache.expiry.insert((expires_at, sequence), key.clone());
        cache.insertion.insert((now, sequence), key.clone());
        cache.entries.insert(
            key,
            NeighborCacheEntry {
                mac_address,
                inserted_at: now,
                expires_at,
                sequence,
            },
        );
        Ok(())
    }
}
