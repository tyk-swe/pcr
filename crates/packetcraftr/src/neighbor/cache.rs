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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use std::time::Duration;

    use super::*;
    use packetcraftr_core::packet::VlanKind;
    use packetcraftr_netio::interface::Id as InterfaceId;

    fn request(target: IpAddr) -> NeighborRequest {
        NeighborRequest {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 2,
            },
            interface_source: match target {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            },
            interface_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            target,
            vlan_tags: vec![VlanTag {
                kind: VlanKind::Ieee8021Q,
                priority: 1,
                drop_eligible: false,
                vlan_id: 7,
            }],
            mtu: 1_500,
            link_type: LinkType::ETHERNET,
        }
    }

    fn options(max_cache_entries: usize, cache_ttl: Duration) -> Options {
        Options {
            max_attempts: 1,
            attempt_timeout: Duration::from_secs(1),
            cache_ttl,
            max_cache_entries,
            max_capture_queue_frames: 1,
            max_captured_bytes: 128,
            snap_length: 128,
        }
    }

    #[test]
    fn cache_expires_entries_and_rejects_deadline_overflow() {
        let cache = NeighborCache::default();
        let key = NeighborCacheKey::from(&request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        cache
            .insert(
                MacAddress([0x02, 0, 0, 0, 0, 2]),
                key.clone(),
                &options(1, Duration::from_secs(60)),
            )
            .expect("short-lived insert");
        cache
            .entries
            .lock()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .expires_at = Instant::now();
        assert_eq!(cache.get(&key).expect("expired lookup"), None);
        assert!(cache.entries.lock().unwrap().is_empty());

        assert!(matches!(
            cache.insert(
                MacAddress([0x02, 0, 0, 0, 0, 2]),
                key,
                &options(1, Duration::MAX),
            ),
            Err(crate::neighbor::Error::InvalidOptions { .. })
        ));
    }
}
