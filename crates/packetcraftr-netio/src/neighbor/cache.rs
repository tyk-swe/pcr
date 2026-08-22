// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Neighbor resolution cache key, entry, and state management.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use super::error::invalid_options;
use super::options::Options;
use super::{Request as NeighborRequest, VlanTag as NeighborVlanTag};
use crate::{interface::Id as InterfaceId, link::MacAddress};
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

#[derive(Debug, Default)]
pub(super) struct NeighborCache {
    entries: Mutex<HashMap<NeighborCacheKey, NeighborCacheEntry>>,
}

impl NeighborCache {
    pub(super) fn get(
        &self,
        key: &NeighborCacheKey,
    ) -> Result<Option<MacAddress>, crate::neighbor::Error> {
        let now = Instant::now();
        let mut cache = self
            .entries
            .lock()
            .map_err(|_| crate::neighbor::Error::State {
                message: "neighbor cache mutex was poisoned".to_owned(),
            })?;
        cache.retain(|_, entry| entry.expires_at > now);
        Ok(cache.get(key).map(|entry| entry.mac_address))
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
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::{interface::Id as InterfaceId, neighbor::VlanKind as NeighborVlanKind};

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
            vlan_tags: vec![NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Q,
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
    fn cache_key_includes_logical_link_and_interface_identity() {
        let original = request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        let original_key = NeighborCacheKey::from(&original);

        let mut changed = original.clone();
        changed.interface.index += 1;
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
        changed = original.clone();
        changed.interface_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
        changed = original.clone();
        changed.interface_mac.0[5] += 1;
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
        changed = original.clone();
        changed.target = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
        changed = original.clone();
        changed.vlan_tags[0].vlan_id += 1;
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
        changed = original;
        changed.link_type = LinkType::RAW;
        assert_ne!(NeighborCacheKey::from(&changed), original_key);
    }

    #[test]
    fn cache_returns_inserted_values_and_evicts_the_oldest_entry() {
        let cache = NeighborCache::default();
        let first = NeighborCacheKey::from(&request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        let second = NeighborCacheKey::from(&request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3))));
        let first_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let second_mac = MacAddress([0x02, 0, 0, 0, 0, 3]);
        let options = options(1, Duration::from_secs(60));

        assert_eq!(cache.get(&first).expect("empty cache"), None);
        cache
            .insert(first_mac, first.clone(), &options)
            .expect("first insert");
        assert_eq!(cache.get(&first).expect("first lookup"), Some(first_mac));
        cache
            .insert(second_mac, second.clone(), &options)
            .expect("second insert");
        assert_eq!(cache.get(&first).expect("evicted lookup"), None);
        assert_eq!(cache.get(&second).expect("second lookup"), Some(second_mac));
    }

    #[test]
    fn cache_expires_entries_and_rejects_deadline_overflow() {
        let cache = NeighborCache::default();
        let key = NeighborCacheKey::from(&request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        cache
            .insert(
                MacAddress([0x02, 0, 0, 0, 0, 2]),
                key.clone(),
                &options(1, Duration::from_nanos(1)),
            )
            .expect("short-lived insert");
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get(&key).expect("expired lookup"), None);

        assert!(matches!(
            cache.insert(
                MacAddress([0x02, 0, 0, 0, 0, 2]),
                key,
                &options(1, Duration::MAX),
            ),
            Err(crate::neighbor::Error::InvalidOptions { .. })
        ));
    }

    #[test]
    fn poisoned_cache_state_fails_closed_for_reads_and_writes() {
        let cache = Arc::new(NeighborCache::default());
        let poison = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _guard = poison.entries.lock().expect("initial mutex lock");
            panic!("poison fixture mutex");
        })
        .join();

        let key = NeighborCacheKey::from(&request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert!(matches!(
            cache.get(&key),
            Err(crate::neighbor::Error::State { .. })
        ));
        assert!(matches!(
            cache.insert(
                MacAddress([0x02, 0, 0, 0, 0, 2]),
                key,
                &options(1, Duration::from_secs(1)),
            ),
            Err(crate::neighbor::Error::State { .. })
        ));
    }
}
