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
    use std::sync::Arc;
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

    fn key(index: u32) -> NeighborCacheKey {
        NeighborCacheKey::from(&request(IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            (index >> 16) as u16,
            index as u16,
        ))))
    }

    fn seed(cache: &NeighborCache, index: u32, inserted_at: Instant, expires_at: Instant) {
        cache.entries.lock().unwrap().insert(
            key(index),
            NeighborCacheEntry {
                mac_address: MacAddress([2, 0, 0, 0, 0, index as u8]),
                inserted_at,
                expires_at,
            },
        );
    }

    #[test]
    fn repeated_hits_preserve_ttl_insertion_age_and_retained_size() {
        let cache = NeighborCache::default();
        let now = Instant::now();
        let inserted = now - Duration::from_secs(10);
        let expires = now + Duration::from_secs(3600);
        seed(&cache, 1, inserted, expires);
        seed(&cache, 2, inserted, now);
        seed(&cache, 3, inserted, now);
        for _ in 0..10 {
            assert_eq!(
                cache.get(&key(1)).unwrap(),
                Some(MacAddress([2, 0, 0, 0, 0, 1]))
            );
            assert_eq!(cache.get(&key(4)).unwrap(), None);
            let entries = cache.entries.lock().unwrap();
            // Hits and misses leave unrelated entries alone; insertion bounds cleanup.
            assert_eq!(entries.len(), 3);
            assert_eq!(entries[&key(1)].inserted_at, inserted);
            assert_eq!(entries[&key(1)].expires_at, expires);
        }
        assert_eq!(cache.get(&key(2)).unwrap(), None);
        assert!(!cache.entries.lock().unwrap().contains_key(&key(2)));
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
    }

    #[test]
    fn insertion_prunes_expired_entries_and_replacement_renews_only_its_entry() {
        let cache = NeighborCache::default();
        let now = Instant::now();
        let old = now - Duration::from_secs(10);
        let expires = now + Duration::from_secs(3600);
        seed(&cache, 1, old, expires);
        seed(&cache, 2, old, now);
        seed(&cache, 3, old, now);
        let settings = options(3, Duration::from_secs(60));
        let mac = MacAddress([2, 0, 0, 0, 0, 42]);
        cache.insert(mac, key(4), &settings).unwrap();
        {
            let entries = cache.entries.lock().unwrap();
            assert_eq!(entries.len(), 2);
            assert!(entries.contains_key(&key(1)));
            assert!(entries.contains_key(&key(4)));
        }
        cache.insert(mac, key(1), &settings).unwrap();
        let entries = cache.entries.lock().unwrap();
        assert_eq!(entries.len(), 2);
        let renewed = &entries[&key(1)];
        assert_eq!(renewed.mac_address, mac);
        assert!(renewed.inserted_at >= now);
        assert_eq!(
            renewed.expires_at.duration_since(renewed.inserted_at),
            settings.cache_ttl
        );
    }

    #[test]
    fn hits_do_not_change_fifo_eviction_and_replacement_is_a_new_insertion() {
        let cache = NeighborCache::default();
        let now = Instant::now();
        let expires = now + Duration::from_secs(3600);
        seed(&cache, 1, now - Duration::from_secs(30), expires);
        seed(&cache, 2, now - Duration::from_secs(20), expires);
        seed(&cache, 3, now - Duration::from_secs(10), expires);
        let settings = options(3, Duration::from_secs(3600));
        let mac = MacAddress([2, 0, 0, 0, 0, 42]);
        for _ in 0..10 {
            assert!(cache.get(&key(1)).unwrap().is_some());
        }
        cache.insert(mac, key(4), &settings).unwrap();
        assert_eq!(cache.get(&key(1)).unwrap(), None);
        assert!(cache.get(&key(2)).unwrap().is_some());
        cache.insert(mac, key(2), &settings).unwrap();
        assert_eq!(cache.entries.lock().unwrap().len(), 3);
        cache.insert(mac, key(5), &settings).unwrap();
        assert_eq!(cache.get(&key(3)).unwrap(), None);
        assert_eq!(cache.get(&key(2)).unwrap(), Some(mac));
        assert_eq!(cache.entries.lock().unwrap().len(), 3);
    }

    #[test]
    fn every_identity_field_separates_cache_hits() {
        let original = key(1);
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.interface.name.push('x');
        variants.push(changed);
        let mut changed = original.clone();
        changed.interface.index += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.interface_source = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        variants.push(changed);
        let mut changed = original.clone();
        changed.interface_mac.0[5] += 1;
        variants.push(changed);
        variants.push(key(2));
        let mut changed = original.clone();
        changed.vlan_tags[0].kind = VlanKind::Ieee8021Ad;
        variants.push(changed);
        let mut changed = original.clone();
        changed.vlan_tags[0].priority += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.vlan_tags[0].drop_eligible = true;
        variants.push(changed);
        let mut changed = original.clone();
        changed.vlan_tags[0].vlan_id += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.vlan_tags.clear();
        variants.push(changed);
        let mut changed = original.clone();
        changed.link_type = LinkType::RAW;
        variants.push(changed);
        let cache = NeighborCache::default();
        let mac = MacAddress([2, 0, 0, 0, 0, 42]);
        cache
            .insert(
                mac,
                original.clone(),
                &options(1, Duration::from_secs(3600)),
            )
            .unwrap();
        for changed in variants {
            assert_eq!(cache.get(&changed).unwrap(), None);
        }
        assert_eq!(cache.get(&original).unwrap(), Some(mac));
    }

    #[test]
    #[ignore = "release measurement; no wall-clock assertions"]
    fn measure_neighbor_cache_hits() {
        use std::sync::Barrier;

        const HITS: usize = 10_000;
        for size in [16, 512, 4096] {
            for readers in [1, 4] {
                let mut samples = Vec::new();
                for _ in 0..5 {
                    let cache = NeighborCache::default();
                    let now = Instant::now();
                    for index in 0..size {
                        seed(&cache, index, now, now + Duration::from_secs(3600));
                    }
                    let ready = Barrier::new(readers + 1);
                    let start = Barrier::new(readers + 1);
                    let end = Barrier::new(readers + 1);
                    let elapsed = std::thread::scope(|scope| {
                        for reader in 0..readers {
                            let (cache, ready, start, end) = (&cache, &ready, &start, &end);
                            scope.spawn(move || {
                                let key = key((reader as u32) % size);
                                ready.wait();
                                start.wait();
                                for _ in 0..HITS {
                                    std::hint::black_box(
                                        cache.get(std::hint::black_box(&key)).unwrap().unwrap(),
                                    );
                                }
                                end.wait();
                            });
                        }
                        // Population and thread startup precede the processing barrier.
                        ready.wait();
                        let begin = Instant::now();
                        start.wait();
                        end.wait();
                        begin.elapsed()
                    });
                    samples.push(elapsed.as_nanos() as f64 / (HITS * readers) as f64);
                    assert_eq!(cache.entries.lock().unwrap().len(), size as usize);
                }
                samples.sort_by(f64::total_cmp);
                println!(
                    "neighbor,entries={size},readers={readers},hits={},ns/hit={:.1}",
                    HITS * readers,
                    samples[2]
                );
            }
        }
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
