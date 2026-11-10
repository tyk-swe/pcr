// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::budget::Cancellation;
use std::time::Instant;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
struct Transmitter(AtomicUsize);
impl transmit::Provider for Transmitter {
    fn send(
        &self,
        outbound: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let bytes = match outbound {
            transmit::Outbound::Layer2(frame) => frame.bytes().clone(),
            _ => unreachable!(),
        };
        Ok(transmit::Report::committed(bytes.len(), bytes))
    }
}
struct Session {
    metadata: capture::Metadata,
    cancellation: Cancellation,
    cancel_before_send: bool,
    reads: usize,
}
impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        self.reads += 1;
        if self.cancel_before_send || !deadline.limit().is_zero() {
            self.cancellation.cancel();
            if !self.cancel_before_send {
                // The wait itself has no cancellation; its parent must retain it.
                assert!(deadline.cancellation().is_none());
                assert!(deadline.check_cancelled().is_err());
            }
        }
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}
struct Captures;
impl capture::Provider for Captures {
    type Capture = Session;
    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<Session, packetcraftr_netio::Error> {
        unreachable!()
    }
}
#[test]
fn incomplete_capture_identity_skips_provider() {
    for interface in [
        packetcraftr_netio::interface::Id {
            name: String::new(),
            index: 1,
        },
        packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 0,
        },
    ] {
        let request = Request {
            interface,
            interface_source: "192.168.1.1".parse().unwrap(),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: "192.168.1.2".parse().unwrap(),
            vlan_tags: vec![],
            mtu: 1500,
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
        };
        let transmitter = Transmitter(AtomicUsize::new(0));
        let state = State::default();
        // Captures::arm_capture panics if the validation boundary is bypassed.
        let result = state
            .over(&transmitter, &Captures)
            .resolve(&request, &Deadline::new(Duration::from_secs(1)));
        assert!(result.is_err());
        assert_eq!(transmitter.0.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn parent_cancellation_stops_reads_and_attempts() {
    for cancel_before_send in [false, true] {
        let request = Request {
            interface: packetcraftr_netio::interface::Id {
                name: "test0".into(),
                index: 1,
            },
            interface_source: "192.168.1.1".parse().unwrap(),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: "192.168.1.2".parse().unwrap(),
            vlan_tags: vec![],
            mtu: 1500,
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
        };
        let cancellation = Cancellation::default();
        let parent =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
        let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
        let mut session = Session {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: request.link_type,
                snap_length: 1500,
                native: Default::default(),
            },
            cancellation,
            cancel_before_send,
            reads: 0,
        };
        let transmitter = Transmitter(AtomicUsize::new(0));
        let state = State::default();
        let active = state.over(&transmitter, &Captures);
        let decision = discovery_decision(&request);
        let bytes = build_request_frame(&request).unwrap();
        let result = active
            .exchange(
                &request,
                &bytes,
                transmit::Route {
                    decision: &decision,
                    mode: Mode::Layer2,
                    lookup_destination: None,
                },
                &mut session,
                &deadline,
            )
            .unwrap();
        let expected = u32::from(!cancel_before_send);
        assert_eq!(result.attempts, expected);
        assert_eq!(transmitter.0.load(Ordering::SeqCst), expected as usize);
        assert_eq!(session.reads, if cancel_before_send { 1 } else { 2 });
    }
}

struct InterruptedSession {
    metadata: capture::Metadata,
    cancellation: Cancellation,
    reads: usize,
    elapsed: Option<Arc<std::sync::Mutex<Duration>>>,
}

impl capture::Session for InterruptedSession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        self.reads += 1;
        match self.reads {
            1 => Ok(None),
            2 => {
                if let Some(elapsed) = &self.elapsed {
                    *elapsed.lock().unwrap() = Duration::from_secs(2);
                }
                Ok(Some(capture::Captured::new(
                    Frame::new(
                        Some(std::time::SystemTime::now()),
                        self.metadata.link_type,
                        [0_u8; 60].to_vec(),
                    )
                    .unwrap(),
                    Some(Instant::now()),
                )))
            }
            _ => {
                self.cancellation.cancel();
                Err(deadline.check_cancelled().unwrap_err().into())
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}

struct InterruptedCapture(std::sync::Mutex<Option<InterruptedSession>>);

impl capture::Provider for InterruptedCapture {
    type Capture = InterruptedSession;

    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        Ok(self.0.lock().unwrap().take().unwrap())
    }
}

#[test]
fn interrupted_read_preserves_attempt_and_evidence() {
    let request = Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.168.1.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: "192.168.1.2".parse().unwrap(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    };
    let cancellation = Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(1)).with_cancellation(Some(cancellation.clone()));
    let deadline = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    let capture = InterruptedCapture(std::sync::Mutex::new(Some(InterruptedSession {
        metadata: capture::Metadata {
            interface: request.interface.clone(),
            link_type: request.link_type,
            snap_length: 1500,
            native: Default::default(),
        },
        cancellation,
        reads: 0,
        elapsed: None,
    })));
    let transmitter = Transmitter(AtomicUsize::new(0));
    let error = State::default()
        .over(&transmitter, &capture)
        .resolve(&request, &deadline)
        .unwrap_err();
    let Error::Io {
        spent: Some(spent),
        source,
        ..
    } = error
    else {
        panic!("expected an interrupted capture read");
    };
    assert_eq!(spent.attempts, 1);
    assert_eq!(transmitter.0.load(Ordering::SeqCst), 1);
    assert_eq!(spent.captured.len(), 1);
    assert_eq!(spent.captured[0].bytes().as_ref(), [0_u8; 60]);
    assert!(matches!(source, packetcraftr_netio::Error::Cancelled(_)));
}

#[test]
fn dequeued_frame_survives_wait_interruption() {
    let request = Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.168.1.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: "192.168.1.2".parse().unwrap(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    };
    let started = Instant::now();
    let elapsed = Arc::new(std::sync::Mutex::new(Duration::ZERO));
    let clock = Arc::clone(&elapsed);
    let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
        started + *clock.lock().unwrap()
    });
    let decision = discovery_decision(&request);
    let bytes = build_request_frame(&request).unwrap();
    let transmitter = Transmitter(AtomicUsize::new(0));
    let mut session = InterruptedSession {
        metadata: capture::Metadata {
            interface: request.interface.clone(),
            link_type: request.link_type,
            snap_length: 1500,
            native: Default::default(),
        },
        cancellation: Cancellation::default(),
        reads: 0,
        elapsed: Some(elapsed),
    };
    let outcome = State::default()
        .over(&transmitter, &Captures)
        .exchange(
            &request,
            &bytes,
            transmit::Route {
                decision: &decision,
                mode: Mode::Layer2,
                lookup_destination: None,
            },
            &mut session,
            &deadline,
        )
        .unwrap();
    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.captured.len(), 1);
    assert_eq!(outcome.captured[0].bytes().as_ref(), [0_u8; 60]);
    assert!(!outcome.evidence_truncated);
}

struct SilentSession {
    metadata: capture::Metadata,
}

impl capture::Session for SilentSession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}

struct SilentCapture(capture::Metadata);

impl capture::Provider for SilentCapture {
    type Capture = SilentSession;

    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<SilentSession, packetcraftr_netio::Error> {
        Ok(SilentSession {
            metadata: self.0.clone(),
        })
    }
}

#[test]
fn not_found_stats_count_every_request_frame() {
    let request = Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.168.1.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: "192.168.1.2".parse().unwrap(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    };
    let capture = SilentCapture(capture::Metadata {
        interface: request.interface.clone(),
        link_type: request.link_type,
        snap_length: 1500,
        native: Default::default(),
    });
    let transmitter = Transmitter(AtomicUsize::new(0));
    let error = State::default()
        .over(&transmitter, &capture)
        .resolve(&request, &Deadline::new(Duration::from_secs(1)))
        .unwrap_err();
    let Error::NotFound {
        attempts,
        request_bytes,
        ..
    } = &error
    else {
        panic!("expected an unanswered neighbor resolution");
    };
    let frame_bytes = build_request_frame(&request).unwrap().len();
    assert_eq!(*request_bytes, frame_bytes);
    assert!(*attempts > 0);
    let stats = error.exchange_stats(Duration::ZERO).unwrap();
    assert_eq!(stats.packets_attempted, u64::from(*attempts));
    assert_eq!(stats.bytes, u64::from(*attempts) * frame_bytes as u64);
}

fn cache_key(index: u16) -> NeighborCacheKey {
    let [high, low] = index.to_be_bytes();
    NeighborCacheKey::from(&Request {
        interface: packetcraftr_netio::interface::Id {
            name: "test0".into(),
            index: 1,
        },
        interface_source: "192.0.2.1".parse().unwrap(),
        interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
        target: std::net::Ipv4Addr::new(198, 51, high, low).into(),
        vlan_tags: vec![],
        mtu: 1500,
        link_type: packetcraftr_core::frame::LinkType::ETHERNET,
    })
}

fn cache_options(capacity: usize, ttl: u64) -> Options {
    Options {
        max_cache_entries: capacity,
        cache_ttl: Duration::from_secs(ttl),
        ..Options::default()
    }
}

#[test]
fn cache_insert_and_get_round_trip() {
    use crate::neighbor::cache::TEST_CACHE_CLOCK;
    use std::cell::Cell;

    struct RestoreClock<'a> {
        clock: &'a Cell<Option<Instant>>,
        previous: Option<Instant>,
    }

    impl Drop for RestoreClock<'_> {
        fn drop(&mut self) {
            self.clock.set(self.previous);
        }
    }

    TEST_CACHE_CLOCK.with(|clock| {
        let _restore = RestoreClock {
            clock,
            previous: clock.replace(Some(Instant::now())),
        };
        let cache = NeighborCache::default();
        let options = cache_options(2, 3600);
        let key = cache_key(1);
        let mac = MacAddress([2, 0, 0, 0, 0, 7]);
        options.validate().unwrap();

        assert_eq!(cache.get(&key).unwrap(), None);
        cache.insert(mac, key.clone(), &options).unwrap();
        assert_eq!(cache.get(&key).unwrap(), Some(mac));
        assert_eq!(cache.get(&cache_key(2)).unwrap(), None);
    });
}

#[test]
fn cache_operations_respect_individual_ttls() {
    let cache = NeighborCache::default();
    let other = NeighborCache::default();
    let start = Instant::now();
    let short = cache_options(3, 4);
    let long = cache_options(3, 20);
    let mac = MacAddress([2, 0, 0, 0, 0, 7]);
    cache.insert_at(mac, cache_key(1), &short, start).unwrap();
    cache
        .insert_at(mac, cache_key(2), &long, start + Duration::from_secs(1))
        .unwrap();
    cache
        .insert_at(mac, cache_key(3), &long, start + Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        cache
            .get_at(&cache_key(1), start + Duration::from_secs(3))
            .unwrap(),
        Some(mac)
    );
    cache
        .insert_at(mac, cache_key(1), &long, start + Duration::from_secs(3))
        .unwrap();
    assert_eq!(
        cache
            .get_at(&cache_key(1), start + Duration::from_secs(4))
            .unwrap(),
        Some(mac)
    );
    assert_eq!(
        cache
            .get_at(&cache_key(2), start + Duration::from_secs(4))
            .unwrap(),
        Some(mac)
    );
    cache
        .insert_at(mac, cache_key(4), &short, start + Duration::from_secs(4))
        .unwrap();
    assert_eq!(
        cache
            .get_at(&cache_key(2), start + Duration::from_secs(4))
            .unwrap(),
        None
    );
    assert_eq!(
        cache
            .get_at(&cache_key(3), start + Duration::from_secs(4))
            .unwrap(),
        Some(mac)
    );
    assert_eq!(
        cache
            .get_at(&cache_key(4), start + Duration::from_secs(8))
            .unwrap(),
        None
    );
    assert_eq!(
        other
            .get_at(&cache_key(1), start + Duration::from_secs(4))
            .unwrap(),
        None
    );
    assert_eq!(cache.metrics().0, 2);
    assert_eq!(cache.metrics().0, cache.metrics().1);
    assert_eq!(cache.metrics().0, cache.metrics().2);
}

#[test]
fn cache_churn_matches_ttl_reference() {
    use std::collections::HashMap;

    let cache = NeighborCache::default();
    let start = Instant::now();
    let mut reference: HashMap<u16, (MacAddress, Instant, Instant, usize)> = HashMap::new();
    for step in 0..2000usize {
        let now = start + Duration::from_secs((step / 4) as u64);
        let key = ((step * 37) % 53) as u16;
        let options = cache_options(11, [3, 17, 40][step % 3]);
        let mac = MacAddress([2, 0, 0, (step / 256) as u8, step as u8, 1]);
        reference.retain(|_, (_, _, expiry, _)| *expiry > now);
        if !reference.contains_key(&key) && reference.len() >= options.max_cache_entries {
            let oldest = *reference
                .iter()
                .min_by_key(|(_, (_, inserted, _, sequence))| (*inserted, *sequence))
                .unwrap()
                .0;
            reference.remove(&oldest);
        }
        reference.insert(key, (mac, now, now + options.cache_ttl, step));
        cache.insert_at(mac, cache_key(key), &options, now).unwrap();
        for index in [key, ((step * 13) % 53) as u16, ((step * 7 + 1) % 53) as u16] {
            let expected = reference
                .get(&index)
                .filter(|(_, _, expiry, _)| *expiry > now)
                .map(|entry| entry.0);
            if expected.is_none() {
                reference.remove(&index);
            }
            assert_eq!(
                cache.get_at(&cache_key(index), now).unwrap(),
                expected,
                "step {step}, key {index}"
            );
        }
        let (entries, expiry, insertion, _) = cache.metrics();
        assert_eq!(
            (entries, expiry, insertion),
            (reference.len(), reference.len(), reference.len())
        );
    }
}

#[test]
fn cache_expiry_scales_with_changed_entries() {
    let start = Instant::now();
    let options = cache_options(4096, 100);
    let mac = MacAddress([2, 0, 0, 0, 0, 1]);
    for population in [1u16, 128, 2048] {
        let cache = NeighborCache::default();
        for index in 0..population {
            cache
                .insert_at(mac, cache_key(index), &options, start)
                .unwrap();
        }
        let before = cache.metrics().3;
        for _ in 0..1000 {
            cache
                .insert_at(mac, cache_key(0), &options, start + Duration::from_secs(1))
                .unwrap();
        }
        let (entries, expiry, insertion, visits) = cache.metrics();
        assert_eq!(
            (entries, expiry, insertion),
            (
                population as usize,
                population as usize,
                population as usize
            )
        );
        assert_eq!(visits - before, 1000);
        cache
            .insert_at(
                mac,
                cache_key(population),
                &options,
                start + Duration::from_secs(102),
            )
            .unwrap();
        let (entries, expiry, insertion, visits_after) = cache.metrics();
        assert_eq!((entries, expiry, insertion), (1, 1, 1));
        assert_eq!(visits_after - visits, population as usize + 1);
    }
}

#[test]
fn concurrent_cache_refresh_preserves_indexes() {
    let cache = Arc::new(NeighborCache::default());
    let start = Instant::now();
    let threads: Vec<_> = (0..8u16)
        .map(|index| {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                let key = cache_key(index);
                let mac = MacAddress([2, 0, 0, 0, 0, index as u8]);
                let options = cache_options(8, 30);
                for _ in 0..300 {
                    cache.insert_at(mac, key.clone(), &options, start).unwrap();
                    assert_eq!(cache.get_at(&key, start).unwrap(), Some(mac));
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        (cache.metrics().0, cache.metrics().1, cache.metrics().2),
        (8, 8, 8)
    );
}

#[test]
fn cache_expiration_sampled_after_lock() {
    use std::sync::mpsc;

    let cache = Arc::new(NeighborCache::default());
    let start = Instant::now();
    let key = cache_key(1);
    let mac = MacAddress([2, 0, 0, 0, 0, 1]);
    cache
        .insert_at(mac, key.clone(), &cache_options(1, 5), start)
        .unwrap();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        std::thread::spawn(move || {
            cache
                .get_with_clock(&key, || {
                    held_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    start
                })
                .unwrap()
        })
    };
    held_rx.recv().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (sampled_tx, sampled_rx) = mpsc::channel();
    let reader = {
        let cache = Arc::clone(&cache);
        let key = key.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            cache
                .get_with_clock(&key, || {
                    sampled_tx.send(()).unwrap();
                    start + Duration::from_secs(5)
                })
                .unwrap()
        })
    };
    started_rx.recv().unwrap();
    assert!(sampled_rx.recv_timeout(Duration::from_millis(100)).is_err());
    release_tx.send(()).unwrap();
    assert_eq!(holder.join().unwrap(), Some(mac));
    assert_eq!(reader.join().unwrap(), None);
    sampled_rx.recv().unwrap();
    assert_eq!(
        (cache.metrics().0, cache.metrics().1, cache.metrics().2),
        (0, 0, 0)
    );
}

#[test]
fn cache_insertion_ttl_includes_lock_wait() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;

    let cache = Arc::new(NeighborCache::default());
    let start = Instant::now();
    let mac = MacAddress([2, 0, 0, 0, 0, 1]);
    let held_key = cache_key(1);
    let inserted_key = cache_key(2);
    let options = cache_options(2, 5);
    cache
        .insert_at(mac, held_key.clone(), &options, start)
        .unwrap();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = {
        let cache = Arc::clone(&cache);
        std::thread::spawn(move || {
            cache
                .get_with_clock(&held_key, || {
                    held_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    start
                })
                .unwrap()
        })
    };
    held_rx.recv().unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let (sampled_tx, sampled_rx) = mpsc::channel();
    let writer = {
        let cache = Arc::clone(&cache);
        let clock = Arc::clone(&clock);
        let key = inserted_key.clone();
        std::thread::spawn(move || {
            cache
                .insert_with_clock(mac, key, &options, || {
                    let elapsed = clock.load(Ordering::SeqCst);
                    sampled_tx.send(()).unwrap();
                    start + Duration::from_secs(elapsed)
                })
                .unwrap();
        })
    };
    let sampled = sampled_rx.recv_timeout(Duration::from_secs(5));
    let overflow = if start.checked_add(Duration::MAX).is_none() {
        let cache = Arc::clone(&cache);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let options = Options {
                cache_ttl: Duration::MAX,
                ..cache_options(2, 5)
            };
            done_tx
                .send(cache.insert_at(mac, cache_key(3), &options, start).is_err())
                .unwrap();
        });
        Some((done_rx.recv_timeout(Duration::from_secs(5)), worker))
    } else {
        None
    };
    clock.store(5, Ordering::SeqCst);
    release_tx.send(()).unwrap();
    assert_eq!(holder.join().unwrap(), Some(mac));
    writer.join().unwrap();
    assert!(sampled.is_ok());
    if let Some((result, worker)) = overflow {
        worker.join().unwrap();
        assert!(result.unwrap());
    }
    assert_eq!(
        cache
            .get_at(&inserted_key, start + Duration::from_secs(5))
            .unwrap(),
        None
    );
}
