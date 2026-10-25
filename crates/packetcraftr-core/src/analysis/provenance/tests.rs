// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Accumulator, SourceFrame, SourceSet, Tracker};
use crate::analysis::{adapter::IpFragments, reassembly::ip, scope::Interner};
use std::time::{Duration, UNIX_EPOCH};

fn source(number: u64) -> SourceFrame {
    SourceFrame {
        number,
        timestamp: UNIX_EPOCH - Duration::from_secs(number),
    }
}

fn fragment_entry(tracker: &mut Tracker, identification: u16) -> ip::DatagramKey {
    let key = ip::Ipv4DatagramKey {
        scope: Interner::new().intern(None, Vec::new()).unwrap(),
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.1".parse().unwrap(),
        identification,
        protocol: 253,
    };
    let fragment = IpFragments {
        atomic: Vec::new(),
        non_atomic: Some(ip::Fragment::Ipv4(ip::Ipv4Fragment {
            key: key.clone(),
            fragment_offset: 0,
            more_fragments: true,
            header: Default::default(),
            payload: Default::default(),
        })),
    };
    tracker
        .remember(
            &fragment,
            &tracker.single(source(identification.into())).unwrap(),
        )
        .unwrap();
    ip::DatagramKey::Ipv4(key)
}

#[test]
fn retirement_preserves_key_order_active_entries_and_omission_counts() {
    let mut tracker = Tracker::new(64 * 1024, 2).unwrap();
    let keys: Vec<_> = [4, 1, 3, 2]
        .into_iter()
        .map(|id| fragment_entry(&mut tracker, id))
        .collect();
    tracker.retire(|key| *key == keys[3]).unwrap();
    let active = tracker.completed(&keys[3]).unwrap().unwrap();
    assert_eq!(active.frames(), [source(2)]);
    for key in &keys[..3] {
        assert!(tracker.completed(key).unwrap().is_none());
    }
    let (incomplete, omitted) = tracker.finish().unwrap();
    assert_eq!(
        incomplete
            .iter()
            .map(|entry| entry.sources[0])
            .collect::<Vec<_>>(),
        [source(1), source(3)]
    );
    assert_eq!(omitted, 1);
}

#[test]
fn assembly_orders_and_deduplicates_sources_without_changing_published_sets() {
    let tracker = Tracker::new(64 * 1024, 16).unwrap();
    let first = tracker.single(source(3)).unwrap();
    let snapshot = first.clone();
    let mut assembly = Accumulator::new(&first).unwrap();
    for number in [1, 4, 2, 3, 1] {
        assembly
            .insert(&tracker.single(source(number)).unwrap())
            .unwrap();
    }
    let result = assembly.freeze().unwrap();
    assert_eq!(
        result.frames(),
        [source(1), source(2), source(3), source(4)]
    );
    assert_eq!(snapshot.frames(), [source(3)]);
    let union = first.union(&result).unwrap();
    assert_eq!(union.frames(), [source(1), source(2), source(3), source(4)]);
    let additional = tracker.single(source(5)).unwrap();
    let union = result.union(&additional).unwrap();
    assert_eq!(
        union.frames(),
        [source(1), source(2), source(3), source(4), source(5)]
    );
    assert_eq!(
        result.frames(),
        [source(1), source(2), source(3), source(4)]
    );
}

fn exhaust(tracker: &Tracker) -> Vec<SourceSet> {
    let held = (10..1000)
        .map_while(|number| match tracker.single(source(number)) {
            Ok(set) => Some(set),
            Err(super::Error::Limit { .. }) => None,
            Err(error) => panic!("unexpected admission error: {error}"),
        })
        .collect();
    assert!(matches!(
        tracker.single(source(1000)),
        Err(super::Error::Limit { .. })
    ));
    held
}

#[test]
fn refused_inserts_and_freezes_preserve_sources_and_release_their_budget() {
    let tracker = Tracker::new(8 * 1024, 16).unwrap();
    for _ in 0..8 {
        let first = tracker.single(source(2)).unwrap();
        let second = tracker.single(source(1)).unwrap();
        let mut assembly = Accumulator::new(&first).unwrap();
        let held = exhaust(&tracker);
        assert!(matches!(
            assembly.insert(&second),
            Err(super::Error::Limit { .. })
        ));
        assert!(matches!(assembly.freeze(), Err(super::Error::Limit { .. })));
        assert_eq!(first.frames(), [source(2)]);
        assert_eq!(second.frames(), [source(1)]);
        drop(held);
        let mut recovered = Accumulator::new(&first).unwrap();
        recovered.insert(&second).unwrap();
        assert_eq!(recovered.freeze().unwrap().frames(), [source(1), source(2)]);
    }
}

#[test]
fn shared_sources_hold_admission_until_the_last_owner_releases_them() {
    let tracker = Tracker::new(8 * 1024, 16).unwrap();
    let held = exhaust(&tracker);
    let shared = held.last().unwrap().clone();
    let mut held = held;
    drop(held.pop());
    assert!(matches!(
        tracker.single(source(1)),
        Err(super::Error::Limit { .. })
    ));
    drop(shared);
    let admitted = tracker.single(source(1)).unwrap();
    assert_eq!(admitted.frames(), [source(1)]);
}

#[test]
fn foreign_sources_are_refused_without_changing_the_assembly() {
    let tracker = Tracker::new(16 * 1024, 16).unwrap();
    let first = tracker.single(source(2)).unwrap();
    let foreign = Tracker::new(16 * 1024, 16)
        .unwrap()
        .single(source(1))
        .unwrap();
    let mut assembly = Accumulator::new(&first).unwrap();
    assert!(matches!(
        assembly.insert(&foreign),
        Err(super::Error::DifferentCapture)
    ));
    assert!(matches!(
        first.union(&foreign),
        Err(super::Error::DifferentCapture)
    ));
    assembly.insert(&first).unwrap();
    assert_eq!(assembly.freeze().unwrap().frames(), [source(2)]);
}
