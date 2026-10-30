// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Private work counters are compiled only into core's unit-test target.
use super::{Accumulator, Lease, SourceFrame, Tracker, work};
use std::time::UNIX_EPOCH;

fn fragment_entry(tracker: &mut Tracker, identification: u16) -> super::DatagramKey {
    let mut scopes = crate::analysis::scope::Interner::default();
    let key = super::DatagramKey::Ipv4(crate::analysis::reassembly::ip::Ipv4DatagramKey {
        scope: scopes.intern(None, Vec::new()).unwrap(),
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.1".parse().unwrap(),
        identification,
        protocol: 253,
    });
    let source = tracker
        .single(SourceFrame {
            number: identification.into(),
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let metadata = tracker.budget.reserve(2048).unwrap();
    tracker
        .entries
        .insert(key.clone(), (Accumulator::new(&source).unwrap(), metadata));
    key
}

fn fill_budget(tracker: &Tracker, limit: usize) -> Vec<Lease> {
    let mut leases = Vec::new();
    let mut chunk = limit.next_power_of_two();
    while chunk > 0 {
        while let Ok(lease) = tracker.budget.reserve(chunk) {
            leases.push(lease);
        }
        chunk /= 2;
    }
    leases
}

fn headroom(tracker: &Tracker, limit: usize) -> usize {
    fill_budget(tracker, limit)
        .iter()
        .map(|lease| lease.bytes)
        .sum()
}

fn fresh_headroom(limit: usize, max_outcomes: usize) -> usize {
    headroom(&Tracker::new(limit, max_outcomes).unwrap(), limit)
}

#[test]
fn retirement_preserves_key_order_active_entries_and_omission_counts() {
    const LIMIT: usize = 64 * 1024;
    let mut tracker = Tracker::new(LIMIT, 2).unwrap();
    let keys: Vec<_> = [4, 1, 3, 2]
        .into_iter()
        .map(|id| fragment_entry(&mut tracker, id))
        .collect();
    tracker.retire(|key| *key == keys[3]).unwrap();
    assert_eq!(tracker.entries.len(), 1);
    assert!(tracker.entries.contains_key(&keys[3]));
    assert_eq!(
        tracker
            .incomplete
            .iter()
            .map(|entry| entry.sources[0].number)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(tracker.outcomes_omitted, 1);
    tracker.retire(|_| false).unwrap();
    assert!(tracker.entries.is_empty());
    assert_eq!(tracker.incomplete.len(), 2);
    assert_eq!(tracker.outcomes_omitted, 2);
    tracker.incomplete.clear();
    assert_eq!(headroom(&tracker, LIMIT), fresh_headroom(LIMIT, 2));
}

#[test]
fn retirement_keeps_extracted_metadata_charged_until_freeze_finishes() {
    const LIMIT: usize = 16 * 1024;
    let mut tracker = Tracker::new(LIMIT, 1).unwrap();
    fragment_entry(&mut tracker, 1);
    let pressure = fill_budget(&tracker, LIMIT);
    assert!(matches!(
        tracker.retire(|_| false),
        Err(super::Error::Limit { .. })
    ));
    assert!(tracker.entries.is_empty());
    assert!(tracker.incomplete.is_empty());
    drop(pressure);
    assert_eq!(headroom(&tracker, LIMIT), fresh_headroom(LIMIT, 1));
    fragment_entry(&mut tracker, 1);
    tracker.retire(|_| false).unwrap();
    assert_eq!(tracker.incomplete.len(), 1);
    tracker.incomplete.clear();
    assert_eq!(headroom(&tracker, LIMIT), fresh_headroom(LIMIT, 1));
}

#[test]
fn assembly_copies_linearly_and_tree_discovery_grows_n_log_n() {
    const MAX_COPIES_PER_SOURCE: usize = 4;
    const MAX_COMPARISONS_PER_SOURCE: usize = 64;
    for n in [64, 256, 1024, 4096] {
        let sources = n as usize;
        let tracker = Tracker::new(16 * 1024 * 1024, 16).unwrap();
        let sets: Vec<_> = (1..=n)
            .map(|number| {
                tracker
                    .single(SourceFrame {
                        number,
                        timestamp: UNIX_EPOCH,
                    })
                    .unwrap()
            })
            .collect();
        work::take();
        let mut repeated = sets[0].clone();
        for set in &sets[1..] {
            repeated = repeated.union(set).unwrap();
        }
        let (_, repeated_copies) = work::take();
        let mut assembly = Accumulator::new(&sets[0]).unwrap();
        for set in &sets[1..] {
            assembly.insert(set).unwrap();
        }
        let result = assembly.freeze().unwrap();
        let (comparisons, copies) = work::take();
        assert_eq!(result.frames(), repeated.frames());
        assert!(copies >= sources, "n={n}: {copies} copies");
        assert!(
            copies <= MAX_COPIES_PER_SOURCE * sources,
            "n={n}: {copies} copies"
        );
        assert!(
            copies < repeated_copies,
            "n={n}: assembly {copies} copies, repeated union {repeated_copies}"
        );
        assert!(
            comparisons <= MAX_COMPARISONS_PER_SOURCE * sources,
            "n={n}: {comparisons} comparisons"
        );
        println!(
            "sources={n} immutable_merge_copies={repeated_copies} assembly_copies={copies} tree_comparisons={comparisons}"
        );
    }
}

#[test]
fn node_admission_and_freeze_overlap_are_charged_before_mutation() {
    const LIMIT: usize = 16 * 1024;
    let tracker = Tracker::new(LIMIT, 16).unwrap();
    let first = tracker
        .single(SourceFrame {
            number: 1,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let mut assembly = Accumulator::new(&first).unwrap();
    let second = tracker
        .single(SourceFrame {
            number: 2,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let pressure = fill_budget(&tracker, LIMIT);
    assert!(matches!(
        assembly.insert(&second),
        Err(super::Error::Limit { .. })
    ));
    assert_eq!(assembly.len(), 1);
    assert!(tracker.budget.reserve(1).is_err());
    assert!(matches!(assembly.freeze(), Err(super::Error::Limit { .. })));
    drop(pressure);
    drop(first);
    drop(second);
    assert_eq!(headroom(&tracker, LIMIT), fresh_headroom(LIMIT, 16));
}

#[test]
fn refused_inserts_and_freezes_release_their_charges() {
    const LIMIT: usize = 16 * 1024;
    let tracker = Tracker::new(LIMIT, 16).unwrap();
    let first = tracker
        .single(SourceFrame {
            number: 2,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let mut assembly = Accumulator::new(&first).unwrap();
    let foreign = Tracker::new(LIMIT, 16)
        .unwrap()
        .single(SourceFrame {
            number: 1,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let before = headroom(&tracker, LIMIT);
    assert!(matches!(
        assembly.insert(&foreign),
        Err(super::Error::DifferentCapture)
    ));
    assert_eq!(assembly.len(), 1);
    assert_eq!(headroom(&tracker, LIMIT), before);
    assembly.insert(&first).unwrap();
    assert_eq!(assembly.len(), 1);
    assert_eq!(headroom(&tracker, LIMIT), before);
    let snapshot = first.clone();
    let result = assembly.freeze().unwrap();
    assert_eq!(result.frames(), snapshot.frames());
    drop(result);
    drop(first);
    drop(snapshot);
    assert_eq!(headroom(&tracker, LIMIT), fresh_headroom(LIMIT, 16));
}
