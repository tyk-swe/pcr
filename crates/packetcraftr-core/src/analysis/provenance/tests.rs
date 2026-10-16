// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Private work counters are compiled only into core's unit-test target. Public
// protocol behavior is covered by the retained integration contracts.
use super::{Accumulator, SourceFrame, Tracker, work};
use std::time::UNIX_EPOCH;

fn fragment_entry(tracker: &mut Tracker, identification: u16) -> super::DatagramKey {
    let mut scopes = crate::analysis::scope::Interner::new();
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

#[test]
fn retirement_preserves_key_order_active_entries_and_omission_counts() {
    let mut tracker = Tracker::new(64 * 1024, 2).unwrap();
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
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        2048 + 2 * (256 + std::mem::size_of::<SourceFrame>())
    );
}

#[test]
fn retirement_keeps_extracted_metadata_charged_until_freeze_finishes() {
    let source_charge = 256 + std::mem::size_of::<SourceFrame>();
    let mut tracker = Tracker::new(2048 + 2048 + 512 + source_charge, 1).unwrap();
    fragment_entry(&mut tracker, 1);
    let occupied = tracker.budget.reserve(source_charge).unwrap();
    assert!(matches!(
        tracker.retire(|_| false),
        Err(super::Error::Limit { .. })
    ));
    assert!(tracker.entries.is_empty());
    assert!(tracker.incomplete.is_empty());
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        2048 + source_charge
    );
    drop(occupied);
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        2048
    );
}

#[test]
fn assembly_copies_once_and_tree_discovery_grows_n_log_n() {
    for n in [64, 256, 1024, 4096] {
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
        let (_, old_copies) = work::take();
        assert_eq!(old_copies, ((n * (n + 1)) / 2 - 1) as usize);
        let mut assembly = Accumulator::new(&sets[0]).unwrap();
        for set in &sets[1..] {
            assembly.insert(set).unwrap();
        }
        let result = assembly.freeze().unwrap();
        let (comparisons, copies) = work::take();
        assert_eq!(result.frames(), repeated.frames());
        assert_eq!(copies, 2 * n as usize);
        assert!(
            comparisons <= n as usize * 64,
            "n={n}: {comparisons} comparisons"
        );
        println!(
            "sources={n} immutable_merge_copies={old_copies} assembly_copies={copies} tree_comparisons={comparisons}"
        );
    }
}

#[test]
fn node_admission_and_freeze_overlap_are_charged_before_mutation() {
    let source_charge = 256 + std::mem::size_of::<SourceFrame>();
    let ceiling = 2048 + 2 * source_charge + 512;
    let tracker = Tracker::new(ceiling, 16).unwrap();
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
    let used = || {
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire)
    };
    assert_eq!(used(), ceiling);
    assert!(matches!(
        assembly.insert(&second),
        Err(super::Error::Limit { .. })
    ));
    assert_eq!(assembly.len(), 1);
    assert_eq!(used(), ceiling);
    // The flat result cannot be allocated by releasing the tree first: both
    // allocations overlap until the conversion has finished.
    assert!(matches!(assembly.freeze(), Err(super::Error::Limit { .. })));
    assert_eq!(used(), 2048 + 2 * source_charge);
    drop(first);
    drop(second);
    assert_eq!(used(), 2048);
}

#[test]
fn refused_inserts_and_freezes_release_exact_charges() {
    let tracker = Tracker::new(16 * 1024, 16).unwrap();
    let first = tracker
        .single(SourceFrame {
            number: 2,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let mut assembly = Accumulator::new(&first).unwrap();
    let foreign = Tracker::new(16 * 1024, 16)
        .unwrap()
        .single(SourceFrame {
            number: 1,
            timestamp: UNIX_EPOCH,
        })
        .unwrap();
    let before = tracker
        .budget
        .used
        .load(std::sync::atomic::Ordering::Acquire);
    assert!(matches!(
        assembly.insert(&foreign),
        Err(super::Error::DifferentCapture)
    ));
    assert_eq!(assembly.len(), 1);
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        before
    );
    assembly.insert(&first).unwrap();
    assert_eq!(assembly.len(), 1);
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        before
    );
    let snapshot = first.clone();
    let result = assembly.freeze().unwrap();
    assert_eq!(result.frames(), snapshot.frames());
    drop(result);
    drop(first);
    drop(snapshot);
    assert_eq!(
        tracker
            .budget
            .used
            .load(std::sync::atomic::Ordering::Acquire),
        2048
    );
}
