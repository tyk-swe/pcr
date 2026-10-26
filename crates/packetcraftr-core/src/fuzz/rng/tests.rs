// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;

use super::SplitMix64;

fn words(seed: u64, count: usize) -> Vec<u64> {
    let mut random = SplitMix64::new(seed);
    (0..count).map(|_| random.next_u64()).collect()
}

#[test]
fn same_seed_reproduces_the_same_word_sequence() {
    for seed in [0, 1, 42, u64::MAX] {
        assert_eq!(words(seed, 32), words(seed, 32), "seed {seed}");
    }
}

#[test]
fn different_seeds_produce_different_word_sequences() {
    assert_ne!(words(0, 16), words(1, 16));
    assert_ne!(words(1, 16), words(2, 16));
    assert_ne!(words(42, 16), words(43, 16));
}

#[test]
fn successive_words_from_one_seed_do_not_repeat() {
    let sequence = words(7, 64);
    let distinct = sequence.iter().collect::<BTreeSet<_>>();
    assert_eq!(distinct.len(), sequence.len());
}

#[test]
fn bytes_returns_exactly_the_requested_length_for_the_seed() {
    for length in [0, 1, 7, 8, 9, 31, 64] {
        let bytes = SplitMix64::new(9).bytes(length);
        assert_eq!(bytes.len(), length);
        assert_eq!(bytes, SplitMix64::new(9).bytes(length));
    }
    assert_ne!(SplitMix64::new(9).bytes(32), SplitMix64::new(10).bytes(32));
}
