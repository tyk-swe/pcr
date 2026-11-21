// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

pub const ATTEMPTS_PER_VARIANT: u32 = 4096;

#[must_use]
pub fn encode_sequence(base: u32, variant_index: usize, attempt_seq: u32) -> Option<u32> {
    if attempt_seq >= ATTEMPTS_PER_VARIANT {
        return None;
    }
    let variant_offset = u32::try_from(variant_index)
        .ok()?
        .checked_mul(ATTEMPTS_PER_VARIANT)?;
    Some(base.wrapping_add(variant_offset.wrapping_add(attempt_seq)))
}

#[must_use]
pub fn decode_sequence(base: u32, sequence: u32) -> (usize, u32) {
    let delta = sequence.wrapping_sub(base);
    (
        (delta / ATTEMPTS_PER_VARIANT) as usize,
        delta % ATTEMPTS_PER_VARIANT,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub variant_index: usize,
    pub attempt_seq: u32,
    pub options_sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub variant_index: usize,
    pub attempts_seen: usize,
    pub distinct_attempts: usize,
    pub option_digests: Vec<String>,
}

#[must_use]
pub fn classify(observations: &[Observation]) -> Vec<Row> {
    let mut by_variant: BTreeMap<
        usize,
        (
            usize,
            std::collections::BTreeSet<u32>,
            std::collections::BTreeSet<String>,
        ),
    > = BTreeMap::new();
    for observation in observations {
        let entry = by_variant.entry(observation.variant_index).or_default();
        entry.0 += 1;
        entry.1.insert(observation.attempt_seq);
        entry.2.insert(observation.options_sha256.clone());
    }
    by_variant
        .into_iter()
        .map(|(variant_index, (seen, attempts, digests))| Row {
            variant_index,
            attempts_seen: seen,
            distinct_attempts: attempts.len(),
            option_digests: digests.into_iter().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_encoding_round_trips_across_the_wrap_boundary() {
        let base = u32::MAX - 10;
        let encoded = encode_sequence(base, 2, 20).unwrap();
        assert_eq!(decode_sequence(base, encoded), (2, 20));
        assert!(encode_sequence(base, 0, ATTEMPTS_PER_VARIANT).is_none());
    }

    #[test]
    fn classify_counts_duplicate_captures_without_double_counting_attempts() {
        let observation = Observation {
            variant_index: 1,
            attempt_seq: 7,
            options_sha256: "a".repeat(64),
        };
        let rows = classify(&[observation.clone(), observation]);
        assert_eq!(rows[0].attempts_seen, 2);
        assert_eq!(rows[0].distinct_attempts, 1);
        assert_eq!(rows[0].option_digests.len(), 1);
    }
}
