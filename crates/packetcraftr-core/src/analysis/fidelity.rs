// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact and truncated-prefix comparison of two captures of the same traffic.

use std::collections::{BTreeMap, VecDeque};
use std::time::SystemTime;

use crate::frame::Frame;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub operator_frames: u64,
    pub sensor_frames: u64,
    pub exact_matches: u64,
    pub truncated_matches: u64,
    pub operator_only: u64,
    pub sensor_only: u64,
    pub link_type_mismatches: u64,
    pub max_abs_skew_ms: Option<u128>,
    pub median_abs_skew_ms: Option<u128>,
}

impl Report {
    #[must_use]
    pub fn seen(&self) -> u64 {
        self.exact_matches + self.truncated_matches
    }

    #[must_use]
    pub fn visibility_percent(&self) -> Option<f64> {
        if self.operator_frames == 0 {
            return None;
        }
        Some(self.seen() as f64 * 100.0 / self.operator_frames as f64)
    }
}

fn skew_ms(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<u128> {
    let (Some(left), Some(right)) = (left, right) else {
        return None;
    };
    let duration = match left.duration_since(right) {
        Ok(duration) => duration,
        Err(error) => error.duration(),
    };
    Some(duration.as_millis())
}

fn median(values: &mut [u128]) -> Option<u128> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

#[must_use]
pub fn compare(operator: &[Frame], sensor: &[Frame]) -> Report {
    let mut report = Report {
        operator_frames: operator.len() as u64,
        sensor_frames: sensor.len() as u64,
        ..Report::default()
    };
    let mut sensor_exact: BTreeMap<&[u8], VecDeque<usize>> = BTreeMap::new();
    for (index, frame) in sensor.iter().enumerate() {
        sensor_exact
            .entry(frame.bytes())
            .or_default()
            .push_back(index);
    }

    let mut operator_matched = vec![false; operator.len()];
    let mut sensor_matched = vec![false; sensor.len()];
    let mut skews = Vec::new();
    for (index, frame) in operator.iter().enumerate() {
        let Some(queue) = sensor_exact.get_mut(frame.bytes().as_ref()) else {
            continue;
        };
        let Some(sensor_index) = queue.pop_front() else {
            continue;
        };
        operator_matched[index] = true;
        sensor_matched[sensor_index] = true;
        report.exact_matches += 1;
        if frame.link_type != sensor[sensor_index].link_type {
            report.link_type_mismatches += 1;
        }
        if let Some(skew) = skew_ms(frame.timestamp, sensor[sensor_index].timestamp) {
            skews.push(skew);
        }
    }

    // A truncated capture keeps a strict prefix of the full frame. Index the
    // remaining operator frames by their lexicographic byte order so a
    // sensor prefix finds its candidate without a pairwise scan.
    let mut operator_by_bytes: BTreeMap<&[u8], VecDeque<usize>> = BTreeMap::new();
    for (index, frame) in operator.iter().enumerate() {
        if !operator_matched[index] {
            operator_by_bytes
                .entry(frame.bytes())
                .or_default()
                .push_back(index);
        }
    }
    for (sensor_index, frame) in sensor.iter().enumerate() {
        if sensor_matched[sensor_index] {
            continue;
        }
        let candidate = operator_by_bytes
            .range(frame.bytes().as_ref()..)
            .next()
            .filter(|(bytes, _)| {
                bytes.starts_with(frame.bytes()) || frame.bytes().starts_with(bytes)
            })
            .map(|(bytes, _)| (**bytes).to_owned());
        let Some(candidate) = candidate else {
            continue;
        };
        let Some(queue) = operator_by_bytes.get_mut(candidate.as_slice()) else {
            continue;
        };
        let Some(operator_index) = queue.pop_front() else {
            continue;
        };
        if queue.is_empty() {
            operator_by_bytes.remove(candidate.as_slice());
        }
        operator_matched[operator_index] = true;
        sensor_matched[sensor_index] = true;
        report.truncated_matches += 1;
        if frame.link_type != operator[operator_index].link_type {
            report.link_type_mismatches += 1;
        }
        if let Some(skew) = skew_ms(operator[operator_index].timestamp, frame.timestamp) {
            skews.push(skew);
        }
    }

    report.operator_only = operator_matched.iter().filter(|matched| !**matched).count() as u64;
    report.sensor_only = sensor_matched.iter().filter(|matched| !**matched).count() as u64;
    report.max_abs_skew_ms = skews.iter().copied().max();
    report.median_abs_skew_ms = median(&mut skews);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::LinkType;
    use std::time::{Duration, UNIX_EPOCH};

    fn frame(bytes: &[u8], at_ms: u64, link_type: LinkType) -> Frame {
        Frame::new(
            Some(UNIX_EPOCH + Duration::from_millis(at_ms)),
            link_type,
            bytes.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn exact_truncated_and_unmatched_frames_are_separate() {
        let operator = vec![
            frame(b"abcdef", 1_000, LinkType::ETHERNET),
            frame(b"ghijkl", 2_000, LinkType::ETHERNET),
            frame(b"mnopqr", 3_000, LinkType::ETHERNET),
        ];
        let sensor = vec![
            frame(b"abcdef", 1_010, LinkType::RAW),
            frame(b"ghij", 2_020, LinkType::ETHERNET),
            frame(b"stuvwx", 9_000, LinkType::ETHERNET),
        ];
        let report = compare(&operator, &sensor);
        assert_eq!(report.exact_matches, 1);
        assert_eq!(report.truncated_matches, 1);
        assert_eq!(report.operator_only, 1);
        assert_eq!(report.sensor_only, 1);
        assert_eq!(report.link_type_mismatches, 1);
        assert_eq!(report.max_abs_skew_ms, Some(20));
        assert_eq!(report.median_abs_skew_ms, Some(20));
        assert_eq!(report.visibility_percent(), Some(200.0 / 3.0));
    }

    #[test]
    fn duplicates_pair_one_to_one_in_order() {
        let operator = vec![
            frame(b"same", 100, LinkType::ETHERNET),
            frame(b"same", 200, LinkType::ETHERNET),
        ];
        let sensor = vec![frame(b"same", 105, LinkType::ETHERNET)];
        let report = compare(&operator, &sensor);
        assert_eq!(report.exact_matches, 1);
        assert_eq!(report.operator_only, 1);
        assert_eq!(report.max_abs_skew_ms, Some(5));
    }

    #[test]
    fn empty_operator_side_has_no_visibility_percentage() {
        let report = compare(&[], &[frame(b"x", 1, LinkType::RAW)]);
        assert_eq!(report.sensor_only, 1);
        assert_eq!(report.visibility_percent(), None);
    }
}
