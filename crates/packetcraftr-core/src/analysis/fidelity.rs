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

#[derive(Default)]
struct TrieNode {
    children: BTreeMap<u8, usize>,
    parent: Option<usize>,
    operator: VecDeque<usize>,
    sensor: VecDeque<usize>,
}

/// Maximum matching for the ancestor relation in a byte trie: pair surplus
/// terminals inside each subtree before carrying the remainder upward.
fn prefix_pairs(
    operator: &[Frame],
    sensor: &[Frame],
    operator_matched: &[bool],
    sensor_matched: &[bool],
) -> Vec<(usize, usize)> {
    let mut nodes = vec![TrieNode::default()];
    let insert = |nodes: &mut Vec<TrieNode>, bytes: &[u8], index: usize, is_operator: bool| {
        let mut node_index = 0_usize;
        for byte in bytes {
            let next = match nodes[node_index].children.get(byte) {
                Some(next) => *next,
                None => {
                    let next = nodes.len();
                    nodes.push(TrieNode {
                        parent: Some(node_index),
                        ..TrieNode::default()
                    });
                    nodes[node_index].children.insert(*byte, next);
                    next
                }
            };
            node_index = next;
        }
        if is_operator {
            nodes[node_index].operator.push_back(index);
        } else {
            nodes[node_index].sensor.push_back(index);
        }
    };
    for (index, frame) in operator.iter().enumerate() {
        if !operator_matched[index] {
            insert(&mut nodes, frame.bytes(), index, true);
        }
    }
    for (index, frame) in sensor.iter().enumerate() {
        if !sensor_matched[index] {
            insert(&mut nodes, frame.bytes(), index, false);
        }
    }

    let own_counts: Vec<(usize, usize)> = nodes
        .iter()
        .map(|node| (node.operator.len(), node.sensor.len()))
        .collect();
    let mut pairs = Vec::new();
    for node_index in (0..nodes.len()).rev() {
        let (own_operator, own_sensor) = own_counts[node_index];
        let mut own_a: VecDeque<usize> = nodes[node_index].operator.drain(..own_operator).collect();
        let mut child_a = std::mem::take(&mut nodes[node_index].operator);
        let mut own_b: VecDeque<usize> = nodes[node_index].sensor.drain(..own_sensor).collect();
        let mut child_b = std::mem::take(&mut nodes[node_index].sensor);
        while !own_a.is_empty() && !child_b.is_empty() {
            pairs.push((
                own_a.pop_front().expect("checked non-empty"),
                child_b.pop_front().expect("checked non-empty"),
            ));
        }
        while !child_a.is_empty() && !own_b.is_empty() {
            pairs.push((
                child_a.pop_front().expect("checked non-empty"),
                own_b.pop_front().expect("checked non-empty"),
            ));
        }
        while !own_a.is_empty() && !own_b.is_empty() {
            pairs.push((
                own_a.pop_front().expect("checked non-empty"),
                own_b.pop_front().expect("checked non-empty"),
            ));
        }
        child_a.append(&mut own_a);
        child_b.append(&mut own_b);
        nodes[node_index].operator = child_a;
        nodes[node_index].sensor = child_b;
        if let Some(parent) = nodes[node_index].parent {
            debug_assert!(parent < node_index);
            let (left, right) = nodes.split_at_mut(node_index);
            let remaining = &mut right[0];
            let parent_node = &mut left[parent];
            parent_node.operator.append(&mut remaining.operator);
            parent_node.sensor.append(&mut remaining.sensor);
        }
    }
    pairs
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

    for (operator_index, sensor_index) in
        prefix_pairs(operator, sensor, &operator_matched, &sensor_matched)
    {
        operator_matched[operator_index] = true;
        sensor_matched[sensor_index] = true;
        report.truncated_matches += 1;
        if sensor[sensor_index].link_type != operator[operator_index].link_type {
            report.link_type_mismatches += 1;
        }
        if let Some(skew) = skew_ms(
            operator[operator_index].timestamp,
            sensor[sensor_index].timestamp,
        ) {
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
    fn prefix_matching_is_symmetric_and_maximum() {
        let operator = vec![
            frame(b"abcdef", 100, LinkType::ETHERNET),
            frame(b"abcxyz", 200, LinkType::ETHERNET),
            frame(b"short", 300, LinkType::ETHERNET),
        ];
        let sensor = vec![
            frame(b"abc", 110, LinkType::ETHERNET),
            frame(b"abcd", 210, LinkType::ETHERNET),
            frame(b"shorter", 310, LinkType::ETHERNET),
        ];
        let report = compare(&operator, &sensor);
        assert_eq!(report.truncated_matches, 3);
        assert_eq!(report.operator_only, 0);
        assert_eq!(report.sensor_only, 0);
    }

    #[test]
    fn empty_operator_side_has_no_visibility_percentage() {
        let report = compare(&[], &[frame(b"x", 1, LinkType::RAW)]);
        assert_eq!(report.sensor_only, 1);
        assert_eq!(report.visibility_percent(), None);
    }
}
