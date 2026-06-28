// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::engine::spec::FragmentSpec;
use crate::network::sender::error::FragmentError;

type Result<T> = std::result::Result<T, FragmentError>;

#[derive(Debug, Clone)]
pub(crate) struct FragmentPlan {
    pub(crate) start: usize,
    pub(crate) len: usize,
    pub(crate) more: bool,
}

pub(crate) fn plan_fragments(
    frag: &FragmentSpec,
    payload_len: usize,
    header_len: usize,
    first_fragment_extra: usize,
) -> Result<Vec<FragmentPlan>> {
    if frag.teardrop {
        return plan_teardrop_fragments(frag, payload_len);
    }
    if frag.overlap {
        return plan_overlap_fragments(frag, payload_len, header_len, first_fragment_extra);
    }
    if let Some(mtu) = frag.mtu {
        return plan_mtu_fragments(frag, payload_len, mtu, header_len, first_fragment_extra);
    }

    let mut fragments = Vec::new();
    if payload_len == 0 {
        fragments.push(FragmentPlan {
            start: 0,
            len: 0,
            more: frag.more_fragments,
        });
    } else {
        fragments.push(FragmentPlan {
            start: 0,
            len: payload_len,
            more: frag.more_fragments,
        });
    }
    Ok(fragments)
}

pub(crate) fn ensure_fragment_alignment(plan: &FragmentPlan) -> Result<()> {
    if !plan.start.is_multiple_of(8) {
        return Err(FragmentError::Misaligned { offset: plan.start });
    }
    Ok(())
}

pub(crate) fn extract_fragment_payload(plan: &FragmentPlan, transport: &[u8]) -> Vec<u8> {
    let mut payload_bytes = vec![0u8; plan.len];
    for (idx, byte) in payload_bytes.iter_mut().enumerate() {
        if let Some(value) = transport.get(plan.start + idx) {
            *byte = *value;
        }
    }
    payload_bytes
}

pub(crate) fn determine_more_flag(
    plan: &FragmentPlan,
    fragment_index: usize,
    total_fragments: usize,
) -> bool {
    if fragment_index == total_fragments - 1 {
        plan.more
    } else {
        true
    }
}

fn plan_mtu_fragments(
    frag: &FragmentSpec,
    payload_len: usize,
    mtu: u16,
    header_len: usize,
    first_fragment_extra: usize,
) -> Result<Vec<FragmentPlan>> {
    let mtu_value = mtu;
    let mtu = mtu as usize;
    if mtu <= header_len {
        return Err(FragmentError::MtuTooSmall {
            mtu: mtu_value,
            context: "headers",
        });
    }

    let available = mtu - header_len;
    if available < first_fragment_extra {
        return Err(FragmentError::MtuTooSmall {
            mtu: mtu_value,
            context: "first-fragment headers",
        });
    }

    if payload_len == 0 {
        return Ok(vec![FragmentPlan {
            start: 0,
            len: 0,
            more: frag.more_fragments,
        }]);
    }

    if available == first_fragment_extra {
        return Err(FragmentError::MtuLeavesNoPayload { mtu: mtu_value });
    }

    let max_payload = align_down(available, 8);
    if max_payload == 0 {
        return Err(FragmentError::MtuLeavesNoPayload { mtu: mtu_value });
    }

    let first_max_payload = align_down(available - first_fragment_extra, 8);
    if first_max_payload == 0 {
        return Err(FragmentError::MtuLeavesNoPayload { mtu: mtu_value });
    }

    if payload_len <= max_payload && payload_len <= first_max_payload {
        return Ok(vec![FragmentPlan {
            start: 0,
            len: payload_len,
            more: frag.more_fragments,
        }]);
    }

    ensure_fragment_allowed(frag)?;

    let mut fragments = Vec::new();
    let mut position = 0usize;

    let first_chunk = payload_len.min(first_max_payload);

    let mut remaining = payload_len;
    remaining -= first_chunk;
    fragments.push(FragmentPlan {
        start: 0,
        len: first_chunk,
        more: remaining > 0 || frag.more_fragments,
    });
    position += first_chunk;

    while position < payload_len {
        let remaining_total = payload_len - position;
        let chunk = if remaining_total > max_payload {
            max_payload
        } else {
            remaining_total
        };
        let more = remaining_total > chunk;
        fragments.push(FragmentPlan {
            start: position,
            len: chunk,
            more,
        });
        position += chunk;
    }
    if let Some(last) = fragments.last_mut() {
        last.more = last.more || frag.more_fragments; // Preserve caller preference on tail
    }
    Ok(fragments)
}

fn plan_overlap_fragments(
    frag: &FragmentSpec,
    payload_len: usize,
    header_len: usize,
    first_fragment_extra: usize,
) -> Result<Vec<FragmentPlan>> {
    ensure_fragment_allowed(frag)?;
    if payload_len < 8 {
        return Err(FragmentError::PayloadTooSmallForOverlap);
    }

    if let Some(mtu) = frag.mtu {
        let mtu_value = mtu;
        let mtu = mtu as usize;
        if mtu <= header_len + first_fragment_extra {
            return Err(FragmentError::MtuLeavesNoPayload { mtu: mtu_value });
        }
    }

    let base_size = frag // Base first fragment on aligned MTU or balanced split
        .mtu
        .map(|mtu| {
            let mtu = mtu as usize;
            let available = mtu
                .saturating_sub(header_len)
                .saturating_sub(first_fragment_extra);
            align_down(available, 8).max(8)
        })
        .unwrap_or_else(|| {
            align_down(std::cmp::max(8, payload_len / 2 + payload_len % 2), 8).max(8)
        });

    let mut first_len = std::cmp::min(payload_len, base_size);
    if !first_len.is_multiple_of(8) {
        first_len = align_down(first_len, 8);
    }
    if first_len == 0 || first_len >= payload_len {
        first_len = align_down(payload_len.saturating_sub(8), 8).max(8);
    }

    let overlap = 8.min(first_len);
    let second_start = first_len - overlap;
    let second_len = std::cmp::max(overlap, payload_len.saturating_sub(second_start));

    let fragments = vec![
        FragmentPlan {
            start: 0,
            len: first_len,
            more: true,
        },
        FragmentPlan {
            start: second_start,
            len: second_len,
            more: frag.more_fragments,
        },
    ];
    Ok(fragments)
}

fn plan_teardrop_fragments(frag: &FragmentSpec, payload_len: usize) -> Result<Vec<FragmentPlan>> {
    ensure_fragment_allowed(frag)?;
    if payload_len < 24 {
        return Err(FragmentError::PayloadTooSmallForTeardrop);
    }

    let first_len = 24usize;
    let second_start = 2 * 8;
    let mut fragments = vec![FragmentPlan {
        start: 0,
        len: first_len,
        more: true,
    }];

    let mut second_len = payload_len.saturating_sub(second_start).clamp(8, 24);
    let third_start = 4 * 8;
    let third_len = payload_len.saturating_sub(third_start);

    if third_len > 0 {
        if !second_len.is_multiple_of(8) {
            second_len = align_down(second_len, 8);
        }

        fragments.push(FragmentPlan {
            start: second_start,
            len: second_len,
            more: true,
        });
        fragments.push(FragmentPlan {
            start: third_start,
            len: third_len,
            more: frag.more_fragments,
        });
    } else {
        fragments.push(FragmentPlan {
            start: second_start,
            len: second_len,
            more: frag.more_fragments,
        });
    }

    Ok(fragments)
}

fn ensure_fragment_allowed(frag: &FragmentSpec) -> Result<()> {
    if frag.dont_fragment {
        return Err(FragmentError::FragmentationNotAllowed);
    }
    Ok(())
}

fn align_down(value: usize, alignment: usize) -> usize {
    value / alignment * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_default_spec() -> FragmentSpec {
        FragmentSpec {
            mtu: None,
            offset: None,
            more_fragments: false,
            dont_fragment: false,
            overlap: false,
            teardrop: false,
            profile: None,
            fragment_id: None,
        }
    }

    #[test]
    fn align_down_rounds_to_previous_boundary() {
        for (value, alignment, expected) in [
            (0, 8, 0),
            (7, 8, 0),
            (8, 8, 8),
            (15, 8, 8),
            (16, 8, 16),
            (25, 8, 24),
            (17, 16, 16),
            (100, 32, 96),
        ] {
            assert_eq!(align_down(value, alignment), expected);
        }
    }

    #[test]
    fn ensure_fragment_alignment_accepts_aligned_offsets_and_rejects_misaligned_offsets() {
        for offset in [0, 8, 24] {
            let plan = FragmentPlan {
                start: offset,
                len: 100,
                more: false,
            };
            assert!(ensure_fragment_alignment(&plan).is_ok());
        }

        for offset in [1, 15] {
            let plan = FragmentPlan {
                start: offset,
                len: 100,
                more: false,
            };
            let result = ensure_fragment_alignment(&plan);
            assert!(
                matches!(result, Err(FragmentError::Misaligned { offset: actual }) if actual == offset)
            );
        }
    }

    #[test]
    fn extract_fragment_payload_copies_requested_range_and_zero_pads() {
        let transport = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        for (start, len, expected) in [
            (0, 4, vec![0x01, 0x02, 0x03, 0x04]),
            (4, 4, vec![0x05, 0x06, 0x07, 0x08]),
            (6, 4, vec![0x07, 0x08, 0x00, 0x00]),
            (10, 3, vec![0x00, 0x00, 0x00]),
        ] {
            let plan = FragmentPlan {
                start,
                len,
                more: false,
            };
            assert_eq!(extract_fragment_payload(&plan, &transport), expected);
        }
    }

    #[test]
    fn determine_more_flag_forces_intermediate_fragments_and_uses_plan_value_on_tail() {
        for (index, total, plan_more, expected) in [
            (0, 3, false, true),
            (1, 3, false, true),
            (2, 3, false, false),
            (2, 3, true, true),
        ] {
            let plan = FragmentPlan {
                start: 0,
                len: 8,
                more: plan_more,
            };
            assert_eq!(determine_more_flag(&plan, index, total), expected);
        }
    }

    #[test]
    fn plan_fragments_returns_single_fragment_for_no_fragmentation() {
        let spec = create_default_spec();
        let result = plan_fragments(&spec, 100, 20, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].len, 100);
        assert!(!result[0].more);
    }

    #[test]
    fn plan_fragments_handles_zero_payload() {
        let spec = create_default_spec();
        let result = plan_fragments(&spec, 0, 20, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].len, 0);
        assert!(!result[0].more);
    }

    #[test]
    fn plan_fragments_respects_more_fragments_flag() {
        let mut spec = create_default_spec();
        spec.more_fragments = true;
        let result = plan_fragments(&spec, 100, 20, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].more);
    }

    #[test]
    fn plan_mtu_fragments_returns_error_when_mtu_too_small_for_headers() {
        let spec = create_default_spec();
        let result = plan_fragments(&spec.with_mtu(10), 100, 20, 0);
        assert!(matches!(
            result,
            Err(FragmentError::MtuTooSmall {
                mtu: 10,
                context: "headers"
            })
        ));
    }

    #[test]
    fn plan_mtu_fragments_returns_error_when_mtu_leaves_no_payload() {
        let spec = create_default_spec();
        let result = plan_fragments(&spec.with_mtu(28), 100, 20, 8);
        assert!(matches!(
            result,
            Err(FragmentError::MtuLeavesNoPayload { mtu: 28 })
        ));
    }

    #[test]
    fn plan_mtu_fragments_single_fragment_when_payload_fits() {
        let mut spec = create_default_spec();
        spec.mtu = Some(100);
        let result = plan_fragments(&spec, 50, 20, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len, 50);
        assert!(!result[0].more);
    }

    #[test]
    fn plan_mtu_fragments_multiple_fragments_when_payload_exceeds_mtu() {
        let mut spec = create_default_spec();
        spec.mtu = Some(60);
        let result = plan_fragments(&spec, 100, 20, 0).unwrap();
        assert!(result.len() >= 3);

        for (i, frag) in result.iter().enumerate() {
            if i < result.len() - 1 {
                assert_eq!(frag.len % 8, 0);
                assert!(frag.more);
            }
        }
    }

    #[test]
    fn plan_mtu_fragments_handles_first_fragment_extra_headers() {
        let mut spec = create_default_spec();
        spec.mtu = Some(100);
        let result = plan_fragments(&spec, 150, 20, 20).unwrap();
        assert!(result.len() >= 2);

        let first_available = 100 - 20 - 20;
        let first_aligned = align_down(first_available, 8);
        assert_eq!(result[0].len, first_aligned);
    }

    #[test]
    fn plan_mtu_fragments_returns_zero_length_for_zero_payload() {
        let mut spec = create_default_spec();
        spec.mtu = Some(100);
        let result = plan_fragments(&spec, 0, 20, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].len, 0);
    }

    #[test]
    fn plan_mtu_fragments_fails_when_dont_fragment_set() {
        let mut spec = create_default_spec();
        spec.mtu = Some(60);
        spec.dont_fragment = true;
        let result = plan_fragments(&spec, 200, 20, 0);
        assert!(matches!(
            result,
            Err(FragmentError::FragmentationNotAllowed)
        ));
    }

    #[test]
    fn fragmented_modes_preserve_explicit_more_flag_on_last_fragment() {
        let cases = [
            FragmentSpec {
                mtu: Some(60),
                more_fragments: true,
                ..create_default_spec()
            },
            FragmentSpec {
                overlap: true,
                more_fragments: true,
                ..create_default_spec()
            },
            FragmentSpec {
                teardrop: true,
                more_fragments: true,
                ..create_default_spec()
            },
        ];

        for spec in cases {
            let result = plan_fragments(&spec, 100, 20, 0).unwrap();
            assert!(result.last().unwrap().more, "{spec:?}");
        }
    }

    #[test]
    fn plan_overlap_fragments_creates_two_overlapping_fragments() {
        let mut spec = create_default_spec();
        spec.overlap = true;
        let result = plan_fragments(&spec, 50, 20, 0).unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].start, 0);
        assert!(result[0].more);

        assert!(result[1].start < result[0].len);
    }

    #[test]
    fn plan_overlap_fragments_returns_error_for_small_payload() {
        let mut spec = create_default_spec();
        spec.overlap = true;
        let result = plan_fragments(&spec, 5, 20, 0);
        assert!(matches!(
            result,
            Err(FragmentError::PayloadTooSmallForOverlap)
        ));
    }

    #[test]
    fn plan_overlap_fragments_respects_mtu_hint() {
        let mut spec = create_default_spec();
        spec.overlap = true;
        spec.mtu = Some(40);
        let result = plan_fragments(&spec, 50, 20, 0).unwrap();
        assert_eq!(result.len(), 2);

        let available = 40 - 20;
        let aligned = align_down(available, 8);
        assert!(result[0].len <= aligned.max(8));
    }

    #[test]
    fn plan_overlap_fragments_fails_when_dont_fragment_set() {
        let mut spec = create_default_spec();
        spec.overlap = true;
        spec.dont_fragment = true;
        let result = plan_fragments(&spec, 50, 20, 0);
        assert!(matches!(
            result,
            Err(FragmentError::FragmentationNotAllowed)
        ));
    }

    #[test]
    fn plan_teardrop_fragments_rejects_payload_causing_out_of_bounds_access() {
        // Reject payloads smaller than 24-byte first fragment min
        let mut spec = create_default_spec();
        spec.teardrop = true;

        for payload_len in 0..24 {
            let result = plan_fragments(&spec, payload_len, 20, 0);
            assert!(
                matches!(result, Err(FragmentError::PayloadTooSmallForTeardrop)),
                "Expected PayloadTooSmallForTeardrop error for payload_len={}, got {:?}",
                payload_len,
                result
            );
        }
    }

    #[test]
    fn plan_teardrop_fragments_accepts_small_payloads() {
        // Payloads between 24 and 32 bytes should be accepted.
        let mut spec = create_default_spec();
        spec.teardrop = true;

        for payload_len in 24..32 {
            let result = plan_fragments(&spec, payload_len, 20, 0);
            assert!(
                result.is_ok(),
                "Expected success for payload_len={}, got {:?}",
                payload_len,
                result
            );
            let fragments = result.unwrap();
            assert!(fragments.len() >= 2);
            assert_eq!(fragments[0].len, 24);
            // Ensure second fragment is within bounds
            assert!(fragments[1].start + fragments[1].len <= payload_len);
        }
    }

    #[test]
    fn plan_teardrop_fragments_accepts_minimum_valid_payload() {
        // Verify minimum safe size (32 bytes)
        let mut spec = create_default_spec();
        spec.teardrop = true;
        let result = plan_fragments(&spec, 32, 20, 0).unwrap();

        // Creates 2 fragments (third_len = 0)
        assert_eq!(result.len(), 2);

        // First fragment: bytes [0, 24)
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].len, 24);
        assert!(result[0].more);

        // Second fragment: bytes [16, 32) - 16 bytes
        assert_eq!(result[1].start, 16);
        assert_eq!(result[1].len, 16);
        assert!(!result[1].more);

        // Verify that extract_fragment_payload won't go out of bounds
        let payload = vec![0xAA; 32];
        let extracted = extract_fragment_payload(&result[1], &payload);
        assert_eq!(extracted.len(), 16);
        assert_eq!(
            extracted,
            vec![0xAA; 16],
            "Should extract real data, not zeros"
        );
    }

    #[test]
    fn plan_teardrop_fragments_creates_three_fragments_for_larger_payload() {
        let mut spec = create_default_spec();
        spec.teardrop = true;
        let result = plan_fragments(&spec, 60, 20, 0).unwrap();
        assert_eq!(result.len(), 3);

        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].len, 24);
        assert!(result[0].more);

        assert_eq!(result[1].start, 16);
        assert!(result[1].more);

        assert_eq!(result[2].start, 32);
        assert!(!result[2].more);
    }

    #[test]
    fn plan_teardrop_fragments_fails_when_dont_fragment_set() {
        let mut spec = create_default_spec();
        spec.teardrop = true;
        spec.dont_fragment = true;
        let result = plan_fragments(&spec, 50, 20, 0);
        assert!(matches!(
            result,
            Err(FragmentError::FragmentationNotAllowed)
        ));
    }

    impl FragmentSpec {
        fn with_mtu(mut self, mtu: u16) -> Self {
            self.mtu = Some(mtu);
            self
        }
    }

    #[test]
    fn plan_teardrop_fragments_ensures_alignment_for_intermediate_fragments() {
        let mut spec = create_default_spec();
        spec.teardrop = true;

        // Payload length 33 causes the second fragment to have len=17 if not aligned.
        // It must be aligned to 16.
        let result = plan_fragments(&spec, 33, 20, 0).unwrap();
        assert!(result.len() >= 2);

        let frag2 = &result[1];
        assert!(frag2.more);
        assert!(
            frag2.len.is_multiple_of(8),
            "Fragment 2 length {} should be a multiple of 8",
            frag2.len
        );
        assert_eq!(frag2.len, 16);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use crate::engine::spec::FragmentSpec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn fragments_reassemble_to_original_payload(
            payload in prop::collection::vec(any::<u8>(), 0..2000),
            mtu in 28u16..1500, // Needs at least 8 bytes payload (20 header + 8)
        ) {
            let spec = FragmentSpec {
                mtu: Some(mtu),
                offset: None,
                more_fragments: false,
                dont_fragment: false,
                overlap: false,
                teardrop: false,
                profile: None,
                fragment_id: None,
            };

            let header_len = 20;
            // 0 extra for first fragment (no options)
            let res = plan_fragments(&spec, payload.len(), header_len, 0);

            prop_assert!(res.is_ok(), "plan_fragments failed for mtu={}: {:?}", mtu, res.err());
            let plans = res.unwrap();

            let mut reassembled = vec![0u8; payload.len()];
            let mut bytes_written = vec![false; payload.len()];

            for plan in plans {
                // Check alignment of start
                prop_assert_eq!(plan.start % 8, 0, "start {} not aligned", plan.start);

                let frag_payload = extract_fragment_payload(&plan, &payload);
                prop_assert_eq!(frag_payload.len(), plan.len);

                for (i, &b) in frag_payload.iter().enumerate() {
                    let pos = plan.start + i;
                    if pos < reassembled.len() {
                        reassembled[pos] = b;
                        bytes_written[pos] = true;
                    }
                }
            }

            prop_assert_eq!(reassembled, payload);
            prop_assert!(bytes_written.iter().all(|&b| b));
        }
    }
}
