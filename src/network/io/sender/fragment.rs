// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::spec::FragmentSpec;
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
        if mtu - header_len - first_fragment_extra < 8 {
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
