// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use packetcraftr::live as workflow;

use super::arguments::CliScanPortSpec;

/// Expand parsed CLI port specs into the stable, deduplicated `Vec<u16>` used
/// by `workflow::scan::Request`. Ranges are inclusive and iterated directly.
///
/// `max_ports` must already be validated by `workflow::scan::Limits::validate`,
/// which guarantees it is non-zero and at most `u16::MAX + 1`, so converting it
/// to `u64` here is lossless and never overflows the distinct-count ceiling.
///
/// Expansion stops as soon as adding another distinct port would exceed
/// `max_ports`; it never fully expands or allocates an oversized range first.
/// Repeated ports that add no new distinct port do not consume the limit.
pub(crate) fn expand_port_specs(
    specs: &[CliScanPortSpec],
    max_ports: usize,
) -> Result<Vec<u16>, workflow::scan::Error> {
    let limit = u64::try_from(max_ports).expect("max_ports fits u64 after Limits::validate");
    let mut ports: Vec<u16> = Vec::new();
    let mut seen: HashSet<u16> = HashSet::new();
    let mut push_distinct = |port: u16| -> Result<(), workflow::scan::Error> {
        if !seen.insert(port) {
            return Ok(());
        }
        let distinct = u64::try_from(ports.len())
            .expect("port count never exceeds the validated max_ports ceiling");
        if distinct >= limit {
            return Err(workflow::scan::Error::InvalidLimit {
                field: "ports",
                value: distinct + 1,
                reason: format!("exceeds max_ports={max_ports}"),
            });
        }
        ports.push(port);
        Ok(())
    };
    for spec in specs {
        match *spec {
            CliScanPortSpec::Single(port) => push_distinct(port)?,
            CliScanPortSpec::RangeInclusive { start, end } => {
                for port in start..=end {
                    push_distinct(port)?;
                }
            }
        }
    }
    Ok(ports)
}
