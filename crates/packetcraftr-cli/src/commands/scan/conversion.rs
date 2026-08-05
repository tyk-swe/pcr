// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use packetcraftr::workflow;

use crate::arguments::CliScanPortSpec;
use crate::errors::CliError;
use crate::runtime::validate_interface_selector;

pub(crate) fn validate_live_interface_selector(
    command: &str,
    selector: Option<&str>,
) -> Result<(), CliError> {
    validate_interface_selector(command, selector).map(|_| ())
}

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

#[cfg(test)]
mod tests {
    use super::CliScanPortSpec;
    use super::expand_port_specs;

    #[test]
    fn singles_retain_first_seen_order() {
        let specs = [
            CliScanPortSpec::Single(443),
            CliScanPortSpec::Single(80),
            CliScanPortSpec::Single(53),
        ];
        assert_eq!(expand_port_specs(&specs, 1024).unwrap(), [443, 80, 53]);
    }

    #[test]
    fn overlapping_ranges_deduplicate_stably() {
        let specs = [
            CliScanPortSpec::RangeInclusive { start: 80, end: 82 },
            CliScanPortSpec::Single(81),
            CliScanPortSpec::RangeInclusive { start: 82, end: 84 },
        ];
        assert_eq!(
            expand_port_specs(&specs, 1024).unwrap(),
            [80, 81, 82, 83, 84]
        );
    }

    #[test]
    fn mixed_first_seen_order_matches_the_documented_example() {
        let specs = [
            CliScanPortSpec::RangeInclusive { start: 80, end: 82 },
            CliScanPortSpec::Single(81),
            CliScanPortSpec::Single(443),
            CliScanPortSpec::RangeInclusive { start: 82, end: 84 },
        ];
        assert_eq!(
            expand_port_specs(&specs, 1024).unwrap(),
            [80, 81, 82, 443, 83, 84]
        );
    }

    #[test]
    fn helper_rejects_immediately_when_the_next_distinct_port_exceeds_max_ports() {
        // Reaching the limit exactly is allowed; the next distinct port rejects.
        let at_limit = [
            CliScanPortSpec::Single(80),
            CliScanPortSpec::Single(81),
            CliScanPortSpec::Single(82),
        ];
        assert_eq!(expand_port_specs(&at_limit, 3).unwrap(), [80, 81, 82]);

        // A range crossing the limit rejects as soon as the next distinct port
        // would exceed it, not after fully expanding.
        let over = [CliScanPortSpec::RangeInclusive { start: 80, end: 84 }];
        let error = expand_port_specs(&over, 3).unwrap_err();
        assert!(matches!(
            error,
            packetcraftr::workflow::scan::Error::InvalidLimit { field: "ports", .. }
        ));
        assert!(
            error.to_string().contains("exceeds max_ports=3"),
            "{}",
            error
        );
    }

    #[test]
    fn repeated_values_that_add_no_distinct_ports_do_not_consume_the_limit() {
        let specs = [
            CliScanPortSpec::Single(80),
            CliScanPortSpec::Single(80),
            CliScanPortSpec::Single(80),
        ];
        assert_eq!(expand_port_specs(&specs, 1).unwrap(), [80]);
    }

    #[test]
    fn empty_specs_remain_empty_preserving_icmp_behavior() {
        let specs: [CliScanPortSpec; 0] = [];
        assert!(expand_port_specs(&specs, 1024).unwrap().is_empty());
    }
}
