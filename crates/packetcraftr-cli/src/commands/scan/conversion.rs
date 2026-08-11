// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;

use super::arguments::CliScanPortSpec;

/// Expand parsed CLI port specs into the stable, deduplicated `Vec<u16>` used
/// by `packetcraftr::scan::Request`. Ranges are inclusive and iterated directly.
///
/// `max_ports` must already be validated by `packetcraftr::scan::Limits::validate`,
/// which guarantees it is non-zero and at most `u16::MAX + 1`, so converting it
/// to `u64` here is lossless and never overflows the distinct-count ceiling.
///
/// Expansion stops as soon as adding another distinct port would exceed
/// `max_ports`; it never fully expands or allocates an oversized range first.
/// Repeated ports that add no new distinct port do not consume the limit.
pub(crate) fn expand_port_specs(
    specs: &[CliScanPortSpec],
    max_ports: usize,
) -> Result<Vec<u16>, packetcraftr::scan::Error> {
    let limit = u64::try_from(max_ports).expect("max_ports fits u64 after Limits::validate");
    let mut ports: Vec<u16> = Vec::new();
    let mut seen: HashSet<u16> = HashSet::new();
    let mut push_distinct = |port: u16| -> Result<(), packetcraftr::scan::Error> {
        if !seen.insert(port) {
            return Ok(());
        }
        let distinct = u64::try_from(ports.len())
            .expect("port count never exceeds the validated max_ports ceiling");
        if distinct >= limit {
            return Err(packetcraftr::scan::Error::InvalidLimit {
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
    use super::*;

    #[test]
    fn expansion_is_stable_deduplicated_and_limit_aware() {
        let specs = [
            CliScanPortSpec::Single(443),
            CliScanPortSpec::RangeInclusive { start: 80, end: 82 },
            CliScanPortSpec::Single(80),
            CliScanPortSpec::RangeInclusive {
                start: 81,
                end: 443,
            },
        ];

        let ports = expand_port_specs(&specs, 364).expect("364 distinct ports fit");
        assert_eq!(&ports[..4], &[443, 80, 81, 82]);
        assert_eq!(ports.len(), 364);
        assert_eq!(ports.last(), Some(&442));

        let repeated = [
            CliScanPortSpec::Single(7),
            CliScanPortSpec::Single(7),
            CliScanPortSpec::RangeInclusive { start: 7, end: 8 },
        ];
        assert_eq!(
            expand_port_specs(&repeated, 2).expect("duplicates do not consume the limit"),
            vec![7, 8],
        );
    }

    #[test]
    fn expansion_stops_at_the_first_distinct_port_over_the_limit() {
        let error = expand_port_specs(
            &[CliScanPortSpec::RangeInclusive {
                start: 1,
                end: u16::MAX,
            }],
            2,
        )
        .expect_err("a third distinct port exceeds the bound");

        match error {
            packetcraftr::scan::Error::InvalidLimit {
                field,
                value,
                reason,
            } => {
                assert_eq!(field, "ports");
                assert_eq!(value, 3);
                assert_eq!(reason, "exceeds max_ports=2");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
