// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded IP-protocol number selections (`0..=255`) with exclusions applied
//! before planning budgets.

use super::Error;
use super::selection::{MAX_PORT_TERMS, Selected};
use crate::probe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProtocolSpec {
    Single(u8),
    RangeInclusive { start: u8, end: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpProtocolSelection {
    pub include: Vec<IpProtocolSpec>,
    pub exclude: Vec<IpProtocolSpec>,
}

/// Expands `include` in first-seen order, removes every protocol in `exclude`,
/// and bounds the distinct remainder by `max_ports`.
pub fn select_ip_protocols(
    selection: &IpProtocolSelection,
    max_ports: usize,
) -> Result<Selected, Error> {
    let IpProtocolSelection { include, exclude } = selection;
    let terms = include.len().saturating_add(exclude.len());
    if terms > MAX_PORT_TERMS {
        return Err(Error::InvalidLimit {
            field: "ip_protocol terms",
            value: u64::try_from(terms).unwrap_or(u64::MAX),
            reason: format!("exceeds {MAX_PORT_TERMS}"),
        });
    }
    let mut excluded = SeenProtocols::default();
    for spec in exclude {
        expand_spec(*spec, |protocol| {
            excluded.insert(protocol);
        })?;
    }
    let mut seen = SeenProtocols::default();
    let mut endpoints = Vec::new();
    let mut removed = 0usize;
    for spec in include {
        expand_spec(*spec, |protocol| {
            if !seen.insert(protocol) {
                return;
            }
            if excluded.contains(protocol) {
                removed += 1;
            } else {
                endpoints.push(probe::Endpoint::Ip { protocol });
            }
        })?;
    }
    if endpoints.is_empty() {
        return Err(Error::InvalidPort {
            message: if removed == 0 {
                "IP-protocol scans require at least one IP protocol number".to_owned()
            } else {
                "IP-protocol exclusions removed every selected IP protocol".to_owned()
            },
        });
    }
    if endpoints.len() > max_ports {
        return Err(Error::InvalidLimit {
            field: "ports",
            value: u64::try_from(endpoints.len()).unwrap_or(u64::MAX),
            reason: format!("exceeds max_ports={max_ports}"),
        });
    }
    Ok(Selected {
        endpoints,
        excluded: removed,
    })
}

fn expand_spec(spec: IpProtocolSpec, mut visit: impl FnMut(u8)) -> Result<(), Error> {
    let (start, end) = match spec {
        IpProtocolSpec::Single(protocol) => (protocol, protocol),
        IpProtocolSpec::RangeInclusive { start, end } => (start, end),
    };
    if start > end {
        return Err(Error::InvalidPort {
            message: format!("IP protocol range {start}-{end} is descending"),
        });
    }
    for protocol in start..=end {
        visit(protocol);
    }
    Ok(())
}

#[derive(Default)]
struct SeenProtocols([u64; 4]);

impl SeenProtocols {
    fn slot(protocol: u8) -> (usize, u64) {
        let index = usize::from(protocol);
        (index / 64, 1 << (index % 64))
    }

    fn insert(&mut self, protocol: u8) -> bool {
        let (word, bit) = Self::slot(protocol);
        let fresh = self.0[word] & bit == 0;
        self.0[word] |= bit;
        fresh
    }

    fn contains(&self, protocol: u8) -> bool {
        let (word, bit) = Self::slot(protocol);
        self.0[word] & bit != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_deduplicates_applies_exclusions_and_bounds_results() {
        let selected = select_ip_protocols(
            &IpProtocolSelection {
                include: vec![
                    IpProtocolSpec::RangeInclusive { start: 1, end: 6 },
                    IpProtocolSpec::Single(4),
                    IpProtocolSpec::Single(132),
                ],
                exclude: vec![
                    IpProtocolSpec::Single(2),
                    IpProtocolSpec::RangeInclusive { start: 4, end: 5 },
                ],
            },
            16,
        )
        .expect("valid selection");
        assert_eq!(
            selected.endpoints,
            vec![
                probe::Endpoint::Ip { protocol: 1 },
                probe::Endpoint::Ip { protocol: 3 },
                probe::Endpoint::Ip { protocol: 6 },
                probe::Endpoint::Ip { protocol: 132 },
            ]
        );
        assert_eq!(selected.excluded, 3);
    }
}
