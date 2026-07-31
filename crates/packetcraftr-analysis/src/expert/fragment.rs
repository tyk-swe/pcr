// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::diagnostic::DiagnosticSeverity;
use packetcraftr_session::fragment::{DatagramKey, Event};

use super::{Finding, new_finding};

pub(super) fn observe(events: &[Event], number: u64, findings: &mut Vec<Finding>) {
    for event in events {
        match event {
            Event::Overlap {
                key,
                offset,
                end,
                length,
                conflicting,
            } => findings.push(new_finding(
                if *conflicting {
                    DiagnosticSeverity::Error
                } else {
                    DiagnosticSeverity::Warning
                },
                if *conflicting {
                    "ip.fragment_overlap_conflicting"
                } else {
                    "ip.fragment_overlap"
                },
                number,
                None,
                format!(
                    "{} fragment {} -> {} identification {} next-header {} overlaps retained \
                     range {}..{} ({} byte(s)); overlapping bytes are {}",
                    family(key),
                    key.source,
                    key.destination,
                    key.identification,
                    key.next_header,
                    offset,
                    end,
                    length,
                    if *conflicting {
                        "conflicting"
                    } else {
                        "identical"
                    }
                ),
            )),
            Event::Expired {
                key,
                received_bytes,
                fragment_count,
                missing_ranges,
                final_length,
            } => {
                if !missing_ranges.is_empty() {
                    let ranges = missing_ranges
                        .iter()
                        .map(|range| format!("{}..{}", range.start, range.end))
                        .collect::<Vec<_>>()
                        .join(", ");
                    findings.push(new_finding(
                        DiagnosticSeverity::Warning,
                        "ip.fragment_gap",
                        number,
                        None,
                        format!(
                            "{} fragment datagram {} -> {} identification {} next-header {} is \
                             missing range(s) {ranges}",
                            family(key),
                            key.source,
                            key.destination,
                            key.identification,
                            key.next_header,
                        ),
                    ));
                }
                findings.push(new_finding(
                    DiagnosticSeverity::Warning,
                    "ip.fragment_incomplete",
                    number,
                    None,
                    format!(
                        "{} fragment datagram {} -> {} identification {} next-header {} did not \
                         reassemble after {} fragment(s) and {} received byte(s); final length {}",
                        family(key),
                        key.source,
                        key.destination,
                        key.identification,
                        key.next_header,
                        fragment_count,
                        received_bytes,
                        final_length
                            .map_or_else(|| "unknown".to_owned(), |length| length.to_string())
                    ),
                ));
            }
            Event::Complete(_) => {}
        }
    }
}

fn family(key: &DatagramKey) -> &'static str {
    if key.source.is_ipv4() { "IPv4" } else { "IPv6" }
}
